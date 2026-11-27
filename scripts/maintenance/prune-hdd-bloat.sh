#!/usr/bin/env bash
# 单机 HDD 受控存量瘦身脚本：
# - 仅清理无业务引用的高频冗余数据：policy_decision_records 中的 insufficient/expired 过程行、
#   以及 ClickHouse system.query_log 运维日志。
# - 严格保护：唯一原文表、所有 matched/whitelist_suppressed 决策记录、所有案件关联证据。
# - 默认 --dry-run 只读估算，显式传 --execute 才按小批次限速清理。
set -euo pipefail

MODE="dry-run"
BATCH_SIZE=5000
MAX_BATCHES=200
SLEEP_SEC=0.3
RETENTION_HOURS=24
PG_CONTAINER="${PG_CONTAINER:-proxy-sentinel-postgres}"
CH_CONTAINER="${CH_CONTAINER:-proxy-sentinel-clickhouse}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --dry-run) MODE="dry-run"; shift ;;
    --execute) MODE="execute"; shift ;;
    --batch-size) BATCH_SIZE="${2:-5000}"; shift 2 ;;
    --max-batches) MAX_BATCHES="${2:-200}"; shift 2 ;;
    --sleep) SLEEP_SEC="${2:-0.3}"; shift 2 ;;
    --retention-hours) RETENTION_HOURS="${2:-24}"; shift 2 ;;
    *) echo "用法: $0 [--dry-run|--execute] [--batch-size N] [--max-batches N] [--sleep SEC] [--retention-hours H]" >&2; exit 2 ;;
  esac
done

echo "[prune-hdd-bloat] mode=$MODE batch_size=$BATCH_SIZE max_batches=$MAX_BATCHES retention_hours=$RETENTION_HOURS"

# 1. ClickHouse system.query_log 控容检查与清理
if docker ps --format '{{.Names}}' | grep -qx "$CH_CONTAINER"; then
  echo "=== [CH] system.query_log 当前体积 ==="
  docker exec "$CH_CONTAINER" clickhouse-client --query "SELECT table, formatReadableSize(sum(bytes_on_disk)) AS size, sum(rows) AS rows FROM system.parts WHERE active AND database='system' AND table LIKE '%log%' GROUP BY table ORDER BY sum(bytes_on_disk) DESC"
  if [[ "$MODE" == "execute" ]]; then
    echo "=== [CH] 为 system 运维日志表设置 3 天 TTL 并清理超期日志 ==="
    for ch_log in query_log processors_profile_log trace_log part_log metric_log asynchronous_metric_log; do
      docker exec "$CH_CONTAINER" clickhouse-client --query "ALTER TABLE system.${ch_log} MODIFY TTL event_date + INTERVAL 3 DAY" >/dev/null 2>&1 || true
      docker exec "$CH_CONTAINER" clickhouse-client --query "ALTER TABLE system.${ch_log} DELETE WHERE event_date < today() - 3" >/dev/null 2>&1 || true
    done
  fi
fi

# 2. PostgreSQL policy_decision_records 非命中过程行受控分批清理
if docker ps --format '{{.Names}}' | grep -qx "$PG_CONTAINER"; then
  echo "=== [PG] policy_decision_records 当前体积 ==="
  docker exec "$PG_CONTAINER" psql -U proxy_sentinel -d proxy_sentinel -c "SELECT pg_size_pretty(pg_total_relation_size('policy_decision_records')) AS total_size, n_live_tup, n_dead_tup FROM pg_stat_user_tables WHERE relname='policy_decision_records';"
  if [[ "$MODE" == "dry-run" ]]; then
    echo "=== [PG] dry-run 模式：确认保护边界（不删 matched/whitelist_suppressed 或任何案件关联记录）==="
    docker exec "$PG_CONTAINER" psql -U proxy_sentinel -d proxy_sentinel -c "SELECT tablename, attname, most_common_vals, most_common_freqs FROM pg_stats WHERE tablename='policy_decision_records' AND attname='result';"
  else
    deleted_total=0
    for ((i=1; i<=MAX_BATCHES; i++)); do
      deleted=$(docker exec "$PG_CONTAINER" psql -U proxy_sentinel -d proxy_sentinel -tA -c "
        WITH victim AS (
          SELECT decision_id FROM policy_decision_records
          WHERE trigger_type='shared_access'
            AND result IN ('insufficient','expired')
            AND evaluated_at < now() - interval '${RETENTION_HOURS} hours'
          LIMIT ${BATCH_SIZE}
        ),
        del AS (
          DELETE FROM policy_decision_records p
          USING victim v
          WHERE p.decision_id = v.decision_id
          RETURNING 1
        )
        SELECT count(*) FROM del;
      ")
      deleted="${deleted:-0}"
      deleted_total=$((deleted_total + deleted))
      if (( i % 20 == 0 || deleted < BATCH_SIZE )); then
        echo "[PG] batch=$i deleted=$deleted total_deleted=$deleted_total"
      fi
      if (( deleted < BATCH_SIZE )); then
        break
      fi
      sleep "$SLEEP_SEC"
    done
    echo "=== [PG] 本轮共清理 insufficient/expired 过程行: $deleted_total ==="
  fi
fi
