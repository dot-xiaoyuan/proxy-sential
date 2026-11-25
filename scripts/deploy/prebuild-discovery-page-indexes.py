#!/usr/bin/env python3
"""Emit a psql script for a discovery index migration's concurrent prebuild or verification."""
from pathlib import Path
import argparse


def prebuild(migration: str, verify_only: bool = False) -> str:
    definitions = migration.split("-- BEGIN PAGE INDEX SPECIFICATIONS\n", 1)[1]
    definitions = definitions.split("\n-- END PAGE INDEX SPECIFICATIONS", 1)[0]
    guard = migration.split("DO $page_indexes$", 1)[1].split("END $page_indexes$;", 1)[0]
    build = f"""SET max_parallel_maintenance_workers=0;
SET lock_timeout='5s';
SELECT format('CREATE INDEX CONCURRENTLY %I ON %I.%I %s',
              index_name,current_schema(),table_name,key_sql)
FROM (
{definitions}
) v(index_name,table_name,key_sql)
WHERE to_regclass(format('%I.%I',current_schema(),index_name)) IS NULL
\\gexec
"""
    return "\\set ON_ERROR_STOP on\n" + ("SET lock_timeout='5s';\n" if verify_only else build) + """BEGIN;
SET LOCAL proxy_sentinel.discovery_page_verify_only='on';
""" + "DO $page_indexes$" + guard + "END $page_indexes$;\nROLLBACK;\n"


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("migration", type=Path, nargs="?",
                        default=Path(__file__).resolve().parents[2] /
                                "migrations/postgres/256_discovery_page_indexes.sql")
    parser.add_argument("--verify-only", action="store_true",
                        help="validate existing indexes without building missing indexes")
    args = parser.parse_args()
    print(prebuild(args.migration.read_text(), args.verify_only), end="")
