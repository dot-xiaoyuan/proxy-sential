# 应用域名包与观测接口 v1

此契约供 featurelib-new 离线生产、Proxy Sentinel 离线消费。现有设备指纹包和游戏加速器规则格式不变。

## 包结构

使用 tar.gz；只允许普通文件：manifest.json、applications.json、domain-rules.json、licenses/ 下的许可文件。不允许路径穿越、链接、重复条目和额外文件。压缩包最大 32 MiB，解压内容最大 128 MiB。

manifest.json 示例：

```json
{"schema_version":"application-domain-bundle/v1","version":"2026.09.08.1","created_at":"2026-09-08T00:00:00Z","sources":[{"name":"reviewed-local","version":"1","license":"internal-rule"}],"files":{"applications.json":{"size":0,"sha256":"由文件实际内容计算"},"domain-rules.json":{"size":0,"sha256":"由文件实际内容计算"},"licenses/NOTICE.txt":{"size":0,"sha256":"由文件实际内容计算"}}}
```

applications.json 是对象，含 applications、ecosystems、infrastructures 三个数组。每个目标含 id、name、category；vendor、aliases 可选。ID 在所属目标类型内稳定唯一。

```json
{"applications":[{"id":"wechat","name":"微信","category":"social","vendor":"Tencent","aliases":["WeChat"]}],"ecosystems":[],"infrastructures":[]}
```

domain-rules.json 是数组。例：

```json
[{"rule_id":"wechat-sni-1","domain":"weixin.qq.com","match_type":"suffix","target_type":"application","target_id":"wechat","confidence":0.95,"source":"reviewed-local","source_version":"1"}]
```

生产者仅导出审核通过的规则。消费者校验结构、来源声明、目标引用及冲突，无法代替生产者的人工作业审核。每条来源 name/version 必须在 manifest 中声明，并随包包含非空许可说明。不能仅通过 AI 置信度发布。

exact 仅完整匹配；suffix 匹配根域及带点边界的子域。统一小写、去尾点及 IDN ASCII；拒绝 IP、公共后缀和非法标签。最长域名优先，同域 exact 优先；同域同类型重复规则（即使目标相同）也应由生产者合并后发布。生态、基础设施不计入具体应用。

## 未知域名 JSONL

每行字段固定为 domain、source_field、first_seen、last_seen、observation_count、sensor_id、bundle_version。source_field 为 dns.query/http.host/tls.sni/quic.sni。同域名不同来源、传感器或版本分别聚合。无库时版本为 none。不包含 IP、账号、完整 URL。

## API

所有接口位于 /api/v1，下列 GET 需要 dpi:read；未知导出需要 exports:read。POST 需要 device-fingerprint-library:update，并遵守现有 CSRF 与全局只读开关。

| 方法与路径 | 行为 |
| --- | --- |
| GET /application-library | 开关、当前/保留版本、后台进度及错误 |
| POST /application-library/import | 原始 gzip 请求体，不是 multipart |
| POST /application-library/rollback | JSON：version |
| POST /application-library/reclassify | 启动最近七天任务，重启后继续 |
| GET /application-activity | 应用排行、计量桶、版本分布 |
| GET /application-activity/observations | 分页明细，limit 1–200，offset 默认 0 |
| GET /application-activity/unknown-domains | JSONL 文件 |

查询支持 window（10m/1h/24h/7d）、from/to（RFC3339，左闭右开）、sensor_id、campus_id、ip、application_id。时间范围必须位于保留的最近七天。application_id 仅筛选应用排行和明细；汇总质量指标、未知域名导出仍针对选定时间/传感器/园区/IP 范围，避免未知数据被应用条件排除。

旧 /activity/reports?dimension=application 继续返回应用协议。

## 连接与计量

适配器仅在已知 sensor、collector 类型、collector instance、源连接 ID 时生成 flow.connection_id；SHA-256 输入是这四个字符串的 JSON 数组。源连接 ID 不能先转浮点数。

DNS 只作为域名观测。HTTP/TLS/QUIC 通过相同 connection_id 关联 flow 累计字节，不通过 DNS 的共享目标 IP 外推。累计上/下行各取最大值；未提供方向计量为 null，不用零伪装。混合完整/缺失连接的应用合计为已知部分，同时返回 missing_meter_connections。

同连接多个应用的字节进入 multi_application 桶。没有具体应用的连接进入 unknown 桶（含生态/基础设施归属）。没有连接标识的非 DNS 事件进入 missing_connection_observations。终端数按 campus_id+IP 去重，不代表自然人数。

字节表示“窗口内有观测连接的累计字节”，不是窗口内传输增量。保留窗口外的早期证据可能不可用。版本分布按窗口内去重观测计数。

confidence 与 featurelib-new v1 约定一致，范围为 [0,1]；0 表示来源未给出量化评分，不表示未通过人工审核。消费者保留 0 并展示“未评估”，不会自动提高分数；应用规则命中仍以审核发布包中的域名映射为依据。
