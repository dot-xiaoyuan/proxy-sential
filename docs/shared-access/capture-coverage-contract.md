# 共享窗口采集覆盖事实契约

通过既有受权限保护的诊断接收路径消费采集端事实，不新增190侧服务。外层为标准 ingest.Diagnostic，Stage=capture_health、Type=capture_coverage、SensorID与Collector.Kind匹配共享窗口采集器与标准事件来源。Timestamp是来源心跳时间，不是查询完成时间。

Details包含 schema_version=capture-coverage/v1、campus_id、access_domain、covered_from、covered_to、complete(bool)、stopped(bool)、query_truncated(bool)、dropped_packets(非负整数)。覆盖区间必须来自真实测量，dropped_packets对应该区间；不能把累计值、默认零或收到流量当成完整覆盖证明。缺字段或类型错误阻断。

每个参与窗口的来源都要求事实不超过5秒、覆盖该窗口完整区间、没有停止/丢包/截断，且范围一致。来源停止后必须报告stopped；无报告则在5秒后过期。范围错误、未来时间、诊断查询失败或读取达到有界上限均不能证明覆盖。最新异常事实不复用旧健康结果。

本契约消费与回放已实现；真实采集端该事实生成和网络范围验收尚未完成，不能标记现场采集健康通过。不凭正常心跳或未知负例解除处罚或增加独立违规轮次。
