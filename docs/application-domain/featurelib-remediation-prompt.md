# featurelib-new 整改任务 Prompt

以下内容可直接发送给独立的 featurelib-new 开发任务。本次 Sentinel 实现没有修改该项目。

```text
请整改 /Users/yuantong/Developer/Projects/golang/featurelib-new，使其成为 Proxy Sentinel 的应用域名特征管理与离线发布程序。

先读取 AGENTS.md，检查实现，再执行整改。所有 git 提交信息使用中文。
只修改 featurelib-new，不修改 Sentinel，不部署生产，不操作生产数据库。
保留旧数据，迁移先生成 dry-run 报告。不要覆盖当前未提交改动。

目标：保留未知域名收集、候选分类、审核及发布能力；修正匹配语义和错误归属，建立稳定应用目录，导出 application-domain-bundle/v1。第一版不做在线同步，不接入 nDPI。

先读取 Sentinel 已落地契约（只读）：
/Users/yuantong/Developer/Projects/golang/proxy-sentinel/docs/application-domain/contract.md
以及 examples/application-domain/matching-vectors.json、unknown-domains.jsonl。
可只读参考 internal/appdomain/bundle.go，或用 go run ./cmd/application-bundle --verify 验证生成包。
两边契约必须一致；不能自行替换为旧游戏加速器 application-signatures.json 格式。

1. 匹配语义和并发
- 新规则仅支持 exact 和 suffix。exact 仅匹配完整域名；suffix 匹配根域及带点边界的子域。
- 删除从子域自动派生父域规则。最长域优先，同域 exact 优先；同优先级目标不同必须报告冲突。
- 统一大小写、尾点、IDN ASCII，拒绝 IP、非法标签、公共后缀规则。
- 使用不可变快照热切换，Match 读取期间不能混用新旧规则和索引。
- 检查 Match/Reload/UpdateFeature 的锁范围、错误路径，修复锁泄漏、竞态和校验失败却污染内存数据的问题。

2. 数据审计和迁移
- 审计 data/app.cfg 与嵌入默认库，报告规则数、应用数、重复、冲突、过宽规则、来源缺失、标签混淆。
- 重点检查 .qq.com → QQ、共享 CDN、厂商服务误判具体应用。
- TikTok 与抖音分别建立目标；统一别名不得合并不同产品。
- 使用稳定 app_id、名称、类别、厂商、别名；不得以列表下标作为持久身份。
- 归属分 application、ecosystem、infrastructure；后两者不能冒充具体应用。
- 旧 wildcard 迁移应报告新增根域覆盖；旧 exact 曾包含子域，迁移为兼容 suffix 候选并标记复核，不静默改变已知语义。
- 自动派生规则不继承审核状态。高风险、来源不明、冲突项进入待审核区。
- 保留源数据备份，迁移幂等，输出 dry-run 和待审核清单。

3. 候选治理
- 未知域名去重、辅助分类、记录证据、审核、发布。
- AI、WHOIS、关键词只生成候选，不能凭置信度自动发布。
- 公共后缀用于分组，不证明整个注册域归属。
- 修改已审核规则的归属或范围必须重新审核；保存来源、版本、置信度。

4. 离线契约
- tar.gz 中仅包含 manifest.json、applications.json、domain-rules.json、licenses/ 下的许可文件。
- schema_version 为 application-domain-bundle/v1。
- manifest 字段：schema_version、version、created_at、sources、files；sources 的每项有 name/version/license；files 每项有 size/sha256。
- applications.json 是对象，含 applications、ecosystems、infrastructures 三个数组。目标含 id/name/category，vendor/aliases 可选。
- domain-rules.json 是数组；每条含 rule_id/domain/match_type/target_type/target_id/confidence/source/source_version。
- 规则来源必须对应 manifest 的 name/version，目标引用必须存在。只有已审核规则可导出。
- 同域同匹配类型重复规则先去重；冲突、未审核、缺少来源或许可应阻止发布。
- 发布版本不可覆盖；数据确定性排序。新建独立导出接口，兼容旧客户端下载接口。
- 导入未知域名 JSONL，字段为 domain/source_field/first_seen/last_seen/observation_count/sensor_id/bundle_version，不要求 IP、账号、完整 URL。
- source_field 为 dns.query/http.host/tls.sni/quic.sni；bundle_version 可能为 none。
- 同文件重复导入幂等，格式错误报告行号，不能静默丢弃。
- 提供格式文档、最小样例包、JSONL 和共同匹配向量。样例数据不能宣称为经人工流量验证的生产库。

5. 开源数据补充
- 支持 V2Fly domain-list-community 离线目录导入，记录来源 commit 和许可。
- 第一版支持 full/domain、正确展开 include 及属性筛选。
- keyword/regexp 列为未支持项，不自动降级为后缀。
- 仅导入人工指定的应用分组；不得把路由分类、厂商集合直接当作具体应用。
- 新导入规则进入候选，经过检查和审核后发布。

6. 验证和交付
- 先补回放/单元测试，再改实现。
- 覆盖精确/子域边界、伪造后缀、父域扩展、共享 CDN、冲突、TikTok/抖音、迁移和导入幂等、包校验、并发热更新。
- 运行相关测试及 go test -race；前端变更完成类型检查与生产构建。
- 用 Sentinel 消费端验证导出包，并用共同测试向量检查匹配一致性。
- 交付整改代码、dry-run 报告、待审核清单、契约文档、样例包、测试结果及剩余数据质量问题。
- 首批关注微信、企业微信、抖音、B站、QQ、腾讯视频。未做真实标注回放前不声称准确率，也不为压低未知比例而扩大域名归属。
```
