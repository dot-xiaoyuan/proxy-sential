# 共享发现与打击能力审查（2026-09-18）

结论：当前不能称为旧防代理的完整业务替代。新版具备标准事件、保守共享判定、事件时账号归责和人工下线的代码基础；30 的专用共享/认证/处置链路未配置。检测仍有时序误判和同质共享漏检，前端未放开人工共享策略，旧版的阶梯通知、限速、停用及黑名单联动未完成等价接入。

本次仅审查并新增证据与报告，未修改业务规则、未启用策略、未下线用户。对照本地旧版 dpi-analyze、antipolicy 的实现与新系统关键主链路。旧功能是否真实有效也需分别证明：旧版有些结果只是 queued/accepted，不等于已送达或控制成功。

## 30 实际状态

2026-09-18 10:56 CST 只读检查：四个常驻进程 active，但实际进程参数和环境均未设置共享开关、共享来源登记、采集范围、身份来源登记或原生处置配置。数据库共享窗口 0、策略身份事实 0、账号会话 0、身份全量快照 0、策略 0、策略执行 0、处置连接器 0。

因此现场现有终端画像和一般风险数据不能证明有认证账号共享检测，更没有配置好的共享打击闭环。服务 ready 仅说明已配置组件运行正常；可选共享链路缺省关闭仍能 ready。证据：artifacts/shared-access-audit-20260918/30-runtime-feature-config.json 和 30-business-state.txt。

## 关键差距与影响

| 优先级 | 能力/逻辑 | 当前情况 | 还需完成 |
| --- | --- | --- | --- |
| P0 | 现场共享观测生产 | risk materialize 的 SharedAccess 默认关闭；30 未设置，shared_access_window 为 0 | 配置受控采集范围和来源、启用独立共享窗口；验证真实事件持续进入 |
| P0 | 真实账号归责 | 身份接收、全量对账、时点重放已有；30 无授权来源登记，无身份事实 | 接入真实认证权威清单与增量，验证 IP 复用、换账号、过期、重启和乱序 |
| P0 | 同账号先后换设备 | 窗口累计 UA/TTL/TLS 多样性，没有检查信号同时出现；复现两段不重叠会话仍 basis_present | 按会话代际及信号时间区间分割，排除先后使用；保留可复核的并发依据 |
| P0 | 链路 MAC 与真实终端混淆 | TTL sidecar 将以太网源 MAC 直接写为 subject.mac；后续默认生成 endpoint | 区分邻接/网关 MAC 与终端 MAC，使用认证、租约及 L2 范围证明终端关联，不能凭重复 IP 定共享 |
| P0 | 共享人工策略页面 | 后端支持 manual+disconnect；前端 shared_access 强制 observe，人工选项禁用 | 对齐表单、校验、OpenAPI与实际支持能力，走页面完成预览/确认/执行/结果验证 |
| P0 | 现场处置接入 | 原生 RADIUS 下线和持久化执行器已有；30 没有连接器及原生配置 | 接通正式认证控制器、权限与影子准入；指定账号先验收，不直接开放自动处罚 |
| P1 | 同质热点/路由器共享 | 测试明确 homogeneous_hotspot=not_matched；同系统、TLS、TTL 下多样性规则无法区分 | 补充可验证的独立连接/终端行为证据与同质共享正例；无法区分时显示未知，不以画像数造设备数 |
| P1 | 证据重复出现/持续性 | Window 只保存特征集合，未保存每类计数及时间序列；少量孤立特征即可满足组合 | 增加每类有效采样量、复现次数、时间共现、异常样本过滤；证明 sustain_seconds 对应持续观测 |
| P1 | 采集完整性与方向 | Complete 主要来自查询未截断及范围/基数检查；没有接入丢包、采集停止、源覆盖证明。parseFrame 把私网源报文都标 outbound | 校验方向和用户侧网络范围；接入采集健康区间，缺失时标证据不足，避免作为恢复/继续处罚依据 |
| P1 | 共享阶梯动作 | generic policy 支持阶段/轮次/冷却/恢复；shared_access 动作入口硬限制 manual+disconnect | 共享通知、持续限速、停用及解除逐项接通；校验时拒绝不支持配置，不能保存后才 blocked |
| P1 | 真实限速/停用/消息 | 通用签名控制器契约和沙箱已有；原生适配仅 disconnect/session.disconnect、radius | 对接真实控制器的限速租约、账号停用/解除、消息模板及送达回执；原生不能靠 action_mapping 获得这些能力 |
| P1 | 自动共享打击 | Input 对 automatic 返回未知；创建/发送动作也禁止 | 依据校园真实标注和风险案件人工复核设计有边界的准入与升级，不是只解禁一个布尔值 |
| P1 | 黑名单与重新登录 | 旧版有 IP/MAC/账号黑名单命中与 DM 下线、北向禁用；新系统未发现等价黑名单登记及登录后强制约束链路 | 优先实现按账号有期限的处罚记录、再登录执行、到期解除及人工例外，避免历史 IP 误伤 |
| P1 | 共享案件至处置工作台 | shared_access_window 刻意不进入普通风险总分；策略试算展示共享结果，但未发现共享账号结果与案件/执行轮次的专门关联 | 建立按账号+接入范围的共享复核队列，关联观测、标签、策略轮次与子动作，支持一处核对完整闭环 |
| P1 | 全窗口数据上限 | 最新共享范围最多 10000，超限整个读取报不完整；物化全局事件上限也会标不完整 | 分范围/分页/有界增量处理，暴露覆盖指标；校园规模负载下验证不会持续 waiting_data |
| P2 | 多校区一个采集源 | CaptureScope 为单园区/接入域绑定；来源登记同 sensor/source 只能一项，校区/网络区域管理不会自动完成采集映射 | 设计明确的采集拓扑和范围映射，跨校区用独立来源或经验证的范围注册 |
| P2 | 策略表达替代旧版 | 已有用户组/产品/VLAN/园区/CIDR/时间段、顺序阶段和违规轮次；未见等价 route_increase 触发和旧 DependsOn/各动作 interval/trigger_count 的完整迁移 | 列出旧策略可转换/不可转换项；共享路由依据必须重新设计证据，不能直接照搬旧阈值 |
| P2 | 账号展示权威一致性 | 策略已用有效身份事实区间，普通账号/会话页面仍有旧汇总读取路径 | 展示同一权威清单、在线/历史时间语义与数据源，避免页面和执行器看见不同在线状态 |

P0 表示阻碍当前共享发现/人工打击主线；P1 为发现质量与完整打击差距；P2 为规模/迁移/运营补齐。自动处罚、限速、停用曾明确暂缓，不将“有意暂缓”描述为程序误删；本表列的是与旧业务替代目标的差距。

## 已实现，不应误判为缺失

- 标准事件与证据边界、独立共享信号组合、来源范围登记、过期/冲突/截断保护；UA、TTL、TLS、DHCP协议栈可用，JA3/JA4不会重复算两类证据。仅 IP 相同、多个 MAC、品牌生态域名不直接作为共享结论。
- 事件时账号归责、身份全量对账、重放去重与有效区间；未知身份不会回退成共享 IP 封禁。
- 人工预览绑定账号/全部当前会话和证据指纹；提交及发送前重校验，幂等、撤销、影子准入、冷却、紧急停止、子动作状态和审计。
- 原生下线持久化 journal、超时后只对账、不盲目重发，控制器确认与会话消失分开观察；重启恢复和部分失败有本地集成。
- 190 已有指定账号真实下线/重新认证记录，但共享输入是合成事件，本地测试控制面执行，不能证明 30 已接通或真实校园检测准确率。
- MAC 厂商/OUI 的品牌参考未删除；保留参考是合理的，不能用它推导热点下游独立设备数。

## 可重复逻辑探针

运行 `go run ./artifacts/shared-access-audit-20260918/probe`。仅合成、只在进程内计算，不访问现场、不产生处置。

1. 同账号、同 IP/园区/接入域：手机先结束，电脑才开始，两个会话无重叠。窗口各出现一个不同 UA/TTL/TLS 特征，Evaluate 返回 basis_present，confidence=0.7，device_lower_bound=1。说明当前不能区分时序切换与共享，结论仍需人工复核。
2. 同一已认证会话中两个孤立的不同协议特征也返回 basis_present。说明没有每类证据最低出现次数约束；不证明真实单设备一定这样发包或校园误报率。

保存结果 logic-probes.json。该探针记录当前不足，不是应保持这种行为的通过验收测试。相关 evidence/sharedaccess/policy/controlplane/srunapi/legacy4k 测试通过，materialize 当前无专属测试文件；既有测试通过没有覆盖以上缺口。

## 代码对照入口

- 共享生产及完整性：[internal/materialize/materialize.go](/Users/yuantong/Developer/Projects/golang/proxy-sentinel/internal/materialize/materialize.go:71)。
- 共享时点归责与特征判定：[internal/sharedaccess/evaluate.go](/Users/yuantong/Developer/Projects/golang/proxy-sentinel/internal/sharedaccess/evaluate.go:156)、[internal/evidence/shared.go](/Users/yuantong/Developer/Projects/golang/proxy-sentinel/internal/evidence/shared.go:96)。
- 同质热点已知漏检：[internal/evidence/shared_campus_test.go](/Users/yuantong/Developer/Projects/golang/proxy-sentinel/internal/evidence/shared_campus_test.go:26)。
- MAC/方向归属：[internal/devicesignal/packet.go](/Users/yuantong/Developer/Projects/golang/proxy-sentinel/internal/devicesignal/packet.go:48)、[internal/store/identity.go](/Users/yuantong/Developer/Projects/golang/proxy-sentinel/internal/store/identity.go:607)。
- 人工页面限制：[frontend/src/pages/PoliciesPage.tsx](/Users/yuantong/Developer/Projects/golang/proxy-sentinel/frontend/src/pages/PoliciesPage.tsx:49)。
- 共享动作限制与发送复核：[internal/controlplane/policy_actions.go](/Users/yuantong/Developer/Projects/golang/proxy-sentinel/internal/controlplane/policy_actions.go:164)；原生能力：[internal/controlplane/native_dispatch.go](/Users/yuantong/Developer/Projects/golang/proxy-sentinel/internal/controlplane/native_dispatch.go:61)。
- 策略校验允许不受支持的共享组合：[internal/policy/engine.go](/Users/yuantong/Developer/Projects/golang/proxy-sentinel/internal/policy/engine.go:61)、[internal/policy/engine.go](/Users/yuantong/Developer/Projects/golang/proxy-sentinel/internal/policy/engine.go:105)；运行时才禁止 automatic 或非 disconnect。
- 身份授权：[internal/controlplane/identity_sources.go](/Users/yuantong/Developer/Projects/golang/proxy-sentinel/internal/controlplane/identity_sources.go:21)；范围登记：[internal/sharedaccess/config.go](/Users/yuantong/Developer/Projects/golang/proxy-sentinel/internal/sharedaccess/config.go:42)。
- 共享结果与普通风险评分分离：[internal/risk/risk.go](/Users/yuantong/Developer/Projects/golang/proxy-sentinel/internal/risk/risk.go:117)。
- 旧版设备/路由条件与策略输入：[旧版 pkg/devices/proxy.go](/Users/yuantong/Developer/Projects/golang/dpi-analyze/pkg/devices/proxy.go:79)。
- 旧通知/限速/下线/禁用注册及实际行为：[旧版 pkg/devices/register.go](/Users/yuantong/Developer/Projects/golang/dpi-analyze/pkg/devices/register.go:28)；旧黑名单 DM：[旧版 internal/analyze/analyze_multi.go](/Users/yuantong/Developer/Projects/golang/dpi-analyze/internal/analyze/analyze_multi.go:365)。

## 建议补齐顺序

1. 先修采集方向和链路 MAC 归属、会话时序切分、最低证据量；补先后换设备与真实正常单设备反例，保持人工复核边界。
2. 为 30 接入真实采集范围/共享窗口与认证权威来源，运营页明确每一段是否启用/新鲜/完整。
3. 前端开放实际支持的人工共享下线，后端配置校验与能力提示同步限制；指定测试账号走页面完整验收，包含多会话与部分失败。
4. 将共享复核案件、证据、执行轮次与当前会话关联；补账号再登录、撤销与恢复展示。
5. 分别接真实消息、限速租约、停用/解除与账号处罚记录，验证后再讨论自动升级。不要为了与旧版界面看齐，把尚未落地的动作标为可执行。

本轮没有授权新现场账号处置，未因旧测试记录而重新操作任何账号。需要补齐的是上述可验证业务链路，完整性能验收仍为独立未完成事项。
