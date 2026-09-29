# 共享上网检测与处置：完整流程及依赖

以2026-09-15代码和当日现场核验为依据。主线是共享行为检测和违规处置，VPN检测暂缓。图中的待接通环节是目标流程，不能解释为现场已经可以处罚。

## 一、业务主流程

```mermaid
flowchart TB
  subgraph S1[一：流量与身份来源]
    NET[终端通过校园网络上网] --> MIRROR[交换机镜像口或TAP]
    MIRROR --> COL[Suricata / Zeek / 轻量设备信号采集]
    COL --> EVT[适配为标准事件\n来源、传感器、IP、时间、连接标识]
    AUTH[认证系统\n账号、用户组、产品、登录会话]
    AUTH -. 现场待接 .-> IDIN[身份适配\n上线、下线、心跳、完整在线快照]
    IDIN --> VALID[身份有效区间\n重复与迟到处理、对账中断检测]
  end
  subgraph S2[二：检测与归责]
    EVT --> SIGNAL[设备信号分析\nTTL、DHCP、UA、TLS、接入身份等]
    RULES[检测规则与设备指纹库] --> SIGNAL
    SIGNAL --> RISK[现有风险评估\n证据、分数、置信度、时间窗口、解释]
    RISK --> CASE[风险处置案件]
    CASE --> REVIEW[管理员调查与复核\n确认、误报、继续观察]
    RISK -. 待完善接线 .-> SHARED[共享行为策略输入\n独立设备证据、数量下界、冲突说明]
    SHARED -.-> ATTR[按事件发生时间归责\n园区＋接入域＋IP＋时间]
    VALID -.-> ATTR
    ATTR --> IDOK{能否唯一确认账号？}
    IDOK -- 否 --> UNKNOWN[保留风险与证据\n显示未知或冲突，不自动处罚]
    IDOK -- 是 --> ACCOUNT[账号及证据关联]
    VALID -. 需要真实在线清单 .-> DEVICES[跨会话、IP去重设备\n稳定标识缺失时保留不确定]
    DEVICES --> QUOTA[独立设备配额评估\n总数、手机、电脑上限]
  end
  subgraph S3[三：策略判断]
    CONFIG[管理员配置防代理策略\n默认禁用、仅观测]
    CONFIG --> MATCH[匹配范围与豁免\n账号、组、产品、园区、VLAN、IP、时段]
    ACCOUNT -.-> MATCH
    QUOTA -. 独立触发类型 .-> MATCH
    REVIEW -. 复核结果供处置参考 .-> MATCH
    MATCH --> ALLOW{组织是否允许或豁免？}
    ALLOW -- 是 --> KEEP[只记录观测与判断依据]
    ALLOW -- 否 --> CONDITIONS[持续时间、重复次数、窗口\n证据时效、策略优先级]
    CONDITIONS --> MODE{处置模式}
    MODE -- 仅观测 --> KEEP
    MODE -- 人工确认 --> APPROVE[有权限的管理员确认]
    MODE -- 自动执行 --> GATE[影子验收准入\n权限、冷却、熔断检查]
    APPROVE --> GATE
  end
  subgraph S4[四：账号处置与恢复]
    GATE -. 现场控制器待接 .-> CHECK[发送前重新核对账号与在线会话]
    CHECK --> ACTION[持久化违规轮次与动作阶段\n幂等键、重试、执行记录]
    ACTION --> CTRL[认证服务器或接入控制器\n执行通知、限速、下线或停用]
    CTRL --> RESULT[接收结果\n成功、失败、部分成功分别记录]
    RESULT --> AUDIT[审计、人工撤销、到期解除]
    RESULT --> NEXT[后续阶段继续判断\n不能因重复输入或重试直接升级]
    NEXT --> CONDITIONS
    AUDIT --> CTRL
  end
  classDef live fill:#eff6ff,stroke:#2563eb,color:#172554;
  classDef pending fill:#fff7ed,stroke:#ea580c,color:#7c2d12;
  class NET,MIRROR,COL,EVT,SIGNAL,RULES,RISK,CASE,REVIEW live;
  class AUTH,IDIN,VALID,SHARED,ATTR,IDOK,ACCOUNT,DEVICES,QUOTA,CONFIG,MATCH,ALLOW,CONDITIONS,MODE,APPROVE,GATE,CHECK,ACTION,CTRL,RESULT,AUDIT,NEXT pending;
```

蓝色为已运行的检测与复核路径；橙色为目标闭环中的环节，部分已有代码，仍依赖现场接入或联调。虚线明确标出尚未接通的关键链路。确认风险不等于已有处罚授权。

同一账号登录多台设备超出配额，与同一出口后面存在共享行为分别判断。只能看到出口MAC时不能据此数清其后设备；应用访问、品牌或单一TTL/UA信号不单独确认共享。

## 二、软件、进程及数据库依赖

```mermaid
flowchart TB
  subgraph HOST[openEuler x86_64服务器 / systemd管理]
    SC[Suricata采集服务] --> LOG[本地采集日志]
    ZK[Zeek采集服务] --> LOG
    DS[轻量设备信号服务] --> LOG
    LOG --> ING[Go实时采集进程\n标准化、批次、去重与游标]
    ING --> CH[(ClickHouse\n标准流量事件、诊断\n应用分类结果)]
    ING --> PG[(PostgreSQL\n采集台账、身份、风险、案件\n策略、动作、审计、任务游标)]
    CH --> MAT[后台风险物化\n窗口证据与风险快照]
    FP[本地设备指纹与检测规则] --> MAT
    MAT --> PG
    PG --> CASEJOB[后台案件同步]
    CH --> CASEJOB
    CASEJOB --> PG
    CH --> APPJOB[应用分类后台任务\n实时与历史分别调度]
    APPJOB --> CH
    APPJOB --> PG
    CH --> API[Go控制面API]
    PG --> API
    PG --> POLICYJOB[策略与动作后台任务]
    POLICYJOB --> PG
    API --> WEB[浏览器管理页面\n由控制面提供前端静态文件]
  end
  BUNDLE[featurelib-new\n维护、审核、发布应用域名包] --> IMPORT[管理员离线导入并校验]
  IMPORT --> LOCAL[本地应用域名库]
  LOCAL --> APPJOB
  AUTH2[外部认证系统] -.-> IDAPI[身份增量 / 完整快照接口]
  IDAPI --> PG
  POLICYJOB -. 真实控制接口待接 .-> NAS[认证服务器 / 接入控制器]
  NAS -. 执行结果 .-> POLICYJOB
```

生产运行依赖Go编译后的程序、前端静态文件、PostgreSQL、ClickHouse及采集器。当前数据库由Docker运行，应用和采集任务由systemd管理。Go、Node.js、pnpm用于开发和构建，不要求在目标机运行前端开发服务器。文件模式保留给开发与回放。

当前部署是旁路镜像检测：采集服务器能看流量，但不因此具备切断用户网络的能力。实际限制必须依赖已接入且具备对应能力的认证系统/控制器。

## 三、应用统计是一条辅助分支

```mermaid
flowchart LR
  EVENT[标准事件中的DNS、HTTP Host、TLS/QUIC SNI] --> LOCAL[本地应用域名规则匹配]
  LOCAL --> KNOWN[已识别应用或生态/基础设施]
  LOCAL --> UNKNOWN[未知域名观测]
  KNOWN --> STATS[连接关联、事件去重\n累计字节取最大值]
  STATS --> UI[应用排行与IP访问明细\n帮助调查]
  UNKNOWN --> EXPORT[导出JSONL]
  EXPORT --> LIB[featurelib-new分类与人工审核]
  LIB --> PACK[发布带版本、摘要和许可的离线包]
  PACK --> IMPORT[Sentinel校验并导入]
  IMPORT --> LOCAL
```

这条分支不是共享处罚的前置依赖。特征库不负责解析全部网络协议，也不负责认定违规。DNS只计域名观测；同一连接多应用的流量单独计量，不能分给多个应用重复累计。

## 四、依赖与缺失影响

| 能力 | 必须依赖什么 | 缺少时的结果 | 现场状态（2026-09-15核验） |
| --- | --- | --- | --- |
| 看到网络行为 | 正确的镜像位置、网卡、采集器、时间与传感器标识 | 无数据或视野不完整，不能把未发现解释为没有共享 | 采集链路运行中 |
| 判断共享风险 | 可见的独立设备信号、检测规则、证据窗口 | 单一弱信号只能提示，无法可靠确认共享 | 已有检测/证据框架，完整shared_access输入待接 |
| 把风险归给账号 | 认证会话、园区/接入域、事件时间、完整对账 | 只能保留IP风险，不能自动归责 | 认证会话0、完整快照来源0 |
| 判断设备配额 | 权威在线清单、稳定设备标识、显式配置上限 | 只能给下界或未知，不能虚构准确台数 | 评估代码已有，实际身份输入未接 |
| 决定如何处理 | 已启用的组织策略、豁免、持续条件及模式 | 风险保留，不构成自动处罚指令 | 页面已恢复，现场策略定义0 |
| 真正限速/下线 | 控制器接口、凭证、能力映射、唯一账号/会话 | 只有记录/影子模拟，不能实际断网 | 启用连接器0，已有沙箱验证 |
| 可靠解除与重试 | 持久化状态、幂等、控制结果、租约与审计 | 可能重复或误解除，必须先验收 | 有代码，现场多会话/叠加限制待验 |
| 应用访问统计 | 本地域名库、标准连接与流量字段、CH分类结果 | 未知率高或计量不可用，不妨碍保留共享风险 | 61条试点规则；实时分类正常，历史补扫受内存限制 |
| 长期稳定运行 | PG/CH容量、保留策略、监测、备份、任务资源限制 | 积压、查询变慢或空间不足 | 根盘90%，设备快照增长需治理 |

## 五、完整替代前的实际推进顺序

1. 补齐共享行为到shared_access策略的输入和正反回放。
2. 接认证源与完整在线清单，补账号详情及归属解释；同时修复历史补扫和容量问题。
3. 配置明确的共享策略和独立设备配额，先观测/试算，再人工确认。
4. 接真实控制器，在受控账号上验证限速、下线、解除和部分失败。
5. 达到既有影子准入与现场准确性门槛后，再按授权启用自动模式。VPN检测不作为以上工作的前置条件。

相关依据：`docs/shared-access/current-priority.md`、`docs/account-policies/identity-reconciliation.md`、`docs/account-policies/implementation-status.md`、`docs/deployment-and-gaps-20260915.md`、`docs/policy-page-loading-fix-20260915.md`及当前策略消费者代码。
