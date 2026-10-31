# 当前工作与下一步（2026-10-31）

## 目标

在只有镜像流量、没有 SNMP/NDM 凭据的前提下，尽可能提升发现设备的识别覆盖率，并把识别结果以“终端台账”的方式展示出来。

要求：

- 不发起主动扫描；
- 不伪造操作系统、接入端口或服务端口；
- 每个结论必须能追溯到镜像证据；
- 低置信度结果明确标注为“线索”。

## 当前已落地

### 数据链路

- 新发现代次：`discovery-fresh-20261031T092000Z`；
- 采集范围文件：`/opt/proxy-sentinel/config/discovery-capture-scope-layered-r7.json`，有效期已延长到 `2026-12-31T00:00:00Z`；
- 被动协议：ARP、DHCP、DNS-SD、SSDP、LLDP；
- LLDP 现场 0 包；SNMP 被动开关暂时关闭，避免 scope mismatch；
- eventbus current、发现页、服务线索和 TTL/DHCP 被动信号已接入。

### 发现页

路径：`/devices?tab=discovery`。

已具备：

- 顶部概览卡片：发现设备、哑终端线索、本页服务线索、本页近期活跃；
- 终端类型图标；
- 地址/名称/MAC、终端类型、制造商/型号、操作系统线索、网络位置、发现依据、服务/端口、证据状态、最近观测、操作；
- 服务/端口来自 DNS-SD/SSDP 镜像公告，例如 `_airplay._tcp · 7386`、`_lyra-mdns._udp · 5353`；
- 设备详情展示厂商、型号、VLAN、网络域、传感器、TTL、DHCP 主机名/厂商类/请求选项、服务线索和证据历史；
- MAC OUI 厂商补全；
- 主机名类型/OS 线索。

### 当前已知边界

- 精确 OS 版本无法从镜像稳定得到，只能给 OS 家族线索；
- 接入交换机物理端口需要 LLDP/FDB/SNMP，当前镜像位置不可得；
- 服务端口只能看到公告或实际流量，不能证明开放/关闭；
- SNMP/NDM 事件不在镜像中；
- 当前页面部分字段是低置信度线索，前端必须保留“线索”标识。

## 代码入口

- 发现页：`frontend/src/pages/PassiveDiscoveryPanel.tsx`
- 发现查询：`internal/discovery/eventbus_query.go`
- 被动信号 API：`internal/controlplane/passive_signals.go`
- 服务线索读取：`internal/store/discovery_services.go`
- 当前切流/清库说明：`docs/discovery-data-reset-20261031.md`
- 高性能流式架构：`docs/high-performance-streaming-architecture-20261030.md`
- 设备中心查询设计：`docs/device-center-storage-query-design.md`

## 下一步任务（按优先级）

### P0：修正发现页布局和空列

- 当前表格列较多，1440 视口下“最近观测/操作”容易互相挤压；
- 需要把操作列固定在右侧，或压缩列宽/合并列；
- 增加三视口检查：390×844、1280×800、1440×900；
- 不允许使用“未识别/未获取/未知/—”占位。

### P0：完善被动 OS 指纹

现有：

- 主机名前缀；
- MAC OUI；
- TTL；
- DHCP vendor class/requested options（API 直接读日志尾部）。

下一步：

1. 把 `device_dhcp_message.log` 正式纳入数据链路，按 MAC/IP 聚合并缓存，不要每页请求重复读大文件；
2. 解析 DHCP option 55、60、61、93；
3. 增加 HTTP User-Agent、TLS JA3/JA4、SMB native OS 信号；
4. 输出 `os_family`、`confidence`、`evidence`，不要输出确定版本；
5. 多个信号冲突时显示冲突，不要取第一条。

### P1：服务端口/服务名称

- 已从 DNS-SD/SSDP payload 提取；
- 增加 observed flow 的 `dst_port` 聚合，区分“服务公告”和“实际访问”；
- 输出证据来源和时间，避免把访问端口当成开放端口；
- 页面按服务类型/端口去重，避免一个服务实例刷多行。

### P1：接入位置

- 当前只有 VLAN/网络域/传感器；
- 若后续能把镜像点放到接入交换机，可补 LLDP/FDB；
- 当前不要用 VLAN 推测物理端口。

### P2：采集可靠性

- 发现 segment 曾因 fact scope mismatch 阻塞，坏段已移到 `/var/lib/proxy-sentinel/discovery-quarantine-20261031`；
- 为同类坏段增加自动隔离和告警，不要无限重试；
- 监控 `discovery_device_current_shadow` 最新时间和 eventbus lag；
- 采集范围有效期到期前自动提醒；
- 不在采集路径里做无界文件读取。

### P2：页面验收

- 发现页总数与 current 表口径对齐；
- 服务线索、OS 线索、类型线索在详情可追溯；
- 页面无 console/page error；
- 390 宽度使用卡片布局，不出现表格爆框。

## 明确不做

- 不主动扫描全网；
- 不猜 SNMP community；
- 不伪造 OS/端口/接入位置；
- 不把线索写成确定结论；
- 不删除唯一原文或未核验归档。

## 验证命令

后端：

```bash
go test ./internal/controlplane ./internal/discovery ./internal/store
go build ./cmd/proxy-sentinel
go build ./cmd/event-bus-current-shadow
```

前端：

```bash
cd frontend
pnpm test --run
pnpm typecheck
pnpm build
```

现场只读核对：

```bash
/opt/proxy-sentinel/scripts/eventbus-184-health.sh
```

页面：

```text
http://222.204.3.184:8088/devices?tab=discovery
```

## 最近提交

```text
85eb38c8 接入被动TTL与DHCP信号
b4cd6e66 增加被动服务端口列并修复采集范围过期
25f8268f 增加镜像流量被动服务线索
00bc6954 优化SNMP网关候选排序
3a26cae6 增加从发现网段选择SNMP候选
```
