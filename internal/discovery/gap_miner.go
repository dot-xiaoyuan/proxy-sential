package discovery

import (
	"fmt"
	"strings"
	"time"
)

// GapMineOptions 定义 204 未识别高频特征只读挖掘的有界参数。
type GapMineOptions struct {
	SensorID string
	Window   time.Duration
	Top      int
}

// NormalizeGapOptions 将窗口和返回条数收敛在安全只读上界内。
func NormalizeGapOptions(opts GapMineOptions) GapMineOptions {
	if strings.TrimSpace(opts.SensorID) == "" {
		opts.SensorID = "campus-204"
	}
	if opts.Window <= 0 {
		opts.Window = 24 * time.Hour
	}
	if opts.Window < time.Hour {
		opts.Window = time.Hour
	}
	if opts.Window > 7*24*time.Hour {
		opts.Window = 7 * 24 * time.Hour
	}
	if opts.Top <= 0 {
		opts.Top = 50
	}
	if opts.Top > 100 {
		opts.Top = 100
	}
	return opts
}

// TwoListOverlap 记录终端列表与发现设备列表在同一窗口内的 MAC 集合交集与差异。
type TwoListOverlap struct {
	TerminalMACs      int64 `json:"terminal_macs"`
	DiscoveryMACs     int64 `json:"discovery_macs"`
	OverlapMACs       int64 `json:"overlap_macs"`
	TerminalOnlyMACs  int64 `json:"terminal_only_macs"`
	DiscoveryOnlyMACs int64 `json:"discovery_only_macs"`
}

// StatusCount 记录硬件识别投影各状态的条目与去重 MAC 数。
type StatusCount struct {
	Status string `json:"status"`
	Count  int64  `json:"count"`
	MACs   int64  `json:"macs"`
}

// FeatureGapItem 表示一类高频特征值及其覆盖规模。
type FeatureGapItem struct {
	Category string `json:"category,omitempty"`
	Value    string `json:"value"`
	Detail   string `json:"detail,omitempty"`
	Entities int64  `json:"entities"`
	Events   int64  `json:"events"`
}

// PortGapItem 表示镜像中高频目标端口及其覆盖源 IP 数。
type PortGapItem struct {
	Proto      string `json:"proto"`
	Port       uint32 `json:"port"`
	Annotation string `json:"annotation"`
	SourceIPs  int64  `json:"source_ips"`
	Buckets    int64  `json:"buckets"`
}

// GapReport 汇总一次只读特征挖掘的完整结果，用于指导规则与协议优先级。
type GapReport struct {
	SensorID             string           `json:"sensor_id"`
	Window               string           `json:"window"`
	GeneratedAt          string           `json:"generated_at"`
	Overlap              TwoListOverlap   `json:"two_list_overlap"`
	HardwareStatuses     []StatusCount    `json:"hardware_statuses"`
	UnmatchedDHCP        []FeatureGapItem `json:"unmatched_dhcp"`
	HTTPDeviceAgents     []FeatureGapItem `json:"http_device_agents"`
	UnconfirmedProtocols []FeatureGapItem `json:"unconfirmed_protocols"`
	MirrorPorts          []PortGapItem    `json:"mirror_ports"`
	TopSNIDomains        []FeatureGapItem `json:"top_sni_domains"`
	Warnings             []string         `json:"warnings,omitempty"`
}

// CampusPortAnnotation 返回校园网被动资产发现关注端口的协议说明。
func CampusPortAnnotation(proto string, port uint32) string {
	switch port {
	case 22:
		return "SSH（服务器/网络设备 Banner）"
	case 23:
		return "Telnet（旧网络设备/工控）"
	case 53:
		return "DNS"
	case 80:
		return "HTTP"
	case 123:
		return "NTP（时钟心跳）"
	case 137, 139:
		return "NetBIOS（Windows/打印主机）"
	case 161:
		return "SNMP（交换机/打印机/UPS）"
	case 443:
		return "HTTPS/TLS"
	case 445:
		return "SMB（Windows/NAS/文件服务）"
	case 502:
		return "Modbus TCP（楼控/工控）"
	case 515:
		return "LPD（网络打印）"
	case 554:
		return "RTSP（摄像机/NVR）"
	case 631:
		return "IPP（网络打印）"
	case 1900:
		return "SSDP/UPnP"
	case 3389:
		return "RDP（Windows 桌面/服务器）"
	case 3702:
		return "WS-Discovery / ONVIF（摄像机/打印）"
	case 5060:
		return "SIP（VoIP 话机/GB28181）"
	case 5246, 5247:
		return "CAPWAP（无线 AP 隧道/发现）"
	case 5353:
		return "mDNS/Bonjour"
	case 8000:
		return "海康威视私有管理端口"
	case 9100:
		return "RAW 9100（网络打印 JetDirect）"
	case 37020:
		return "海康 SADP 发现"
	case 37777:
		return "大华私有服务端口"
	case 37810:
		return "大华设备发现协议"
	case 47808:
		return "BACnet/IP（楼宇自控）"
	default:
		return strings.ToUpper(proto)
	}
}

// RenderGapReportMarkdown 将挖掘结果渲染为便于审阅与排期的简体中文 Markdown 报告。
func RenderGapReportMarkdown(r GapReport) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# 被动发现未识别特征摸底报告（%s · 窗口 %s）\n\n", r.SensorID, r.Window)
	fmt.Fprintf(&b, "- 生成时间：%s\n\n", r.GeneratedAt)

	if len(r.Warnings) > 0 {
		b.WriteString("## 采样告警\n\n")
		for _, w := range r.Warnings {
			fmt.Fprintf(&b, "- %s\n", w)
		}
		b.WriteString("\n")
	}

	b.WriteString("## 1. 终端列表与发现设备双表口径对比\n\n")
	b.WriteString("| 终端列表去重 MAC | 发现列表去重 MAC | 两表交集 | 仅终端列表 | 仅发现列表 |\n")
	b.WriteString("| ---: | ---: | ---: | ---: | ---: |\n")
	fmt.Fprintf(&b, "| %d | %d | %d | %d | %d |\n\n",
		r.Overlap.TerminalMACs, r.Overlap.DiscoveryMACs, r.Overlap.OverlapMACs,
		r.Overlap.TerminalOnlyMACs, r.Overlap.DiscoveryOnlyMACs)

	if len(r.HardwareStatuses) > 0 {
		b.WriteString("## 2. 硬件投影当前状态分布\n\n")
		b.WriteString("| 状态 | 身份数 | 去重 MAC |\n| --- | ---: | ---: |\n")
		for _, item := range r.HardwareStatuses {
			fmt.Fprintf(&b, "| `%s` | %d | %d |\n", item.Status, item.Count, item.MACs)
		}
		b.WriteString("\n")
	}

	writeFeatureSection := func(title, colEntity string, items []FeatureGapItem) {
		fmt.Fprintf(&b, "## %s\n\n", title)
		if len(items) == 0 {
			b.WriteString("暂无样本。\n\n")
			return
		}
		fmt.Fprintf(&b, "| 类别 | 特征值 | 补充字段 | %s | 事件数 |\n| --- | --- | --- | ---: | ---: |\n", colEntity)
		for _, item := range items {
			fmt.Fprintf(&b, "| %s | `%s` | %s | %d | %d |\n",
				escapeMDCell(item.Category),
				escapeMDCell(item.Value),
				escapeMDCell(item.Detail),
				item.Entities,
				item.Events,
			)
		}
		b.WriteString("\n")
	}

	writeFeatureSection("3. 高频 DHCP 指纹（Vendor Class / Options）", "去重 MAC", r.UnmatchedDHCP)
	writeFeatureSection("4. 高频 HTTP 设备与客户端特征（UA / Server / Title）", "去重 IP", r.HTTPDeviceAgents)
	writeFeatureSection("5. 高频设备协议响应（SNMP / mDNS / SSDP / WS-Discovery / SIP）", "去重 IP", r.UnconfirmedProtocols)

	b.WriteString("## 6. 镜像高价值目标端口覆盖\n\n")
	if len(r.MirrorPorts) == 0 {
		b.WriteString("暂无样本。\n\n")
	} else {
		b.WriteString("| 协议 | 端口 | 用途说明 | 覆盖源 IP | 10 分钟桶数 |\n| --- | ---: | --- | ---: | ---: |\n")
		for _, item := range r.MirrorPorts {
			fmt.Fprintf(&b, "| %s | %d | %s | %d | %d |\n",
				strings.ToUpper(item.Proto), item.Port, escapeMDCell(item.Annotation), item.SourceIPs, item.Buckets)
		}
		b.WriteString("\n")
	}

	writeFeatureSection("7. 高频 TLS SNI 域名", "去重 IP", r.TopSNIDomains)
	return b.String()
}

func escapeMDCell(raw string) string {
	clean := strings.TrimSpace(strings.ReplaceAll(strings.ReplaceAll(raw, "\n", " "), "\r", " "))
	clean = strings.ReplaceAll(clean, "|", "\\|")
	if len(clean) > 120 {
		return clean[:117] + "..."
	}
	return clean
}
