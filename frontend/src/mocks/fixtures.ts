import type {
  AuditLog,
  Evidence,
  EventTypeCount,
  IngestDiagnostic,
  IngestStatus,
  ActivityOverview,
  IpActivityProfile,
  NormalizedEventSummary,
  Overview,
  RiskSnapshot,
  Session,
  ShadowRun,
  FingerprintConflictItem,
  DpiProtocolFlowItem,
  DpiTrendPoint,
  DpiFlowSample,
  IpDeviceInventory,
} from '../shared/api/types'

export const mockSession: Session = {
  user: { id: 'ops-001', name: '运营复核员' },
  role: 'operator',
  permissions: [
    'risks:read',
    'evidence:read',
    'events:read',
    'labels:create',
    'shadow:read',
    'audit:read',
    'rules:reload',
    'ingest:read',
    'dpi:read',
  ],
}

export const riskSnapshots: RiskSnapshot[] = [
  {
    ip: '10.255.0.59',
    score: 88,
    level: 'confirmed',
    confidence: 0.86,
    window: '10m0s',
    evidence_ids: ['evidence-ua-59', 'evidence-ja3-59', 'evidence-port-59'],
    summary: 'confirmed 级别风险由 multi_ja3_ja4、multi_user_agent、port_distribution 证据共同贡献；当前仍为影子判断，需要结合负证据和人工复核',
    recommended_action: 'shadow_confirm_review',
    updated_at: '2026-07-24T05:19:15Z',
    suspected_device_count: 2,
    device_summary: '当前观测到 2 个设备候选；需优先查看强/中信号来源确认是否共享上网',
    device_confidence: 0.68,
  },
  {
    ip: '10.255.0.98',
    score: 71,
    level: 'high',
    confidence: 0.79,
    window: '10m0s',
    evidence_ids: ['evidence-ua-98', 'evidence-ja3-98'],
    summary: 'high 级别风险由 multi_ja3_ja4、multi_user_agent 证据共同贡献；当前仍为影子判断，需要结合负证据和人工复核',
    recommended_action: 'shadow_manual_review',
    updated_at: '2026-07-24T05:18:44Z',
    suspected_device_count: 2,
    device_summary: '当前观测到 2 个设备候选；需优先查看强/中信号来源确认是否共享上网',
    device_confidence: 0.62,
  },
  {
    ip: '2001:db8::37',
    score: 45,
    level: 'suspicious',
    confidence: 0.65,
    window: '10m0s',
    evidence_ids: ['evidence-domain-v6', 'evidence-port-v6'],
    summary: 'suspicious 级别风险由 domain_diversity、port_distribution 证据共同贡献；弱证据不作为确认依据',
    recommended_action: 'shadow_watch',
    updated_at: '2026-07-24T05:16:10Z',
    suspected_device_count: 1,
    device_summary: '当前仅有 UA/访问行为等弱信号；UA 可伪造，不能据此确认品牌或多设备',
    device_confidence: 0.34,
  },
  {
    ip: '10.255.0.25',
    score: 12,
    level: 'normal',
    confidence: 0.95,
    window: '1h0m0s',
    evidence_ids: ['evidence-normal-25'],
    summary: '已识别设备，行为表现与单用户终端匹配，无共享/代理指纹',
    recommended_action: 'record',
    updated_at: '2026-07-24T05:15:00Z',
    suspected_device_count: 1,
    device_summary: '当前观测到单个设备候选；仍需结合 DHCP/OUI/TCP 指纹等强信号提升准确性',
    device_confidence: 0.62,
  },
  {
    ip: '10.255.0.88',
    score: 8,
    level: 'normal',
    confidence: 0.98,
    window: '1h0m0s',
    evidence_ids: [],
    summary: '已识别设备，研发测试部门固化终端，流量状态良好',
    recommended_action: 'record',
    updated_at: '2026-07-24T05:12:00Z',
    suspected_device_count: 1,
    device_summary: '当前观测到单个设备候选；仍需结合 DHCP/OUI/TCP 指纹等强信号提升准确性',
    device_confidence: 0.62,
  },
  {
    ip: '10.255.0.15',
    score: 18,
    level: 'normal',
    confidence: 0.31,
    window: '10m0s',
    evidence_ids: [],
    summary: '未发现该 IP 的有效风险证据',
    recommended_action: 'record',
    updated_at: '2026-07-24T05:15:00Z',
    suspected_device_count: 0,
    device_summary: '当前标准事件中没有足够设备识别信号，无法判断该 IP 背后设备数量或品牌',
    device_confidence: 0,
  },
]

export const deviceInventoriesByIp: Record<string, IpDeviceInventory> = {
  '10.255.0.59': {
    ip: '10.255.0.59',
    window: '1h',
    suspected_device_count: 2,
    confidence: 0.68,
    status: 'multi_candidate',
    summary: '当前观测到 2 个设备候选；需优先查看强/中信号来源确认是否共享上网',
    first_seen: '2026-07-24T05:18:52Z',
    last_seen: '2026-07-24T05:19:02Z',
    signals: [
      {
        signal_id: 'signal-ja3-59',
        ip: '10.255.0.59',
        source: 'tls_fingerprint',
        kind: 'ja3',
        value: 'android-okhttp',
        normalized_value: 'android-okhttp',
        strength: 'medium',
        confidence: 0.62,
        weight: 48,
        first_seen: '2026-07-24T05:19:02Z',
        last_seen: '2026-07-24T05:19:02Z',
        event_ids: ['event-tls-59-b'],
      },
      {
        signal_id: 'signal-ua-59',
        ip: '10.255.0.59',
        source: 'http_ua',
        kind: 'user_agent',
        value: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
        normalized_value: 'mozilla/5.0 (windows nt 10.0; win64; x64)',
        strength: 'weak',
        confidence: 0.35,
        weight: 20,
        first_seen: '2026-07-24T05:18:52Z',
        last_seen: '2026-07-24T05:18:52Z',
        event_ids: ['event-http-59-a'],
      },
    ],
    devices: [
      {
        device_id: 'device-android-stack',
        ip: '10.255.0.59',
        label: 'Android / mobile',
        brand: 'unknown',
        vendor: 'unknown',
        os_family: 'Android',
        device_type: 'mobile',
        model: 'unknown',
        confidence: 0.62,
        signal_count: 2,
        strong_signal_count: 0,
        medium_signal_count: 1,
        weak_signal_count: 1,
        signals: [],
        fingerprints: ['ja3:android-okhttp'],
        first_seen: '2026-07-24T05:18:52Z',
        last_seen: '2026-07-24T05:19:02Z',
        summary: '由 JA3/JA4、TCP 栈等中等强度信号支撑，建议结合强信号复核',
      },
      {
        device_id: 'device-windows-ua',
        ip: '10.255.0.59',
        label: 'Windows / desktop',
        brand: 'unknown',
        vendor: 'unknown',
        os_family: 'Windows',
        device_type: 'desktop',
        model: 'unknown',
        confidence: 0.34,
        signal_count: 1,
        strong_signal_count: 0,
        medium_signal_count: 0,
        weak_signal_count: 1,
        signals: [],
        fingerprints: [],
        first_seen: '2026-07-24T05:18:52Z',
        last_seen: '2026-07-24T05:18:52Z',
        summary: '仅由 UA/访问行为弱信号推断，不能作为准确设备识别结论',
      },
    ],
    conflicts: [
      {
        conflict_id: 'device-conflict-59',
        ip: '10.255.0.59',
        type: 'tls_stack_conflict',
        strength: 'medium',
        confidence: 0.62,
        summary: '同一 IP 出现多个 TLS JA3/JA4 指纹，提示可能存在多客户端栈',
        samples: ['ja3:android-okhttp', 'ja4:windows-edge'],
        last_seen: '2026-07-24T05:19:02Z',
        related_device_ids: ['device-android-stack', 'device-windows-ua'],
      },
    ],
  },
}

export const evidenceByIp: Record<string, Evidence[]> = {
  '10.255.0.59': [
    {
      evidence_id: 'evidence-ua-59',
      ip: '10.255.0.59',
      type: 'multi_user_agent',
      window: '10m0s',
      score: 35,
      confidence: 0.85,
      severity: 'high',
      reason: '10m0s 内出现 5 个不同 User-Agent，可能对应多设备或共享上网',
      samples: [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
        'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X)',
        'okhttp/4.12.0',
        'Dalvik/2.1.0 (Linux; U; Android 14)',
        'Mozilla/5.0 (Linux; Android 13; Tablet)',
      ],
      created_at: '2026-07-24T05:19:15Z',
    },
    {
      evidence_id: 'evidence-ja3-59',
      ip: '10.255.0.59',
      type: 'multi_ja3_ja4',
      window: '10m0s',
      score: 30,
      confidence: 0.85,
      severity: 'medium',
      reason: '10m0s 内出现 4 个不同 TLS 指纹，可能对应多客户端栈',
      samples: ['ja3:chrome-desktop', 'ja3:ios-safari', 'ja4:android-okhttp', 'ja4:windows-edge'],
      created_at: '2026-07-24T05:19:15Z',
    },
    {
      evidence_id: 'evidence-port-59',
      ip: '10.255.0.59',
      type: 'port_distribution',
      window: '10m0s',
      score: 23,
      confidence: 0.65,
      severity: 'low',
      reason: '10m0s 内访问 7 个不同目的端口，连接模式需要结合其他证据判断',
      samples: ['80', '443', '993', '5228', '8080'],
      created_at: '2026-07-24T05:19:15Z',
    },
  ],
  '10.255.0.98': [
    {
      evidence_id: 'evidence-ua-98',
      ip: '10.255.0.98',
      type: 'multi_user_agent',
      window: '10m0s',
      score: 35,
      confidence: 0.75,
      severity: 'high',
      reason: '10m0s 内出现 3 个不同 User-Agent，移动端和 PC 端同时出现',
      samples: ['Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5)', 'Mozilla/5.0 (Android 14)', 'curl/8.7.1'],
      created_at: '2026-07-24T05:18:44Z',
    },
    {
      evidence_id: 'evidence-ja3-98',
      ip: '10.255.0.98',
      type: 'multi_ja3_ja4',
      window: '10m0s',
      score: 30,
      confidence: 0.85,
      severity: 'medium',
      reason: 'TLS 指纹与 UA 栈不一致，需要人工复核是否为加速器或共享上网',
      samples: ['ja3:desktop-chrome', 'ja4:android-webview'],
      created_at: '2026-07-24T05:18:44Z',
    },
  ],
  '2001:db8::37': [
    {
      evidence_id: 'evidence-domain-v6',
      ip: '2001:db8::37',
      type: 'domain_diversity',
      window: '10m0s',
      score: 24,
      confidence: 0.65,
      severity: 'low',
      reason: 'DNS/SNI/HTTP Host 多样性偏高，但该弱证据不能单独确认代理',
      samples: ['updates.example.test', 'cdn.example.test', 'game.example.test', 'chat.example.test'],
      created_at: '2026-07-24T05:17:31Z',
    },
    {
      evidence_id: 'evidence-port-v6',
      ip: '2001:db8::37',
      type: 'port_distribution',
      window: '10m0s',
      score: 21,
      confidence: 0.65,
      severity: 'low',
      reason: '目的端口分布异常，需要结合负证据排除下载器或游戏加速器',
      samples: ['80', '443', '3478', '5000', '5228'],
      created_at: '2026-07-24T05:17:31Z',
    },
  ],
  '10.255.0.15': [],
}

export const eventsByIp: Record<string, NormalizedEventSummary[]> = {
  '10.255.0.59': [
    {
      event_id: 'event-http-59-a',
      source: 'suricata',
      type: 'http',
      timestamp: '2026-07-24T05:18:52Z',
      observer: { sensor_id: 'office-30', interface: 'ens1f1' },
      subject: { ip: '10.255.0.59' },
      flow: { src_ip: '10.255.0.59', dst_ip: '198.51.100.43', dst_port: 80, proto: 'tcp', direction: 'outbound' },
      payload: { host: 'portal.example.test', user_agent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)' },
      confidence: 1,
      raw_ref: { backend: 'suricata', line_offset: 988 },
    },
    {
      event_id: 'event-tls-59-b',
      source: 'suricata',
      type: 'tls',
      timestamp: '2026-07-24T05:19:02Z',
      observer: { sensor_id: 'office-30', interface: 'ens1f1' },
      subject: { ip: '10.255.0.59' },
      flow: { src_ip: '10.255.0.59', dst_ip: '198.51.100.44', dst_port: 443, proto: 'tcp', direction: 'outbound' },
      payload: { sni: 'api.example.test', ja3: 'android-okhttp', ja4: 'android-okhttp' },
      confidence: 1,
      raw_ref: { backend: 'suricata', line_offset: 992 },
    },
  ],
  '10.255.0.98': [],
  '2001:db8::37': [],
  '10.255.0.15': [],
}

export const activityByIp: Record<string, IpActivityProfile> = {
  '10.255.0.59': {
    ip: '10.255.0.59',
    window: 'latest-run',
    event_count: 128,
    first_seen: '2026-07-24T05:10:00Z',
    last_seen: '2026-07-24T05:19:02Z',
    event_type_counts: [
      { value: 'dns', count: 48 },
      { value: 'tls', count: 45 },
      { value: 'http', count: 22 },
      { value: 'flow', count: 13 },
    ],
    protocol_counts: [
      { value: 'tcp', count: 80 },
      { value: 'udp', count: 48 },
    ],
    top_domains: [
      { value: 'api.example.test', count: 18, last_seen: '2026-07-24T05:19:02Z' },
      { value: 'portal.example.test', count: 11, last_seen: '2026-07-24T05:18:52Z' },
      { value: 'updates.example.test', count: 9, last_seen: '2026-07-24T05:17:41Z' },
      { value: 'push.example.test', count: 7, last_seen: '2026-07-24T05:16:12Z' },
    ],
    top_http_hosts: [
      { value: 'portal.example.test', count: 11, last_seen: '2026-07-24T05:18:52Z' },
      { value: 'cdn.example.test', count: 6, last_seen: '2026-07-24T05:15:33Z' },
    ],
    top_tls_sni: [
      { value: 'api.example.test', count: 18, last_seen: '2026-07-24T05:19:02Z' },
      { value: 'push.example.test', count: 7, last_seen: '2026-07-24T05:16:12Z' },
    ],
    top_user_agents: [
      { value: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)', count: 8, last_seen: '2026-07-24T05:18:52Z' },
      { value: 'okhttp/4.12.0', count: 5, last_seen: '2026-07-24T05:17:12Z' },
      { value: 'Dalvik/2.1.0 (Linux; U; Android 14)', count: 4, last_seen: '2026-07-24T05:16:01Z' },
    ],
    top_tls_fingerprints: [
      { value: 'ja3:android-okhttp', count: 12, last_seen: '2026-07-24T05:19:02Z' },
      { value: 'ja4:android-okhttp', count: 12, last_seen: '2026-07-24T05:19:02Z' },
      { value: 'ja3:chrome-desktop', count: 10, last_seen: '2026-07-24T05:18:20Z' },
    ],
    top_dst_ports: [
      { value: '443', count: 62, last_seen: '2026-07-24T05:19:02Z' },
      { value: '53', count: 48, last_seen: '2026-07-24T05:18:58Z' },
      { value: '80', count: 18, last_seen: '2026-07-24T05:18:52Z' },
    ],
    top_dst_ips: [
      { value: '198.51.100.44', count: 18, last_seen: '2026-07-24T05:19:02Z' },
      { value: '198.51.100.43', count: 11, last_seen: '2026-07-24T05:18:52Z' },
    ],
    recent_accesses: [
      {
        timestamp: '2026-07-24T05:19:02Z',
        event_id: 'event-tls-59-b',
        type: 'tls',
        target_kind: 'tls_sni',
        target: 'api.example.test',
        dst_ip: '198.51.100.44',
        dst_port: 443,
        proto: 'tcp',
      },
      {
        timestamp: '2026-07-24T05:18:52Z',
        event_id: 'event-http-59-a',
        type: 'http',
        target_kind: 'http_host',
        target: 'portal.example.test',
        method: 'GET',
        user_agent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
        dst_ip: '198.51.100.43',
        dst_port: 80,
        proto: 'tcp',
      },
    ],
  },
}

export const activityOverview: ActivityOverview = {
  sensor_id: 'office-30',
  window: '1h',
  event_count: 3820,
  active_ip_count: 146,
  access_object_count: 287,
  active_risk_ip_count: 3,
  first_seen: '2026-07-24T04:20:00Z',
  last_seen: '2026-07-24T05:19:15Z',
  event_type_counts: [
    { value: 'dns', count: 1580, last_seen: '2026-07-24T05:19:10Z' },
    { value: 'flow', count: 1140, last_seen: '2026-07-24T05:19:15Z' },
    { value: 'tls', count: 830, last_seen: '2026-07-24T05:19:02Z' },
    { value: 'http', count: 270, last_seen: '2026-07-24T05:18:52Z' },
  ],
  protocol_counts: [
    { value: 'tcp', count: 2240, last_seen: '2026-07-24T05:19:15Z' },
    { value: 'udp', count: 1580, last_seen: '2026-07-24T05:19:10Z' },
  ],
  top_domains: [
    { value: 'api.example.test', count: 182, last_seen: '2026-07-24T05:19:02Z' },
    { value: 'updates.example.test', count: 143, last_seen: '2026-07-24T05:18:41Z' },
    { value: 'cdn.example.test', count: 118, last_seen: '2026-07-24T05:18:12Z' },
    { value: 'push.example.test', count: 91, last_seen: '2026-07-24T05:16:12Z' },
  ],
  top_http_hosts: [
    { value: 'portal.example.test', count: 64, last_seen: '2026-07-24T05:18:52Z' },
    { value: 'cdn.example.test', count: 48, last_seen: '2026-07-24T05:15:33Z' },
  ],
  top_tls_sni: [
    { value: 'api.example.test', count: 132, last_seen: '2026-07-24T05:19:02Z' },
    { value: 'push.example.test', count: 91, last_seen: '2026-07-24T05:16:12Z' },
  ],
  top_user_agents: [
    { value: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)', count: 58, last_seen: '2026-07-24T05:18:52Z' },
    { value: 'okhttp/4.12.0', count: 44, last_seen: '2026-07-24T05:17:12Z' },
    { value: 'Dalvik/2.1.0 (Linux; U; Android 14)', count: 31, last_seen: '2026-07-24T05:16:01Z' },
  ],
  top_tls_fingerprints: [
    { value: 'ja3:chrome-desktop', count: 106, last_seen: '2026-07-24T05:18:20Z' },
    { value: 'ja3:android-okhttp', count: 82, last_seen: '2026-07-24T05:19:02Z' },
    { value: 'ja4:android-okhttp', count: 82, last_seen: '2026-07-24T05:19:02Z' },
  ],
  top_dst_ports: [
    { value: '443', count: 1720, last_seen: '2026-07-24T05:19:15Z' },
    { value: '53', count: 1580, last_seen: '2026-07-24T05:19:10Z' },
    { value: '80', count: 270, last_seen: '2026-07-24T05:18:52Z' },
    { value: '5228', count: 92, last_seen: '2026-07-24T05:16:12Z' },
  ],
  top_dst_ips: [
    { value: '198.51.100.44', count: 182, last_seen: '2026-07-24T05:19:02Z' },
    { value: '198.51.100.43', count: 111, last_seen: '2026-07-24T05:18:52Z' },
  ],
  top_source_ips: [
    { value: '10.255.0.59', count: 128, last_seen: '2026-07-24T05:19:02Z' },
    { value: '10.255.0.98', count: 94, last_seen: '2026-07-24T05:18:44Z' },
    { value: '2001:db8::37', count: 76, last_seen: '2026-07-24T05:17:31Z' },
  ],
  top_active_risk_ips: [
    {
      ip: '10.255.0.59',
      risk_level: 'confirmed',
      score: 88,
      event_count: 128,
      top_domains: [
        { value: 'api.example.test', count: 18, last_seen: '2026-07-24T05:19:02Z' },
        { value: 'portal.example.test', count: 11, last_seen: '2026-07-24T05:18:52Z' },
      ],
      last_seen: '2026-07-24T05:19:02Z',
    },
    {
      ip: '10.255.0.98',
      risk_level: 'high',
      score: 71,
      event_count: 94,
      top_domains: [{ value: 'updates.example.test', count: 14, last_seen: '2026-07-24T05:18:44Z' }],
      last_seen: '2026-07-24T05:18:44Z',
    },
    {
      ip: '2001:db8::37',
      risk_level: 'suspicious',
      score: 45,
      event_count: 76,
      top_domains: [{ value: 'game.example.test', count: 9, last_seen: '2026-07-24T05:17:31Z' }],
      last_seen: '2026-07-24T05:17:31Z',
    },
  ],
}

export const shadowRuns: ShadowRun[] = [
  {
    run_id: '20260724-131645',
    started_at: '2026-07-24T05:16:45Z',
    finished_at: '2026-07-24T05:19:15Z',
    sensor_id: 'office-30',
    previous_offset: 102400,
    new_offset: 218770,
    truncated: false,
    normalized: { read: 1000, emitted: 862, skipped: 119, malformed: 19 },
    evidence_count: 7,
    risk_count: 4,
    risk_list_count: 3,
  },
  {
    run_id: '20260724-130000',
    started_at: '2026-07-24T05:00:00Z',
    finished_at: '2026-07-24T05:10:00Z',
    sensor_id: 'office-30',
    previous_offset: 0,
    new_offset: 102400,
    truncated: true,
    normalized: { read: 520, emitted: 481, skipped: 33, malformed: 6 },
    evidence_count: 3,
    risk_count: 2,
    risk_list_count: 1,
  },
]

export const auditLogs: AuditLog[] = [
  {
    audit_id: 'audit-001',
    actor: 'ops-001',
    action: 'labels.create',
    target: 'ip:10.255.0.98',
    outcome: 'mock accepted',
    created_at: '2026-07-24T05:21:00Z',
  },
  {
    audit_id: 'audit-002',
    actor: 'system',
    action: 'shadow.run',
    target: '20260724-131645',
    outcome: 'risk_list_count=3',
    created_at: '2026-07-24T05:19:15Z',
  },
]

export const overview: Overview = {
  level_counts: { normal: 1, suspicious: 1, high: 1, confirmed: 1 },
  pending_reviews: 2,
  latest_shadow_run: shadowRuns[0],
  throughput: { events: 862, evidence: 7, risks: 4 },
  top_evidence: [
    { type: 'multi_user_agent', count: 2 },
    { type: 'multi_ja3_ja4', count: 2 },
    { type: 'port_distribution', count: 2 },
    { type: 'domain_diversity', count: 1 },
  ],
}

export const ingestStatus: IngestStatus = {
  sensor_id: 'office-30',
  collector: { kind: 'suricata', version: '6.0.20', interface: 'ens1f1' },
  storage_mode: 'dual',
  latest_run_id: shadowRuns[0].run_id,
  latest_run_at: shadowRuns[0].finished_at,
  healthy: true,
  severity: 'info',
  summary: 'collector and normalization pipeline are producing standard events',
  last_counters: { read: 1000, emitted: 862, skipped: 119, malformed: 19 },
  last_event_type_dist: { flow: 250, dns: 250, tls: 250, http: 112 },
}

export const ingestEventTypes: EventTypeCount[] = [
  { type: 'flow', count: 250 },
  { type: 'dns', count: 250 },
  { type: 'tls', count: 250 },
  { type: 'http', count: 112 },
]

export const ingestDiagnostics: IngestDiagnostic[] = [
  {
    schema_version: 'v1',
    diagnostic_id: 'diag-20260724-131645',
    timestamp: shadowRuns[0].finished_at,
    sensor_id: 'office-30',
    collector: { kind: 'suricata', version: '6.0.20', interface: 'ens1f1' },
    stage: 'normalize',
    type: 'stats',
    severity: 'warning',
    summary: 'collector run completed with skipped or malformed input records',
    counters: { read: 1000, emitted: 862, skipped: 119, malformed: 19 },
    by_type: { flow: 250, dns: 250, tls: 250, http: 112 },
    raw_ref: { backend: 'suricata', source: '/var/log/suricata/eve.json', offset: 218770 },
    details: { run_id: shadowRuns[0].run_id, truncated: false },
  },
  {
    schema_version: 'v1',
    diagnostic_id: 'diag-20260724-130000',
    timestamp: shadowRuns[1].finished_at,
    sensor_id: 'office-30',
    collector: { kind: 'suricata', version: '6.0.20', interface: 'ens1f1' },
    stage: 'normalize',
    type: 'stats',
    severity: 'warning',
    summary: 'collector run completed with skipped or rotated input',
    counters: { read: 520, emitted: 481, skipped: 33, malformed: 6 },
    by_type: { flow: 160, dns: 151, tls: 100, http: 70 },
    raw_ref: { backend: 'suricata', source: '/var/log/suricata/eve.json', offset: 102400 },
    details: { run_id: shadowRuns[1].run_id, truncated: true },
  },
]

export function getActivityOverviewByWindow(window: string): ActivityOverview {
  let scale = 1.0
  let eventCount = 3820
  let activeIpCount = 146
  let accessObjectCount = 287
  let activeRiskIpCount = 3
  let topRiskIps = activityOverview.top_active_risk_ips

  if (window === '10m') {
    scale = 0.16
    eventCount = 640
    activeIpCount = 38
    accessObjectCount = 52
    activeRiskIpCount = 2
    topRiskIps = activityOverview.top_active_risk_ips.slice(0, 2)
  } else if (window === '24h') {
    scale = 24.0
    eventCount = 91600
    activeIpCount = 820
    accessObjectCount = 1450
    activeRiskIpCount = 7
    topRiskIps = [
      ...activityOverview.top_active_risk_ips,
      {
        ip: '10.255.1.102',
        risk_level: 'suspicious',
        score: 55,
        event_count: 840,
        top_domains: [{ value: 'cloud.example.test', count: 120 }],
        last_seen: '2026-07-24T05:14:00Z',
      },
    ]
  }

  const scaleCounts = (items: Array<{ value: string; count: number; last_seen?: string }>) =>
    items.map((item) => ({
      ...item,
      count: Math.max(1, Math.round(item.count * scale)),
    }))

  const targetWindow: ActivityOverview['window'] =
    window === '10m' || window === '24h' || window === '1h' || window === 'latest-run'
      ? window
      : '1h'

  return {
    ...activityOverview,
    window: targetWindow,
    event_count: eventCount,
    active_ip_count: activeIpCount,
    access_object_count: accessObjectCount,
    active_risk_ip_count: activeRiskIpCount,
    event_type_counts: scaleCounts(activityOverview.event_type_counts),
    protocol_counts: scaleCounts(activityOverview.protocol_counts),
    top_domains: scaleCounts(activityOverview.top_domains),
    top_http_hosts: scaleCounts(activityOverview.top_http_hosts),
    top_tls_sni: scaleCounts(activityOverview.top_tls_sni),
    top_user_agents: scaleCounts(activityOverview.top_user_agents),
    top_tls_fingerprints: scaleCounts(activityOverview.top_tls_fingerprints),
    top_dst_ports: scaleCounts(activityOverview.top_dst_ports),
    top_dst_ips: scaleCounts(activityOverview.top_dst_ips),
    top_source_ips: scaleCounts(activityOverview.top_source_ips),
    top_active_risk_ips: topRiskIps.map((item) => ({
      ...item,
      event_count: Math.max(1, Math.round(item.event_count * scale)),
    })),
  }
}

export const mockFingerprintConflicts: FingerprintConflictItem[] = [
  {
    id: 'conflict-01',
    ip: '10.255.0.59',
    conflict_type: 'ua_conflict',
    type_label: 'UA 客户端碰撞',
    risk_level: 'confirmed',
    confidence: 0.92,
    device_count: 3,
    detected_samples: [
      'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
      'Mozilla/5.0 (iPhone; CPU iPhone OS 17_4)',
      'Dalvik/2.1.0 (Linux; U; Android 14)',
    ],
    reason: '同 1 分钟窗口内交错出现 Windows PC、iPhone 以及 Android 架构的 HTTP Header',
    last_seen: '2026-07-28T05:19:02Z',
  },
  {
    id: 'conflict-02',
    ip: '10.255.0.98',
    conflict_type: 'ja3_mismatch',
    type_label: 'JA3 / JA4 栈错配',
    risk_level: 'high',
    confidence: 0.84,
    device_count: 2,
    detected_samples: [
      'ja3:771,4865-4866-4867... (Chrome Desktop)',
      'ja3:771,49195-49199... (Android Webview)',
    ],
    reason: 'TLS Client Hello 指纹与 User-Agent 声明的浏览器内核参数不匹配，疑似代理中转',
    last_seen: '2026-07-28T05:18:44Z',
  },
  {
    id: 'conflict-03',
    ip: '2001:db8::37',
    conflict_type: 'ttl_step',
    type_label: 'TTL 阶梯步进',
    risk_level: 'suspicious',
    confidence: 0.68,
    device_count: 2,
    detected_samples: ['TTL: 64 (Linux/Android 游程)', 'TTL: 128 (Windows 游程)'],
    reason: 'IP 报头 TTL 在 64 与 128 之间交替出现，匹配二级路由器/NAT 共享拓扑',
    last_seen: '2026-07-28T05:17:31Z',
  },
]

export const mockDpiProtocolFlows: DpiProtocolFlowItem[] = [
  {
    protocol: 'TLS',
    app_protocol: 'TLS',
    share_percent: 48.5,
    event_count: 1850,
    bps_mbps: 24.5,
    top_apps: ['api.example.test', 'push.example.test', 'cloud.example.test'],
    category: 'Encrypted Security',
  },
  {
    protocol: 'HTTP',
    app_protocol: 'HTTP',
    share_percent: 24.2,
    event_count: 924,
    bps_mbps: 12.1,
    top_apps: ['portal.example.test', 'cdn.example.test'],
    category: 'Web/API',
  },
  {
    protocol: 'DNS',
    app_protocol: 'DNS',
    share_percent: 18.3,
    event_count: 698,
    bps_mbps: 0.85,
    top_apps: ['Core DNS Resolver', 'DoH Endpoint'],
    category: 'Core Infrastructure',
  },
  {
    protocol: 'P2P/Proxy',
    app_protocol: 'P2P/Proxy',
    share_percent: 9.0,
    event_count: 348,
    bps_mbps: 6.8,
    top_apps: ['V2Ray/Shadowsocks Tunnel', 'WireGuard Portal'],
    category: 'Proxy/Tethering',
  },
]

export const mockDpiTrendPoints: DpiTrendPoint[] = [
  { time: '2026-07-28T00:00:00Z', active_devices: 42, risk_ips: 2, event_count: 7200, pps: 3400, bps_mbps: 28.5, cps: 120, estimated: false },
  { time: '2026-07-28T04:00:00Z', active_devices: 18, risk_ips: 1, event_count: 2700, pps: 1200, bps_mbps: 8.2, cps: 45, estimated: false },
  { time: '2026-07-28T08:00:00Z', active_devices: 95, risk_ips: 4, event_count: 22800, pps: 8900, bps_mbps: 76.4, cps: 380, estimated: false },
  { time: '2026-07-28T12:00:00Z', active_devices: 146, risk_ips: 7, event_count: 37200, pps: 15400, bps_mbps: 142.0, cps: 620, estimated: false },
  { time: '2026-07-28T16:00:00Z', active_devices: 168, risk_ips: 8, event_count: 44400, pps: 18200, bps_mbps: 168.5, cps: 740, estimated: false },
  { time: '2026-07-28T20:00:00Z', active_devices: 120, risk_ips: 5, event_count: 29400, pps: 11200, bps_mbps: 98.2, cps: 490, estimated: false },
]

export const mockFlowSamples: Record<string, DpiFlowSample[]> = {
  '10.255.0.59': [
    {
      flow_id: 'flow-59-001',
      event_id: 'event-tls-59-b',
      timestamp: '2026-07-28T05:19:02Z',
      sensor_id: 'office-30',
      interface_name: 'ens1f1',
      src_ip: '10.255.0.59',
      src_port: 54102,
      dst_ip: '198.51.100.44',
      dst_port: 443,
      protocol: 'TCP',
      app_protocol: 'TLS 1.3',
      tls_sni: 'api.example.test',
      ja3: '771,4865-4866-4867,0-23-65281-10-11-35-16-5-13-18-51-45-43-21',
      ja4: 't13d1516h2_8daaf6152771_026778401344',
      ttl: 64,
      ipid: 12840,
      payload_summary: 'TLS Client Hello (extension sni=api.example.test, alpn=h2,http/1.1)',
    },
    {
      flow_id: 'flow-59-002',
      event_id: 'event-http-59-a',
      timestamp: '2026-07-28T05:18:52Z',
      sensor_id: 'office-30',
      interface_name: 'ens1f1',
      src_ip: '10.255.0.59',
      src_port: 52190,
      dst_ip: '198.51.100.43',
      dst_port: 80,
      protocol: 'TCP',
      app_protocol: 'HTTP/1.1',
      user_agent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36',
      ttl: 128,
      ipid: 44102,
      payload_summary: 'GET /portal/dashboard HTTP/1.1 (Host: portal.example.test)',
    },
  ],
  '10.255.0.98': [
    {
      flow_id: 'flow-98-001',
      event_id: 'event-tls-98-a',
      timestamp: '2026-07-28T05:18:44Z',
      sensor_id: 'office-30',
      interface_name: 'ens1f1',
      src_ip: '10.255.0.98',
      src_port: 49812,
      dst_ip: '198.51.100.88',
      dst_port: 443,
      protocol: 'TCP',
      app_protocol: 'TLS 1.2',
      tls_sni: 'auth.example.test',
      ja3: '771,49195-49199-49196-49200,0-10-11-23-65281-16-5-13-18',
      ttl: 64,
      ipid: 8910,
      payload_summary: 'TLS Client Hello (JA3 mismatch with Chrome UA)',
    },
  ],
}
