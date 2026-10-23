import { http, HttpResponse } from 'msw'

const now = () => new Date().toISOString()

const templates = [
  { template_id: 'proxy-reminder', name: '代理行为提醒', channel_type: 'http', subject: '策略提醒', body: '账号 {{account}} 在 {{ip}} 触发 {{policy_name}}', variables: ['account', 'ip', 'policy_name'], enabled: true, revision: 1 },
]

const channels = [
  { channel_id: 'duty-webhook', name: '值班 Webhook', channel_type: 'http', endpoint_url: 'https://example.invalid/notify', auth_type: 'bearer', has_secret: true, is_default: true, enabled: true, revision: 1, config: { timeout_seconds: 10 } },
]

const outbox = [
  { notification_id: 'notification-demo-1', idempotency_key: 'demo-1', account_id: 'student-01', template: 'proxy-reminder', parameters: { account: 'student-01' }, status: 'sent', channel_id: 'duty-webhook', attempts: 1, remote_id: 'remote-1', sent_at: now(), created_at: now(), updated_at: now() },
  { notification_id: 'notification-demo-2', idempotency_key: 'demo-2', account_id: 'student-02', template: 'proxy-reminder', parameters: { account: 'student-02' }, status: 'failed', channel_id: 'duty-webhook', attempts: 3, last_error: '通道拒绝请求: HTTP 400', created_at: now(), updated_at: now() },
]

const blacklist = [
  { entry_id: 'blacklist-demo-1', type: 'account', value: 'offender-01', reason: '确认代理行为', enabled: true, valid_from: now(), revision: 1, created_by: 'admin', updated_by: 'admin', created_at: now(), updated_at: now() },
]

const targetRules = [
  { rule_id: 'ncu-sensitive-range', name: '敏感网段访问', enabled: false, behavior_type: 'configured_ip_range', target_type: 'cidr', targets: ['10.155.32.0/24'], window_seconds: 3600, threshold: 3, direction: 'any', push_enabled: false, push_without_account: false, created_at: now(), updated_at: now() },
]

const targetFindings = [
  { finding_id: 'dtt-demo-1', rule_id: 'ncu-sensitive-range', rule_name: '敏感网段访问', subject_ip: '10.155.9.9', account_id: 'student-03', behavior_type: 'configured_ip_range', matched_targets: ['10.155.32.0/24'], unique_destinations: 4, hit_count: 9, direction: 'outbound', window_start: now(), window_end: now(), first_seen: now(), last_seen: now(), pushed: false, created_at: now() },
]

const reportChannels = [
  { channel_id: 'ncu-behavior', name: '网络安全行为上报', endpoint_url: 'https://example.invalid/security-behavior/report', auth_type: 'oauth2_client_credentials', token_endpoint: 'https://example.invalid/api/v1/auth/get-access-token', token_method: 'GET', has_secret: true, enabled: true, revision: 1, batch_size: 100, timeout_seconds: 10, field_mapping: { behavior_type: 'event_type', account: 'account' }, success_status_codes: [200], updated_at: now() },
]

const reportOutbox = [
  { report_id: 'shared-record:shared-observe-demo:ncu-behavior', idempotency_key: 'shared-record:shared-observe-demo:ncu-behavior', channel_id: 'ncu-behavior', event_type: 'proxy_behavior', subject_type: 'account', subject_id: 'campus-student-001', account_id: 'campus-student-001', ip: '192.0.2.44', target: '', target_type: '', occurred_at: now(), status: 'recorded', attempts: 0, http_status: 0, policy_decision_id:'shared-observe-demo',observation_id:'shared-behavior-test',evidence_version:'8e79c1a7fabc0123456789abcdef012345',created_at: now(), updated_at: now() },
  { report_id: 'report-demo-1', idempotency_key: 'demo-report-1', channel_id: 'ncu-behavior', event_type: 'poison_behavior', subject_type: 'ip', subject_id: '10.155.9.9', account_id: 'student-03', ip: '10.155.9.9', target: 'w1', target_type: 'window', occurred_at: now(), status: 'queued', attempts: 0, http_status: 0, created_at: now(), updated_at: now() },
]

const page = (items: unknown[]) => ({ items, page: { limit: 20, next_cursor: null, total: items.length } })

export const notificationHandlers = [
  http.get('/api/v1/notifications/templates', () => HttpResponse.json({ items: templates, allowed_variables: ['account', 'ip', 'policy_name', 'date'] })),
  http.get('/api/v1/notifications/channels', () => HttpResponse.json({ items: channels })),
  http.get('/api/v1/notifications/outbox', () => HttpResponse.json(page(outbox))),
  http.get('/api/v1/notifications/outbox/:notificationId', ({ params }) => HttpResponse.json({
    notification: outbox.find((item) => item.notification_id === params.notificationId) ?? outbox[0],
    attempts: [{ attempt_id: 'attempt-1', notification_id: String(params.notificationId), attempt: 1, status: 'sent', http_status: 200, remote_id: 'remote-1', started_at: now(), finished_at: now() }],
  })),
  http.post('/api/v1/notifications/test', () => HttpResponse.json({ channel_id: 'duty-webhook', status: 'succeeded', http_status: 200, remote_id: 'preview-1' })),
]

export const blacklistHandlers = [
  http.get('/api/v1/blacklist', () => HttpResponse.json({ ...page(blacklist), checked_at: now() })),
  http.post('/api/v1/blacklist', async ({ request }) => {
    const payload = await request.json() as Record<string, unknown>
    return HttpResponse.json({ ...payload, entry_id: `blacklist-${Date.now()}`, valid_from: now(), revision: 1, created_by: 'ops-001', updated_by: 'ops-001', created_at: now(), updated_at: now() }, { status: 201 })
  }),
]

export const destinationTargetHandlers = [
  http.get('/api/v1/destination-targets/rules', () => HttpResponse.json({ items: targetRules, behavior_types: ['configured_ip_range', 'high_frequency_internal'] })),
  http.post('/api/v1/destination-targets/rules/:ruleId/preview', () => HttpResponse.json({ rule_id: 'ncu-sensitive-range', rule_enabled: false, observations: 42, window_seconds: 3600, items: [{ subject_ip: '10.155.9.9', matched_targets: ['10.155.32.0/24'], unique_destinations: 4, hit_count: 9, direction: 'outbound', first_seen: now(), last_seen: now() }] })),
  http.get('/api/v1/destination-targets/findings', () => HttpResponse.json(page(targetFindings))),
]

export const behaviorReportHandlers = [
  http.get('/api/v1/behavior-reports/channels', () => HttpResponse.json({ items: reportChannels, event_types: ['poison_behavior', 'proxy_behavior', 'ai_relay_audit'] })),
  http.post('/api/v1/behavior-reports/channels/:channelId/test', () => HttpResponse.json({ channel_id: 'ncu-behavior', status: 'succeeded', http_status: 200, remote_id: 'preview-1' })),
  http.post('/api/v1/behavior-reports/channels/:channelId/preview', () => HttpResponse.json({ channel_id: 'ncu-behavior', payload: { behavior_type: 'malware', account: 'student-03', source_ip: '10.155.9.9' } })),
  http.get('/api/v1/behavior-reports/outbox', ({request}) => {const status=new URL(request.url).searchParams.get('status');return HttpResponse.json(page(status?reportOutbox.filter(row=>row.status===status):reportOutbox))}),
  http.get('/api/v1/behavior-reports/outbox/:reportId', ({ params }) => HttpResponse.json({
    report: reportOutbox.find((item) => item.report_id === params.reportId) ?? reportOutbox[0],
    attempts: String(params.reportId).startsWith('shared-record:')?[]:[{ attempt_id: 'attempt-1', report_id: String(params.reportId), attempt: 1, status: 'failed', http_status: 502, error: '平台暂时不可用', started_at: now(), finished_at: now() }],
  })),
]
