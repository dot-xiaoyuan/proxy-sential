import type { BrandInference, EndpointDeviceInventory, EndpointIdentityProfile } from '../shared/api/types'

const seen = new Date().toISOString()
export const domainOnlyInference: BrandInference = {
  status: 'inferred', brand: 'Apple', confidence: .7, rule_version: 'domain-v4-mock', window: '7d', as_of: seen,
  explanation: '两个 Apple 设备服务达到观察门槛；评分不是统计概率',
  candidates: [{ brand: 'Apple', confidence: .7, evidence: ['albert.apple.com', 'courier.push.apple.com'].map((domain, index) => ({
    match: { domain, rule_domain: index ? 'push.apple.com' : domain, ecosystem: 'Apple', category: index ? 'push' : 'activation', confidence: .65, source: 'Apple enterprise networks', source_url: 'https://support.apple.com/en-ie/101555', source_version: 'reviewed-2026-09-08', purpose: index ? 'Apple 设备推送连接' : 'Apple 设备激活', brand_eligible: true },
    first_seen: seen, last_seen: seen, count: 1, event_source: index ? 'tls' : 'http', event_ids: [`domain-evidence-${index}`], rule_version: 'domain-v4-mock',
  })) }],
}
export const domainOnlyDevice: EndpointDeviceInventory = {
  endpoint_id: 'mac:02:00:00:00:90:08', primary_mac: '02:00:00:00:90:08', entity_role: 'endpoint', registration_status: 'unregistered', merge_status: 'active',
  accounts: [], ips: ['198.18.90.8'], access_ids: [], current_ip: '198.18.90.8', identity_confidence: .9, recognition_confidence: 0,
  brand: '', brand_confidence: 0, randomized_mac: true, summary: '只有域名证据的终端', brand_inference: domainOnlyInference,
  ecosystem_hint: 'Apple', ecosystem_confidence: .7, ecosystem_evidence_count: 2, last_seen: seen,
}
export const domainOnlyProfile: EndpointIdentityProfile = {
  endpoint_id: domainOnlyDevice.endpoint_id, summary: domainOnlyDevice.summary, accounts: [], sessions: [], ip_history: [], access_history: [],
  endpoint: { endpoint_id: domainOnlyDevice.endpoint_id, primary_mac: domainOnlyDevice.primary_mac, entity_role: 'endpoint', identity_confidence: .9, attributes: {}, first_seen: seen, last_seen: seen, registration_status: 'unregistered', merge_status: 'active' },
  recognition: domainOnlyDevice, brand_inference: domainOnlyInference,
}
