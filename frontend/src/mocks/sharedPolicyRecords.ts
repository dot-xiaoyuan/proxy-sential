import type { SharedPolicyDecision } from '../pages/SharedPolicyRecords'
export const sharedDecisionFixture: SharedPolicyDecision = {
 decision_id: 'shared-observe-demo', observation_id: 'shared-behavior-test', policy_revision: 1,
 evidence_version: '8e79c1a7fabc0123456789abcdef012345', account_id: 'campus-student-001', ip: '192.0.2.44',
 campus_id: 'ncu', access_domain: 'bond0-router-minimal-overnight', evaluated_at: new Date().toISOString(),
 evidence_expires_at: new Date(Date.now() + 180000).toISOString(), mode: 'observe', planned_action: 'disconnect', delivery_status: 'not_sent',
 result: 'matched', reasons: ['confirmed_shared_observation'],
 evidence: { rule_version: 'shared-access/v5', from: new Date(Date.now() - 60000).toISOString(), to: new Date().toISOString(), device_lower_bound: 2, records: [{ event_id: 'handshake-' + 'a'.repeat(96), source: 'handshake-sidecar', collector_instance_id: 'ncu184-router-minimal-demo' }] },
}
export function sharedDecisionMock(url: URL) {
 const result = url.searchParams.get('result') || 'matched'
 const item = { ...sharedDecisionFixture, result, reasons: result === 'insufficient' ? ['capture_interval_incomplete:handshake-sidecar', 'identity_snapshot_index_pending'] : result === 'expired' ? ['shared_evidence_expired'] : sharedDecisionFixture.reasons }
 return { processing: url.searchParams.get('include_processing')==='true'&&result==='insufficient'?[{ip:'2001:db8:1234:5678:90ab:cdef:1234:5678',state:'failed',first_received_at:new Date().toISOString()}]:[], items: url.searchParams.get('account_id') === 'empty' ? [] : [item], next_cursor: url.searchParams.get('cursor') ? '' : 'demo-cursor' }
}
