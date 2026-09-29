import type { components } from '../../shared/api/generated'
import type { ProxyProtocolEvidence } from '../../shared/api/types'
import { request } from '../../shared/api/client'
export interface Scope { accounts?: string[]; groups?: string[]; products?: string[]; campuses?: string[]; vlans?: string[]; cidrs?: string[]; weekdays?: number[]; start_minute?: number | null; end_minute?: number | null }
export interface Stage { action: string; connector_id: string; after_seconds: number; min_episodes: number; duration_seconds: number; rate_kbps: number; template: string }
export interface Policy { policy_id: string; name: string; enabled: boolean; priority: number; mode: string; trigger: string; scope: Scope; exempt: Scope; limits: {total: number | null; mobile: number | null; pc: number | null}; sustain_seconds: number; window_seconds: number; recovery_seconds: number; cooldown_seconds: number; stages: Stage[]; revision?: number }
export interface Quota { state: string; total: number; mobile: number; pc: number; other: number; uncertain_sessions: number; coverage_complete: boolean; reasons: string[]; devices: { id: string; class: string; session_ids: string[] }[] }
export interface Simulation { account_id: string; inventory: Quota; sessions: components['schemas']['PolicyIdentitySession'][]; explanations: {policy_id: string; reason: string; selected: boolean}[]; evaluations: {policy_id: string; quota?: Quota; proxy_evidence?: ProxyProtocolEvidence[]; shared_evaluation?: components['schemas']['SharedAccessEvaluation'][]; shared_error?: string; input: {known: boolean; violated: boolean; reasons: string[]}}[] }
export interface Execution { proxy_evidence?: ProxyProtocolEvidence[]; execution_id: string; account_id: string; policy_id: string; state: string; episode: number; reasons: string[]; stages: { index: number; status: string; action_ids: string[] }[] }
export interface ApprovalPreviewData { fingerprint: string; account_id: string; stage_index: number; stage: Stage; evidence_ids: string[]; sessions: {session_id:string;ip:string;campus_id:string;access_domain:string}[] }
export const policiesAPI = {
 approvalPreview: (id:string) => request<ApprovalPreviewData>(`/policy-executions/${encodeURIComponent(id)}/approval-preview`),
 list: () => request<{items: Policy[]}>('/policies'),
 save: (p: Policy, creating: boolean) => request<Policy>(creating ? '/policies' : `/policies/${encodeURIComponent(p.policy_id)}`, {method: creating ? 'POST' : 'PUT', body: JSON.stringify(p)}),
 simulate: (id: string, account: string) => request<Simulation>(`/policies/${encodeURIComponent(id)}/simulate`, {method:'POST',body:JSON.stringify({account_id:account})}),
 executions: () => request<{items:Execution[]}>('/policy-executions'),
 operation: (id: string, op: 'approve' | 'revoke', fingerprint?:string) => request(`/policy-executions/${encodeURIComponent(id)}/${op}`, {method:'POST',body: op==='approve' ? JSON.stringify({fingerprint}) : undefined}),
}
