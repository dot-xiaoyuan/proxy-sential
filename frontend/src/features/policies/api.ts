import type { components } from '../../shared/api/generated'
import type { ProxyProtocolEvidence } from '../../shared/api/types'
import { request } from '../../shared/api/client'
export interface Scope { accounts?: string[]; sources?: string[]; groups?: string[]; products?: string[]; campuses?: string[]; vlans?: string[]; cidrs?: string[]; weekdays?: number[]; start_minute?: number | null; end_minute?: number | null }
export interface Stage { action: string; connector_id: string; after_seconds: number; min_episodes: number; duration_seconds: number; rate_kbps: number; template: string; depends_on?: string[]; interval_seconds?: number; sync_notify?: boolean; put_black?: boolean }
export interface PolicyOrigin { source: string; snapshot_id: string; external_product_id?: string; external_policy_ids?: string[]; conversion_version: string; import_batch_id: string; reference_fields?: string[] }
export interface Policy { policy_id: string; name: string; enabled: boolean; priority: number; mode: string; trigger: string; action_model?: string; scope: Scope; exempt: Scope; limits: {total: number | null; mobile: number | null; pc: number | null; sessions?: number | null}; sustain_seconds: number; window_seconds: number; recovery_seconds: number; cooldown_seconds: number; stages: Stage[]; revision?: number; origin?: PolicyOrigin }
export interface Quota { state: string; total: number; mobile: number; pc: number; other: number; uncertain_sessions: number; coverage_complete: boolean; reasons: string[]; devices: { id: string; class: string; session_ids: string[] }[] }
export interface Simulation { account_id: string; inventory: Quota; sessions: components['schemas']['PolicyIdentitySession'][]; explanations: {policy_id: string; reason: string; selected: boolean}[]; evaluations: {policy_id: string; quota?: Quota; proxy_evidence?: ProxyProtocolEvidence[]; shared_evaluation?: components['schemas']['SharedAccessEvaluation'][]; shared_error?: string; input: {known: boolean; violated: boolean; reasons: string[]}}[] }
export interface Execution { proxy_evidence?: ProxyProtocolEvidence[]; execution_id: string; account_id: string; policy_id: string; state: string; episode: number; reasons: string[]; stages: { index: number; status: string; action_ids: string[] }[] }
export interface ApprovalPreviewData { fingerprint: string; account_id: string; stage_index: number; stage: Stage; evidence_ids: string[]; sessions: {session_id:string;ip:string;campus_id:string;access_domain:string}[] }
export interface ProductCatalogItem { source: string; product_id: string; name: string; snapshot_id: string; active: boolean; updated_at: string; document: {control_ids?: string[]} }
export interface FourKDirectoryItem { id:string; name?:string }
export interface FourKDirectory { source:string; products:FourKDirectoryItem[]; groups:FourKDirectoryItem[]; accounts:FourKDirectoryItem[]; vlans:FourKDirectoryItem[]; product_observed_at?:string; identity_observed_at?:string; identity_sessions:number; controls:number }
export interface ProductPolicyStatus { enabled: boolean; active_products: number; active_controls: number; snapshots: number; last_received_at?: string | null }
export interface ImportItem { external_type: string; external_id: string; name: string; disposition: 'direct'|'reference_only'|'configuration_required'|'rejected'; reasons: string[]; policy?: Policy }
export interface ImportBatch { batch_id: string; status: 'previewed'|'published'; preview: {snapshot_id:string;source:string;items:ImportItem[];summary:Record<string,number>} }
export interface PolicyDecision { decision_id:string; policy_id:string; policy_revision:number; account_id:string; known:boolean; violated:boolean; evaluated_at:string; product_ids:string[]; group_ids:string[]; identity_snapshot_ids?:string[]; session_bindings:string[]; reasons:string[]; execution_state:string; origin?:PolicyOrigin }
export const policiesAPI = {
 approvalPreview: (id:string) => request<ApprovalPreviewData>(`/policy-executions/${encodeURIComponent(id)}/approval-preview`),
 list: () => request<{items: Policy[]}>('/policies'),
 save: (p: Policy, creating: boolean) => request<Policy>(creating ? '/policies' : `/policies/${encodeURIComponent(p.policy_id)}`, {method: creating ? 'POST' : 'PUT', body: JSON.stringify(p)}),
 simulate: (id: string, account: string) => request<Simulation>(`/policies/${encodeURIComponent(id)}/simulate`, {method:'POST',body:JSON.stringify({account_id:account})}),
 executions: () => request<{items:Execution[]}>('/policy-executions'),
 operation: (id: string, op: 'approve' | 'revoke', fingerprint?:string) => request(`/policy-executions/${encodeURIComponent(id)}/${op}`, {method:'POST',body: op==='approve' ? JSON.stringify({fingerprint}) : undefined}),
 productPolicyStatus: () => request<ProductPolicyStatus>('/integrations/product-policy/status'),
 productCatalog: () => request<{items:ProductCatalogItem[]}>('/integrations/product-policy/catalog'),
 fourKDirectory: () => request<FourKDirectory>('/integrations/4k-directory'),
 previewImport: (source:string) => request<ImportBatch>('/policy-imports/preview',{method:'POST',body:JSON.stringify({source})}),
 publishImport: (batchId:string) => request<{batch_id:string;status:string;policies:Policy[];replayed:boolean}>(`/policy-imports/${encodeURIComponent(batchId)}/publish`,{method:'POST'}),
 decisions: () => request<{items:PolicyDecision[]}>('/policy-decisions?limit=50'),
}
