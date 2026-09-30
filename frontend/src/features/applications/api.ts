import { request, getApiBase } from '../../shared/api/client'
export interface ApplicationJob { status: string; version: string; processed: number; error?: string; requested_control?: string; last_success?: string; batch_millis?: number; retries?: number; lag_seconds?: number; available_from?: string; available_to?: string }
export interface LibraryStatus { enabled: boolean; config?: { credential_configured?: boolean; enabled: boolean; update_url: string; history_interval_ms?: number; last_pull_at?: string; last_pull_error?: string }; library: { version: string; versions: string[]; rule_count: number; activated_at: string }; job: ApplicationJob; last_scan: string; error?: string; retained_observations: number; retained_observations_known?: boolean; processing?: { storage: string; realtime: ApplicationJob; history: ApplicationJob; reconcile: ApplicationJob; query_millis: number } }
export interface AppItem { application_id: string; name: string; category: string; terminal_count: number; connection_count: number; observation_count: number; upload_bytes: number | null; download_bytes: number | null; missing_meter_connections: number; last_seen: string }
export interface Bucket { connection_count: number; upload_bytes: number | null; download_bytes: number | null; missing_meter_connections: number }
export interface AppReport { as_of?: string; statistics_as_of?: string; items: AppItem[]; versions: Record<string, number>; dns_observations: number; unknown_observations: number; missing_connection_observations: number; unknown: Bucket; multi_application: Bucket; observation_count: number; traffic_basis: string }
export interface Observation { event_id: string; timestamp: string; ip: string; sensor_id: string; campus_id: string; connection_id?: string; domain?: string; source_field?: string; bundle_version: string; match: { target_type?: string; target_id?: string; name?: string; rule_id?: string; confidence: number; source?: string; source_version?: string } }
export interface ApplicationExport { export_id: string; status: string; row_count: number; error?: string }
export const applicationAPI = {
 configure: (enabled: boolean, update_url: string, token?: string, history_interval_ms?: number) => request<LibraryStatus>('/application-library/config', {method: 'POST', body: JSON.stringify({enabled,update_url,token,history_interval_ms})}),
 pull: (token: string) => request<LibraryStatus>('/application-library/pull', {method: 'POST', body: JSON.stringify({token})}),
 status: () => request<LibraryStatus>('/application-library'),
 report: (q: string) => request<AppReport>(`/application-activity?${q}`),
 observations: (q: string) => request<{items: Observation[]; total: number; next_cursor?: string}>(`/application-activity/observations?${q}`),
 import: (file: File) => request<LibraryStatus>('/application-library/import', {method: 'POST', body: file, headers: {'Content-Type': 'application/gzip'}}),
 rollback: (version: string) => request<LibraryStatus>('/application-library/rollback', {method: 'POST', body: JSON.stringify({version})}),
 control: (operation: 'pause'|'resume'|'cancel') => request<LibraryStatus>(`/application-library/jobs/${operation}`, {method: 'POST'}),
 reclassify: () => request<LibraryStatus>('/application-library/reclassify', {method: 'POST'}),
 export: (q: string) => request<ApplicationExport>(`/application-activity/unknown-domains?${q}`),
 cancelExport: (id: string) => request<ApplicationExport>(`/exports/${encodeURIComponent(id)}/cancel`, {method: 'POST'}),
 exportStatus: (id: string) => request<ApplicationExport>(`/exports/${encodeURIComponent(id)}`),
 downloadExport: async (id: string) => {
 const response = await fetch(`${getApiBase()}/exports/${encodeURIComponent(id)}/download`, {credentials: 'include'})
 if (!response.ok) throw new Error('待补特征域名下载失败')
 const url = URL.createObjectURL(await response.blob()); const a = document.createElement('a'); a.href = url; a.download = 'unknown-domains.jsonl'; a.click(); setTimeout(() => URL.revokeObjectURL(url), 1000)

 },
}
export function formatBytes(n: number | null | undefined): string { if (n == null) return '不可用'; if (n < 1024) return `${n} B`; const index = Math.min(4, Math.floor(Math.log(n) / Math.log(1024))); return `${(n / 1024 ** index).toFixed(1)} ${['B','KiB','MiB','GiB','TiB'][index]}` }
