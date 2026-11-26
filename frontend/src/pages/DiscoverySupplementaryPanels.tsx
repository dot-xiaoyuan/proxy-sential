import { ArrowRightOutlined, ReloadOutlined } from '@ant-design/icons'
import { useQuery } from '@tanstack/react-query'
import { Button, Skeleton } from 'antd'
import { ApiError, request } from '../shared/api/client'
import { useSession } from '../shared/api/queries'
import type { ActivityOverview, DeviceInventoryMetadataResponse } from '../shared/api/types'
import { can } from '../shared/auth/permissions'
import { observedTimeTitle } from '../shared/ui/observedTime'
import { ReportLink } from './DiscoveryReportCharts'

const countFormat = new Intl.NumberFormat('zh-CN')
const eventLabels: Record<string, string> = {
  dns: 'DNS',
  tls: 'TLS',
  http: 'HTTP',
  flow: '流记录',
  connection: '连接',
  device: '设备观测',
  arp: 'ARP',
  ndp: 'NDP',
  dhcp: 'DHCP',
  mdns: 'mDNS',
  ssdp: 'SSDP',
  snmp: 'SNMP',
  lldp: 'LLDP',
}

function supplementaryWindow(discoveryWindow: string): { value: '24h' | '7d' | '30d'; label: string; fallbackFrom15m: boolean } {
  if (discoveryWindow === '168h') return { value: '7d', label: '近 7 天', fallbackFrom15m: false }
  if (discoveryWindow === '720h') return { value: '30d', label: '近 30 天', fallbackFrom15m: false }
  return { value: '24h', label: '近 24 小时', fallbackFrom15m: discoveryWindow === '15m' }
}

function cleanFacetValues(values?: string[]) {
  return (values ?? []).filter(value => value.trim() && !/^(unknown|未知|未识别|未获取|—|-)$/i.test(value.trim()))
}

export function DiscoverySupplementaryPanels({ window }: { window: string }) {
  const { data: session } = useSession()
  const readIdentity = can(session, 'identity:read')
  const readTraffic = can(session, 'dpi:read')
  const assetSite = session?.site_profile === 'passive_assets'
  const period = supplementaryWindow(window)

  const authenticated = Boolean(session?.user?.id)

  const inventory = useQuery({
    queryKey: ['report-supplementary-inventory', period.value],
    queryFn: ({ signal }) => request<DeviceInventoryMetadataResponse>(`/device-inventory/metadata?view=recent&window=${period.value}`, { signal }),
    enabled: authenticated && readIdentity,
    retry: false,
    staleTime: 60_000,
    refetchOnWindowFocus: false,
  })

  const activity = useQuery({
    queryKey: ['report-supplementary-activity', period.value],
    queryFn: ({ signal }) => request<ActivityOverview>(`/activity/overview?window=${period.value}&view=summary`, { signal }),
    enabled: authenticated && readTraffic,
    retry: false,
    staleTime: 60_000,
    refetchOnWindowFocus: false,
  })

  if (!authenticated || (!readIdentity && !readTraffic)) return null

  const terminals = inventory.data
  const currentInventory = terminals?.read_model_state
  const inventoryPreparing = currentInventory?.available === false ||
    (inventory.error instanceof ApiError && /"inventory_projection_not_ready"/.test(inventory.error.message))
  const inventoryUrl = `/devices?tab=terminal&view=recent&window=${period.value}`
  const brandFacets = cleanFacetValues(terminals?.facets?.brands)
  const osFacets = cleanFacetValues(terminals?.facets?.os_families)

  const traffic = activity.data
  const activityNote = traffic?.data_freshness
  const networkUrl = `/activity?section=access&tab=network&window=${period.value}`
  const topEvents = [...(traffic?.event_type_counts ?? [])]
    .filter(row => row.value && row.count > 0)
    .sort((a, b) => b.count - a.count)
    .slice(0, 5)
  const eventMax = Math.max(traffic?.event_count ?? 0, topEvents[0]?.count ?? 0, 1)

  return (
    <section className="report-supplementary" aria-label="关联台账与全网访问概况">
      <div className="report-supplementary-heading">
        <h4>关联台账与访问概况</h4>
        <p>
          独立异步统计，口径与上方被动发现各自独立
          {period.fallbackFrom15m && '；当前 15 分钟窗口下按近 24 小时展示'}
        </p>
      </div>
      <div className="coverage-panels">
        {readIdentity && (
          <section className="coverage-panel report-supp-panel" aria-labelledby="supp-inventory-heading" aria-busy={inventory.isFetching}>
            <header className="coverage-panel-heading">
              <div>
                <h4 id="supp-inventory-heading">终端台账</h4>
                <p>{period.label}内有观测的台账终端</p>
              </div>
              <div className="report-supp-actions">
                <Button size="small" type="text" aria-label="重新读取终端台账" title="重新读取终端台账" icon={<ReloadOutlined />} loading={inventory.isFetching} onClick={() => void inventory.refetch()} />
                <ReportLink to={inventoryUrl} className="report-inline-link">终端列表 <ArrowRightOutlined aria-hidden="true" /></ReportLink>
              </div>
            </header>
            {inventory.isFetching && !terminals ? (
              <Skeleton active paragraph={{ rows: 2 }} title={false} />
            ) : inventoryPreparing ? (
              <p className="coverage-empty" role="status">终端统计仍在生成。</p>
            ) : inventory.isError && !terminals ? (
              <p className="coverage-empty" role="status">终端统计暂不可用，不影响上方资产报表。</p>
            ) : terminals ? (
              <div className="report-supp-body">
                <div className="report-supp-kpi">
                  <strong>{countFormat.format(terminals.total)}</strong>
                  <span>个近期终端</span>
                </div>
                {brandFacets.length > 0 && (
                  <div className="report-supp-facet">
                    <span>品牌</span>
                    <ul>
                      {brandFacets.slice(0, 6).map(name => (
                        <li key={name}>
                          <ReportLink to={`${inventoryUrl}&brand=${encodeURIComponent(name)}`}>{name}</ReportLink>
                        </li>
                      ))}
                      {brandFacets.length > 6 && (
                        <li><ReportLink to={inventoryUrl}>全部 {countFormat.format(brandFacets.length)} 项</ReportLink></li>
                      )}
                    </ul>
                  </div>
                )}
                {osFacets.length > 0 && (
                  <div className="report-supp-facet">
                    <span>操作系统</span>
                    <ul>
                      {osFacets.slice(0, 6).map(name => (
                        <li key={name}>
                          <ReportLink to={`${inventoryUrl}&os_family=${encodeURIComponent(name)}`}>{name}</ReportLink>
                        </li>
                      ))}
                      {osFacets.length > 6 && (
                        <li><ReportLink to={inventoryUrl}>全部 {countFormat.format(osFacets.length)} 项</ReportLink></li>
                      )}
                    </ul>
                  </div>
                )}
                {terminals.as_of && (
                  <footer className="coverage-timestamps">
                    <span>台账统计于 {observedTimeTitle(terminals.as_of)}</span>
                  </footer>
                )}
              </div>
            ) : null}
          </section>
        )}

        {readTraffic && (
          <section className="coverage-panel report-supp-panel" aria-labelledby="supp-traffic-heading" aria-busy={activity.isFetching}>
            <header className="coverage-panel-heading">
              <div>
                <h4 id="supp-traffic-heading">网络访问概况</h4>
                <p>{period.label}标准事件与活跃访问汇总</p>
              </div>
              <div className="report-supp-actions">
                <Button size="small" type="text" aria-label="重新读取网络访问" title="重新读取网络访问" icon={<ReloadOutlined />} loading={activity.isFetching} onClick={() => void activity.refetch()} />
                {!assetSite && (
                  <ReportLink to={networkUrl} className="report-inline-link">访问分析 <ArrowRightOutlined aria-hidden="true" /></ReportLink>
                )}
              </div>
            </header>
            {activity.isFetching && !traffic ? (
              <Skeleton active paragraph={{ rows: 3 }} title={false} />
            ) : activity.isError && !traffic ? (
              <p className="coverage-empty" role="status">
                {activity.error instanceof ApiError && activity.error.status === 504
                  ? '网络访问统计读取超时，不影响上方资产报表。'
                  : '网络访问统计暂不可用，不影响上方资产报表。'}
              </p>
            ) : traffic ? (
              <div className="report-supp-body">
                <dl className="report-supp-stats">
                  <div>
                    <dt>标准事件</dt>
                    <dd><strong>{countFormat.format(traffic.event_count)}</strong> <small>条</small></dd>
                  </div>
                  <div>
                    <dt>活跃 IP</dt>
                    <dd><strong>{countFormat.format(traffic.active_ip_count)}</strong> <small>个</small></dd>
                  </div>
                  <div>
                    <dt>访问对象</dt>
                    <dd><strong>{countFormat.format(traffic.access_object_count)}</strong> <small>个</small></dd>
                  </div>
                </dl>
                {topEvents.length > 0 && (
                  <ol className="report-supp-events">
                    {topEvents.map(row => (
                      <li key={row.value}>
                        <span>{eventLabels[row.value] ?? row.value}</span>
                        <progress className="coverage-progress" value={row.count} max={eventMax} aria-hidden="true" />
                        <strong>{countFormat.format(row.count)}</strong>
                      </li>
                    ))}
                  </ol>
                )}
                {(activityNote?.as_of || traffic.statistics_as_of) && (
                  <footer className="coverage-timestamps">
                    <span>访问统计于 {observedTimeTitle(activityNote?.as_of || traffic.statistics_as_of)}</span>
                    {activityNote?.partial && <span className="coverage-warning">仅覆盖部分时间范围</span>}
                  </footer>
                )}
              </div>
            ) : null}
          </section>
        )}
      </div>
    </section>
  )
}
