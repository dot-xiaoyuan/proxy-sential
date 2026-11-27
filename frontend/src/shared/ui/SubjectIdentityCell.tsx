import { Typography } from 'antd'

export type SubjectIdentityCellProps = {
  accountId?: string | null
  ip?: string | null
  mac?: string | null
  endpointId?: string | null
  extra?: React.ReactNode
}

// 统一剥离内部 mac: 主键前缀，避免在列表中裸露技术标识。
function formatMacOrEndpoint(mac?: string | null, endpointId?: string | null): string {
  const cleanMac = (mac ?? '').trim()
  if (cleanMac) return cleanMac.replace(/^mac:/i, '')
  const cleanEndpoint = (endpointId ?? '').trim()
  if (!cleanEndpoint) return ''
  if (/^mac:/i.test(cleanEndpoint)) return cleanEndpoint.replace(/^mac:/i, '')
  return cleanEndpoint
}

// 全局统一的“账号 / IP / MAC”分层单元格：主标识加粗，IP 次行等宽可复制，MAC 弱化展示。
export function SubjectIdentityCell({
  accountId,
  ip,
  mac,
  endpointId,
  extra,
}: SubjectIdentityCellProps) {
  const account = (accountId ?? '').trim()
  const address = (ip ?? '').trim()
  const hardware = formatMacOrEndpoint(mac, endpointId)

  if (!account && !address && !hardware && !extra) return null

  return (
    <div className="ps-subject-identity">
      {account ? (
        <div className="ps-subject-primary-row">
          <span className="ps-subject-account mono" title={account}>
            {account}
          </span>
          <Typography.Text className="ps-subject-copy" copyable={{ text: account }} />
        </div>
      ) : address ? (
        <div className="ps-subject-primary-row">
          <span className="ps-subject-ip-primary mono" title={address}>
            {address}
          </span>
          <Typography.Text className="ps-subject-copy" copyable={{ text: address }} />
        </div>
      ) : null}

      {account && address && (
        <div className="ps-subject-secondary-row">
          <span className="ps-subject-ip mono" title={address}>
            {address}
          </span>
          <Typography.Text className="ps-subject-copy" copyable={{ text: address }} />
        </div>
      )}

      {hardware && (
        <div className="ps-subject-meta-row">
          <span className="ps-subject-mac mono" title={hardware}>
            {hardware}
          </span>
        </div>
      )}

      {extra && <div className="ps-subject-extra">{extra}</div>}
    </div>
  )
}
