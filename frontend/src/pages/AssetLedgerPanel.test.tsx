import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { render, screen } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'
import { AssetLedgerPanel, parseCampusLedgerCSV } from './AssetLedgerPanel'
import { api } from '../shared/api/client'

describe('parseCampusLedgerCSV', () => {
  it('parses header CSV with MAC and IP rows', () => {
    const rows = parseCampusLedgerCSV(
      'mac,ip,asset_name,expected_type,department\nAA:BB:CC:DD:EE:01,10.42.1.11,教1-AP,access_point,网络中心\n,10.42.1.12,教2-AP,access_point,教务处',
    )
    expect(rows).toHaveLength(2)
    expect(rows[0].mac).toBe('AA:BB:CC:DD:EE:01')
    expect(rows[1].ip).toBe('10.42.1.12')
    expect(rows[1].department).toBe('教务处')
  })
})

describe('AssetLedgerPanel', () => {
  it('renders four-quadrant reconciliation metrics and diff table', async () => {
    const listSpy = vi.spyOn(api, 'assetLedgers').mockResolvedValue({
      writable: true,
      items: [
        {
          ledger_id: 'ledger-1',
          name: '核心瘦AP台账',
          source_kind: 'ac_ap',
          entry_count: 472,
          imported_at: '2026-11-26T09:00:00Z',
        },
      ],
    })
    const reconcileSpy = vi.spyOn(api, 'reconcileAssetLedger').mockResolvedValue({
      ledger: {
        ledger_id: 'ledger-1',
        name: '核心瘦AP台账',
        source_kind: 'ac_ap',
        entry_count: 472,
        imported_at: '2026-11-26T09:00:00Z',
      },
      window: '24h',
      reconciled_at: '2026-11-26T10:00:00Z',
      summary: {
        ledger_total: 472,
        observed_total: 485,
        registered_active: 460,
        discovered_unregistered: 13,
        ledger_offline: 8,
        attribute_mismatch: 4,
      },
      items: [
        {
          status: 'discovered_unregistered',
          ip: '10.42.9.88',
          observed_type: 'access_point',
          detail: '被动发现已观测到活跃记录，但不在当前台账中',
        },
      ],
      truncated: false,
    })

    const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
    render(
      <QueryClientProvider client={qc}>
        <AssetLedgerPanel />
      </QueryClientProvider>,
    )

    expect(await screen.findByText('校园资产台账对账')).toBeInTheDocument()
    expect(await screen.findByText('10.42.9.88')).toBeInTheDocument()
    expect(screen.getByText('460')).toBeInTheDocument()
    expect(screen.getByText('13')).toBeInTheDocument()

    listSpy.mockRestore()
    reconcileSpy.mockRestore()
  })
})
