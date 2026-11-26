import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'
import { AssetAnnotationCard } from './AssetAnnotationCard'
import { api } from '../shared/api/client'

describe('AssetAnnotationCard', () => {
  it('loads existing annotation and saves updated note when writable', async () => {
    const getSpy = vi.spyOn(api, 'assetAnnotations').mockResolvedValue({
      writable: true,
      items: [
        {
          target_key: 'ip:10.42.1.11',
          verification_status: 'verified',
          department: '网络中心',
          note: '一楼吸顶 AP',
          updated_by: 'admin',
          updated_at: '2026-11-26T08:00:00Z',
        },
      ],
    })
    const putSpy = vi.spyOn(api, 'upsertAssetAnnotation').mockResolvedValue({
      target_key: 'ip:10.42.1.11',
      verification_status: 'verified',
      department: '网络中心',
      note: '已复核机柜端口',
      updated_by: 'admin',
      updated_at: '2026-11-26T09:00:00Z',
    })

    const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
    render(
      <QueryClientProvider client={qc}>
        <AssetAnnotationCard
          targetKey="ip:10.42.1.11"
          sensorId="campus-204"
          typeOptions={[{ value: 'access_point', label: '无线接入点' }]}
        />
      </QueryClientProvider>,
    )

    expect(await screen.findByDisplayValue('网络中心')).toBeInTheDocument()
    const noteInput = screen.getByLabelText('核验备注')
    fireEvent.change(noteInput, { target: { value: '已复核机柜端口' } })
    fireEvent.click(screen.getByRole('button', { name: /保存标注/ }))

    await waitFor(() => {
      expect(putSpy).toHaveBeenCalledWith(expect.objectContaining({
        target_key: 'ip:10.42.1.11',
        note: '已复核机柜端口',
      }))
    })
    getSpy.mockRestore()
    putSpy.mockRestore()
  })

  it('hides save controls when server reports read-only', async () => {
    const getSpy = vi.spyOn(api, 'assetAnnotations').mockResolvedValue({
      writable: false,
      items: [],
    })
    const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
    render(
      <QueryClientProvider client={qc}>
        <AssetAnnotationCard
          targetKey="mac:aa:bb:cc:dd:ee:ff"
          typeOptions={[{ value: 'printer', label: '打印机' }]}
        />
      </QueryClientProvider>,
    )

    expect(await screen.findByText(/严格只读模式/)).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /保存标注/ })).not.toBeInTheDocument()
    getSpy.mockRestore()
  })
})
