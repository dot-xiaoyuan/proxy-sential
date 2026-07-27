import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it } from 'vitest'

import { renderWithProviders } from '../../test/render'
import { LabelPanel } from './LabelPanel'

describe('LabelPanel', () => {
  it('disables fields when permission is missing', () => {
    const setup = renderWithProviders(<LabelPanel disabled evidenceIds={[]} targetId="10.0.0.1" />)
    render(setup.ui, { wrapper: setup.wrapper })
    expect(screen.getByRole('button', { name: '提交标注' })).toBeDisabled()
  })

  it('requires reason before submit', async () => {
    const user = userEvent.setup()
    const setup = renderWithProviders(<LabelPanel evidenceIds={['evidence-test']} targetId="10.0.0.1" />)
    render(setup.ui, { wrapper: setup.wrapper })
    await user.click(screen.getByRole('button', { name: '提交标注' }))
    expect(await screen.findByText('请选择复核结论')).toBeInTheDocument()
    expect(await screen.findByText('请填写至少 2 个字符的原因')).toBeInTheDocument()
  })
})
