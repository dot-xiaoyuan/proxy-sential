import { describe, expect, it } from 'vitest'
import { routerObservationQueryFromParams } from './RouterObservationsPanel'

describe('router observation default role', () => {
  it('defaults to network equipment and hides candidates so the headline count only covers likely and confirmed records', () => {
    expect(routerObservationQueryFromParams(new URLSearchParams())).toEqual({ role: 'network', include_candidates: false })
  })

  it('keeps an explicit access-point filter available', () => {
    expect(routerObservationQueryFromParams(new URLSearchParams('router_role=ap&router_confidence_min=60'))).toEqual({ role: 'ap', include_candidates: false, confidence_min: 60 })
  })

  it('restores an explicit candidate inclusion from the URL', () => {
    expect(routerObservationQueryFromParams(new URLSearchParams('router_include_candidates=true'))).toEqual({ role: 'network', include_candidates: true })
  })

  it('preserves the current authentication identity filter as a boolean', () => {
    expect(routerObservationQueryFromParams(new URLSearchParams('router_has_auth_binding=true'))).toEqual({ role: 'network', include_candidates: false, has_auth_binding: true })
  })
})
