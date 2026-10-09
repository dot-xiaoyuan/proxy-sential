import { describe, expect, it } from 'vitest'
import { routerObservationQueryFromParams } from './RouterObservationsPanel'

describe('router observation default role', () => {
  it('defaults to routers so access points are not included in the headline count', () => {
    expect(routerObservationQueryFromParams(new URLSearchParams())).toEqual({ role: 'router', include_candidates: true })
  })

  it('keeps an explicit access-point filter available', () => {
    expect(routerObservationQueryFromParams(new URLSearchParams('router_role=ap&router_confidence_min=60'))).toEqual({ role: 'ap', include_candidates: true, confidence_min: 60 })
  })

  it('preserves the current authentication identity filter as a boolean', () => {
    expect(routerObservationQueryFromParams(new URLSearchParams('router_has_auth_binding=true'))).toEqual({ role: 'router', include_candidates: true, has_auth_binding: true })
  })
})
