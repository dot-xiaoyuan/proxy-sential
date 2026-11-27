import { describe, expect, it } from 'vitest'
import { routerObservationQueryFromParams } from './RouterObservationsPanel'

describe('router observation role view', () => {
  it('defaults to the router view and includes clearly labelled candidates', () => {
    expect(routerObservationQueryFromParams(new URLSearchParams())).toEqual({
      role: 'router',
      include_candidates: true,
    })
  })

  it('switches to access points from the view parameter', () => {
    expect(
      routerObservationQueryFromParams(
        new URLSearchParams('routers_view=ap&router_confidence_min=60'),
      ),
    ).toEqual({ role: 'ap', include_candidates: true, confidence_min: 60 })
  })

  it('keeps the current view when candidate inclusion is enabled', () => {
    expect(
      routerObservationQueryFromParams(
        new URLSearchParams('routers_view=ap&router_include_candidates=true'),
      ),
    ).toEqual({ role: 'ap', include_candidates: true })
  })

  it('allows the operator to exclude candidate clues explicitly', () => {
    expect(
      routerObservationQueryFromParams(new URLSearchParams('router_include_candidates=false')),
    ).toEqual({ role: 'router', include_candidates: false })
  })

  it('preserves the authentication identity filter and ignores a stale role filter', () => {
    expect(
      routerObservationQueryFromParams(
        new URLSearchParams('routers_view=ap&router_role=router&router_has_auth_binding=true'),
      ),
    ).toEqual({ role: 'ap', include_candidates: true, has_auth_binding: true })
  })
})
