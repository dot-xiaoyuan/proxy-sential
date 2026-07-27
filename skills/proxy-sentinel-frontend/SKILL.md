---
name: proxy-sentinel-frontend
description: Plan, implement, task-split, or review the Proxy Sentinel frontend operations console. Use when working on frontend architecture, React/TypeScript/Ant Design UI, OpenAPI contracts, MSW mocks, Antigravity task design, review workflows, shadow mode pages, risk/evidence UI, labels, audit placeholders, or frontend code review for this project.
---

# Proxy Sentinel Frontend

## Overview

Use this skill for Proxy Sentinel frontend work. Keep the frontend aligned with the detection architecture: Capture Backend -> Adapter -> Normalized Event -> Evidence -> Risk -> Decision.

## Non-Negotiable Boundaries

- Model UI from Normalized Event, Evidence, RiskSnapshot, Label, ShadowRun, AuditLog, and Session.
- Do not bind pages, filters, components, or mocks to Suricata raw fields.
- Do not make enforcement actions look final while the backend is still in shadow mode.
- Always show risk score together with evidence IDs and human-readable explanation.
- Keep weak evidence such as `domain_diversity` and `port_distribution` visually distinct from confirmed proxy conclusions.

## Frontend Defaults

- Place code under `frontend/`.
- Use Vite, React, TypeScript, Ant Design, TanStack Query, MSW, Vitest, and Playwright.
- Generate API types from `schemas/control-plane-v1.openapi.yaml`; do not hand-maintain duplicate DTOs.
- Put server state in TanStack Query. Put filters in URL query params. Use local state only for UI controls.
- Build dense operational screens, not marketing pages or decorative dashboards.

## Task Design Rules

When preparing Antigravity work:

- Include route, user goal, API endpoints, permission points, mock data needs, and acceptance tests.
- Require a screenshot or Playwright result for every UI task.
- Require empty, loading, error, and long-text states for table/detail work.
- Note whether the task still uses mock API or real backend API.

## Code Review Checklist

- Check that UI does not read raw capture backend fields.
- Check that every risk display includes evidence and summary.
- Check that labels require a reason and produce an auditable action.
- Check that permission-gated controls are disabled when the mock session lacks permission.
- Check that IPv6, long User-Agent, and long evidence reason text wrap without layout breakage.
- Run `pnpm generate:api`, `pnpm typecheck`, `pnpm lint`, `pnpm test`, and targeted Playwright tests when reviewing implementation.

## Useful Local References

- `docs/frontend-architecture.md`
- `docs/frontend-tasks.md`
- `schemas/control-plane-v1.openapi.yaml`
- `docs/risk-engine.md`
- `docs/event-model.md`
