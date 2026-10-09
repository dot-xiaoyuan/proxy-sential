import { useEffect, useRef } from "react";
import {
  keepPreviousData,
  useInfiniteQuery,
  useMutation,
  useQuery,
  useQueryClient,
} from "@tanstack/react-query";

import { api } from "./client";
import type {
  CaseHistoryKind,
  ActivityOverviewQuery,
  CreateLabelRequest,
  DeviceQuery,
  EventQuery,
  EvidenceQuery,
  IdentityQuery,
  ListQuery,
  Page,
  ProxyReviewQuery,
  RiskQuery,
  UpdateEndpointRegistrationRequest,
  OrganizationKind,
} from "./types";

function usePagedQuery<
  TQuery extends { cursor?: string },
  TData extends { page: Page },
>(
  query: TQuery,
  keyFor: (value: TQuery) => readonly unknown[],
  load: (value: TQuery) => Promise<TData>,
  enabled = true,
  refetchInterval: number | false = false,
) {
  const client = useQueryClient();
  const queryFingerprint = JSON.stringify(query);
  const queryRef = useRef(query);
  if (JSON.stringify(queryRef.current) !== queryFingerprint)
    queryRef.current = query;
  const stableQuery = queryRef.current;
  const result = useQuery({
    queryKey: keyFor(stableQuery),
    queryFn: () => load(stableQuery),
    enabled,
    refetchInterval,
    refetchIntervalInBackground: false,
    placeholderData: keepPreviousData,
    staleTime: 60_000,
    gcTime: 30 * 60_000,
  });
  const nextCursor = result.data?.page.next_cursor;
  useEffect(() => {
    if (!enabled || !nextCursor) return;
    const nextQuery = { ...stableQuery, cursor: nextCursor };
    void client.prefetchQuery({
      queryKey: keyFor(nextQuery),
      queryFn: () => load(nextQuery),
    });
  }, [
    client,
    enabled,
    keyFor,
    load,
    nextCursor,
    queryFingerprint,
    stableQuery,
  ]);
  return result;
}

export const queryKeys = {
  session: ["session"] as const,
  overview: (query: ActivityOverviewQuery) => ["overview", query] as const,
  systemStatus: ["system-status"] as const,
  activityOverview: (query: ActivityOverviewQuery) =>
    ["activity-overview", query] as const,
  activityReport: (
    query: ActivityOverviewQuery & { dimension: string; limit?: number },
  ) => ["activity-report", query] as const,
  proxyReviews: (query: ProxyReviewQuery) => ["proxy-reviews", query] as const,
  dpiOverview: (query: ActivityOverviewQuery) =>
    ["dpi-overview", query] as const,
  dpiTrends: (query: ActivityOverviewQuery) => ["dpi-trends", query] as const,
  dpiProtocolFlows: (query: ActivityOverviewQuery) =>
    ["dpi-protocol-flows", query] as const,
  dpiFingerprintConflicts: (query: ActivityOverviewQuery) =>
    ["dpi-fingerprint-conflicts", query] as const,
  dpiFlows: (query: EventQuery) => ["dpi-flows", query] as const,
  dpiIpFlows: (ip: string, query: EventQuery) =>
    ["dpi-ip-flows", ip, query] as const,
  dpiFlow: (flowId: string) => ["dpi-flow", flowId] as const,
  devices: (query: DeviceQuery) => ["devices", query] as const,
  device: (deviceId: string, query: DeviceQuery) =>
    ["device", deviceId, query] as const,
  deviceSignals: (query: DeviceQuery) => ["device-signals", query] as const,
  deviceFingerprintConflicts: (query: DeviceQuery) =>
    ["device-fingerprint-conflicts", query] as const,
  risks: (query: RiskQuery) => ["risks", query] as const,
  ipRisk: (ip: string) => ["ip-risk", ip] as const,
  ipEvidence: (ip: string, query: EvidenceQuery) =>
    ["ip-evidence", ip, query] as const,
  ipActivity: (ip: string) => ["ip-activity", ip] as const,
  ipDevices: (ip: string, query: DeviceQuery) =>
    ["ip-devices", ip, query] as const,
  ipEvents: (ip: string, limit: number) => ["ip-events", ip, limit] as const,
  accountIdentity: (accountId: string, query: IdentityQuery) =>
    ["account-identity", accountId, query] as const,
  endpointIdentity: (endpointId: string, query: IdentityQuery) =>
    ["endpoint-identity", endpointId, query] as const,
  events: (query: EventQuery) => ["events", query] as const,
  ingestStatus: ["ingest-status"] as const,
  ingestRuns: (query: ListQuery) => ["ingest-runs", query] as const,
  ingestDiagnostics: (query: ListQuery) =>
    ["ingest-diagnostics", query] as const,
  ingestEventTypes: ["ingest-event-types"] as const,
  ingestErrors: (query: ListQuery) => ["ingest-errors", query] as const,
  auditLogs: (query: ListQuery) => ["audit-logs", query] as const,
  auditLog: (auditId: string) => ["audit-log", auditId] as const,
  proxyReview: (caseId: string, window: string) =>
    ["proxy-review", caseId, window] as const,
  event: (eventId: string) => ["event", eventId] as const,
  ingestDiagnostic: (diagnosticId: string) =>
    ["ingest-diagnostic", diagnosticId] as const,
  deviceFingerprintLibrary: ["device-fingerprint-library"] as const,
  deviceRecognitionSummary: ["device-recognition-summary"] as const,
  cases: (query: object) => ["cases", query] as const,
  caseDetail: (caseId: string) => ["case", caseId] as const,
  organization: ["organization"] as const,
  actionConnectors: ["action-connectors"] as const,
  actions: (query: object) => ["actions", query] as const,
  users: ["users"] as const,
  campusExceptions: ["campus-exceptions"] as const,
};

export function useSession() {
  return useQuery({ queryKey: queryKeys.session, queryFn: api.session });
}

export function useOverview(query: ActivityOverviewQuery = {}) {
  return useQuery({
    queryKey: queryKeys.overview(query),
    queryFn: () => api.overview(query),
  });
}

export function useSystemStatus() {
  return useQuery({
    queryKey: queryKeys.systemStatus,
    queryFn: api.systemStatus,
    refetchInterval: 5000,
  });
}

export function useLogin() {
  const client = useQueryClient();
  return useMutation({
    mutationFn: api.login,
    onSuccess: (session) => {
      client.setQueryData(queryKeys.session, session);
    },
  });
}
export function useLogout() {
  const client = useQueryClient();
  return useMutation({
    mutationFn: api.logout,
    onSuccess: () => {
      client.clear();
    },
  });
}

export function useActivityOverview(query: ActivityOverviewQuery, enabled = true) {
  return useQuery({
    queryKey: queryKeys.activityOverview(query),
    queryFn: () => api.activityOverview(query),
    enabled,
  });
}

export function useActivityReport(
  query: ActivityOverviewQuery & { dimension: string; limit?: number },
  enabled = true,
) {
  return useQuery({
    queryKey: queryKeys.activityReport(query),
    queryFn: () => api.activityReport(query),
    enabled,
    staleTime: 60_000,
    gcTime: 30 * 60_000,
  });
}

export function useProxyReviews(query: ProxyReviewQuery) {
  return usePagedQuery(query, queryKeys.proxyReviews, api.proxyReviews);
}

export function useProxyReview(caseId: string, window: "24h" | "7d") {
  return useQuery({
    queryKey: queryKeys.proxyReview(caseId, window),
    queryFn: () => api.proxyReview(caseId, window),
    enabled: !!caseId,
  });
}

export function useDpiOverview(query: ActivityOverviewQuery) {
  return useQuery({
    queryKey: queryKeys.dpiOverview(query),
    queryFn: () => api.dpiOverview(query),
  });
}

export function useDpiTrends(query: ActivityOverviewQuery, enabled = true) {
  return useQuery({
    queryKey: queryKeys.dpiTrends(query),
    queryFn: () => api.dpiTrends(query),
    enabled,
  });
}

export function useDpiProtocolFlows(
  query: ActivityOverviewQuery,
  enabled = true,
) {
  return useQuery({
    queryKey: queryKeys.dpiProtocolFlows(query),
    queryFn: () => api.dpiProtocolFlows(query),
    enabled,
  });
}

export function useDpiFingerprintConflicts(
  query: ActivityOverviewQuery,
  enabled = true,
) {
  return useQuery({
    queryKey: queryKeys.dpiFingerprintConflicts(query),
    queryFn: () => api.dpiFingerprintConflicts(query),
    enabled,
  });
}

export function useDpiFlows(query: EventQuery) {
  return usePagedQuery(query, queryKeys.dpiFlows, api.dpiFlows);
}

export function useDpiIpFlows(ip: string, query: EventQuery, enabled = true) {
  return useQuery({
    queryKey: queryKeys.dpiIpFlows(ip, query),
    queryFn: () => api.dpiIpFlows(ip, query),
    enabled: !!ip && enabled,
  });
}

export function useDpiFlow(flowId: string) {
  return useQuery({
    queryKey: queryKeys.dpiFlow(flowId),
    queryFn: () => api.dpiFlow(flowId),
    enabled: !!flowId,
  });
}

export function useDevices(query: DeviceQuery, enabled = true) {
  return useQuery({
    queryKey: queryKeys.devices(query),
    queryFn: () => api.deviceInventory(query),
    enabled,
    placeholderData: keepPreviousData,
    staleTime: Infinity,
    gcTime: 30 * 60_000,
    refetchOnWindowFocus: false,
    refetchOnMount: false,
    refetchOnReconnect: false,
  });
}

export function useLegacyDevices(query: DeviceQuery, enabled = true) {
  return useQuery({
    queryKey: ["legacy-devices", query],
    queryFn: () => api.devices(query),
    enabled,
    staleTime: 60_000,
    refetchOnWindowFocus: false,
  });
}

export function useDevice(deviceId: string, query: DeviceQuery) {
  return useQuery({
    queryKey: queryKeys.device(deviceId, query),
    queryFn: () => api.device(deviceId, query),
    enabled: !!deviceId,
  });
}

export function useDeviceSignals(query: DeviceQuery, enabled = true) {
  return useQuery({
    queryKey: queryKeys.deviceSignals(query),
    queryFn: () => api.deviceSignals(query),
    enabled,
  });
}

export function useDeviceFingerprintConflicts(query: DeviceQuery) {
  return useQuery({
    queryKey: queryKeys.deviceFingerprintConflicts(query),
    queryFn: () => api.deviceFingerprintConflicts(query),
  });
}

export function useRisks(query: RiskQuery) {
  return usePagedQuery(query, queryKeys.risks, api.risks);
}

export function useIpRisk(ip: string, enabled = true) {
  return useQuery({
    queryKey: queryKeys.ipRisk(ip),
    queryFn: () => api.ipRisk(ip),
    enabled: !!ip && enabled,
  });
}

export function useIpEvidence(
  ip: string,
  query: EvidenceQuery = { limit: 20 },
  enabled = true,
) {
  return useQuery({
    queryKey: queryKeys.ipEvidence(ip, query),
    queryFn: () => api.ipEvidence(ip, query),
    enabled: !!ip && enabled,
  });
}

export function useIpActivity(ip: string, enabled = true) {
  return useQuery({
    queryKey: queryKeys.ipActivity(ip),
    queryFn: () => api.ipActivity(ip),
    enabled: !!ip && enabled,
  });
}

export function useAccountIdentity(
  accountId: string,
  query: IdentityQuery = {},
) {
  return useQuery({
    queryKey: queryKeys.accountIdentity(accountId, query),
    queryFn: () => api.accountIdentity(accountId, query),
    enabled: !!accountId,
  });
}

export function useEndpointIdentity(
  endpointId: string,
  query: IdentityQuery = {},
) {
  return useQuery({
    queryKey: queryKeys.endpointIdentity(endpointId, query),
    queryFn: () => api.endpointIdentity(endpointId, query),
    enabled: !!endpointId,
    refetchInterval: 15000,
    refetchIntervalInBackground: false,
  });
}

export function useUpdateEndpointRegistration() {
  const client = useQueryClient();
  return useMutation({
    mutationFn: ({
      endpointId,
      payload,
    }: {
      endpointId: string;
      payload: UpdateEndpointRegistrationRequest;
    }) => api.updateEndpointRegistration(endpointId, payload),
    onSuccess: (_, variables) => {
      void client.invalidateQueries({
        queryKey: ["endpoint-identity", variables.endpointId],
      });
      void client.invalidateQueries({ queryKey: ["devices"] });
      void client.invalidateQueries({ queryKey: ["audit-logs"] });
    },
  });
}

export function useIpDevices(
  ip: string,
  query: DeviceQuery = { window: "1h" },
  enabled = true,
) {
  return useQuery({
    queryKey: queryKeys.ipDevices(ip, query),
    queryFn: () => api.ipDevices(ip, query),
    enabled: !!ip && enabled,
  });
}

export function useIpEvents(ip: string, limit = 20, enabled = true) {
  return useQuery({
    queryKey: queryKeys.ipEvents(ip, limit),
    queryFn: () => api.ipEvents(ip, limit),
    enabled: !!ip && enabled,
  });
}

export function useEvents(query: EventQuery, enabled = true) {
  return usePagedQuery(query, queryKeys.events, api.events, enabled);
}

export function useEvent(eventId: string) {
  return useQuery({
    queryKey: queryKeys.event(eventId),
    queryFn: () => api.event(eventId),
    enabled: !!eventId,
  });
}

export function useIngestStatus() {
  return useQuery({
    queryKey: queryKeys.ingestStatus,
    queryFn: api.ingestStatus,
  });
}

export function useIngestRuns(query: ListQuery = { limit: 20 }) {
  return usePagedQuery(query, queryKeys.ingestRuns, api.ingestRuns);
}

export function useIngestDiagnostics(
  query: ListQuery = { limit: 20 },
  enabled = true,
) {
  return usePagedQuery(
    query,
    queryKeys.ingestDiagnostics,
    api.ingestDiagnostics,
    enabled,
  );
}

export function useIngestEventTypes(enabled = true) {
  return useQuery({
    queryKey: queryKeys.ingestEventTypes,
    queryFn: api.ingestEventTypes,
    enabled,
  });
}

export function useIngestErrors(
  query: ListQuery = { limit: 20 },
  enabled = true,
) {
  return usePagedQuery(
    query,
    queryKeys.ingestErrors,
    api.ingestErrors,
    enabled,
  );
}

export function useCreateLabel() {
  const client = useQueryClient();
  return useMutation({
    mutationFn: (payload: CreateLabelRequest) => api.createLabel(payload),
    onSuccess: (_, variables) => {
      void client.invalidateQueries({ queryKey: ["audit-logs"] });
      void client.invalidateQueries({ queryKey: ["overview"] });
      void client.invalidateQueries({ queryKey: ["risks"] });
      void client.invalidateQueries({ queryKey: ["proxy-reviews"] });
      if (variables.target_type === "ip") {
        void client.invalidateQueries({
          queryKey: queryKeys.ipRisk(variables.target_id),
        });
      }
    },
  });
}

export function useAuditLogs(query: ListQuery = { limit: 20 }) {
  return usePagedQuery(query, queryKeys.auditLogs, api.auditLogs);
}

export function useAuditLog(auditId: string) {
  return useQuery({
    queryKey: queryKeys.auditLog(auditId),
    queryFn: () => api.auditLog(auditId),
    enabled: !!auditId,
  });
}

export function useIngestDiagnostic(diagnosticId: string) {
  return useQuery({
    queryKey: queryKeys.ingestDiagnostic(diagnosticId),
    queryFn: () => api.ingestDiagnostic(diagnosticId),
    enabled: !!diagnosticId,
  });
}

export function useDeviceFingerprintLibrary(enabled = true) {
  return useQuery({
    queryKey: queryKeys.deviceFingerprintLibrary,
    queryFn: api.deviceFingerprintLibrary,
    enabled,
  });
}

export function useDeviceRecognitionSummary(enabled = true) {
  return useQuery({
    queryKey: queryKeys.deviceRecognitionSummary,
    queryFn: api.deviceRecognitionSummary,
    enabled,
    staleTime: 60_000,
    refetchOnWindowFocus: false,
  });
}

export function useUpdateDeviceFingerprintLibrary() {
  const client = useQueryClient();
  return useMutation({
    mutationFn: api.updateDeviceFingerprintLibrary,
    onSuccess: () => {
      void client.invalidateQueries({
        queryKey: queryKeys.deviceFingerprintLibrary,
      });
      void client.invalidateQueries({ queryKey: ["devices"] });
    },
  });
}

export function useValidateDeviceFingerprintBundle() {
  return useMutation({ mutationFn: api.validateDeviceFingerprintBundle });
}
export function useImportDeviceFingerprintBundle() {
  const client = useQueryClient();
  return useMutation({
    mutationFn: api.importDeviceFingerprintBundle,
    onSuccess: () => {
      void client.invalidateQueries({
        queryKey: queryKeys.deviceFingerprintLibrary,
      });
      void client.invalidateQueries({ queryKey: ["devices"] });
    },
  });
}

export function useReloadRules() {
  const client = useQueryClient();
  return useMutation({
    mutationFn: api.reloadRules,
    onSuccess: () => {
      void client.invalidateQueries({ queryKey: ["audit-logs"] });
    },
  });
}

export function useCases(
  query: ListQuery & {
    status?: string;
    assignee_id?: string;
    campus_id?: string;
    department?: string;
    person_type?: string;
    ssid?: string;
    vlan?: string;
    ap?: string;
    nas_ip?: string;
    window?: string;
    include_router_observations?: boolean;
  } = {},
) {
  return usePagedQuery(query, queryKeys.cases, api.cases);
}
export function useCase(caseId: string) {
  return useQuery({
    queryKey: queryKeys.caseDetail(caseId),
    queryFn: () => api.caseDetail(caseId),
    enabled: !!caseId,
  });
}
export function useCaseMutation() {
  const client = useQueryClient();
  return useMutation({
    mutationFn: async (request: {
      caseId: string;
      operation: "assign" | "status" | "priority" | "disposition" | "comment";
      value: string;
      reason?: string;
    }) => {
      switch (request.operation) {
        case "assign":
          return api.assignCase(request.caseId, request.value);
        case "status":
          return api.updateCaseStatus(request.caseId, request.value);
        case "priority":
          return api.updateCasePriority(request.caseId, request.value);
        case "disposition":
          return api.resolveCase(
            request.caseId,
            request.value,
            request.reason ?? "人工复核",
          );
        default:
          return api.commentCase(request.caseId, request.value);
      }
    },
    onSuccess: (item) => {
      client.setQueryData(queryKeys.caseDetail(item.case_id), item);
      void client.invalidateQueries({queryKey: ["case-history",item.case_id]});
      void client.invalidateQueries({queryKey: queryKeys.caseDetail(item.case_id)});
      void client.invalidateQueries({ queryKey: ["cases"] });
      void client.invalidateQueries({ queryKey: ["overview"] });
    },
  });
}
export function useCasesBatchMutation() {
  const client = useQueryClient();
  return useMutation({
    mutationFn: (request: {
      caseIds: string[];
      operation: "assign" | "close";
      assigneeId?: string;
    }) =>
      api.mutateCasesBatch(
        request.caseIds,
        request.operation,
        request.assigneeId,
      ),
    onSuccess: () => {
      void client.invalidateQueries({ queryKey: ["cases"] });
      void client.invalidateQueries({ queryKey: ["overview"] });
    },
  });
}
export function useOrganization(enabled = true) {
  return useQuery({
    queryKey: queryKeys.organization,
    queryFn: api.organization,
    enabled,
  });
}
export function useOrganizationList<K extends OrganizationKind>(
  kind: K,
  query: ListQuery = {},
) {
  return usePagedQuery(
    query,
    (value) => ["organization", kind, value] as const,
    (value) => api.organizationList(kind, value),
  );
}
export function useOrganizationMutation() {
  const client = useQueryClient();
  return useMutation({
    mutationFn: (request: { kind: string; payload: Record<string, unknown> }) =>
      api.saveOrganization(request.kind, request.payload),
    onSuccess: () =>
      void client.invalidateQueries({ queryKey: queryKeys.organization }),
  });
}
export function useActionConnectors(enabled = true) {
  return useQuery({
    queryKey: queryKeys.actionConnectors,
    queryFn: api.actionConnectors,
    enabled,
  });
}
export function useActions(query: ListQuery = {}) {
  return usePagedQuery(query, queryKeys.actions, api.actions);
}
export function useActionMutation() {
  const client = useQueryClient();
  return useMutation({
    mutationFn: (request: {
      payload: {
        case_id?: string;
        connector_id: string;
        action_type: string;
        ip: string;
        campus_id?: string;
        duration_seconds?: number;
      };
      idempotencyKey: string;
    }) => api.executeAction(request.payload, request.idempotencyKey),
    onSuccess: () => void client.invalidateQueries({ queryKey: ["actions"] }),
  });
}
export function useUsers(query: ListQuery = {}) {
  return usePagedQuery(
    query,
    () => [...queryKeys.users, query] as const,
    api.users,
  );
}
export function useUserMutation() {
  const client = useQueryClient();
  return useMutation({
    mutationFn: (request: {
      userId?: string;
      operation?: "profile" | "password" | "disable" | "enable";
      payload: import("./types").UserMutation;
    }) =>
      request.userId && request.operation
        ? api.updateUser(request.userId, request.operation, request.payload)
        : api.createUser(request.payload),
    onSuccess: () =>
      void client.invalidateQueries({ queryKey: queryKeys.users }),
  });
}
export function useCampusExceptions(query: ListQuery = {}) {
  return usePagedQuery(
    query,
    () => [...queryKeys.campusExceptions, query] as const,
    api.campusExceptions,
  );
}
export function useCampusExceptionMutation() {
  const client = useQueryClient();
  return useMutation({
    mutationFn: (request: {
      exceptionId?: string;
      payload?: import("./types").CampusException;
    }) =>
      request.exceptionId
        ? api.disableCampusException(request.exceptionId)
        : api.createCampusException(request.payload!),
    onSuccess: () => {
      void client.invalidateQueries({ queryKey: queryKeys.campusExceptions });
      void client.invalidateQueries({ queryKey: ["risks"] });
      void client.invalidateQueries({ queryKey: ["cases"] });
    },
  });
}

export function useCaseHistory(caseId: string, kind: CaseHistoryKind, enabled: boolean) {
  return useInfiniteQuery({queryKey: ['case-history',caseId,kind], initialPageParam: '0', queryFn: ({pageParam}) => api.caseHistory(caseId,kind,pageParam), getNextPageParam: (page) => page.page.next_cursor ?? undefined, enabled: enabled && !!caseId})
}
