import { apiClient } from "@/lib/api/client";
import { API_ENDPOINTS } from "@/lib/api/endpoints";
import {
  MetricsSummaryResponse,
  MitreMetricsResponse,
  WhatIfPolicyRequest,
  WhatIfPolicyResponse,
} from "@/types/backend";

export async function fetchMetrics(): Promise<MetricsSummaryResponse> {
  const response = await apiClient.get<MetricsSummaryResponse>(
    API_ENDPOINTS.metrics.overview
  );
  return response.data;
}

export async function checkBackendHealth(): Promise<{ status: string; service: string }> {
  const response = await apiClient.get<{ status: string; service: string }>(
    API_ENDPOINTS.health
  );
  return response.data;
}

export async function fetchMitreMetrics(): Promise<MitreMetricsResponse> {
  const response = await apiClient.get<MitreMetricsResponse>(
    API_ENDPOINTS.metrics.mitre
  );
  return response.data;
}

export async function simulateWhatIfPolicy(
  params: WhatIfPolicyRequest
): Promise<WhatIfPolicyResponse> {
  const response = await apiClient.post<WhatIfPolicyResponse>(
    API_ENDPOINTS.metrics.whatIf,
    params
  );
  return response.data;
}
