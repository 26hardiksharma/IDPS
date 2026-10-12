import { apiClient } from "@/lib/api/client";
import { API_ENDPOINTS } from "@/lib/api/endpoints";
import { MetricsSummaryResponse } from "@/types/backend";

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
