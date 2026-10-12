import { apiClient } from "@/lib/api/client";
import { API_ENDPOINTS } from "@/lib/api/endpoints";
import {
  IncidentSummaryResponse,
  IncidentDetailResponse,
  ExplanationResponse,
  UpdateIncidentStatusRequest,
} from "@/types/backend";

export interface IncidentFilters {
  run_id?: string;
  severity?: string;
  status?: string;
  limit?: number;
  offset?: number;
}

export async function fetchIncidents(
  filters: IncidentFilters = {}
): Promise<IncidentSummaryResponse[]> {
  const response = await apiClient.get<IncidentSummaryResponse[]>(
    API_ENDPOINTS.incidents.list,
    { params: filters }
  );
  return response.data;
}

export async function fetchIncidentDetail(
  incidentId: string
): Promise<IncidentDetailResponse> {
  const response = await apiClient.get<IncidentDetailResponse>(
    API_ENDPOINTS.incidents.detail(incidentId)
  );
  return response.data;
}

export async function updateIncidentStatus(
  incidentId: string,
  data: UpdateIncidentStatusRequest
): Promise<{ incident_id: string; status: string }> {
  const response = await apiClient.patch<{ incident_id: string; status: string }>(
    API_ENDPOINTS.incidents.updateStatus(incidentId),
    data
  );
  return response.data;
}

export async function generateExplanation(
  incidentId: string
): Promise<ExplanationResponse> {
  const response = await apiClient.post<ExplanationResponse>(
    API_ENDPOINTS.incidents.explanations(incidentId)
  );
  return response.data;
}

export async function fetchExplanation(
  explanationId: string
): Promise<ExplanationResponse> {
  const response = await apiClient.get<ExplanationResponse>(
    API_ENDPOINTS.explanations.detail(explanationId)
  );
  return response.data;
}
