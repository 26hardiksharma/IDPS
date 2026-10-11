import { apiClient } from "@/lib/api/client";
import { API_ENDPOINTS } from "@/lib/api/endpoints";
import {
  RunSummaryResponse,
  CreateRunRequest,
  ExecuteRunResponse,
  EvidenceRecord,
} from "@/types/backend";

export async function fetchRuns(limit = 50, offset = 0): Promise<RunSummaryResponse[]> {
  const response = await apiClient.get<RunSummaryResponse[]>(API_ENDPOINTS.runs.list, {
    params: { limit, offset },
  });
  return response.data;
}

export async function fetchRunDetail(runId: string): Promise<RunSummaryResponse> {
  const response = await apiClient.get<RunSummaryResponse>(API_ENDPOINTS.runs.detail(runId));
  return response.data;
}

export async function createRun(data: CreateRunRequest): Promise<RunSummaryResponse> {
  const response = await apiClient.post<RunSummaryResponse>(API_ENDPOINTS.runs.create, data);
  return response.data;
}

export async function executeRun(runId: string): Promise<ExecuteRunResponse> {
  const response = await apiClient.post<ExecuteRunResponse>(API_ENDPOINTS.runs.execute(runId));
  return response.data;
}

export async function fetchRunEvidence(
  runId: string,
  limit = 100,
  offset = 0
): Promise<EvidenceRecord[]> {
  const response = await apiClient.get<EvidenceRecord[]>(API_ENDPOINTS.runs.evidence(runId), {
    params: { limit, offset },
  });
  return response.data;
}
