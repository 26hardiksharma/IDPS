import { apiClient } from "@/lib/api/client";
import { API_ENDPOINTS } from "@/lib/api/endpoints";
import {
  RuleVersionResponse,
  RegisterCandidateRuleRequest,
} from "@/types/backend";

export async function fetchRules(
  includeCandidates = true
): Promise<RuleVersionResponse[]> {
  const response = await apiClient.get<RuleVersionResponse[]>(
    API_ENDPOINTS.rules.list,
    {
      params: { include_candidates: includeCandidates },
    }
  );
  return response.data;
}

export async function submitCandidateRule(
  data: RegisterCandidateRuleRequest
): Promise<RuleVersionResponse> {
  const response = await apiClient.post<RuleVersionResponse>(
    API_ENDPOINTS.rules.candidates,
    data
  );
  return response.data;
}
