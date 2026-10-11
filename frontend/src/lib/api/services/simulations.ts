import { apiClient } from "@/lib/api/client";
import { API_ENDPOINTS } from "@/lib/api/endpoints";
import {
  CreateSimulationRequest,
  SimulationResponse,
} from "@/types/backend";

export async function submitResponseSimulation(
  incidentId: string,
  data: CreateSimulationRequest
): Promise<SimulationResponse> {
  const response = await apiClient.post<SimulationResponse>(
    API_ENDPOINTS.incidents.responseSimulations(incidentId),
    data
  );
  return response.data;
}

export async function fetchSimulations(
  incidentId?: string,
  limit = 50,
  offset = 0
): Promise<SimulationResponse[]> {
  const response = await apiClient.get<SimulationResponse[]>(
    API_ENDPOINTS.simulations.list,
    {
      params: {
        incident_id: incidentId,
        limit,
        offset,
      },
    }
  );
  return response.data;
}
