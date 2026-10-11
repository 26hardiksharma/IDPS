export const API_ENDPOINTS = {
  // Health
  health: "/health",

  // Analysis Runs
  runs: {
    list: "/api/runs",
    create: "/api/runs",
    detail: (runId: string) => `/api/runs/${encodeURIComponent(runId)}`,
    execute: (runId: string) => `/api/runs/${encodeURIComponent(runId)}/execute`,
    evidence: (runId: string) => `/api/runs/${encodeURIComponent(runId)}/evidence`,
  },

  // Incidents
  incidents: {
    list: "/api/incidents",
    detail: (incidentId: string) => `/api/incidents/${encodeURIComponent(incidentId)}`,
    updateStatus: (incidentId: string) =>
      `/api/incidents/${encodeURIComponent(incidentId)}/status`,
    explanations: (incidentId: string) =>
      `/api/incidents/${encodeURIComponent(incidentId)}/explanations`,
    responseSimulations: (incidentId: string) =>
      `/api/incidents/${encodeURIComponent(incidentId)}/response-simulations`,
  },

  // Explanations
  explanations: {
    detail: (explanationId: string) =>
      `/api/explanations/${encodeURIComponent(explanationId)}`,
  },

  // Rules & Models
  rules: {
    list: "/api/rules",
    candidates: "/api/rules/candidates",
  },

  // Metrics
  metrics: {
    overview: "/api/metrics",
  },

  // Standalone response simulation audit log
  simulations: {
    list: "/api/response-simulations",
  },
} as const;
