"use client";

import { use, useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import Link from "next/link";
import { PageContainer } from "@/components/layout/page-container";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { SeverityBadge } from "@/components/shared/severity-badge";
import { IncidentStatusBadge } from "@/components/shared/status-badge";
import { DemoDataBadge } from "@/components/shared/demo-badge";
import { AiExplanationPanel } from "@/components/shared/ai-explanation-panel";
import { ProvenanceChain } from "@/components/shared/provenance-chain";
import { SimulationBanner } from "@/components/shared/simulation-banner";
import {
  fetchIncidentDetail,
  updateIncidentStatus,
} from "@/lib/api/services/incidents";
import { submitResponseSimulation } from "@/lib/api/services/simulations";
import { SAMPLE_INCIDENTS } from "@/lib/fixtures/sample-data";
import { Button } from "@/components/ui/button";
import { ArrowLeft, TerminalSquare, RefreshCw } from "lucide-react";
import { toast } from "sonner";
import { IncidentStatus } from "@/types/backend";
import { SeverityLevel } from "@/types/detection";
import { IncidentStatus as OldIncidentStatus } from "@/types/incident";

export default function IncidentDetailPage({
  params,
}: {
  params: Promise<{ incidentId: string }>;
}) {
  const resolvedParams = use(params);
  const incidentId = resolvedParams.incidentId;
  const queryClient = useQueryClient();

  const [activeTab, setActiveTab] = useState<"detections" | "factors" | "simulation">("detections");
  const [proposedAction, setProposedAction] = useState("isolate_source_ip");
  const [actionTarget, setActionTarget] = useState("");
  const [actionScope, setActionScope] = useState("host");

  const {
    data: incident,
    isPending,
    isError,
    refetch,
  } = useQuery({
    queryKey: ["incident-detail", incidentId],
    queryFn: () => fetchIncidentDetail(incidentId),
    retry: 1,
  });

  const statusMutation = useMutation({
    mutationFn: (newStatus: IncidentStatus) =>
      updateIncidentStatus(incidentId, { status: newStatus }),
    onSuccess: (data) => {
      toast.success(`Incident status updated to ${data.status}`);
      queryClient.invalidateQueries({ queryKey: ["incident-detail", incidentId] });
      queryClient.invalidateQueries({ queryKey: ["incidents-list"] });
    },
    onError: (err: unknown) => {
      const axiosErr = err as { response?: { data?: { message?: string } } };
      toast.error(axiosErr?.response?.data?.message || "Failed to update incident status");
    },
  });

  const simulationMutation = useMutation({
    mutationFn: () =>
      submitResponseSimulation(incidentId, {
        proposed_action: proposedAction,
        action_target: actionTarget || (incident?.detections[0]?.src_ip || "192.0.2.45"),
        action_scope: actionScope,
        actor: "analyst_local",
      }),
    onSuccess: (res) => {
      toast.success(
        `Simulation recorded in audit store (ID: ${res.simulation_id}). SAFETY: No network changes made.`
      );
      queryClient.invalidateQueries({ queryKey: ["simulations-list"] });
    },
    onError: (err: unknown) => {
      const axiosErr = err as { response?: { data?: { message?: string } } };
      toast.error(axiosErr?.response?.data?.message || "Failed to submit simulation");
    },
  });

  // Fallback demo fixture
  const sampleInc =
    SAMPLE_INCIDENTS.find((i) => i.id === incidentId) || SAMPLE_INCIDENTS[0];
  const isDemo = Boolean(isError || !incident);

  const displayIncident = incident || {
    incident_id: sampleInc.id,
    run_id: sampleInc.run_id,
    status: (sampleInc.status === "new" ? "open" : sampleInc.status === "in_review" ? "under_review" : "open") as IncidentStatus,
    severity: sampleInc.severity,
    risk_score: sampleInc.risk_score / 100,
    score_factors: sampleInc.scoring_factors as unknown as Record<string, unknown>,
    correlation_reason: "Temporal correlation window + source IP match",
    first_seen: sampleInc.first_seen,
    last_seen: sampleInc.last_seen,
    policy_version_id: sampleInc.correlation_policy_version,
    detections: [
      {
        detection_id: "det_sample_01",
        detector_type: "signature",
        detector_name: "Snort 3: ET SCAN Potential SSH Scan",
        event_time: sampleInc.first_seen,
        src_ip: sampleInc.src_ips[0],
        dst_ip: sampleInc.dst_ips[0],
        severity: "critical",
        score: null,
        rule_version_id: "rule_v1.2",
        model_version_id: null,
      },
      {
        detection_id: "det_sample_02",
        detector_type: "anomaly",
        detector_name: "Isolation Forest Anomaly Threshold",
        event_time: sampleInc.first_seen,
        src_ip: sampleInc.src_ips[0],
        dst_ip: sampleInc.dst_ips[0],
        severity: "high",
        score: 0.89,
        rule_version_id: null,
        model_version_id: "iforest_v1.0",
      },
    ],
    created_at: sampleInc.first_seen,
    updated_at: sampleInc.last_seen,
  };

  const handleStatusChange = (newStatus: IncidentStatus) => {
    if (incident) {
      statusMutation.mutate(newStatus);
    } else {
      toast.info(`Status update simulated (${newStatus})`);
    }
  };

  return (
    <PageContainer
      title={`Incident: ${incidentId}`}
      description="Inspect constituent signature and anomaly detections, deterministic score breakdown, provenance lineage, and validated explanations."
      actions={
        <div className="flex items-center gap-2">
          <Link href="/incidents">
            <Button variant="outline" size="sm" className="gap-1 text-xs">
              <ArrowLeft className="size-3.5" />
              Back to Queue
            </Button>
          </Link>
          {isDemo ? (
            <DemoDataBadge />
          ) : (
            <span className="inline-flex items-center gap-1.5 rounded-md border border-emerald-500/30 bg-emerald-500/10 px-2 py-0.5 text-xs font-medium text-emerald-700 dark:text-emerald-400">
              <span className="size-1.5 rounded-full bg-emerald-500 animate-pulse" />
              Live Backend
            </span>
          )}
          <button
            onClick={() => refetch()}
            className="rounded-md border p-1 text-muted-foreground hover:text-foreground"
            title="Refresh Incident"
          >
            <RefreshCw className={isPending ? "size-3.5 animate-spin" : "size-3.5"} />
          </button>
        </div>
      }
    >
      <div className="space-y-6">
        {/* Core Overview Bar */}
        <div className="grid gap-4 sm:grid-cols-4">
          <Card>
            <CardHeader className="pb-1">
              <CardTitle className="text-xs font-medium text-muted-foreground uppercase">
                Severity
              </CardTitle>
            </CardHeader>
            <CardContent>
              <SeverityBadge severity={displayIncident.severity} />
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="pb-1">
              <CardTitle className="text-xs font-medium text-muted-foreground uppercase">
                Deterministic Risk Score
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold font-mono text-rose-600 dark:text-rose-400">
                {Math.round(displayIncident.risk_score * 100)}
                <span className="text-xs text-muted-foreground">/100</span>
              </div>
              <p className="text-[11px] text-muted-foreground">Authoritative decision</p>
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="pb-1">
              <CardTitle className="text-xs font-medium text-muted-foreground uppercase">
                Review Status
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-1">
              <IncidentStatusBadge status={displayIncident.status as OldIncidentStatus} />
              <div className="flex gap-1 pt-1">
                {(["open", "under_review", "acknowledged", "closed"] as IncidentStatus[]).map((st) => (
                  <button
                    key={st}
                    onClick={() => handleStatusChange(st)}
                    disabled={statusMutation.isPending}
                    className={`rounded px-1.5 py-0.5 text-[10px] font-mono border ${
                      displayIncident.status === st
                        ? "bg-foreground text-background font-bold"
                        : "bg-muted text-muted-foreground hover:text-foreground"
                    }`}
                  >
                    {st.slice(0, 4)}
                  </button>
                ))}
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="pb-1">
              <CardTitle className="text-xs font-medium text-muted-foreground uppercase">
                Correlated Run
              </CardTitle>
            </CardHeader>
            <CardContent>
              <Link
                href={`/runs/${displayIncident.run_id}`}
                className="font-mono text-xs font-medium text-blue-600 dark:text-blue-400 hover:underline block truncate"
              >
                {displayIncident.run_id}
              </Link>
              <p className="text-[11px] text-muted-foreground mt-1">
                Policy: {displayIncident.policy_version_id}
              </p>
            </CardContent>
          </Card>
        </div>

        {/* Provenance Lineage */}
        <ProvenanceChain
          runId={displayIncident.run_id}
          incidentId={displayIncident.incident_id}
          policyVersionId={displayIncident.policy_version_id}
          explanationId={"exp_available"}
          hasSimulations={true}
        />

        {/* AI Explanation Panel */}
        <AiExplanationPanel
          incidentId={incidentId}
          explanation={null}
          onRefresh={() => refetch()}
        />

        {/* Navigation Tabs for Details */}
        <div className="flex items-center gap-2 border-b pb-2 text-xs font-medium">
          <button
            onClick={() => setActiveTab("detections")}
            className={`rounded-md px-3 py-1.5 transition-colors ${
              activeTab === "detections"
                ? "bg-muted text-foreground font-semibold"
                : "text-muted-foreground hover:text-foreground"
            }`}
          >
            Constituent Detections ({displayIncident.detections.length})
          </button>
          <button
            onClick={() => setActiveTab("factors")}
            className={`rounded-md px-3 py-1.5 transition-colors ${
              activeTab === "factors"
                ? "bg-muted text-foreground font-semibold"
                : "text-muted-foreground hover:text-foreground"
            }`}
          >
            Risk Scoring Factors
          </button>
          <button
            onClick={() => setActiveTab("simulation")}
            className={`rounded-md px-3 py-1.5 transition-colors ${
              activeTab === "simulation"
                ? "bg-muted text-foreground font-semibold"
                : "text-muted-foreground hover:text-foreground"
            }`}
          >
            Simulate Response
          </button>
        </div>

        {/* Tab 1: Constituent Detections Table */}
        {activeTab === "detections" && (
          <Card>
            <CardHeader>
              <CardTitle className="text-base font-semibold">
                Detections Grouped into Incident
              </CardTitle>
              <CardDescription>
                Raw findings from Snort 3 signature matches and statistical/ML anomaly engine.
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="rounded-md border overflow-x-auto">
                <table className="w-full text-left text-xs">
                  <thead className="bg-muted/50 border-b font-medium text-muted-foreground">
                    <tr>
                      <th className="p-3">Detection ID</th>
                      <th className="p-3">Detector Engine</th>
                      <th className="p-3">Detector Name</th>
                      <th className="p-3">Severity / Score</th>
                      <th className="p-3">Endpoints</th>
                      <th className="p-3">Rule / Model Hash</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-border">
                    {displayIncident.detections.map((det) => (
                      <tr key={det.detection_id} className="hover:bg-muted/30 transition-colors">
                        <td className="p-3 font-mono font-medium">{det.detection_id}</td>
                        <td className="p-3">
                          <span
                            className={`rounded px-1.5 py-0.5 text-[10px] font-mono uppercase ${
                              det.detector_type === "signature"
                                ? "bg-blue-500/15 text-blue-700 dark:text-blue-400"
                                : "bg-amber-500/15 text-amber-700 dark:text-amber-400"
                            }`}
                          >
                            {det.detector_type}
                          </span>
                        </td>
                        <td className="p-3 font-medium text-foreground">{det.detector_name}</td>
                        <td className="p-3">
                          {det.severity && <SeverityBadge severity={det.severity as SeverityLevel} />}
                          {det.score !== null && det.score !== undefined && (
                            <span className="font-mono text-xs ml-1">
                              Score: {det.score.toFixed(2)}
                            </span>
                          )}
                        </td>
                        <td className="p-3 font-mono text-[11px] text-muted-foreground">
                          {det.src_ip || "—"} → {det.dst_ip || "—"}
                        </td>
                        <td className="p-3 font-mono text-[11px] text-muted-foreground">
                          {det.rule_version_id || det.model_version_id || "default"}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </CardContent>
          </Card>
        )}

        {/* Tab 2: Scoring Factors */}
        {activeTab === "factors" && (
          <Card>
            <CardHeader>
              <CardTitle className="text-base font-semibold">
                Deterministic Risk Calculation Factors
              </CardTitle>
              <CardDescription>
                Auditable breakdown showing how individual weights produced the final risk score.
              </CardDescription>
            </CardHeader>
            <CardContent>
              {displayIncident.score_factors ? (
                <pre className="rounded-md bg-muted/60 p-4 font-mono text-xs overflow-x-auto text-foreground">
                  {JSON.stringify(displayIncident.score_factors, null, 2)}
                </pre>
              ) : (
                <div className="text-xs text-muted-foreground">
                  Scoring factors not explicitly structured for this incident record.
                </div>
              )}
            </CardContent>
          </Card>
        )}

        {/* Tab 3: Fast Response Simulation from Incident */}
        {activeTab === "simulation" && (
          <Card>
            <CardHeader>
              <CardTitle className="text-base font-semibold">
                Simulate Incident Response
              </CardTitle>
              <CardDescription>
                Quickly test containment actions directly linked to this incident.
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <SimulationBanner variant="warning" />

              <div className="grid gap-4 sm:grid-cols-3">
                <div className="space-y-1">
                  <label className="text-xs font-medium">Proposed Action</label>
                  <select
                    value={proposedAction}
                    onChange={(e) => setProposedAction(e.target.value)}
                    className="w-full rounded-md border border-input bg-background px-3 py-1.5 text-xs"
                  >
                    <option value="isolate_source_ip">Simulate Source IP Drop</option>
                    <option value="rate_limit_traffic">Simulate Rate Limiting</option>
                    <option value="block_port_simulation">Simulate Port Block</option>
                  </select>
                </div>

                <div className="space-y-1">
                  <label className="text-xs font-medium">Action Target</label>
                  <input
                    type="text"
                    value={actionTarget}
                    onChange={(e) => setActionTarget(e.target.value)}
                    placeholder={displayIncident.detections[0]?.src_ip || "192.0.2.45"}
                    className="w-full rounded-md border border-input bg-background px-3 py-1.5 text-xs font-mono"
                  />
                </div>

                <div className="space-y-1">
                  <label className="text-xs font-medium">Scope</label>
                  <select
                    value={actionScope}
                    onChange={(e) => setActionScope(e.target.value)}
                    className="w-full rounded-md border border-input bg-background px-3 py-1.5 text-xs"
                  >
                    <option value="host">Host Level (Simulated)</option>
                    <option value="subnet">Subnet Level (Simulated)</option>
                  </select>
                </div>
              </div>

              <div className="flex justify-end pt-2">
                <Button
                  size="sm"
                  className="gap-1.5 text-xs"
                  disabled={simulationMutation.isPending}
                  onClick={() => simulationMutation.mutate()}
                >
                  <TerminalSquare className="size-3.5" />
                  {simulationMutation.isPending ? "Recording Simulation..." : "Simulate Action"}
                </Button>
              </div>
            </CardContent>
          </Card>
        )}
      </div>
    </PageContainer>
  );
}
