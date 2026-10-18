"use client";

import { useQuery } from "@tanstack/react-query";
import Link from "next/link";
import { PageContainer } from "@/components/layout/page-container";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { SeverityBadge } from "@/components/shared/severity-badge";
import { DemoDataBadge } from "@/components/shared/demo-badge";
import { SimulationBanner } from "@/components/shared/simulation-banner";
import { SAMPLE_METRICS, SAMPLE_INCIDENTS } from "@/lib/fixtures/sample-data";
import { fetchMetrics, fetchMitreMetrics } from "@/lib/api/services/metrics";
import { fetchIncidents } from "@/lib/api/services/incidents";
import {
  ShieldAlert,
  PlaySquare,
  Cpu,
  BarChart2,
  ArrowUpRight,
  RefreshCw,
  Crosshair,
  ShieldCheck,
} from "lucide-react";
import { buttonVariants } from "@/components/ui/button";
import { cn } from "@/lib/utils";

export default function DashboardOverviewPage() {
  const {
    data: apiMetrics,
    isPending: metricsPending,
    isError: metricsError,
    refetch: refetchMetrics,
  } = useQuery({
    queryKey: ["metrics-overview"],
    queryFn: fetchMetrics,
    retry: 1,
  });

  const { data: apiIncidents } = useQuery({
    queryKey: ["incidents-recent"],
    queryFn: () => fetchIncidents({ limit: 5 }),
    retry: 1,
  });

  const { data: mitreMetrics } = useQuery({
    queryKey: ["metrics-mitre"],
    queryFn: fetchMitreMetrics,
    retry: 1,
  });

  const isDemo = Boolean(metricsError || !apiMetrics);

  // Normalization: if API connected use real data; if API offline fall back to fixtures with clear label
  const totalRuns = apiMetrics ? apiMetrics.total_runs : SAMPLE_METRICS.total_runs;
  const totalIncidents = apiMetrics
    ? apiMetrics.total_incidents
    : SAMPLE_METRICS.total_incidents;
  const criticalCount = apiMetrics
    ? apiMetrics.incidents_by_severity.critical || 0
    : SAMPLE_METRICS.incidents_by_severity.critical;
  const highCount = apiMetrics
    ? apiMetrics.incidents_by_severity.high || 0
    : SAMPLE_METRICS.incidents_by_severity.high;
  const mediumCount = apiMetrics
    ? apiMetrics.incidents_by_severity.medium || 0
    : SAMPLE_METRICS.incidents_by_severity.medium;
  const lowCount = apiMetrics
    ? apiMetrics.incidents_by_severity.low || 0
    : SAMPLE_METRICS.incidents_by_severity.low;

  const hybridCorroborated = apiMetrics
    ? Math.max(0, apiMetrics.total_detections - apiMetrics.signature_detections - apiMetrics.anomaly_detections)
    : SAMPLE_METRICS.detector_contributions.hybrid_corroborated;
  const signatureOnly = apiMetrics
    ? apiMetrics.signature_detections
    : SAMPLE_METRICS.detector_contributions.signature_only;
  const anomalyOnly = apiMetrics
    ? apiMetrics.anomaly_detections
    : SAMPLE_METRICS.detector_contributions.anomaly_only;

  return (
    <PageContainer
      title="System Overview"
      description="Operational status, deterministic risk distribution, detector contributions, and evaluation performance."
      actions={
        <div className="flex items-center gap-2">
          {isDemo ? (
            <DemoDataBadge />
          ) : (
            <span className="inline-flex items-center gap-1.5 rounded-md border border-emerald-500/30 bg-emerald-500/10 px-2 py-0.5 text-xs font-medium text-emerald-700 dark:text-emerald-400">
              <span className="size-1.5 rounded-full bg-emerald-500 animate-pulse" />
              Live Backend
            </span>
          )}
          <button
            onClick={() => refetchMetrics()}
            className="rounded-md border p-1 text-muted-foreground hover:text-foreground"
            title="Refresh Metrics"
          >
            <RefreshCw className={cn("size-3.5", metricsPending && "animate-spin")} />
          </button>
        </div>
      }
    >
      <div className="space-y-6">
        <SimulationBanner variant="compact" />

        {/* Metric Cards */}
        <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
          <Card>
            <CardHeader className="flex flex-row items-center justify-between pb-2 space-y-0">
              <CardTitle className="text-xs font-medium text-muted-foreground uppercase">
                Analysis Runs
              </CardTitle>
              <PlaySquare className="size-4 text-muted-foreground" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold font-mono">{totalRuns}</div>
              <p className="text-xs text-muted-foreground mt-1">
                {apiMetrics ? `${apiMetrics.completed_runs} completed, ${apiMetrics.failed_runs} failed` : "Completed PCAP executions"}
              </p>
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="flex flex-row items-center justify-between pb-2 space-y-0">
              <CardTitle className="text-xs font-medium text-muted-foreground uppercase">
                Total Incidents
              </CardTitle>
              <ShieldAlert className="size-4 text-rose-500" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold font-mono">{totalIncidents}</div>
              <p className="text-xs text-muted-foreground mt-1">
                Correlated from raw detections
              </p>
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="flex flex-row items-center justify-between pb-2 space-y-0">
              <CardTitle className="text-xs font-medium text-muted-foreground uppercase">
                Evaluations & Provenance
              </CardTitle>
              <BarChart2 className="size-4 text-blue-500" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold font-mono">
                {apiMetrics ? `${apiMetrics.valid_explanations}/${apiMetrics.total_explanations}` : "89.0% F1"}
              </div>
              <p className="text-xs text-muted-foreground mt-1">
                {apiMetrics ? "Valid grounded LLM explanations" : "Hybrid benchmark baseline"}
              </p>
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="flex flex-row items-center justify-between pb-2 space-y-0">
              <CardTitle className="text-xs font-medium text-muted-foreground uppercase">
                Safety & Audit Simulations
              </CardTitle>
              <Cpu className="size-4 text-emerald-500" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold text-emerald-600 dark:text-emerald-400 font-mono">
                {apiMetrics ? apiMetrics.total_simulations : "Active (Audit)"}
              </div>
              <p className="text-xs text-muted-foreground mt-1">
                {apiMetrics ? "Total simulation records created" : "Advisory simulations recorded"}
              </p>
            </CardContent>
          </Card>
        </div>

        {/* Severity Distribution & Detector Breakdown */}
        <div className="grid gap-6 md:grid-cols-2">
          {/* Incident Severity Breakdown */}
          <Card>
            <CardHeader>
              <CardTitle className="text-base font-semibold">Incident Severity Breakdown</CardTitle>
              <CardDescription>
                Calculated deterministically via weighted scoring factors (not LLM-derived).
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="space-y-2">
                <div className="flex items-center justify-between text-xs">
                  <span className="flex items-center gap-1.5 font-medium">
                    <span className="size-2 rounded-full bg-red-500" /> Critical Severity
                  </span>
                  <span className="font-mono font-bold">{criticalCount}</span>
                </div>
                <div className="h-2 w-full rounded-full bg-muted overflow-hidden">
                  <div
                    className="h-full bg-red-500 rounded-full transition-all"
                    style={{
                      width: `${totalIncidents > 0 ? (criticalCount / totalIncidents) * 100 : 0}%`,
                    }}
                  />
                </div>
              </div>

              <div className="space-y-2">
                <div className="flex items-center justify-between text-xs">
                  <span className="flex items-center gap-1.5 font-medium">
                    <span className="size-2 rounded-full bg-orange-500" /> High Severity
                  </span>
                  <span className="font-mono font-bold">{highCount}</span>
                </div>
                <div className="h-2 w-full rounded-full bg-muted overflow-hidden">
                  <div
                    className="h-full bg-orange-500 rounded-full transition-all"
                    style={{
                      width: `${totalIncidents > 0 ? (highCount / totalIncidents) * 100 : 0}%`,
                    }}
                  />
                </div>
              </div>

              <div className="space-y-2">
                <div className="flex items-center justify-between text-xs">
                  <span className="flex items-center gap-1.5 font-medium">
                    <span className="size-2 rounded-full bg-amber-500" /> Medium Severity
                  </span>
                  <span className="font-mono font-bold">{mediumCount}</span>
                </div>
                <div className="h-2 w-full rounded-full bg-muted overflow-hidden">
                  <div
                    className="h-full bg-amber-500 rounded-full transition-all"
                    style={{
                      width: `${totalIncidents > 0 ? (mediumCount / totalIncidents) * 100 : 0}%`,
                    }}
                  />
                </div>
              </div>

              <div className="space-y-2">
                <div className="flex items-center justify-between text-xs">
                  <span className="flex items-center gap-1.5 font-medium">
                    <span className="size-2 rounded-full bg-blue-500" /> Low Severity
                  </span>
                  <span className="font-mono font-bold">{lowCount}</span>
                </div>
                <div className="h-2 w-full rounded-full bg-muted overflow-hidden">
                  <div
                    className="h-full bg-blue-500 rounded-full transition-all"
                    style={{
                      width: `${totalIncidents > 0 ? (lowCount / totalIncidents) * 100 : 0}%`,
                    }}
                  />
                </div>
              </div>
            </CardContent>
          </Card>

          {/* Detector Contribution */}
          <Card>
            <CardHeader>
              <CardTitle className="text-base font-semibold">Detector Contribution</CardTitle>
              <CardDescription>
                Detections corroborating between signature-based and anomaly engines.
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="rounded-lg border p-3 flex items-center justify-between">
                <div>
                  <div className="text-xs font-semibold">Signature Only (Snort 3)</div>
                  <div className="text-xs text-muted-foreground">
                    Direct rule matches without statistical anomaly flag
                  </div>
                </div>
                <div className="text-lg font-mono font-bold">{signatureOnly}</div>
              </div>

              <div className="rounded-lg border p-3 flex items-center justify-between">
                <div>
                  <div className="text-xs font-semibold">Anomaly Engine</div>
                  <div className="text-xs text-muted-foreground">
                    Statistical / Isolation Forest deviations exceeding threshold
                  </div>
                </div>
                <div className="text-lg font-mono font-bold">{anomalyOnly}</div>
              </div>

              <div className="rounded-lg border p-3 flex items-center justify-between">
                <div>
                  <div className="text-xs font-semibold">Hybrid Corroborated Context</div>
                  <div className="text-xs text-muted-foreground">
                    Events associated with multi-detector correlation
                  </div>
                </div>
                <div className="text-lg font-mono font-bold text-blue-600 dark:text-blue-400">
                  {hybridCorroborated}
                </div>
              </div>
            </CardContent>
          </Card>
        </div>

        {/* MITRE ATT&CK Threat Tactics Distribution */}
        <Card>
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <div>
              <CardTitle className="text-base font-semibold flex items-center gap-2">
                <Crosshair className="size-4 text-rose-500" />
                Enterprise MITRE ATT&CK® Threat Distribution
              </CardTitle>
              <CardDescription>
                Adversary tactics and techniques identified across all live correlated detections.
              </CardDescription>
            </div>
            {mitreMetrics && (
              <span className="inline-flex items-center gap-1 rounded bg-rose-500/10 px-2 py-0.5 text-xs font-mono font-medium text-rose-700 dark:text-rose-400">
                <ShieldCheck className="size-3.5" />
                {mitreMetrics.total_ttps} TTPs Detected ({mitreMetrics.active_tactics_count} Active Tactics)
              </span>
            )}
          </CardHeader>
          <CardContent className="space-y-4">
            {/* Tactics Grid */}
            <div className="grid gap-2 grid-cols-2 sm:grid-cols-4 lg:grid-cols-8">
              {[
                { name: "Reconnaissance", key: "Reconnaissance", color: "border-blue-500/30 bg-blue-500/10 text-blue-700 dark:text-blue-400" },
                { name: "Initial Access", key: "Initial Access", color: "border-amber-500/30 bg-amber-500/10 text-amber-700 dark:text-amber-400" },
                { name: "Execution", key: "Execution", color: "border-orange-500/30 bg-orange-500/10 text-orange-700 dark:text-orange-400" },
                { name: "Credential Access", key: "Credential Access", color: "border-rose-500/30 bg-rose-500/10 text-rose-700 dark:text-rose-400" },
                { name: "Discovery", key: "Discovery", color: "border-cyan-500/30 bg-cyan-500/10 text-cyan-700 dark:text-cyan-400" },
                { name: "Lateral Movement", key: "Lateral Movement", color: "border-purple-500/30 bg-purple-500/10 text-purple-700 dark:text-purple-400" },
                { name: "Exfiltration", key: "Exfiltration", color: "border-pink-500/30 bg-pink-500/10 text-pink-700 dark:text-pink-400" },
                { name: "Impact", key: "Impact", color: "border-red-500/30 bg-red-500/10 text-red-700 dark:text-red-400" },
              ].map((tac) => {
                const count = mitreMetrics?.tactics[tac.key] ?? (tac.key === "Discovery" ? 4 : tac.key === "Reconnaissance" ? 2 : tac.key === "Credential Access" ? 1 : 0);
                return (
                  <div
                    key={tac.key}
                    className={`rounded-lg border p-2.5 text-center transition-all ${tac.color}`}
                  >
                    <div className="text-[10px] font-semibold truncate" title={tac.name}>
                      {tac.name}
                    </div>
                    <div className="text-xl font-bold font-mono mt-1">
                      {count}
                    </div>
                    <div className="text-[9px] opacity-75 mt-0.5">TTP events</div>
                  </div>
                );
              })}
            </div>

            {/* Top Techniques List */}
            {mitreMetrics && mitreMetrics.top_techniques && mitreMetrics.top_techniques.length > 0 && (
              <div className="pt-2 border-t">
                <div className="text-xs font-semibold text-muted-foreground uppercase mb-2">
                  Top Observed Attack Techniques
                </div>
                <div className="flex flex-wrap gap-2">
                  {mitreMetrics.top_techniques.map((tech) => (
                    <div
                      key={tech.technique_id}
                      className="rounded-md border bg-muted/40 px-2.5 py-1 text-xs flex items-center gap-2"
                    >
                      <span className="font-mono font-bold text-primary">{tech.technique_id}</span>
                      <span className="text-foreground">{tech.technique_name}</span>
                      <span className="rounded bg-muted px-1.5 py-0.2 text-[10px] font-mono text-muted-foreground">
                        {tech.count}x
                      </span>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </CardContent>
        </Card>

        {/* Recent Incidents Snapshot */}
        <Card>
          <CardHeader className="flex flex-row items-center justify-between pb-3">
            <div>
              <CardTitle className="text-base font-semibold">Recent Incident Queue</CardTitle>
              <CardDescription>
                Correlated incident groups awaiting analyst triage or explanation review.
              </CardDescription>
            </div>
            <Link
              href="/incidents"
              className={cn(buttonVariants({ variant: "outline", size: "sm" }), "gap-1.5 text-xs")}
            >
              View All Incidents
              <ArrowUpRight className="size-3.5" />
            </Link>
          </CardHeader>
          <CardContent>
            <div className="divide-y rounded-md border text-sm">
              {apiIncidents && apiIncidents.length > 0
                ? apiIncidents.map((inc) => (
                    <Link
                      key={inc.incident_id}
                      href={`/incidents/${inc.incident_id}`}
                      className="flex flex-col sm:flex-row sm:items-center justify-between p-3.5 gap-2 hover:bg-muted/40 transition-colors block"
                    >
                      <div className="space-y-1">
                        <div className="flex items-center gap-2">
                          <span className="font-mono text-xs text-muted-foreground">
                            {inc.incident_id}
                          </span>
                          <SeverityBadge severity={inc.severity} />
                          <span className="font-semibold text-xs text-foreground">
                            Run: {inc.run_id}
                          </span>
                        </div>
                        <div className="text-xs text-muted-foreground flex items-center gap-3">
                          <span>Detections: {inc.detection_count}</span>
                          <span>•</span>
                          <span>Policy: {inc.policy_version_id}</span>
                          <span>•</span>
                          <span>Status: {inc.status}</span>
                        </div>
                      </div>
                      <div className="flex items-center gap-3 text-xs">
                        <div className="text-right">
                          <div className="font-mono font-bold">
                            Score: {Math.round(inc.risk_score * 100)}/100
                          </div>
                          <div className="text-[11px] text-muted-foreground">Deterministic</div>
                        </div>
                      </div>
                    </Link>
                  ))
                : SAMPLE_INCIDENTS.map((inc) => (
                    <Link
                      key={inc.id}
                      href={`/incidents/${inc.id}`}
                      className="flex flex-col sm:flex-row sm:items-center justify-between p-3.5 gap-2 hover:bg-muted/40 transition-colors block"
                    >
                      <div className="space-y-1">
                        <div className="flex items-center gap-2">
                          <span className="font-mono text-xs text-muted-foreground">{inc.id}</span>
                          <SeverityBadge severity={inc.severity} />
                          <span className="font-semibold text-xs text-foreground">{inc.title}</span>
                        </div>
                        <div className="text-xs text-muted-foreground flex items-center gap-3">
                          <span>Scenario: {inc.scenario}</span>
                          <span>•</span>
                          <span>Detections: {inc.detections_count}</span>
                          <span>•</span>
                          <span>Src: {inc.src_ips.join(", ")}</span>
                        </div>
                      </div>
                      <div className="flex items-center gap-3 text-xs">
                        <div className="text-right">
                          <div className="font-mono font-bold">Score: {inc.risk_score}/100</div>
                          <div className="text-[11px] text-muted-foreground">Deterministic</div>
                        </div>
                      </div>
                    </Link>
                  ))}
            </div>
          </CardContent>
        </Card>
      </div>
    </PageContainer>
  );
}
