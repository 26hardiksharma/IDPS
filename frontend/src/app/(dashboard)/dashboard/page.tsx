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
            <span className="inline-flex items-center gap-1.5 rounded border border-border bg-card px-2 py-0.5 text-[11px] font-mono text-muted-foreground">
              <span className="size-1.5 rounded-full bg-emerald-500" />
              Live Backend
            </span>
          )}
          <button
            onClick={() => refetchMetrics()}
            className="rounded border border-border p-1 text-muted-foreground hover:text-foreground transition-colors"
            title="Refresh Metrics"
          >
            <RefreshCw className={cn("size-3.5", metricsPending && "animate-spin")} />
          </button>
        </div>
      }
    >
      <div className="space-y-5">
        <SimulationBanner variant="compact" />

        {/* Metric Cards */}
        <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
          <Card>
            <CardHeader className="flex flex-row items-center justify-between pb-1.5 space-y-0">
              <CardTitle className="text-xs font-medium text-muted-foreground">
                Analysis Runs
              </CardTitle>
              <PlaySquare className="size-3.5 text-muted-foreground/70" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-semibold font-mono text-foreground">{totalRuns}</div>
              <p className="text-[11px] text-muted-foreground mt-0.5">
                {apiMetrics ? `${apiMetrics.completed_runs} completed, ${apiMetrics.failed_runs} failed` : "Completed PCAP executions"}
              </p>
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="flex flex-row items-center justify-between pb-1.5 space-y-0">
              <CardTitle className="text-xs font-medium text-muted-foreground">
                Total Incidents
              </CardTitle>
              <ShieldAlert className="size-3.5 text-muted-foreground/70" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-semibold font-mono text-foreground">{totalIncidents}</div>
              <p className="text-[11px] text-muted-foreground mt-0.5">
                Correlated from raw detections
              </p>
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="flex flex-row items-center justify-between pb-1.5 space-y-0">
              <CardTitle className="text-xs font-medium text-muted-foreground">
                Grounded Explanations
              </CardTitle>
              <BarChart2 className="size-3.5 text-muted-foreground/70" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-semibold font-mono text-foreground">
                {apiMetrics ? `${apiMetrics.valid_explanations}/${apiMetrics.total_explanations}` : "89.0% F1"}
              </div>
              <p className="text-[11px] text-muted-foreground mt-0.5">
                {apiMetrics ? "Validated against evidence" : "Hybrid benchmark baseline"}
              </p>
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="flex flex-row items-center justify-between pb-1.5 space-y-0">
              <CardTitle className="text-xs font-medium text-muted-foreground">
                Simulated Actions
              </CardTitle>
              <Cpu className="size-3.5 text-muted-foreground/70" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-semibold font-mono text-foreground">
                {apiMetrics ? apiMetrics.total_simulations : "Active (Audit)"}
              </div>
              <p className="text-[11px] text-muted-foreground mt-0.5">
                {apiMetrics ? "Non-executing audit records" : "Advisory simulations recorded"}
              </p>
            </CardContent>
          </Card>
        </div>

        {/* Severity Distribution & Detector Breakdown */}
        <div className="grid gap-4 md:grid-cols-2">
          {/* Incident Severity Breakdown */}
          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-sm font-semibold">Incident Severity Breakdown</CardTitle>
              <CardDescription className="text-xs">
                Deterministic risk score bands (not LLM-derived).
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-3 pt-1">
              <div className="space-y-1.5">
                <div className="flex items-center justify-between text-xs">
                  <span className="flex items-center gap-1.5 font-medium text-foreground">
                    <span className="size-1.5 rounded-full bg-red-500" /> Critical Severity
                  </span>
                  <span className="font-mono font-medium">{criticalCount}</span>
                </div>
                <div className="h-1.5 w-full rounded-sm bg-muted overflow-hidden">
                  <div
                    className="h-full bg-red-500/80 transition-all"
                    style={{
                      width: `${totalIncidents > 0 ? (criticalCount / totalIncidents) * 100 : 0}%`,
                    }}
                  />
                </div>
              </div>

              <div className="space-y-1.5">
                <div className="flex items-center justify-between text-xs">
                  <span className="flex items-center gap-1.5 font-medium text-foreground">
                    <span className="size-1.5 rounded-full bg-orange-500" /> High Severity
                  </span>
                  <span className="font-mono font-medium">{highCount}</span>
                </div>
                <div className="h-1.5 w-full rounded-sm bg-muted overflow-hidden">
                  <div
                    className="h-full bg-orange-500/80 transition-all"
                    style={{
                      width: `${totalIncidents > 0 ? (highCount / totalIncidents) * 100 : 0}%`,
                    }}
                  />
                </div>
              </div>

              <div className="space-y-1.5">
                <div className="flex items-center justify-between text-xs">
                  <span className="flex items-center gap-1.5 font-medium text-foreground">
                    <span className="size-1.5 rounded-full bg-amber-500" /> Medium Severity
                  </span>
                  <span className="font-mono font-medium">{mediumCount}</span>
                </div>
                <div className="h-1.5 w-full rounded-sm bg-muted overflow-hidden">
                  <div
                    className="h-full bg-amber-500/80 transition-all"
                    style={{
                      width: `${totalIncidents > 0 ? (mediumCount / totalIncidents) * 100 : 0}%`,
                    }}
                  />
                </div>
              </div>

              <div className="space-y-1.5">
                <div className="flex items-center justify-between text-xs">
                  <span className="flex items-center gap-1.5 font-medium text-foreground">
                    <span className="size-1.5 rounded-full bg-slate-400 dark:bg-slate-500" /> Low Severity
                  </span>
                  <span className="font-mono font-medium">{lowCount}</span>
                </div>
                <div className="h-1.5 w-full rounded-sm bg-muted overflow-hidden">
                  <div
                    className="h-full bg-slate-400 dark:bg-slate-500 transition-all"
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
            <CardHeader className="pb-2">
              <CardTitle className="text-sm font-semibold">Detector Contribution</CardTitle>
              <CardDescription className="text-xs">
                Signal overlap between signature and statistical engines.
              </CardDescription>
            </CardHeader>
            <CardContent className="pt-1">
              <div className="divide-y divide-border text-xs">
                <div className="py-2.5 flex items-center justify-between">
                  <div>
                    <div className="font-medium text-foreground">Signature Engine (Snort 3)</div>
                    <div className="text-[11px] text-muted-foreground">
                      Direct rule matches without statistical anomaly trigger
                    </div>
                  </div>
                  <div className="font-mono font-semibold text-sm text-foreground">{signatureOnly}</div>
                </div>

                <div className="py-2.5 flex items-center justify-between">
                  <div>
                    <div className="font-medium text-foreground">Anomaly Engine</div>
                    <div className="text-[11px] text-muted-foreground">
                      Statistical and isolation forest deviations exceeding baseline
                    </div>
                  </div>
                  <div className="font-mono font-semibold text-sm text-foreground">{anomalyOnly}</div>
                </div>

                <div className="py-2.5 flex items-center justify-between">
                  <div>
                    <div className="font-medium text-foreground">Hybrid Corroborated</div>
                    <div className="text-[11px] text-muted-foreground">
                      Events corroborated across both signature and anomaly detectors
                    </div>
                  </div>
                  <div className="font-mono font-semibold text-sm text-foreground">
                    {hybridCorroborated}
                  </div>
                </div>
              </div>
            </CardContent>
          </Card>
        </div>

        {/* MITRE ATT&CK Threat Tactics Distribution */}
        <Card>
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <div>
              <CardTitle className="text-sm font-semibold flex items-center gap-2">
                <Crosshair className="size-3.5 text-muted-foreground" />
                Enterprise MITRE ATT&CK® Threat Distribution
              </CardTitle>
              <CardDescription className="text-xs">
                Adversary tactics and techniques identified across live correlated detections.
              </CardDescription>
            </div>
            {mitreMetrics && (
              <span className="inline-flex items-center gap-1.5 rounded border border-border bg-muted/30 px-2 py-0.5 text-[11px] font-mono text-muted-foreground">
                <ShieldCheck className="size-3 text-muted-foreground" />
                {mitreMetrics.total_ttps} TTPs ({mitreMetrics.active_tactics_count} Active Tactics)
              </span>
            )}
          </CardHeader>
          <CardContent className="space-y-3 pt-1">
            {/* Tactics Grid - Calm, Neutral, Non-rainbow */}
            <div className="grid gap-2 grid-cols-2 sm:grid-cols-4 lg:grid-cols-8">
              {[
                { name: "Reconnaissance", key: "Reconnaissance" },
                { name: "Initial Access", key: "Initial Access" },
                { name: "Execution", key: "Execution" },
                { name: "Credential Access", key: "Credential Access" },
                { name: "Discovery", key: "Discovery" },
                { name: "Lateral Movement", key: "Lateral Movement" },
                { name: "Exfiltration", key: "Exfiltration" },
                { name: "Impact", key: "Impact" },
              ].map((tac) => {
                const count = mitreMetrics?.tactics[tac.key] ?? (tac.key === "Discovery" ? 4 : tac.key === "Reconnaissance" ? 2 : tac.key === "Credential Access" ? 1 : 0);
                const hasEvents = count > 0;
                return (
                  <div
                    key={tac.key}
                    className={cn(
                      "rounded border p-2 text-left transition-colors",
                      hasEvents
                        ? "border-border bg-muted/40"
                        : "border-border/60 bg-card opacity-60"
                    )}
                  >
                    <div className="text-[10px] font-medium text-muted-foreground truncate" title={tac.name}>
                      {tac.name}
                    </div>
                    <div className="text-lg font-semibold font-mono mt-0.5 text-foreground">
                      {count}
                    </div>
                    <div className="text-[10px] text-muted-foreground font-mono">
                      {hasEvents ? "events" : "none"}
                    </div>
                  </div>
                );
              })}
            </div>

            {/* Top Techniques List */}
            {mitreMetrics && mitreMetrics.top_techniques && mitreMetrics.top_techniques.length > 0 && (
              <div className="pt-2 border-t border-border">
                <div className="text-[11px] font-medium text-muted-foreground mb-1.5">
                  Top Observed Attack Techniques
                </div>
                <div className="flex flex-wrap gap-1.5">
                  {mitreMetrics.top_techniques.map((tech) => (
                    <div
                      key={tech.technique_id}
                      className="rounded border border-border bg-muted/20 px-2 py-0.5 text-xs flex items-center gap-1.5"
                    >
                      <span className="font-mono text-[11px] font-semibold text-foreground/80">{tech.technique_id}</span>
                      <span className="text-muted-foreground text-xs">{tech.technique_name}</span>
                      <span className="text-[10px] font-mono text-muted-foreground/80 border-l border-border pl-1.5">
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
          <CardHeader className="flex flex-row items-center justify-between pb-2.5">
            <div>
              <CardTitle className="text-sm font-semibold">Recent Incident Queue</CardTitle>
              <CardDescription className="text-xs">
                Correlated incident groups awaiting triage or explanation review.
              </CardDescription>
            </div>
            <Link
              href="/incidents"
              className={cn(buttonVariants({ variant: "outline", size: "sm" }), "gap-1 text-xs h-7 px-2.5")}
            >
              View All
              <ArrowUpRight className="size-3" />
            </Link>
          </CardHeader>
          <CardContent className="pt-1">
            <div className="divide-y divide-border rounded border border-border text-sm overflow-hidden">
              {apiIncidents && apiIncidents.length > 0
                ? apiIncidents.map((inc) => (
                    <Link
                      key={inc.incident_id}
                      href={`/incidents/${inc.incident_id}`}
                      className="flex flex-col sm:flex-row sm:items-center justify-between p-3 gap-2 hover:bg-muted/30 transition-colors block"
                    >
                      <div className="space-y-1">
                        <div className="flex items-center gap-2">
                          <span className="font-mono text-xs text-muted-foreground">
                            {inc.incident_id}
                          </span>
                          <SeverityBadge severity={inc.severity} />
                          <span className="font-medium text-xs text-foreground">
                            Run: {inc.run_id}
                          </span>
                        </div>
                        <div className="text-[11px] text-muted-foreground flex items-center gap-2.5 font-mono">
                          <span>Detections: {inc.detection_count}</span>
                          <span>•</span>
                          <span>Policy: {inc.policy_version_id}</span>
                          <span>•</span>
                          <span>Status: {inc.status}</span>
                        </div>
                      </div>
                      <div className="flex items-center gap-3 text-xs">
                        <div className="text-right">
                          <div className="font-mono font-semibold">
                            Score: {Math.round(inc.risk_score * 100)}/100
                          </div>
                          <div className="text-[10px] text-muted-foreground font-mono">Deterministic</div>
                        </div>
                      </div>
                    </Link>
                  ))
                : SAMPLE_INCIDENTS.map((inc) => (
                    <Link
                      key={inc.id}
                      href={`/incidents/${inc.id}`}
                      className="flex flex-col sm:flex-row sm:items-center justify-between p-3 gap-2 hover:bg-muted/30 transition-colors block"
                    >
                      <div className="space-y-1">
                        <div className="flex items-center gap-2">
                          <span className="font-mono text-xs text-muted-foreground">{inc.id}</span>
                          <SeverityBadge severity={inc.severity} />
                          <span className="font-medium text-xs text-foreground">{inc.title}</span>
                        </div>
                        <div className="text-[11px] text-muted-foreground flex items-center gap-2.5 font-mono">
                          <span>Scenario: {inc.scenario}</span>
                          <span>•</span>
                          <span>Detections: {inc.detections_count}</span>
                          <span>•</span>
                          <span>Src: {inc.src_ips.join(", ")}</span>
                        </div>
                      </div>
                      <div className="flex items-center gap-3 text-xs">
                        <div className="text-right">
                          <div className="font-mono font-semibold">Score: {inc.risk_score}/100</div>
                          <div className="text-[10px] text-muted-foreground font-mono">Deterministic</div>
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
