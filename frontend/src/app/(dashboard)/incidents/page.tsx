"use client";

import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import Link from "next/link";
import { PageContainer } from "@/components/layout/page-container";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { SeverityBadge } from "@/components/shared/severity-badge";
import { IncidentStatusBadge, ValidationStatusBadge } from "@/components/shared/status-badge";
import { DemoDataBadge } from "@/components/shared/demo-badge";
import { SAMPLE_INCIDENTS } from "@/lib/fixtures/sample-data";
import { fetchIncidents } from "@/lib/api/services/incidents";
import { Cpu, RefreshCw, Search } from "lucide-react";
import { IncidentSummaryResponse, ValidationStatus } from "@/types/backend";
import { IncidentStatus } from "@/types/incident";

export default function IncidentsPage() {
  const [severityFilter, setSeverityFilter] = useState<string>("all");
  const [statusFilter, setStatusFilter] = useState<string>("all");
  const [searchQuery, setSearchQuery] = useState<string>("");

  const {
    data: apiIncidents,
    isPending,
    isError,
    refetch,
  } = useQuery({
    queryKey: [
      "incidents-list",
      severityFilter !== "all" ? severityFilter : undefined,
      statusFilter !== "all" ? statusFilter : undefined,
    ],
    queryFn: () =>
      fetchIncidents({
        severity: severityFilter !== "all" ? severityFilter : undefined,
        status: statusFilter !== "all" ? statusFilter : undefined,
        limit: 100,
      }),
    retry: 1,
  });

  const isDemo = Boolean(isError || !apiIncidents);

  // Filter sample or API incidents
  const incidents = apiIncidents && apiIncidents.length > 0 ? apiIncidents : null;

  return (
    <PageContainer
      title="Incident Queue"
      description="Review correlated security incidents, deterministic severity scores, linked evidence, and advisory explanation statuses."
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
            onClick={() => refetch()}
            className="rounded-md border p-1 text-muted-foreground hover:text-foreground"
            title="Refresh Incident Queue"
          >
            <RefreshCw className={isPending ? "size-3.5 animate-spin" : "size-3.5"} />
          </button>
        </div>
      }
    >
      <div className="space-y-6">
        {/* Core Architectural Invariant Note */}
        <div className="rounded-lg border border-blue-500/20 bg-blue-500/5 p-3 text-xs text-blue-900 dark:text-blue-200 flex items-start gap-2.5">
          <Cpu className="size-4 shrink-0 text-blue-600 dark:text-blue-400 mt-0.5" />
          <div>
            <span className="font-semibold">Security Invariant: </span>
            Detection results & deterministic risk scores are authoritative. LLM summaries from Ollama are advisory and validated against recorded evidence before display.
          </div>
        </div>

        <Card>
          <CardHeader className="flex flex-col sm:flex-row sm:items-center justify-between pb-3 gap-3">
            <div>
              <CardTitle className="text-base font-semibold">Correlated Security Incidents</CardTitle>
              <CardDescription>
                Grouped via explicit correlation policies based on time window, address tuples, and scenario rules.
              </CardDescription>
            </div>

            {/* Filter controls */}
            <div className="flex flex-wrap items-center gap-2 text-xs">
              <div className="flex items-center gap-1 border rounded-md px-2 py-1 bg-background">
                <Search className="size-3 text-muted-foreground" />
                <input
                  type="text"
                  placeholder="Search ID..."
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  className="bg-transparent outline-none w-24 sm:w-32 text-xs"
                />
              </div>

              <select
                value={severityFilter}
                onChange={(e) => setSeverityFilter(e.target.value)}
                className="rounded-md border border-input bg-background px-2 py-1 text-xs text-foreground focus:outline-hidden focus:ring-1 focus:ring-ring"
              >
                <option value="all">All Severities</option>
                <option value="critical">Critical</option>
                <option value="high">High</option>
                <option value="medium">Medium</option>
                <option value="low">Low</option>
              </select>

              <select
                value={statusFilter}
                onChange={(e) => setStatusFilter(e.target.value)}
                className="rounded-md border border-input bg-background px-2 py-1 text-xs text-foreground focus:outline-hidden focus:ring-1 focus:ring-ring"
              >
                <option value="all">All Statuses</option>
                <option value="open">Open</option>
                <option value="under_review">Under Review</option>
                <option value="acknowledged">Acknowledged</option>
                <option value="closed">Closed</option>
              </select>
            </div>
          </CardHeader>

          <CardContent>
            <div className="rounded-md border overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead className="bg-muted/50 border-b font-medium text-muted-foreground">
                  <tr>
                    <th className="p-3">Incident ID</th>
                    <th className="p-3">Run ID</th>
                    <th className="p-3">Severity</th>
                    <th className="p-3">Deterministic Score</th>
                    <th className="p-3">Review Status</th>
                    <th className="p-3">Detection Count</th>
                    <th className="p-3">GenAI Explanation</th>
                    <th className="p-3">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border">
                  {incidents ? (
                    incidents
                      .filter((inc) =>
                        searchQuery ? inc.incident_id.toLowerCase().includes(searchQuery.toLowerCase()) : true
                      )
                      .map((inc: IncidentSummaryResponse) => (
                        <tr key={inc.incident_id} className="hover:bg-muted/30 transition-colors">
                          <td className="p-3 font-mono font-medium text-foreground">
                            <Link
                              href={`/incidents/${inc.incident_id}`}
                              className="text-blue-600 dark:text-blue-400 hover:underline"
                            >
                              {inc.incident_id}
                            </Link>
                          </td>
                          <td className="p-3 font-mono text-[11px] text-muted-foreground">
                            <Link href={`/runs/${inc.run_id}`} className="hover:underline">
                              {inc.run_id}
                            </Link>
                          </td>
                          <td className="p-3">
                            <SeverityBadge severity={inc.severity} />
                          </td>
                          <td className="p-3">
                            <div className="font-mono font-bold text-sm">
                              {Math.round(inc.risk_score * 100)}
                              <span className="text-muted-foreground text-xs">/100</span>
                            </div>
                            <div className="text-[10px] text-muted-foreground">
                              Policy: {inc.policy_version_id}
                            </div>
                          </td>
                          <td className="p-3">
                            <IncidentStatusBadge status={inc.status as IncidentStatus} />
                          </td>
                          <td className="p-3 font-mono font-medium">
                            {inc.detection_count} detections
                          </td>
                          <td className="p-3">
                            {inc.explanation_status ? (
                              <ValidationStatusBadge status={inc.explanation_status as ValidationStatus} />
                            ) : (
                              <span className="text-muted-foreground text-xs">Not Requested</span>
                            )}
                          </td>
                          <td className="p-3">
                            <Link
                              href={`/incidents/${inc.incident_id}`}
                              className="text-xs font-semibold text-blue-600 dark:text-blue-400 hover:underline"
                            >
                              Inspect
                            </Link>
                          </td>
                        </tr>
                      ))
                  ) : (
                    SAMPLE_INCIDENTS.map((inc) => (
                      <tr key={inc.id} className="hover:bg-muted/30 transition-colors">
                        <td className="p-3 font-mono font-medium text-foreground">
                          <Link
                            href={`/incidents/${inc.id}`}
                            className="text-blue-600 dark:text-blue-400 hover:underline"
                          >
                            {inc.id}
                          </Link>
                        </td>
                        <td className="p-3 font-mono text-[11px] text-muted-foreground">
                          <Link href={`/runs/${inc.run_id}`} className="hover:underline">
                            {inc.run_id}
                          </Link>
                        </td>
                        <td className="p-3">
                          <SeverityBadge severity={inc.severity} />
                        </td>
                        <td className="p-3">
                          <div className="font-mono font-bold text-sm">
                            {inc.risk_score}
                            <span className="text-muted-foreground text-xs">/100</span>
                          </div>
                          <div className="text-[10px] text-muted-foreground font-mono">
                            Corrob: {inc.scoring_factors.multi_detector_corroboration ? "Yes" : "No"}
                          </div>
                        </td>
                        <td className="p-3">
                          <IncidentStatusBadge status={inc.status} />
                        </td>
                        <td className="p-3 font-mono">
                          {inc.detections_count} detections
                        </td>
                        <td className="p-3">
                          {inc.explanation_validation_status ? (
                            <ValidationStatusBadge status={inc.explanation_validation_status} />
                          ) : (
                            <span className="text-muted-foreground text-xs">Not Requested</span>
                          )}
                        </td>
                        <td className="p-3">
                          <Link
                            href={`/incidents/${inc.id}`}
                            className="text-xs font-semibold text-blue-600 dark:text-blue-400 hover:underline"
                          >
                            Inspect
                          </Link>
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          </CardContent>
        </Card>
      </div>
    </PageContainer>
  );
}
