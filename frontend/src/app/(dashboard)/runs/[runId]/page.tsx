"use client";

import { use } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import Link from "next/link";
import { PageContainer } from "@/components/layout/page-container";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { RunStatusBadge } from "@/components/shared/status-badge";
import { DemoDataBadge } from "@/components/shared/demo-badge";
import { fetchRunDetail, fetchRunEvidence, executeRun } from "@/lib/api/services/runs";
import { SAMPLE_RUNS } from "@/lib/fixtures/sample-data";
import { Button } from "@/components/ui/button";
import { ArrowLeft, Play, RefreshCw, FileText, Hash, Layers } from "lucide-react";
import { toast } from "sonner";

export default function RunDetailPage({ params }: { params: Promise<{ runId: string }> }) {
  const resolvedParams = use(params);
  const runId = resolvedParams.runId;
  const queryClient = useQueryClient();

  const {
    data: run,
    isPending: runPending,
    isError: runError,
    refetch: refetchRun,
  } = useQuery({
    queryKey: ["run-detail", runId],
    queryFn: () => fetchRunDetail(runId),
    retry: 1,
    refetchInterval: (query) => {
      // Auto-poll if running or queued
      const data = query.state.data;
      if (data && (data.status === "running" || data.status === "queued")) {
        return 3000;
      }
      return false;
    },
  });

  const {
    data: evidenceList,
    isPending: evidencePending,
  } = useQuery({
    queryKey: ["run-evidence", runId],
    queryFn: () => fetchRunEvidence(runId, 50, 0),
    retry: 1,
    enabled: Boolean(!runError && run),
  });

  const executeMutation = useMutation({
    mutationFn: () => executeRun(runId),
    onSuccess: (res) => {
      toast.success(`Run completed: ${res.incidents_created} incidents, ${res.detections} detections`);
      queryClient.invalidateQueries({ queryKey: ["run-detail", runId] });
      queryClient.invalidateQueries({ queryKey: ["run-evidence", runId] });
      queryClient.invalidateQueries({ queryKey: ["runs-list"] });
    },
    onError: (err: unknown) => {
      const axiosErr = err as { response?: { data?: { message?: string } } };
      toast.error(axiosErr?.response?.data?.message || "Execution failed");
    },
  });

  // Fallback demo fixture if run ID matches sample or API offline
  const sampleRun = SAMPLE_RUNS.find((r) => r.id === runId) || SAMPLE_RUNS[0];
  const isDemo = Boolean(runError || !run);

  const displayRun = run || {
    run_id: sampleRun.id,
    status: sampleRun.status,
    input_path: sampleRun.pcap_filename,
    input_hash: sampleRun.file_hash,
    scenario_id: "lab_scenario_syn_flood",
    run_profile: sampleRun.run_profile,
    detector_mode: "hybrid",
    snort_version: sampleRun.snort_version || "Snort 3.1.75.0",
    error_summary: null,
    started_at: sampleRun.started_at,
    finished_at: sampleRun.finished_at,
    created_at: sampleRun.started_at,
  };

  return (
    <PageContainer
      title={`Run Detail: ${runId}`}
      description="Inspect execution timeline, engine configurations, input cryptographic verification, and observed evidence packets."
      actions={
        <div className="flex items-center gap-2">
          <Link href="/runs">
            <Button variant="outline" size="sm" className="gap-1 text-xs">
              <ArrowLeft className="size-3.5" />
              Back to Runs
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
            onClick={() => refetchRun()}
            className="rounded-md border p-1 text-muted-foreground hover:text-foreground"
            title="Refresh Run"
          >
            <RefreshCw className={runPending ? "size-3.5 animate-spin" : "size-3.5"} />
          </button>
          {displayRun.status === "queued" && (
            <Button
              size="sm"
              className="gap-1.5 text-xs"
              disabled={executeMutation.isPending}
              onClick={() => executeMutation.mutate()}
            >
              <Play className="size-3.5 text-emerald-500" />
              Execute Pipeline
            </Button>
          )}
        </div>
      }
    >
      <div className="space-y-6">
        {/* Run Metadata Grid */}
        <div className="grid gap-4 md:grid-cols-3">
          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-xs font-medium text-muted-foreground uppercase flex items-center gap-1.5">
                <Layers className="size-3.5 text-blue-500" />
                Pipeline Status
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-2">
              <div className="flex items-center gap-2">
                <RunStatusBadge status={displayRun.status} />
                <span className="font-mono text-xs uppercase rounded bg-muted px-2 py-0.5">
                  {displayRun.detector_mode}
                </span>
              </div>
              <p className="text-xs text-muted-foreground font-mono">
                Profile: {displayRun.run_profile}
              </p>
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-xs font-medium text-muted-foreground uppercase flex items-center gap-1.5">
                <FileText className="size-3.5 text-amber-500" />
                Input Target
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-1">
              <div className="font-mono text-xs font-medium text-foreground truncate">
                {displayRun.input_path}
              </div>
              <div className="text-[11px] text-muted-foreground">
                Scenario: {displayRun.scenario_id || "Unspecified"}
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-xs font-medium text-muted-foreground uppercase flex items-center gap-1.5">
                <Hash className="size-3.5 text-emerald-500" />
                Cryptographic Provenance
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-1">
              <div className="font-mono text-[11px] text-muted-foreground truncate" title={displayRun.input_hash}>
                SHA-256: {displayRun.input_hash}
              </div>
              <div className="text-[11px] text-muted-foreground">
                Snort Engine: {displayRun.snort_version || "Snort 3.1.75"}
              </div>
            </CardContent>
          </Card>
        </div>

        {/* Execution Timeline Card */}
        <Card>
          <CardHeader>
            <CardTitle className="text-base font-semibold">Execution Timeline</CardTitle>
            <CardDescription>
              Reproducible timestamps for pipeline start, completion, and duration.
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="grid gap-4 sm:grid-cols-3 text-xs">
              <div className="rounded-md border p-3">
                <div className="text-muted-foreground">Created At</div>
                <div className="font-mono font-medium text-foreground mt-1">
                  {new Date(displayRun.created_at).toLocaleString()}
                </div>
              </div>

              <div className="rounded-md border p-3">
                <div className="text-muted-foreground">Started At</div>
                <div className="font-mono font-medium text-foreground mt-1">
                  {displayRun.started_at ? new Date(displayRun.started_at).toLocaleString() : "Not started"}
                </div>
              </div>

              <div className="rounded-md border p-3">
                <div className="text-muted-foreground">Finished At</div>
                <div className="font-mono font-medium text-foreground mt-1">
                  {displayRun.finished_at ? new Date(displayRun.finished_at).toLocaleString() : "In progress / Pending"}
                </div>
              </div>
            </div>

            {displayRun.error_summary && (
              <div className="mt-4 rounded-md border border-destructive/30 bg-destructive/10 p-3 text-xs text-destructive">
                <div className="font-semibold">Pipeline Error Summary:</div>
                <div className="font-mono mt-1">{displayRun.error_summary}</div>
              </div>
            )}
          </CardContent>
        </Card>

        {/* Evidence Records Card */}
        <Card>
          <CardHeader>
            <CardTitle className="text-base font-semibold">Captured Evidence Records</CardTitle>
            <CardDescription>
              Structured flow and packet evidence records linked to this run (authoritative ground truth).
            </CardDescription>
          </CardHeader>
          <CardContent>
            {evidenceList && evidenceList.length > 0 ? (
              <div className="rounded-md border overflow-x-auto">
                <table className="w-full text-left text-xs">
                  <thead className="bg-muted/50 border-b font-medium text-muted-foreground">
                    <tr>
                      <th className="p-3">Evidence ID</th>
                      <th className="p-3">Source Type</th>
                      <th className="p-3">Protocol</th>
                      <th className="p-3">Source & Destination</th>
                      <th className="p-3">Event Time</th>
                      <th className="p-3">Content Hash</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-border">
                    {evidenceList.map((ev) => (
                      <tr key={ev.evidence_id} className="hover:bg-muted/30 transition-colors">
                        <td className="p-3 font-mono font-medium">{ev.evidence_id}</td>
                        <td className="p-3">
                          <span className="rounded bg-muted px-1.5 py-0.5 text-[10px] font-mono uppercase">
                            {ev.source_type}
                          </span>
                        </td>
                        <td className="p-3 font-mono">{ev.protocol || "IP"}</td>
                        <td className="p-3 font-mono text-[11px]">
                          <div>{ev.src_ip || "—"}:{ev.src_port || ""}</div>
                          <div className="text-muted-foreground">→ {ev.dst_ip || "—"}:{ev.dst_port || ""}</div>
                        </td>
                        <td className="p-3 font-mono text-[11px] text-muted-foreground">
                          {ev.event_time || new Date(ev.created_at).toLocaleTimeString()}
                        </td>
                        <td className="p-3 font-mono text-[10px] text-muted-foreground max-w-[120px] truncate" title={ev.content_hash || ""}>
                          {ev.content_hash || "—"}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : (
              <div className="rounded-md border border-dashed p-8 text-center text-xs text-muted-foreground">
                {evidencePending
                  ? "Loading captured evidence records..."
                  : "No evidence records captured for this run yet, or execution is pending."}
              </div>
            )}
          </CardContent>
        </Card>
      </div>
    </PageContainer>
  );
}
