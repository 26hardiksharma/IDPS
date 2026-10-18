"use client";

import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import Link from "next/link";
import { PageContainer } from "@/components/layout/page-container";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { RunStatusBadge } from "@/components/shared/status-badge";
import { DemoDataBadge } from "@/components/shared/demo-badge";
import { SAMPLE_RUNS } from "@/lib/fixtures/sample-data";
import { fetchRuns, createRun, executeRun } from "@/lib/api/services/runs";
import { Plus, Play, RefreshCw } from "lucide-react";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
  DialogFooter,
} from "@/components/ui/dialog";
import { toast } from "sonner";
import { CreateRunRequest, RunSummaryResponse, DetectorMode } from "@/types/backend";

export default function AnalysisRunsPage() {
  const queryClient = useQueryClient();
  const [openNewRun, setOpenNewRun] = useState(false);
  const [inputPath, setInputPath] = useState("data/pcaps/dns_anomaly.pcap");
  const [scenarioId, setScenarioId] = useState("scenario_syn_flood_01");
  const [detectorMode, setDetectorMode] = useState<DetectorMode>("hybrid");
  const [runProfile, setRunProfile] = useState("default");

  const {
    data: apiRuns,
    isPending,
    isError,
    refetch,
  } = useQuery({
    queryKey: ["runs-list"],
    queryFn: () => fetchRuns(50, 0),
    retry: 1,
  });

  const createMutation = useMutation({
    mutationFn: (data: CreateRunRequest) => createRun(data),
    onSuccess: (newRun) => {
      toast.success(`Analysis run queued (${newRun.run_id})`);
      queryClient.invalidateQueries({ queryKey: ["runs-list"] });
      setOpenNewRun(false);
      // Auto-trigger execute
      executeMutation.mutate(newRun.run_id);
    },
    onError: (err: unknown) => {
      const axiosErr = err as { response?: { data?: { message?: string } } };
      toast.error(axiosErr?.response?.data?.message || "Failed to create analysis run");
    },
  });

  const executeMutation = useMutation({
    mutationFn: (runId: string) => executeRun(runId),
    onSuccess: (res) => {
      toast.success(
        `Run completed: ${res.incidents_created} incidents, ${res.detections} detections`
      );
      queryClient.invalidateQueries({ queryKey: ["runs-list"] });
      queryClient.invalidateQueries({ queryKey: ["metrics-overview"] });
    },
    onError: (err: unknown) => {
      const axiosErr = err as { response?: { data?: { message?: string } } };
      toast.error(axiosErr?.response?.data?.message || "Run execution encountered errors");
    },
  });

  const isDemo = Boolean(isError || !apiRuns);

  const handleCreateRun = (e: React.FormEvent) => {
    e.preventDefault();
    if (!inputPath.trim()) {
      toast.error("Please provide a valid relative PCAP path");
      return;
    }
    createMutation.mutate({
      input_path: inputPath.trim(),
      scenario_id: scenarioId.trim() || undefined,
      run_profile: runProfile,
      detector_mode: detectorMode,
    });
  };

  return (
    <PageContainer
      title="Analysis Runs"
      description="Manage and inspect PCAP analysis executions, pipeline states, input file hashes, and detector engine versions."
      actions={
        <div className="flex items-center gap-2">
          {isDemo ? (
            <DemoDataBadge />
          ) : (
            <span className="inline-flex items-center gap-1.5 rounded-md border border-emerald-500/30 bg-emerald-500/10 px-2 py-0.5 text-xs font-medium text-emerald-700 dark:text-emerald-400">
              <span className="size-1.5 animate-pulse rounded-full bg-emerald-500" />
              Live Backend
            </span>
          )}
          <button
            onClick={() => refetch()}
            className="text-muted-foreground hover:text-foreground rounded-md border p-1"
            title="Refresh Runs"
          >
            <RefreshCw className={isPending ? "size-3.5 animate-spin" : "size-3.5"} />
          </button>
          <Button size="sm" className="gap-1.5 text-xs" onClick={() => setOpenNewRun(true)}>
            <Plus className="size-3.5" />
            New Analysis Run
          </Button>
        </div>
      }
    >
      <div className="space-y-5">
        <Card>
          <CardHeader className="pb-2.5">
            <CardTitle className="text-sm font-semibold">Configured Execution History</CardTitle>
            <CardDescription className="text-xs">
              Reproducible detections tracked against specific rule and model hashes.
            </CardDescription>
          </CardHeader>
          <CardContent className="pt-1">
            <div className="overflow-x-auto rounded border border-border">
              <table className="w-full text-left text-xs">
                <thead className="bg-muted/30 text-muted-foreground border-b border-border font-mono text-[11px]">
                  <tr>
                    <th className="py-2.5 px-3 font-medium">Run ID</th>
                    <th className="py-2.5 px-3 font-medium">PCAP Target</th>
                    <th className="py-2.5 px-3 font-medium">Mode</th>
                    <th className="py-2.5 px-3 font-medium">Status</th>
                    <th className="py-2.5 px-3 font-medium">Engines / Hash</th>
                    <th className="py-2.5 px-3 font-medium">Execution Window</th>
                    <th className="py-2.5 px-3 font-medium text-right">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-border divide-y">
                  {apiRuns && apiRuns.length > 0
                    ? apiRuns.map((run: RunSummaryResponse) => (
                        <tr key={run.run_id} className="hover:bg-muted/20 transition-colors">
                          <td className="text-foreground py-2.5 px-3 font-mono font-medium">
                            <Link
                              href={`/runs/${run.run_id}`}
                              className="text-foreground hover:underline font-mono"
                            >
                              {run.run_id}
                            </Link>
                          </td>
                          <td className="py-2.5 px-3">
                            <div className="text-foreground font-mono text-[11px]">
                              {run.input_path}
                            </div>
                            {run.scenario_id && (
                              <div className="text-muted-foreground text-[10px] font-mono">
                                Scenario: {run.scenario_id}
                              </div>
                            )}
                          </td>
                          <td className="py-2.5 px-3">
                            <div className="flex items-center gap-1.5 font-mono text-[10px]">
                              <span className="rounded border border-border bg-muted/40 px-1.5 py-0.2 text-muted-foreground uppercase">
                                {run.detector_mode}
                              </span>
                            </div>
                          </td>
                          <td className="py-2.5 px-3">
                            <RunStatusBadge status={run.status} />
                          </td>
                          <td className="text-muted-foreground py-2.5 px-3 font-mono text-[11px]">
                            <div>{run.snort_version || "Snort: local"}</div>
                            <div className="max-w-[120px] truncate text-[10px] text-muted-foreground/80">
                              {run.input_hash.slice(0, 10)}...
                            </div>
                          </td>
                          <td className="text-muted-foreground py-2.5 px-3 font-mono text-[11px]">
                            <div>
                              {run.started_at ? new Date(run.started_at).toLocaleTimeString() : "—"}
                            </div>
                            <div className="text-[10px] text-muted-foreground/80">
                              {run.finished_at
                                ? new Date(run.finished_at).toLocaleTimeString()
                                : "Pending"}
                            </div>
                          </td>
                          <td className="py-2.5 px-3 text-right">
                            <div className="flex items-center justify-end gap-1.5">
                              {run.status === "queued" && (
                                <Button
                                  size="sm"
                                  variant="outline"
                                  className="h-6 gap-1 text-[11px] px-2"
                                  disabled={executeMutation.isPending}
                                  onClick={() => executeMutation.mutate(run.run_id)}
                                >
                                  <Play className="size-3 text-foreground/80" />
                                  Execute
                                </Button>
                              )}
                              <Link
                                href={`/runs/${run.run_id}`}
                                className="text-muted-foreground hover:text-foreground text-xs font-medium hover:underline"
                              >
                                Details
                              </Link>
                            </div>
                          </td>
                        </tr>
                      ))
                    : SAMPLE_RUNS.map((run) => (
                        <tr key={run.id} className="hover:bg-muted/20 transition-colors">
                          <td className="text-foreground py-2.5 px-3 font-mono font-medium">
                            <Link
                              href={`/runs/${run.id}`}
                              className="text-foreground hover:underline font-mono"
                            >
                              {run.id}
                            </Link>
                          </td>
                          <td className="p-3">
                            <div className="text-foreground font-medium">{run.pcap_filename}</div>
                            <div className="text-muted-foreground font-mono text-[11px]">
                              Started: {new Date(run.started_at).toLocaleTimeString()}
                            </div>
                          </td>
                          <td className="p-3">
                            <span className="bg-muted rounded px-2 py-0.5 font-mono text-[11px]">
                              {run.run_profile}
                            </span>
                          </td>
                          <td className="p-3">
                            <RunStatusBadge status={run.status} />
                          </td>
                          <td className="text-muted-foreground p-3 text-[11px]">
                            <div>{run.snort_version || "Snort: N/A"}</div>
                            <div>{run.anomaly_model_version || "ML: N/A"}</div>
                          </td>
                          <td className="text-muted-foreground p-3 font-mono text-[11px]">
                            {new Date(run.started_at).toLocaleTimeString()}
                          </td>
                          <td className="p-3">
                            <Link
                              href={`/runs/${run.id}`}
                              className="text-muted-foreground hover:text-foreground text-xs font-medium underline-offset-2 hover:underline"
                            >
                              Details
                            </Link>
                          </td>
                        </tr>
                      ))}
                </tbody>
              </table>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* New Analysis Run Dialog */}
      <Dialog open={openNewRun} onOpenChange={setOpenNewRun}>
        <DialogContent className="sm:max-w-md">
          <DialogHeader>
            <DialogTitle>Configure New Analysis Run</DialogTitle>
            <DialogDescription>
              Queue an analysis execution over an approved PCAP dataset or lab test scenario.
            </DialogDescription>
          </DialogHeader>

          <form onSubmit={handleCreateRun} className="space-y-4 pt-2">
            <div className="space-y-1">
              <label className="text-foreground text-xs font-medium">
                PCAP Input Path (Relative to PCAP_ROOT)
              </label>
              <input
                type="text"
                value={inputPath}
                onChange={(e) => setInputPath(e.target.value)}
                placeholder="e.g. data/pcaps/dns_anomaly.pcap"
                className="border-input bg-background text-foreground focus:ring-ring w-full rounded-md border px-3 py-1.5 font-mono text-xs focus:ring-1 focus:outline-hidden"
                required
              />
              <p className="text-muted-foreground text-[10px]">
                Must be an authorized file inside the local lab corpus root.
              </p>
            </div>

            <div className="space-y-1">
              <label className="text-foreground text-xs font-medium">
                Scenario Identifier (Optional)
              </label>
              <input
                type="text"
                value={scenarioId}
                onChange={(e) => setScenarioId(e.target.value)}
                placeholder="e.g. syn_flood_eval_v1"
                className="border-input bg-background text-foreground focus:ring-ring w-full rounded-md border px-3 py-1.5 text-xs focus:ring-1 focus:outline-hidden"
              />
            </div>

            <div className="grid grid-cols-2 gap-3">
              <div className="space-y-1">
                <label className="text-foreground text-xs font-medium">Detector Mode</label>
                <select
                  value={detectorMode}
                  onChange={(e) => setDetectorMode(e.target.value as DetectorMode)}
                  className="border-input bg-background text-foreground focus:ring-ring w-full rounded-md border px-3 py-1.5 text-xs focus:ring-1 focus:outline-hidden"
                >
                  <option value="hybrid">Hybrid (Snort + Anomaly)</option>
                  <option value="signature">Signature Only</option>
                  <option value="anomaly">Anomaly Only</option>
                </select>
              </div>

              <div className="space-y-1">
                <label className="text-foreground text-xs font-medium">Run Profile</label>
                <input
                  type="text"
                  value={runProfile}
                  onChange={(e) => setRunProfile(e.target.value)}
                  className="border-input bg-background text-foreground focus:ring-ring w-full rounded-md border px-3 py-1.5 text-xs focus:ring-1 focus:outline-hidden"
                />
              </div>
            </div>

            <DialogFooter className="pt-2">
              <Button
                type="button"
                variant="outline"
                size="sm"
                onClick={() => setOpenNewRun(false)}
              >
                Cancel
              </Button>
              <Button
                type="submit"
                size="sm"
                disabled={createMutation.isPending}
                className="gap-1.5"
              >
                {createMutation.isPending ? "Creating..." : "Queue & Execute"}
              </Button>
            </DialogFooter>
          </form>
        </DialogContent>
      </Dialog>
    </PageContainer>
  );
}
