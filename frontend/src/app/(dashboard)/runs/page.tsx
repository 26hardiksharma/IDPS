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
  const [inputPath, setInputPath] = useState("tests/pcaps/syn_flood_lab.pcap");
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
      toast.success(`Run completed: ${res.incidents_created} incidents, ${res.detections} detections`);
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
              <span className="size-1.5 rounded-full bg-emerald-500 animate-pulse" />
              Live Backend
            </span>
          )}
          <button
            onClick={() => refetch()}
            className="rounded-md border p-1 text-muted-foreground hover:text-foreground"
            title="Refresh Runs"
          >
            <RefreshCw className={isPending ? "size-3.5 animate-spin" : "size-3.5"} />
          </button>
          <Button
            size="sm"
            className="gap-1.5 text-xs"
            onClick={() => setOpenNewRun(true)}
          >
            <Plus className="size-3.5" />
            New Analysis Run
          </Button>
        </div>
      }
    >
      <div className="space-y-6">
        <Card>
          <CardHeader>
            <CardTitle className="text-base font-semibold">Configured Execution History</CardTitle>
            <CardDescription>
              Each run produces reproducible detections tracked against specific rule and model hashes.
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="rounded-md border overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead className="bg-muted/50 border-b font-medium text-muted-foreground">
                  <tr>
                    <th className="p-3">Run ID</th>
                    <th className="p-3">PCAP Target</th>
                    <th className="p-3">Profile / Mode</th>
                    <th className="p-3">Status</th>
                    <th className="p-3">Engines</th>
                    <th className="p-3">Started / Finished</th>
                    <th className="p-3">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border">
                  {apiRuns && apiRuns.length > 0 ? (
                    apiRuns.map((run: RunSummaryResponse) => (
                      <tr key={run.run_id} className="hover:bg-muted/30 transition-colors">
                        <td className="p-3 font-mono font-medium text-foreground">
                          <Link
                            href={`/runs/${run.run_id}`}
                            className="hover:underline text-blue-600 dark:text-blue-400"
                          >
                            {run.run_id}
                          </Link>
                        </td>
                        <td className="p-3">
                          <div className="font-medium text-foreground font-mono text-[11px]">
                            {run.input_path}
                          </div>
                          {run.scenario_id && (
                            <div className="text-[10px] text-muted-foreground">
                              Scenario: {run.scenario_id}
                            </div>
                          )}
                        </td>
                        <td className="p-3">
                          <div className="flex flex-col gap-1">
                            <span className="rounded bg-muted px-2 py-0.5 font-mono text-[10px] w-fit">
                              {run.run_profile}
                            </span>
                            <span className="rounded bg-blue-500/10 text-blue-700 dark:text-blue-400 px-1.5 py-0.5 font-mono text-[10px] w-fit uppercase">
                              {run.detector_mode}
                            </span>
                          </div>
                        </td>
                        <td className="p-3">
                          <RunStatusBadge status={run.status} />
                        </td>
                        <td className="p-3 text-[11px] text-muted-foreground font-mono">
                          <div>{run.snort_version || "Snort: local"}</div>
                          <div className="text-[10px] truncate max-w-[120px]">
                            Hash: {run.input_hash.slice(0, 10)}...
                          </div>
                        </td>
                        <td className="p-3 font-mono text-[11px] text-muted-foreground">
                          <div>
                            {run.started_at ? new Date(run.started_at).toLocaleTimeString() : "—"}
                          </div>
                          <div className="text-[10px]">
                            {run.finished_at ? new Date(run.finished_at).toLocaleTimeString() : "Pending"}
                          </div>
                        </td>
                        <td className="p-3">
                          <div className="flex items-center gap-1.5">
                            {run.status === "queued" && (
                              <Button
                                size="sm"
                                variant="outline"
                                className="h-7 text-[11px] gap-1"
                                disabled={executeMutation.isPending}
                                onClick={() => executeMutation.mutate(run.run_id)}
                              >
                                <Play className="size-3 text-emerald-600" />
                                Execute
                              </Button>
                            )}
                            <Link
                              href={`/runs/${run.run_id}`}
                              className="text-xs text-muted-foreground hover:text-foreground font-medium underline-offset-2 hover:underline ml-1"
                            >
                              Details
                            </Link>
                          </div>
                        </td>
                      </tr>
                    ))
                  ) : (
                    SAMPLE_RUNS.map((run) => (
                      <tr key={run.id} className="hover:bg-muted/30 transition-colors">
                        <td className="p-3 font-mono font-medium text-foreground">
                          <Link
                            href={`/runs/${run.id}`}
                            className="hover:underline text-blue-600 dark:text-blue-400"
                          >
                            {run.id}
                          </Link>
                        </td>
                        <td className="p-3">
                          <div className="font-medium text-foreground">{run.pcap_filename}</div>
                          <div className="text-[11px] text-muted-foreground font-mono">
                            Started: {new Date(run.started_at).toLocaleTimeString()}
                          </div>
                        </td>
                        <td className="p-3">
                          <span className="rounded bg-muted px-2 py-0.5 font-mono text-[11px]">
                            {run.run_profile}
                          </span>
                        </td>
                        <td className="p-3">
                          <RunStatusBadge status={run.status} />
                        </td>
                        <td className="p-3 text-[11px] text-muted-foreground">
                          <div>{run.snort_version || "Snort: N/A"}</div>
                          <div>{run.anomaly_model_version || "ML: N/A"}</div>
                        </td>
                        <td className="p-3 font-mono text-[11px] text-muted-foreground">
                          {new Date(run.started_at).toLocaleTimeString()}
                        </td>
                        <td className="p-3">
                          <Link
                            href={`/runs/${run.id}`}
                            className="text-xs text-muted-foreground hover:text-foreground font-medium underline-offset-2 hover:underline"
                          >
                            Details
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
              <label className="text-xs font-medium text-foreground">
                PCAP Input Path (Relative to PCAP_ROOT)
              </label>
              <input
                type="text"
                value={inputPath}
                onChange={(e) => setInputPath(e.target.value)}
                placeholder="e.g. tests/pcaps/syn_flood_lab.pcap"
                className="w-full rounded-md border border-input bg-background px-3 py-1.5 text-xs font-mono text-foreground focus:outline-hidden focus:ring-1 focus:ring-ring"
                required
              />
              <p className="text-[10px] text-muted-foreground">
                Must be an authorized file inside the local lab corpus root.
              </p>
            </div>

            <div className="space-y-1">
              <label className="text-xs font-medium text-foreground">Scenario Identifier (Optional)</label>
              <input
                type="text"
                value={scenarioId}
                onChange={(e) => setScenarioId(e.target.value)}
                placeholder="e.g. syn_flood_eval_v1"
                className="w-full rounded-md border border-input bg-background px-3 py-1.5 text-xs text-foreground focus:outline-hidden focus:ring-1 focus:ring-ring"
              />
            </div>

            <div className="grid grid-cols-2 gap-3">
              <div className="space-y-1">
                <label className="text-xs font-medium text-foreground">Detector Mode</label>
                <select
                  value={detectorMode}
                  onChange={(e) => setDetectorMode(e.target.value as DetectorMode)}
                  className="w-full rounded-md border border-input bg-background px-3 py-1.5 text-xs text-foreground focus:outline-hidden focus:ring-1 focus:ring-ring"
                >
                  <option value="hybrid">Hybrid (Snort + Anomaly)</option>
                  <option value="signature">Signature Only</option>
                  <option value="anomaly">Anomaly Only</option>
                </select>
              </div>

              <div className="space-y-1">
                <label className="text-xs font-medium text-foreground">Run Profile</label>
                <input
                  type="text"
                  value={runProfile}
                  onChange={(e) => setRunProfile(e.target.value)}
                  className="w-full rounded-md border border-input bg-background px-3 py-1.5 text-xs text-foreground focus:outline-hidden focus:ring-1 focus:ring-ring"
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
