"use client";

import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { PageContainer } from "@/components/layout/page-container";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { SimulationBanner } from "@/components/shared/simulation-banner";
import { DemoDataBadge } from "@/components/shared/demo-badge";
import { SAMPLE_SIMULATIONS } from "@/lib/fixtures/sample-data";
import { fetchSimulations, submitResponseSimulation } from "@/lib/api/services/simulations";
import { fetchIncidents } from "@/lib/api/services/incidents";
import { Button } from "@/components/ui/button";
import { toast } from "sonner";
import { TerminalSquare, History, RefreshCw, ShieldCheck } from "lucide-react";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
  DialogFooter,
} from "@/components/ui/dialog";

export default function ResponseSimulationPage() {
  const queryClient = useQueryClient();
  const [selectedIncidentId, setSelectedIncidentId] = useState("");
  const [targetScope, setTargetScope] = useState("192.0.2.45 / 60s");
  const [selectedAction, setSelectedAction] = useState("simulate_source_isolation");
  const [actorName] = useState("analyst_local");
  const [confirmOpen, setConfirmOpen] = useState(false);

  const {
    data: apiSimulations,
    isPending: simPending,
    isError: simError,
    refetch: refetchSimulations,
  } = useQuery({
    queryKey: ["simulations-list"],
    queryFn: () => fetchSimulations(undefined, 50, 0),
    retry: 1,
  });

  const { data: incidentsList } = useQuery({
    queryKey: ["incidents-for-simulation"],
    queryFn: () => fetchIncidents({ limit: 20 }),
    retry: 1,
  });

  const isDemo = Boolean(simError || !apiSimulations);

  const simMutation = useMutation({
    mutationFn: () => {
      const incId = selectedIncidentId || (incidentsList?.[0]?.incident_id || "inc_sample_01");
      return submitResponseSimulation(incId, {
        proposed_action: selectedAction,
        action_target: targetScope,
        action_scope: "host",
        actor: actorName,
      });
    },
    onSuccess: (data) => {
      toast.success(
        `Simulation audit recorded (ID: ${data.simulation_id}). SAFETY: No network changes made.`
      );
      queryClient.invalidateQueries({ queryKey: ["simulations-list"] });
      queryClient.invalidateQueries({ queryKey: ["metrics-overview"] });
      setConfirmOpen(false);
    },
    onError: (err: unknown) => {
      const axiosErr = err as { response?: { data?: { message?: string } } };
      toast.error(axiosErr?.response?.data?.message || "Simulation failed to record in audit store");
      setConfirmOpen(false);
    },
  });

  const handleExecuteClick = (e: React.FormEvent) => {
    e.preventDefault();
    setConfirmOpen(true);
  };

  const confirmAndSubmit = () => {
    simMutation.mutate();
  };

  return (
    <PageContainer
      title="Response Simulation"
      description="Simulate containment and mitigation policies in an isolated audit sandbox without modifying active network controls."
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
            onClick={() => refetchSimulations()}
            className="rounded-md border p-1 text-muted-foreground hover:text-foreground"
            title="Refresh Simulation Audit"
          >
            <RefreshCw className={simPending ? "size-3.5 animate-spin" : "size-3.5"} />
          </button>
        </div>
      }
    >
      <div className="space-y-6">
        {/* Mandatory Permanent Security Disclaimer Banner */}
        <SimulationBanner variant="warning" />

        {/* Simulation Execution Card */}
        <Card>
          <CardHeader>
            <CardTitle className="text-base font-semibold">Simulate Mitigation Action</CardTitle>
            <CardDescription>
              Record an analyst decision and test proposed containment actions. All executions are strictly advisory audit records.
            </CardDescription>
          </CardHeader>
          <CardContent>
            <form onSubmit={handleExecuteClick} className="space-y-4">
              <div className="grid gap-4 sm:grid-cols-3">
                <div className="space-y-1">
                  <label className="text-xs font-medium text-foreground">Target Incident</label>
                  <select
                    value={selectedIncidentId}
                    onChange={(e) => setSelectedIncidentId(e.target.value)}
                    className="w-full rounded-md border border-input bg-background px-3 py-1.5 text-xs text-foreground focus:outline-hidden focus:ring-1 focus:ring-ring"
                  >
                    <option value="">Select an incident (default)</option>
                    {incidentsList?.map((inc) => (
                      <option key={inc.incident_id} value={inc.incident_id}>
                        {inc.incident_id} ({inc.severity})
                      </option>
                    ))}
                  </select>
                </div>

                <div className="space-y-1">
                  <label className="text-xs font-medium text-foreground">Simulation Action</label>
                  <select
                    value={selectedAction}
                    onChange={(e) => setSelectedAction(e.target.value)}
                    className="w-full rounded-md border border-input bg-background px-3 py-1.5 text-xs text-foreground focus:outline-hidden focus:ring-1 focus:ring-ring"
                  >
                    <option value="simulate_source_isolation">Simulate Source IP Isolation (Drop)</option>
                    <option value="simulate_rate_limit">Simulate Rate Limiting (Token Bucket)</option>
                    <option value="simulate_port_quarantine">Simulate Port Quarantine</option>
                  </select>
                </div>

                <div className="space-y-1">
                  <label className="text-xs font-medium text-foreground">Target Scope</label>
                  <input
                    type="text"
                    value={targetScope}
                    onChange={(e) => setTargetScope(e.target.value)}
                    placeholder="e.g. 192.0.2.45 / 60s"
                    className="w-full rounded-md border border-input bg-background px-3 py-1.5 text-xs text-foreground font-mono focus:outline-hidden focus:ring-1 focus:ring-ring"
                    required
                  />
                </div>
              </div>

              <div className="flex items-center justify-between pt-2">
                <span className="text-[11px] text-muted-foreground font-mono">
                  State invariant: simulated_only = true
                </span>
                <Button type="submit" size="sm" className="text-xs gap-1.5">
                  <TerminalSquare className="size-3.5" />
                  Execute Simulation
                </Button>
              </div>
            </form>
          </CardContent>
        </Card>

        {/* Audit Trail History */}
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <History className="size-4 text-muted-foreground" />
              <span>Simulated Response Audit Trail</span>
            </CardTitle>
            <CardDescription className="text-xs">
              Persistent log of simulated actions, actors, and safety audit assertions.
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="rounded-md border border-border overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead className="bg-muted/40 border-b border-border font-medium text-muted-foreground font-mono">
                  <tr>
                    <th className="py-2.5 px-3 font-medium">Audit ID</th>
                    <th className="py-2.5 px-3 font-medium">Incident ID</th>
                    <th className="py-2.5 px-3 font-medium">Proposed Action</th>
                    <th className="py-2.5 px-3 font-medium">Target Scope</th>
                    <th className="py-2.5 px-3 font-medium">Safety Mode</th>
                    <th className="py-2.5 px-3 font-medium">Policy Decision</th>
                    <th className="py-2.5 px-3 font-medium">Timestamp</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border">
                  {apiSimulations && apiSimulations.length > 0 ? (
                    apiSimulations.map((sim) => (
                      <tr key={sim.simulation_id} className="hover:bg-muted/30 transition-colors">
                        <td className="py-2.5 px-3 font-mono font-medium text-foreground">{sim.simulation_id}</td>
                        <td className="py-2.5 px-3 font-mono text-[11px] text-foreground hover:underline">
                          {sim.incident_id}
                        </td>
                        <td className="py-2.5 px-3 font-medium text-foreground">{sim.proposed_action}</td>
                        <td className="py-2.5 px-3 font-mono text-[11px] text-muted-foreground">{sim.action_target || "—"}</td>
                        <td className="py-2.5 px-3">
                          <span className="inline-flex items-center rounded border border-amber-500/25 bg-amber-500/10 px-1.5 py-0.5 font-mono text-[10px] text-amber-800 dark:text-amber-300 font-medium uppercase tracking-wide">
                            Simulation Only
                          </span>
                        </td>
                        <td className="py-2.5 px-3 font-mono text-[11px] text-muted-foreground">
                          {sim.policy_decision || "simulated_accepted"}
                        </td>
                        <td className="py-2.5 px-3 font-mono text-[11px] text-muted-foreground">
                          {sim.created_at ? new Date(sim.created_at).toLocaleTimeString() : "—"}
                        </td>
                      </tr>
                    ))
                  ) : (
                    SAMPLE_SIMULATIONS.map((sim) => (
                      <tr key={sim.id} className="hover:bg-muted/30 transition-colors">
                        <td className="py-2.5 px-3 font-mono font-medium text-foreground">{sim.id}</td>
                        <td className="py-2.5 px-3 font-mono text-[11px] text-foreground hover:underline">
                          {sim.incident_id}
                        </td>
                        <td className="py-2.5 px-3 font-medium text-foreground">{sim.action}</td>
                        <td className="py-2.5 px-3 font-mono text-[11px] text-muted-foreground">{sim.target_scope}</td>
                        <td className="py-2.5 px-3">
                          <span className="inline-flex items-center rounded border border-amber-500/25 bg-amber-500/10 px-1.5 py-0.5 font-mono text-[10px] text-amber-800 dark:text-amber-300 font-medium uppercase tracking-wide">
                            Simulation Only
                          </span>
                        </td>
                        <td className="py-2.5 px-3 font-mono text-[11px] text-muted-foreground">
                          simulated_accepted
                        </td>
                        <td className="py-2.5 px-3 font-mono text-[11px] text-muted-foreground">
                          {new Date(sim.timestamp).toLocaleTimeString()}
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

      {/* Confirmation Dialog */}
      <Dialog open={confirmOpen} onOpenChange={setConfirmOpen}>
        <DialogContent className="sm:max-w-md">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2 text-base font-semibold">
              <ShieldCheck className="size-4 text-muted-foreground" />
              Confirm Response Simulation
            </DialogTitle>
            <DialogDescription className="text-xs">
              This action will evaluate the proposed response against simulation policies and write an immutable audit record.
            </DialogDescription>
          </DialogHeader>

          <div className="rounded-md border border-amber-500/25 bg-amber-500/5 p-3 text-xs text-foreground/90 font-mono space-y-1">
            <div className="font-semibold text-amber-800 dark:text-amber-300">Safety Boundary Affirmation:</div>
            <p>
              No active host or network changes will be made. Iptables, packet routing, and network interfaces remain untouched.
            </p>
          </div>

          <div className="text-xs space-y-1 py-1 font-mono text-muted-foreground">
            <div>Action: <span className="text-foreground">{selectedAction}</span></div>
            <div>Target: <span className="text-foreground">{targetScope}</span></div>
          </div>

          <DialogFooter className="pt-2">
            <Button
              type="button"
              variant="outline"
              size="sm"
              onClick={() => setConfirmOpen(false)}
            >
              Cancel
            </Button>
            <Button
              size="sm"
              disabled={simMutation.isPending}
              onClick={confirmAndSubmit}
              className="gap-1.5"
            >
              {simMutation.isPending ? "Recording..." : "Confirm & Record"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </PageContainer>
  );
}
