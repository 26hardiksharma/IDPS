"use client";

import { useState } from "react";
import { useMutation } from "@tanstack/react-query";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { simulateWhatIfPolicy } from "@/lib/api/services/metrics";
import { Sliders, RotateCcw, TrendingUp, TrendingDown, ArrowRight, CheckCircle2, Play } from "lucide-react";
import { WhatIfPolicyResponse } from "@/types/backend";
import { toast } from "sonner";

export function WhatIfSandbox() {
  const [sigWeight, setSigWeight] = useState(40);
  const [anomWeight, setAnomWeight] = useState(30);
  const [corrobBonus, setCorrobBonus] = useState(10);
  const [critThresh, setCritThresh] = useState(75);
  const [highThresh, setHighThresh] = useState(50);
  const [medThresh, setMedThresh] = useState(25);

  const [result, setResult] = useState<WhatIfPolicyResponse | null>(null);

  const mutation = useMutation({
    mutationFn: () =>
      simulateWhatIfPolicy({
        signature_weight: sigWeight,
        anomaly_weight: anomWeight,
        corroboration_bonus: corrobBonus,
        critical_threshold: critThresh,
        high_threshold: highThresh,
        medium_threshold: medThresh,
      }),
    onSuccess: (data) => {
      setResult(data);
      toast.success(`Recalibrated ${data.total_evaluated} incidents with custom weights`);
    },
    onError: () => {
      toast.error("Failed to run policy what-if calibration");
    },
  });

  const handleReset = () => {
    setSigWeight(40);
    setAnomWeight(30);
    setCorrobBonus(10);
    setCritThresh(75);
    setHighThresh(50);
    setMedThresh(25);
    setResult(null);
  };

  const getSeverityBadgeClass = (sev: string) => {
    switch (sev.toLowerCase()) {
      case "critical":
        return "bg-red-500/10 text-red-700 dark:text-red-400 border-red-500/20";
      case "high":
        return "bg-orange-500/10 text-orange-700 dark:text-orange-400 border-orange-500/20";
      case "medium":
        return "bg-amber-500/10 text-amber-700 dark:text-amber-400 border-amber-500/20";
      default:
        return "bg-slate-500/10 text-slate-700 dark:text-slate-400 border-slate-500/20";
    }
  };

  return (
    <Card className="border-border">
      <CardHeader className="pb-3 border-b border-border bg-muted/20">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
          <div className="flex items-center gap-2">
            <div className="rounded-md border border-border bg-card p-1.5 text-muted-foreground">
              <Sliders className="size-4" />
            </div>
            <div>
              <CardTitle className="text-sm font-semibold">
                Interactive &quot;What-If&quot; Policy Calibration Sandbox
              </CardTitle>
              <CardDescription className="text-xs">
                Simulate how altering deterministic risk weights shifts severity distributions across stored incidents.
              </CardDescription>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <Button
              variant="outline"
              size="sm"
              onClick={handleReset}
              className="gap-1 text-xs h-7"
            >
              <RotateCcw className="size-3" />
              Reset Defaults
            </Button>
            <Button
              size="sm"
              onClick={() => mutation.mutate()}
              disabled={mutation.isPending}
              className="gap-1.5 text-xs h-7"
            >
              <Play className="size-3 fill-current" />
              {mutation.isPending ? "Evaluating..." : "Run Calibration"}
            </Button>
          </div>
        </div>
      </CardHeader>

      <CardContent className="p-4 space-y-6">
        {/* Sliders Grid */}
        <div className="grid gap-4 sm:grid-cols-3">
          <div className="rounded-lg border bg-muted/20 p-3 space-y-2">
            <div className="flex items-center justify-between text-xs">
              <span className="font-medium text-foreground">Signature Signal Weight</span>
              <span className="font-mono font-bold text-primary">{sigWeight} pts</span>
            </div>
            <input
              type="range"
              min={10}
              max={60}
              step={5}
              value={sigWeight}
              onChange={(e) => setSigWeight(Number(e.target.value))}
              className="w-full accent-primary cursor-pointer h-1.5 bg-muted rounded-lg"
            />
            <div className="text-[10px] text-muted-foreground flex justify-between">
              <span>Conservative (10)</span>
              <span>Default (40)</span>
              <span>Aggressive (60)</span>
            </div>
          </div>

          <div className="rounded-lg border border-border bg-card p-3 space-y-2">
            <div className="flex items-center justify-between text-xs">
              <span className="font-medium text-foreground">Anomaly Engine Weight</span>
              <span className="font-mono font-bold text-foreground">{anomWeight} pts</span>
            </div>
            <input
              type="range"
              min={10}
              max={60}
              step={5}
              value={anomWeight}
              onChange={(e) => setAnomWeight(Number(e.target.value))}
              className="w-full accent-primary cursor-pointer h-1.5 bg-muted rounded-lg"
            />
            <div className="text-[10px] text-muted-foreground flex justify-between font-mono">
              <span>Low (10)</span>
              <span>Default (30)</span>
              <span>High (60)</span>
            </div>
          </div>

          <div className="rounded-lg border border-border bg-card p-3 space-y-2">
            <div className="flex items-center justify-between text-xs">
              <span className="font-medium text-foreground">Corroboration Bonus</span>
              <span className="font-mono font-bold text-foreground">{corrobBonus} pts</span>
            </div>
            <input
              type="range"
              min={0}
              max={25}
              step={5}
              value={corrobBonus}
              onChange={(e) => setCorrobBonus(Number(e.target.value))}
              className="w-full accent-primary cursor-pointer h-1.5 bg-muted rounded-lg"
            />
            <div className="text-[10px] text-muted-foreground flex justify-between font-mono">
              <span>None (0)</span>
              <span>Default (10)</span>
              <span>High (25)</span>
            </div>
          </div>
        </div>

        {/* Results Comparison */}
        {result ? (
          <div className="space-y-4 pt-2 border-t border-border">
            <div className="flex items-center justify-between">
              <div className="text-xs font-semibold text-foreground flex items-center gap-1.5">
                <CheckCircle2 className="size-4 text-emerald-600 dark:text-emerald-400" />
                Recalibration Results ({result.total_evaluated} Incidents Evaluated)
              </div>
              <span className="text-[11px] font-mono text-muted-foreground">
                Authoritative Deterministic Arithmetic
              </span>
            </div>

            {/* Distribution Shift Bar */}
            <div className="grid gap-4 sm:grid-cols-2">
              <div className="rounded-md border border-border bg-card p-3 space-y-2">
                <div className="text-xs font-mono font-medium text-muted-foreground">
                  Baseline Policy Distribution
                </div>
                <div className="grid grid-cols-4 gap-2 text-center">
                  {(["critical", "high", "medium", "low"] as const).map((sev) => (
                    <div key={sev} className={`rounded p-1.5 border text-xs ${getSeverityBadgeClass(sev)}`}>
                      <div className="text-[10px] font-mono uppercase">{sev}</div>
                      <div className="text-base font-semibold font-mono">
                        {result.before_distribution[sev] || 0}
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              <div className="rounded-md border border-primary/25 bg-primary/5 p-3 space-y-2">
                <div className="text-xs font-mono font-medium text-foreground">
                  Calibrated Policy Distribution (Simulated)
                </div>
                <div className="grid grid-cols-4 gap-2 text-center">
                  {(["critical", "high", "medium", "low"] as const).map((sev) => (
                    <div key={sev} className={`rounded p-1.5 border text-xs ${getSeverityBadgeClass(sev)}`}>
                      <div className="text-[10px] font-mono uppercase">{sev}</div>
                      <div className="text-base font-semibold font-mono">
                        {result.after_distribution[sev] || 0}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </div>

            {/* Incident Score Shift List */}
            {result.score_shifts && result.score_shifts.length > 0 && (
              <div className="space-y-1.5">
                <div className="text-xs font-medium text-muted-foreground">
                  Sample Incident Rescoring Shifts
                </div>
                <div className="divide-y rounded-md border text-xs max-h-48 overflow-y-auto">
                  {result.score_shifts.map((shift) => (
                    <div
                      key={shift.incident_id}
                      className="p-2 flex items-center justify-between hover:bg-muted/30"
                    >
                      <span className="font-mono font-medium text-[11px] text-muted-foreground truncate max-w-[200px]">
                        {shift.incident_id}
                      </span>
                      <div className="flex items-center gap-3">
                        <span className={`rounded px-1.5 py-0.5 text-[10px] font-mono border ${getSeverityBadgeClass(shift.old_severity)}`}>
                          {shift.old_severity.toUpperCase()} ({shift.old_score})
                        </span>
                        <ArrowRight className="size-3 text-muted-foreground" />
                        <span className={`rounded px-1.5 py-0.5 text-[10px] font-mono border ${getSeverityBadgeClass(shift.new_severity)}`}>
                          {shift.new_severity.toUpperCase()} ({shift.new_score})
                        </span>
                        {shift.new_score > shift.old_score ? (
                          <TrendingUp className="size-3.5 text-rose-500" />
                        ) : shift.new_score < shift.old_score ? (
                          <TrendingDown className="size-3.5 text-blue-500" />
                        ) : null}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        ) : (
          <div className="rounded-md border border-dashed p-4 text-center text-xs text-muted-foreground">
            Adjust the sliders above and click <span className="font-medium text-foreground">&quot;Run Calibration&quot;</span> to see real-time impact on risk scores and severity classifications.
          </div>
        )}
      </CardContent>
    </Card>
  );
}
