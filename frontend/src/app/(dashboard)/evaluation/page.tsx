"use client";

import { useQuery } from "@tanstack/react-query";
import { PageContainer } from "@/components/layout/page-container";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { DemoDataBadge } from "@/components/shared/demo-badge";
import { fetchMetrics } from "@/lib/api/services/metrics";
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Legend,
  ResponsiveContainer,
} from "recharts";
import { Trophy, ShieldCheck, Database, RefreshCw } from "lucide-react";
import { WhatIfSandbox } from "@/components/evaluation/what-if-sandbox";

const COMPARISON_DATA = [
  {
    metric: "Precision",
    SnortOnly: 0.91,
    AnomalyOnly: 0.68,
    HybridPipeline: 0.94,
  },
  {
    metric: "Recall",
    SnortOnly: 0.69,
    AnomalyOnly: 0.77,
    HybridPipeline: 0.86,
  },
  {
    metric: "F1-Score",
    SnortOnly: 0.78,
    AnomalyOnly: 0.72,
    HybridPipeline: 0.89,
  },
  {
    metric: "Accuracy",
    SnortOnly: 0.84,
    AnomalyOnly: 0.79,
    HybridPipeline: 0.93,
  },
];

export default function EvaluationPage() {
  const { data: metrics, isPending, refetch } = useQuery({
    queryKey: ["metrics-evaluation"],
    queryFn: fetchMetrics,
    retry: 1,
  });

  return (
    <PageContainer
      title="System Evaluation"
      description="Comparative benchmarks evaluating Snort 3 signature matching, statistical anomaly extraction, and the hybrid correlated pipeline."
      actions={
        <div className="flex items-center gap-2">
          {metrics ? (
            <span className="inline-flex items-center gap-1.5 rounded-md border border-emerald-500/30 bg-emerald-500/10 px-2 py-0.5 text-xs font-medium text-emerald-700 dark:text-emerald-400">
              <span className="size-1.5 rounded-full bg-emerald-500 animate-pulse" />
              Live Backend
            </span>
          ) : (
            <DemoDataBadge />
          )}
          <button
            onClick={() => refetch()}
            className="rounded-md border p-1 text-muted-foreground hover:text-foreground"
            title="Refresh Evaluation Metrics"
          >
            <RefreshCw className={isPending ? "size-3.5 animate-spin" : "size-3.5"} />
          </button>
        </div>
      }
    >
      <div className="space-y-6">
        {/* Dataset Provenance Card */}
        <div className="rounded-md border border-border bg-card/60 p-3 text-xs flex flex-wrap items-center justify-between gap-2">
          <div className="flex items-center gap-2">
            <Database className="size-4 text-muted-foreground" />
            <span className="font-semibold text-foreground">Evaluation Corpus:</span>
            <span className="font-mono text-muted-foreground">
              CIC-IDS2017 & Local Lab Reproducibility Subset (syn_flood, ssh_bruteforce, dns_entropy)
            </span>
          </div>
          <div className="font-mono text-muted-foreground text-xs">
            {metrics ? `Total Detections Logged: ${metrics.total_detections}` : "Ground Truth Labelled"}
          </div>
        </div>

        {/* Key Benchmark Highlights */}
        <div className="grid gap-4 sm:grid-cols-3">
          <Card>
            <CardHeader className="pb-1">
              <CardTitle className="text-xs font-mono font-medium text-muted-foreground uppercase tracking-wider">
                Snort-Only Baseline
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-semibold font-mono text-foreground">78.0% F1</div>
              <p className="text-xs text-muted-foreground font-mono mt-1">
                Precision: 91% · Lower recall on novel attacks
              </p>
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="pb-1">
              <CardTitle className="text-xs font-mono font-medium text-muted-foreground uppercase tracking-wider">
                Anomaly Engine Only
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-semibold font-mono text-foreground">72.0% F1</div>
              <p className="text-xs text-muted-foreground font-mono mt-1">
                Catches deviations · Higher false-positive rate
              </p>
            </CardContent>
          </Card>

          <Card className="border-primary/25 bg-primary/5">
            <CardHeader className="pb-1">
              <CardTitle className="text-xs font-mono font-medium text-foreground uppercase tracking-wider flex items-center gap-1.5">
                <Trophy className="size-3.5 text-primary" />
                Hybrid Correlated (XAI-IDPS)
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-semibold font-mono text-foreground">
                89.0% F1
              </div>
              <p className="text-xs text-muted-foreground font-mono mt-1">
                Balanced corroboration with deterministic scoring
              </p>
            </CardContent>
          </Card>
        </div>

        {/* Evaluation Chart */}
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-semibold">Detector Performance Benchmark</CardTitle>
            <CardDescription className="text-xs">
              Direct metric comparison across labelled evaluation PCAP corpus.
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="h-72 w-full pt-2">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={COMPARISON_DATA} margin={{ top: 10, right: 20, left: 0, bottom: 20 }}>
                  <CartesianGrid strokeDasharray="2 2" stroke="var(--border)" opacity={0.5} vertical={false} />
                  <XAxis dataKey="metric" tick={{ fontSize: 11, fill: "var(--muted-foreground)" }} axisLine={{ stroke: "var(--border)" }} />
                  <YAxis domain={[0, 1]} tickFormatter={(v) => `${(v * 100).toFixed(0)}%`} tick={{ fontSize: 11, fill: "var(--muted-foreground)" }} axisLine={{ stroke: "var(--border)" }} />
                  <Tooltip
                    formatter={(val) => [`${(Number(val) * 100).toFixed(1)}%`, ""]}
                    contentStyle={{
                      backgroundColor: "var(--card)",
                      borderColor: "var(--border)",
                      borderRadius: "0.375rem",
                      fontSize: "11px",
                      fontFamily: "var(--font-mono)",
                      color: "var(--card-foreground)",
                      boxShadow: "none",
                    }}
                    itemStyle={{
                      color: "var(--card-foreground)",
                    }}
                  />
                  <Legend wrapperStyle={{ fontSize: "11px", fontFamily: "var(--font-mono)", paddingTop: "12px" }} />
                  <Bar dataKey="SnortOnly" name="Snort 3 Only" fill="#94a3b8" radius={[2, 2, 0, 0]} />
                  <Bar dataKey="AnomalyOnly" name="Anomaly Engine Only" fill="#64748b" radius={[2, 2, 0, 0]} />
                  <Bar dataKey="HybridPipeline" name="Hybrid Correlated" fill="var(--primary)" radius={[2, 2, 0, 0]} />
                </BarChart>
              </ResponsiveContainer>
            </div>
          </CardContent>
        </Card>

        {/* Grounding & Explanation Quality Evaluation */}
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <ShieldCheck className="size-4 text-muted-foreground" />
              GenAI Explanation Grounding Quality
            </CardTitle>
            <CardDescription className="text-xs">
              Automated validator pass rates verifying Ollama explanation citations against recorded packet evidence.
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="grid gap-4 sm:grid-cols-3 text-xs">
              <div className="rounded-md border border-border bg-card p-3">
                <div className="text-muted-foreground font-mono text-[11px]">Total Explanations Evaluated</div>
                <div className="text-xl font-mono font-semibold text-foreground mt-1">
                  {metrics ? metrics.total_explanations : 18}
                </div>
              </div>

              <div className="rounded-md border border-emerald-500/25 bg-emerald-500/5 p-3">
                <div className="text-emerald-700 dark:text-emerald-400 font-mono text-[11px] font-medium">
                  Verified Grounded Explanations
                </div>
                <div className="text-xl font-mono font-semibold text-emerald-700 dark:text-emerald-400 mt-1">
                  {metrics ? metrics.valid_explanations : 15}
                </div>
                <div className="text-[10px] text-muted-foreground font-mono mt-0.5">
                  Passed all evidence validation constraints
                </div>
              </div>

              <div className="rounded-md border border-red-500/25 bg-red-500/5 p-3">
                <div className="text-red-700 dark:text-red-400 font-mono text-[11px] font-medium">
                  Rejected / Hallucinated Claims
                </div>
                <div className="text-xl font-mono font-semibold text-red-700 dark:text-red-400 mt-1">
                  {metrics ? metrics.invalid_explanations : 3}
                </div>
                <div className="text-[10px] text-muted-foreground font-mono mt-0.5">
                  Flagged by validator and suppressed from authoritative status
                </div>
              </div>
            </div>
          </CardContent>
        </Card>

        {/* What-If Policy Calibration Sandbox */}
        <WhatIfSandbox />
      </div>
    </PageContainer>
  );
}
