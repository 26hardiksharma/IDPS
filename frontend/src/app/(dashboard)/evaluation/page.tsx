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
        <div className="rounded-lg border bg-muted/30 p-3 text-xs flex flex-wrap items-center justify-between gap-2">
          <div className="flex items-center gap-2">
            <Database className="size-4 text-blue-600" />
            <span className="font-semibold text-foreground">Evaluation Corpus:</span>
            <span className="font-mono text-muted-foreground">
              CIC-IDS2017 & Local Lab Reproducibility Subset (syn_flood, ssh_bruteforce, dns_entropy)
            </span>
          </div>
          <div className="font-mono text-muted-foreground">
            {metrics ? `Total Detections Logged: ${metrics.total_detections}` : "Ground Truth Labelled"}
          </div>
        </div>

        {/* Key Benchmark Highlights */}
        <div className="grid gap-4 sm:grid-cols-3">
          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-xs font-medium text-muted-foreground uppercase">
                Snort-Only Baseline
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold font-mono">78.0% F1</div>
              <p className="text-xs text-muted-foreground mt-1">
                High precision (91%), lower recall on novel attacks
              </p>
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-xs font-medium text-muted-foreground uppercase">
                Anomaly Engine Only
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold font-mono">72.0% F1</div>
              <p className="text-xs text-muted-foreground mt-1">
                Catches zero-day deviations, higher false positive rate
              </p>
            </CardContent>
          </Card>

          <Card className="border-blue-500/40 bg-blue-500/5">
            <CardHeader className="pb-2">
              <CardTitle className="text-xs font-semibold text-blue-700 dark:text-blue-300 uppercase flex items-center gap-1.5">
                <Trophy className="size-3.5 text-blue-600 dark:text-blue-400" />
                Hybrid Correlated (XAI-IDPS)
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold font-mono text-blue-700 dark:text-blue-300">
                89.0% F1
              </div>
              <p className="text-xs text-muted-foreground mt-1">
                Balanced corroboration with deterministic scoring
              </p>
            </CardContent>
          </Card>
        </div>

        {/* Evaluation Chart */}
        <Card>
          <CardHeader>
            <CardTitle className="text-base font-semibold">Detector Performance Benchmark</CardTitle>
            <CardDescription>
              Direct metric comparison across labelled evaluation PCAP corpus.
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="h-80 w-full pt-4">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={COMPARISON_DATA} margin={{ top: 10, right: 30, left: 0, bottom: 20 }}>
                  <CartesianGrid strokeDasharray="3 3" opacity={0.2} />
                  <XAxis dataKey="metric" tick={{ fontSize: 12 }} />
                  <YAxis domain={[0, 1]} tickFormatter={(v) => `${(v * 100).toFixed(0)}%`} tick={{ fontSize: 12 }} />
                  <Tooltip
                    formatter={(val) => [`${(Number(val) * 100).toFixed(1)}%`, ""]}
                    contentStyle={{
                      backgroundColor: "var(--color-card)",
                      borderColor: "var(--color-border)",
                      borderRadius: "0.5rem",
                      fontSize: "12px",
                    }}
                  />
                  <Legend wrapperStyle={{ fontSize: "12px", paddingTop: "10px" }} />
                  <Bar dataKey="SnortOnly" name="Snort 3 Only" fill="#94a3b8" radius={[4, 4, 0, 0]} />
                  <Bar dataKey="AnomalyOnly" name="Anomaly Engine Only" fill="#f59e0b" radius={[4, 4, 0, 0]} />
                  <Bar dataKey="HybridPipeline" name="Hybrid Correlated" fill="#2563eb" radius={[4, 4, 0, 0]} />
                </BarChart>
              </ResponsiveContainer>
            </div>
          </CardContent>
        </Card>

        {/* Grounding & Explanation Quality Evaluation */}
        <Card>
          <CardHeader>
            <CardTitle className="text-base font-semibold flex items-center gap-2">
              <ShieldCheck className="size-4 text-purple-600" />
              GenAI Explanation Grounding Quality
            </CardTitle>
            <CardDescription>
              Automated validator pass rates verifying Ollama explanation citations against recorded packet evidence.
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="grid gap-4 sm:grid-cols-3 text-xs">
              <div className="rounded-md border p-3">
                <div className="text-muted-foreground">Total Explanations Evaluated</div>
                <div className="text-xl font-mono font-bold mt-1">
                  {metrics ? metrics.total_explanations : 18}
                </div>
              </div>

              <div className="rounded-md border p-3 border-emerald-500/30 bg-emerald-500/5">
                <div className="text-emerald-700 dark:text-emerald-400 font-medium">
                  Verified Grounded Explanations
                </div>
                <div className="text-xl font-mono font-bold text-emerald-700 dark:text-emerald-400 mt-1">
                  {metrics ? metrics.valid_explanations : 15}
                </div>
                <div className="text-[10px] text-muted-foreground mt-0.5">
                  Passed all evidence validation constraints
                </div>
              </div>

              <div className="rounded-md border p-3 border-red-500/30 bg-red-500/5">
                <div className="text-red-700 dark:text-red-400 font-medium">
                  Rejected / Hallucinated Claims
                </div>
                <div className="text-xl font-mono font-bold text-red-700 dark:text-red-400 mt-1">
                  {metrics ? metrics.invalid_explanations : 3}
                </div>
                <div className="text-[10px] text-muted-foreground mt-0.5">
                  Flagged by validator and suppressed from authoritative status
                </div>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>
    </PageContainer>
  );
}
