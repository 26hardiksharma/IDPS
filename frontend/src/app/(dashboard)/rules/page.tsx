"use client";

import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import * as z from "zod";
import { PageContainer } from "@/components/layout/page-container";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { DemoDataBadge } from "@/components/shared/demo-badge";
import { SAMPLE_RULES } from "@/lib/fixtures/sample-data";
import { fetchRules, submitCandidateRule } from "@/lib/api/services/rules";
import { toast } from "sonner";
import { CheckCircle, Info, RefreshCw } from "lucide-react";
import { RuleVersionResponse } from "@/types/backend";

const candidateRuleSchema = z.object({
  rule_id: z.string().min(3, "Identifier must be at least 3 characters"),
  version: z.string().min(1, "Version is required"),
  content: z.string().min(10, "Rule definition must contain at least 10 characters"),
  source: z.string().min(1, "Source is required"),
});

type CandidateRuleFormValues = {
  rule_id: string;
  version: string;
  content: string;
  source: string;
};

export default function RuleRegistryPage() {
  const queryClient = useQueryClient();

  const {
    data: apiRules,
    isPending,
    isError,
    refetch,
  } = useQuery({
    queryKey: ["rules-list"],
    queryFn: () => fetchRules(true),
    retry: 1,
  });

  const candidateMutation = useMutation({
    mutationFn: (data: CandidateRuleFormValues) =>
      submitCandidateRule({
        rule_id: data.rule_id,
        version: data.version,
        content: data.content,
        source: data.source,
      }),
    onSuccess: (newRule) => {
      toast.success(
        `Candidate rule registered (${newRule.rule_id}). Not auto-deployed — stays in candidate status.`
      );
      queryClient.invalidateQueries({ queryKey: ["rules-list"] });
      reset();
    },
    onError: (err: unknown) => {
      const axiosErr = err as { response?: { data?: { message?: string } } };
      toast.error(axiosErr?.response?.data?.message || "Failed to register candidate rule");
    },
  });

  const isDemo = Boolean(isError || !apiRules);

  const {
    register,
    handleSubmit,
    reset,
    formState: { errors, isSubmitting },
  } = useForm<CandidateRuleFormValues>({
    resolver: zodResolver(candidateRuleSchema),
    defaultValues: {
      rule_id: "LOCAL-10002",
      version: "1.0",
      content:
        'alert tcp $EXTERNAL_NET any -> $HOME_NET 22 (msg:"LOCAL SSH Brute Force Rate"; flags:S; threshold:type both, track by_src, count 10, seconds 30; sid:10002; rev:1;)',
      source: "local",
    },
  });

  const onSubmit = (data: CandidateRuleFormValues) => {
    candidateMutation.mutate(data);
  };

  return (
    <PageContainer
      title="Rule Registry"
      description="Inspect versioned Snort 3 signature definitions, baseline anomaly thresholds, and submit candidate rules for analyst evaluation."
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
            title="Refresh Rules"
          >
            <RefreshCw className={isPending ? "size-3.5 animate-spin" : "size-3.5"} />
          </button>
        </div>
      }
    >
      <div className="space-y-6">
        {/* Policy Boundary Notice */}
        <div className="rounded-md border border-amber-500/25 bg-amber-500/5 px-3.5 py-2.5 text-xs text-foreground/90 font-mono flex items-center gap-2">
          <Info className="size-3.5 shrink-0 text-amber-600 dark:text-amber-400" />
          <span>
            Candidate rules require offline verification against labelled corpus.
            Candidate rules are never automatically deployed into active detection.
          </span>
        </div>

        {/* Existing Rules Table */}
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-semibold">Registered Rules & Baseline Models</CardTitle>
            <CardDescription className="text-xs">
              Version-tracked signatures and models used for reproducible detection provenance.
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="rounded-md border border-border overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead className="bg-muted/40 border-b border-border font-medium text-muted-foreground font-mono">
                  <tr>
                    <th className="py-2.5 px-3 font-medium">Rule ID / SID</th>
                    <th className="py-2.5 px-3 font-medium">Version</th>
                    <th className="py-2.5 px-3 font-medium">Source</th>
                    <th className="py-2.5 px-3 font-medium">Status</th>
                    <th className="py-2.5 px-3 font-medium">SHA-256 Hash</th>
                    <th className="py-2.5 px-3 font-medium">Registered</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border">
                  {apiRules && apiRules.length > 0 ? (
                    apiRules.map((rule: RuleVersionResponse) => (
                      <tr key={rule.rule_version_id} className="hover:bg-muted/30 transition-colors">
                        <td className="py-2.5 px-3 font-mono font-medium text-foreground">
                          {rule.rule_id}
                        </td>
                        <td className="py-2.5 px-3 font-mono text-muted-foreground">{rule.version}</td>
                        <td className="py-2.5 px-3">
                          <span className="rounded border border-border bg-muted/60 px-1.5 py-0.5 text-[11px] capitalize font-mono text-muted-foreground">
                            {rule.source}
                          </span>
                        </td>
                        <td className="py-2.5 px-3">
                          {rule.status === "active" ? (
                            <span className="inline-flex items-center gap-1 font-mono text-[11px] text-emerald-700 dark:text-emerald-400">
                              <CheckCircle className="size-3" /> Active
                            </span>
                          ) : (
                            <span className="inline-flex items-center rounded border border-amber-500/25 bg-amber-500/10 px-1.5 py-0.5 font-mono text-[11px] text-amber-800 dark:text-amber-300">
                              Candidate
                            </span>
                          )}
                        </td>
                        <td className="py-2.5 px-3 font-mono text-[11px] text-muted-foreground max-w-[120px] truncate" title={rule.sha256}>
                          {rule.sha256}
                        </td>
                        <td className="py-2.5 px-3 font-mono text-[11px] text-muted-foreground">
                          {new Date(rule.created_at).toLocaleDateString()}
                        </td>
                      </tr>
                    ))
                  ) : (
                    SAMPLE_RULES.map((rule) => (
                      <tr key={rule.id} className="hover:bg-muted/30 transition-colors">
                        <td className="py-2.5 px-3 font-mono font-medium text-foreground">{rule.rule_identifier}</td>
                        <td className="py-2.5 px-3 font-mono text-muted-foreground">{rule.version}</td>
                        <td className="py-2.5 px-3">
                          <span className="rounded border border-border bg-muted/60 px-1.5 py-0.5 text-[11px] capitalize font-mono text-muted-foreground">
                            {rule.source.replace("_", " ")}
                          </span>
                        </td>
                        <td className="py-2.5 px-3">
                          {rule.is_active ? (
                            <span className="inline-flex items-center gap-1 font-mono text-[11px] text-emerald-700 dark:text-emerald-400">
                              <CheckCircle className="size-3" /> Active
                            </span>
                          ) : (
                            <span className="inline-flex items-center rounded border border-amber-500/25 bg-amber-500/10 px-1.5 py-0.5 font-mono text-[11px] text-amber-800 dark:text-amber-300">
                              Candidate
                            </span>
                          )}
                        </td>
                        <td className="py-2.5 px-3 font-mono text-[11px] text-muted-foreground max-w-[120px] truncate">
                          {rule.rule_hash}
                        </td>
                        <td className="py-2.5 px-3 font-mono text-[11px] text-muted-foreground">
                          {new Date(rule.created_at).toLocaleDateString()}
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          </CardContent>
        </Card>

        {/* Candidate Rule Submission Form */}
        <Card>
          <CardHeader>
            <CardTitle className="text-base font-semibold">Propose Candidate Detection Rule</CardTitle>
            <CardDescription>
              Submit a newly proposed Snort signature for offline corpus verification.
            </CardDescription>
          </CardHeader>
          <CardContent>
            <form onSubmit={handleSubmit(onSubmit)} className="space-y-4">
              <div className="grid gap-4 sm:grid-cols-3">
                <div className="space-y-1">
                  <label className="text-xs font-medium text-foreground">Rule Identifier (SID/Name)</label>
                  <input
                    {...register("rule_id")}
                    placeholder="e.g. CAND-003"
                    className="w-full rounded-md border border-input bg-background px-3 py-1.5 text-xs text-foreground placeholder:text-muted-foreground focus:outline-hidden focus:ring-1 focus:ring-ring"
                  />
                  {errors.rule_id && (
                    <p className="text-[11px] text-red-500">{errors.rule_id.message}</p>
                  )}
                </div>

                <div className="space-y-1">
                  <label className="text-xs font-medium text-foreground">Version</label>
                  <input
                    {...register("version")}
                    placeholder="e.g. 1.0"
                    className="w-full rounded-md border border-input bg-background px-3 py-1.5 text-xs text-foreground placeholder:text-muted-foreground focus:outline-hidden focus:ring-1 focus:ring-ring"
                  />
                  {errors.version && (
                    <p className="text-[11px] text-red-500">{errors.version.message}</p>
                  )}
                </div>

                <div className="space-y-1">
                  <label className="text-xs font-medium text-foreground">Rule Source</label>
                  <input
                    {...register("source")}
                    placeholder="e.g. local"
                    className="w-full rounded-md border border-input bg-background px-3 py-1.5 text-xs text-foreground placeholder:text-muted-foreground focus:outline-hidden focus:ring-1 focus:ring-ring"
                  />
                </div>
              </div>

              <div className="space-y-1">
                <label className="text-xs font-medium text-foreground">Snort Rule Definition (Content)</label>
                <textarea
                  {...register("content")}
                  rows={3}
                  placeholder='alert tcp any any -> any 22 (msg:"..."; sid:...;)'
                  className="w-full rounded-md border border-input bg-background px-3 py-1.5 text-xs font-mono text-foreground placeholder:text-muted-foreground focus:outline-hidden focus:ring-1 focus:ring-ring"
                />
                {errors.content && (
                  <p className="text-[11px] text-red-500">{errors.content.message}</p>
                )}
              </div>

              <div className="flex justify-end">
                <Button
                  type="submit"
                  size="sm"
                  disabled={isSubmitting || candidateMutation.isPending}
                  className="text-xs"
                >
                  {candidateMutation.isPending ? "Submitting..." : "Submit Candidate Rule"}
                </Button>
              </div>
            </form>
          </CardContent>
        </Card>
      </div>
    </PageContainer>
  );
}
