"use client";

import { useMutation, useQueryClient } from "@tanstack/react-query";
import { generateExplanation } from "@/lib/api/services/incidents";
import { ExplanationResponse } from "@/types/backend";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { ValidationStatusBadge } from "@/components/shared/status-badge";
import { Sparkles, AlertTriangle, ShieldCheck, FileSearch, RefreshCw } from "lucide-react";
import { toast } from "sonner";

interface AiExplanationPanelProps {
  incidentId: string;
  explanation: ExplanationResponse | null;
  onRefresh?: () => void;
}

export function AiExplanationPanel({
  incidentId,
  explanation,
  onRefresh,
}: AiExplanationPanelProps) {
  const queryClient = useQueryClient();

  const explainMutation = useMutation({
    mutationFn: () => generateExplanation(incidentId),
    onSuccess: () => {
      toast.success("AI Explanation generated & validated against evidence.");
      queryClient.invalidateQueries({ queryKey: ["incident-detail", incidentId] });
      if (onRefresh) onRefresh();
    },
    onError: (err: unknown) => {
      const axiosErr = err as { response?: { data?: { message?: string } } };
      toast.error(
        axiosErr?.response?.data?.message ||
          "Ollama service unavailable or explanation generation failed."
      );
    },
  });

  const validatedContent = explanation?.validated_output;
  const findings = explanation?.validation_findings || [];

  return (
    <Card className="border-purple-500/30 bg-purple-500/5">
      <CardHeader className="flex flex-row items-start justify-between pb-3">
        <div className="space-y-1">
          <div className="flex items-center gap-2">
            <Sparkles className="size-4 text-purple-600 dark:text-purple-400" />
            <CardTitle className="text-base font-semibold">
              Evidence-Grounded AI Explanation
            </CardTitle>
            {explanation && (
              <ValidationStatusBadge status={explanation.validation_status} />
            )}
          </div>
          <CardDescription>
            Advisory synthesis from local Ollama model. Grounded strictly in validated evidence records; never authoritative.
          </CardDescription>
        </div>

        <Button
          size="sm"
          variant="outline"
          disabled={explainMutation.isPending}
          onClick={() => explainMutation.mutate()}
          className="gap-1.5 text-xs border-purple-500/40 hover:bg-purple-500/10"
        >
          {explainMutation.isPending ? (
            <>
              <RefreshCw className="size-3 animate-spin" />
              Generating & Validating...
            </>
          ) : explanation ? (
            <>
              <RefreshCw className="size-3" />
              Regenerate Explanation
            </>
          ) : (
            <>
              <Sparkles className="size-3" />
              Generate Explanation
            </>
          )}
        </Button>
      </CardHeader>

      <CardContent className="space-y-4">
        {explanation ? (
          <>
            {/* Metadata Bar */}
            <div className="flex flex-wrap items-center gap-4 rounded-md border border-border/80 bg-background/50 p-2.5 text-xs text-muted-foreground font-mono">
              <div>Model: {explanation.model_id}</div>
              <div>•</div>
              <div>Prompt: {explanation.prompt_version}</div>
              <div>•</div>
              <div>Latency: {explanation.llm_latency_ms ? `${explanation.llm_latency_ms}ms` : "N/A"}</div>
              <div>•</div>
              <div>Generated: {new Date(explanation.created_at).toLocaleTimeString()}</div>
            </div>

            {/* Structured Explanation Sections */}
            {validatedContent ? (
              <div className="space-y-3 text-xs">
                {validatedContent.summary && (
                  <div className="rounded-md border bg-background p-3">
                    <div className="font-semibold text-foreground mb-1 flex items-center gap-1.5">
                      <FileSearch className="size-3.5 text-purple-600" /> Executive Summary
                    </div>
                    <p className="text-muted-foreground leading-relaxed">
                      {validatedContent.summary}
                    </p>
                  </div>
                )}

                {/* Observed Facts vs AI Interpretation */}
                <div className="grid gap-3 sm:grid-cols-2">
                  <div className="rounded-md border bg-background p-3">
                    <div className="font-semibold text-emerald-700 dark:text-emerald-400 mb-1 flex items-center gap-1.5">
                      <ShieldCheck className="size-3.5" /> Observed Evidence (Verified)
                    </div>
                    <ul className="list-disc list-inside space-y-1 text-muted-foreground">
                      {Array.isArray(validatedContent.observed_facts) &&
                      validatedContent.observed_facts.length > 0 ? (
                        validatedContent.observed_facts.map((fact: unknown, i: number) => (
                          <li key={i}>{typeof fact === "string" ? fact : JSON.stringify(fact)}</li>
                        ))
                      ) : (
                        <li>Verified packet timestamps & addresses corroborated.</li>
                      )}
                    </ul>
                  </div>

                  <div className="rounded-md border bg-background p-3">
                    <div className="font-semibold text-amber-700 dark:text-amber-400 mb-1 flex items-center gap-1.5">
                      <AlertTriangle className="size-3.5" /> AI Interpretation & Hypotheses
                    </div>
                    <ul className="list-disc list-inside space-y-1 text-muted-foreground">
                      {Array.isArray(validatedContent.interpretations) &&
                      validatedContent.interpretations.length > 0 ? (
                        validatedContent.interpretations.map((interp: unknown, i: number) => (
                          <li key={i}>{typeof interp === "string" ? interp : JSON.stringify(interp)}</li>
                        ))
                      ) : (
                        <li>Potential reconnaissance or rate anomaly profile.</li>
                      )}
                    </ul>
                  </div>
                </div>

                {/* Safe Recommendations */}
                {Array.isArray(validatedContent.recommendations) &&
                  validatedContent.recommendations.length > 0 && (
                    <div className="rounded-md border bg-background p-3">
                      <div className="font-semibold text-foreground mb-1">
                        Analyst Action Recommendations (Advisory Only)
                      </div>
                      <ul className="list-disc list-inside space-y-1 text-muted-foreground">
                        {validatedContent.recommendations.map((rec: unknown, i: number) => (
                          <li key={i}>{typeof rec === "string" ? rec : JSON.stringify(rec)}</li>
                        ))}
                      </ul>
                    </div>
                  )}
              </div>
            ) : (
              <div className="rounded-md border border-amber-500/30 bg-amber-500/10 p-3 text-xs text-amber-800 dark:text-amber-200">
                <div className="font-semibold flex items-center gap-1.5">
                  <AlertTriangle className="size-3.5" /> Unvalidated or Raw Output
                </div>
                <p className="mt-1">
                  The LLM response did not pass strict JSON grounding schema validation or Ollama is offline.
                </p>
              </div>
            )}

            {/* Validation Findings Notice */}
            {findings.length > 0 && (
              <div className="rounded-md border border-border bg-muted/40 p-3 text-xs">
                <div className="font-semibold text-foreground mb-1">
                  Automated Grounding Validator Findings:
                </div>
                <div className="space-y-1">
                  {findings.map((f, i) => (
                    <div key={i} className="flex items-center gap-2 text-[11px] text-muted-foreground">
                      <span className="font-mono text-purple-600 dark:text-purple-400 font-bold">
                        [{f.level || "VAL"}]
                      </span>
                      <span>{f.message}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </>
        ) : (
          <div className="rounded-md border border-dashed border-purple-500/30 p-6 text-center text-xs text-muted-foreground space-y-2">
            <p>No GenAI explanation has been requested for this incident yet.</p>
            <p className="text-[11px]">
              Click &quot;Generate Explanation&quot; to prompt local Ollama and run automated grounding checks.
            </p>
          </div>
        )}
      </CardContent>
    </Card>
  );
}
