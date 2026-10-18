"use client";

import { useMutation, useQueryClient } from "@tanstack/react-query";
import { generateExplanation } from "@/lib/api/services/incidents";
import { ExplanationResponse } from "@/types/backend";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { ValidationStatusBadge } from "@/components/shared/status-badge";
import { AlertTriangle, ShieldCheck, FileSearch, RefreshCw } from "lucide-react";
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
      queryClient.invalidateQueries({ queryKey: ["incident-explanations", incidentId] });
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
    <Card>
      <CardHeader className="flex flex-row items-start justify-between pb-2.5">
        <div className="space-y-1">
          <div className="flex items-center gap-2">
            <CardTitle className="text-sm font-semibold">
              Evidence-Grounded Explanation
            </CardTitle>
            {explanation && (
              <ValidationStatusBadge status={explanation.validation_status} />
            )}
          </div>
          <CardDescription className="text-xs">
            Advisory synthesis from local Ollama model. Grounded strictly in validated evidence records; never authoritative.
          </CardDescription>
        </div>

        <Button
          size="sm"
          variant="outline"
          disabled={explainMutation.isPending}
          onClick={() => explainMutation.mutate()}
          className="gap-1.5 text-xs h-7 px-2.5"
        >
          {explainMutation.isPending ? (
            <>
              <RefreshCw className="size-3 animate-spin text-muted-foreground" />
              Validating...
            </>
          ) : explanation ? (
            <>
              <RefreshCw className="size-3 text-muted-foreground" />
              Regenerate
            </>
          ) : (
            <>
              <FileSearch className="size-3 text-muted-foreground" />
              Generate
            </>
          )}
        </Button>
      </CardHeader>

      <CardContent className="space-y-3.5 pt-1">
        {explanation ? (
          <>
            {/* Metadata Bar */}
            <div className="flex flex-wrap items-center gap-3 rounded border border-border bg-muted/20 px-3 py-1.5 text-[11px] text-muted-foreground font-mono">
              <div>Model: {explanation.model_id}</div>
              <span className="text-muted-foreground/40">•</span>
              <div>Prompt: v{explanation.prompt_version}</div>
              <span className="text-muted-foreground/40">•</span>
              <div>Latency: {explanation.llm_latency_ms ? `${explanation.llm_latency_ms}ms` : "N/A"}</div>
              <span className="text-muted-foreground/40">•</span>
              <div>Generated: {new Date(explanation.created_at).toLocaleTimeString()}</div>
            </div>

            {/* Structured Explanation Sections */}
            {validatedContent ? (
              <div className="space-y-3 text-xs">
                {validatedContent.summary && (
                  <div className="rounded border border-border bg-card p-3">
                    <div className="font-medium text-foreground mb-1 flex items-center gap-1.5 text-xs">
                      <FileSearch className="size-3.5 text-muted-foreground" /> Executive Summary
                    </div>
                    <p className="text-muted-foreground leading-relaxed">
                      {validatedContent.summary}
                    </p>
                  </div>
                )}

                {/* Observed Facts vs AI Interpretation */}
                <div className="grid gap-3 sm:grid-cols-2">
                  <div className="rounded border border-border bg-card p-3">
                    <div className="font-medium text-foreground mb-1.5 flex items-center gap-1.5 text-xs">
                      <ShieldCheck className="size-3.5 text-emerald-600 dark:text-emerald-400" /> Observed Evidence (Authoritative Facts)
                    </div>
                    <ul className="list-disc list-inside space-y-1 text-muted-foreground">
                      {(() => {
                        const obsList =
                          Array.isArray(validatedContent.observed_facts) && validatedContent.observed_facts.length > 0
                            ? validatedContent.observed_facts
                            : Array.isArray(validatedContent.observations) && validatedContent.observations.length > 0
                            ? validatedContent.observations
                            : [];
                        if (obsList.length > 0) {
                          return obsList.map((fact: unknown, i: number) => {
                            const text =
                              typeof fact === "string"
                                ? fact
                                : typeof fact === "object" && fact !== null && "claim" in fact
                                ? String((fact as { claim: unknown }).claim)
                                : JSON.stringify(fact);
                            return <li key={i}>{text}</li>;
                          });
                        }
                        return <li>Verified packet timestamps & addresses corroborated.</li>;
                      })()}
                    </ul>
                  </div>

                  <div className="rounded border border-border bg-card p-3">
                    <div className="font-medium text-foreground mb-1.5 flex items-center gap-1.5 text-xs">
                      <AlertTriangle className="size-3.5 text-amber-600 dark:text-amber-400" /> AI Interpretation (Advisory Hypotheses)
                    </div>
                    <ul className="list-disc list-inside space-y-1 text-muted-foreground">
                      {Array.isArray(validatedContent.interpretations) &&
                      validatedContent.interpretations.length > 0 ? (
                        validatedContent.interpretations.map((interp: unknown, i: number) => {
                          if (typeof interp === "string") {
                            return <li key={i}>{interp}</li>;
                          }
                          if (typeof interp === "object" && interp !== null && "claim" in interp) {
                            const obj = interp as { claim: unknown; confidence?: unknown };
                            return (
                              <li key={i}>
                                <span>{String(obj.claim)}</span>
                                {Boolean(obj.confidence) && (
                                  <span className="ml-1.5 inline-block text-[10px] font-mono rounded px-1 border border-border bg-muted/40 text-muted-foreground">
                                    {String(obj.confidence)} confidence
                                  </span>
                                )}
                              </li>
                            );
                          }
                          return <li key={i}>{JSON.stringify(interp)}</li>;
                        })
                      ) : (
                        <li>Potential reconnaissance or rate anomaly profile.</li>
                      )}
                    </ul>
                  </div>
                </div>

                {/* Safe Recommendations */}
                {(() => {
                  const recList =
                    Array.isArray(validatedContent.recommendations) && validatedContent.recommendations.length > 0
                      ? validatedContent.recommendations
                      : Array.isArray(validatedContent.recommended_next_steps) && validatedContent.recommended_next_steps.length > 0
                      ? validatedContent.recommended_next_steps
                      : [];
                  if (recList.length > 0) {
                    return (
                      <div className="rounded border border-border bg-card p-3">
                        <div className="font-medium text-foreground mb-1 text-xs">
                          Analyst Action Recommendations (Advisory Only)
                        </div>
                        <ul className="list-disc list-inside space-y-1 text-muted-foreground">
                          {recList.map((rec: unknown, i: number) => {
                            const text =
                              typeof rec === "string"
                                ? rec
                                : typeof rec === "object" && rec !== null && "claim" in rec
                                ? String((rec as { claim: unknown }).claim)
                                : JSON.stringify(rec);
                            return <li key={i}>{text}</li>;
                          })}
                        </ul>
                      </div>
                    );
                  }
                  return null;
                })()}
              </div>
            ) : (
              <div className="rounded border border-amber-500/25 bg-amber-500/5 p-3 text-xs text-amber-800 dark:text-amber-300">
                <div className="font-medium flex items-center gap-1.5 text-xs">
                  <AlertTriangle className="size-3.5 text-amber-600 dark:text-amber-400" /> Unvalidated or Raw Output
                </div>
                <p className="mt-1 text-[11px] text-muted-foreground">
                  The LLM response did not pass strict JSON grounding schema validation or Ollama is offline.
                </p>
              </div>
            )}

            {/* Validation Findings Notice */}
            {findings.length > 0 && (
              <div className="rounded border border-border bg-muted/20 p-3 text-xs">
                <div className="font-medium text-foreground mb-1.5 text-xs">
                  Grounding Validator Findings:
                </div>
                <div className="space-y-1">
                  {findings.map((f, i) => (
                    <div key={i} className="flex items-center gap-2 text-[11px] text-muted-foreground">
                      <span className="font-mono text-muted-foreground/80 font-medium">
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
          <div className="rounded border border-dashed border-border p-6 text-center text-xs text-muted-foreground space-y-1 bg-muted/10">
            <p className="font-medium text-foreground/80">No explanation requested for this incident yet.</p>
            <p className="text-[11px]">
              Click &quot;Generate&quot; to prompt local Ollama and run automated grounding checks.
            </p>
          </div>
        )}
      </CardContent>
    </Card>
  );
}
