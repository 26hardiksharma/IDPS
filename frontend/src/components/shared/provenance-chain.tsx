import Link from "next/link";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { GitCommit, ArrowRight, Shield, PlaySquare, AlertCircle, Sparkles, TerminalSquare } from "lucide-react";

interface ProvenanceChainProps {
  runId: string;
  incidentId: string;
  policyVersionId: string;
  explanationId?: string | null;
  hasSimulations?: boolean;
}

export function ProvenanceChain({
  runId,
  incidentId,
  policyVersionId,
  explanationId,
  hasSimulations,
}: ProvenanceChainProps) {
  const steps = [
    {
      label: "Analysis Run",
      id: runId,
      href: `/runs/${runId}`,
      icon: PlaySquare,
      color: "text-blue-500",
    },
    {
      label: "Correlation Policy",
      id: policyVersionId,
      href: null,
      icon: Shield,
      color: "text-amber-500",
    },
    {
      label: "Correlated Incident",
      id: incidentId,
      href: `/incidents/${incidentId}`,
      icon: AlertCircle,
      color: "text-rose-500",
    },
    {
      label: "AI Explanation",
      id: explanationId || "None",
      href: null,
      icon: Sparkles,
      color: "text-purple-500",
    },
    {
      label: "Response Simulation",
      id: hasSimulations ? "Audited" : "None",
      href: "/response-simulation",
      icon: TerminalSquare,
      color: "text-emerald-500",
    },
  ];

  return (
    <Card>
      <CardHeader className="pb-3">
        <CardTitle className="text-base font-semibold flex items-center gap-2">
          <GitCommit className="size-4 text-muted-foreground" />
          End-to-End Provenance Lineage
        </CardTitle>
        <CardDescription>
          Explicit forensic provenance linking raw execution, policy rules, incident decision, and downstream actions.
        </CardDescription>
      </CardHeader>
      <CardContent>
        <div className="flex flex-col md:flex-row items-stretch md:items-center gap-2 overflow-x-auto py-2">
          {steps.map((step, idx) => {
            const Icon = step.icon;
            return (
              <div key={idx} className="flex items-center gap-2">
                <div className="rounded-lg border bg-card p-3 min-w-[150px] shadow-xs">
                  <div className="flex items-center gap-1.5 text-[11px] font-semibold text-muted-foreground mb-1">
                    <Icon className={`size-3.5 ${step.color}`} />
                    <span>{step.label}</span>
                  </div>
                  {step.href ? (
                    <Link
                      href={step.href}
                      className="font-mono text-xs font-semibold text-foreground hover:underline text-blue-600 dark:text-blue-400 truncate block"
                    >
                      {step.id}
                    </Link>
                  ) : (
                    <div className="font-mono text-xs text-foreground truncate">{step.id}</div>
                  )}
                </div>

                {idx < steps.length - 1 && (
                  <ArrowRight className="size-4 text-muted-foreground hidden md:block shrink-0" />
                )}
              </div>
            );
          })}
        </div>
      </CardContent>
    </Card>
  );
}
