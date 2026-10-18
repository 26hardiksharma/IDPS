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
    },
    {
      label: "Policy Version",
      id: policyVersionId,
      href: null,
      icon: Shield,
    },
    {
      label: "Correlated Incident",
      id: incidentId,
      href: `/incidents/${incidentId}`,
      icon: AlertCircle,
    },
    {
      label: "AI Explanation",
      id: explanationId || "None",
      href: null,
      icon: Sparkles,
    },
    {
      label: "Response Simulation",
      id: hasSimulations ? "Audited" : "None",
      href: "/response-simulation",
      icon: TerminalSquare,
    },
  ];

  return (
    <Card>
      <CardHeader className="pb-2.5">
        <CardTitle className="text-sm font-semibold flex items-center gap-2">
          <GitCommit className="size-3.5 text-muted-foreground" />
          End-to-End Provenance Lineage
        </CardTitle>
        <CardDescription className="text-xs">
          Forensic chain linking raw PCAP execution, policy rules, incident decision, and downstream simulation.
        </CardDescription>
      </CardHeader>
      <CardContent className="pt-1">
        <div className="flex flex-col md:flex-row items-stretch md:items-center gap-2 overflow-x-auto py-1">
          {steps.map((step, idx) => {
            const Icon = step.icon;
            return (
              <div key={idx} className="flex items-center gap-2">
                <div className="rounded border border-border bg-card p-2.5 min-w-[145px]">
                  <div className="flex items-center gap-1.5 text-[11px] font-medium text-muted-foreground mb-1">
                    <Icon className="size-3 text-muted-foreground/80" />
                    <span>{step.label}</span>
                  </div>
                  {step.href ? (
                    <Link
                      href={step.href}
                      className="font-mono text-xs font-medium text-foreground hover:underline truncate block"
                    >
                      {step.id}
                    </Link>
                  ) : (
                    <div className="font-mono text-xs text-muted-foreground truncate">{step.id}</div>
                  )}
                </div>

                {idx < steps.length - 1 && (
                  <ArrowRight className="size-3.5 text-muted-foreground/40 hidden md:block shrink-0" />
                )}
              </div>
            );
          })}
        </div>
      </CardContent>
    </Card>
  );
}
