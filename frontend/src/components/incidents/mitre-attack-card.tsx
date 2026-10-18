"use client";

import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { MitreTTP } from "@/types/backend";
import { Shield, ExternalLink, Crosshair } from "lucide-react";

interface MitreAttackCardProps {
  ttps?: MitreTTP[];
}

const TACTIC_COLORS: Record<string, { bg: string; text: string; border: string }> = {
  Reconnaissance: { bg: "bg-blue-500/10", text: "text-blue-700 dark:text-blue-400", border: "border-blue-500/20" },
  Discovery: { bg: "bg-cyan-500/10", text: "text-cyan-700 dark:text-cyan-400", border: "border-cyan-500/20" },
  "Initial Access": { bg: "bg-amber-500/10", text: "text-amber-700 dark:text-amber-400", border: "border-amber-500/20" },
  Execution: { bg: "bg-orange-500/10", text: "text-orange-700 dark:text-orange-400", border: "border-orange-500/20" },
  "Credential Access": { bg: "bg-rose-500/10", text: "text-rose-700 dark:text-rose-400", border: "border-rose-500/20" },
  "Lateral Movement": { bg: "bg-purple-500/10", text: "text-purple-700 dark:text-purple-400", border: "border-purple-500/20" },
  Exfiltration: { bg: "bg-pink-500/10", text: "text-pink-700 dark:text-pink-400", border: "border-pink-500/20" },
  Impact: { bg: "bg-red-500/10", text: "text-red-700 dark:text-red-400", border: "border-red-500/20" },
};

export function MitreAttackCard({ ttps }: MitreAttackCardProps) {
  if (!ttps || ttps.length === 0) {
    return (
      <Card>
        <CardHeader>
          <CardTitle className="text-base font-semibold flex items-center gap-2">
            <Shield className="size-4 text-primary" />
            MITRE ATT&CK® TTP Alignment
          </CardTitle>
          <CardDescription>
            Tactics, Techniques, and Procedures mapped from correlated signatures and anomaly indicators.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <p className="text-xs text-muted-foreground">
            No specific MITRE ATT&CK techniques identified for the constituent detections.
          </p>
        </CardContent>
      </Card>
    );
  }

  return (
    <Card>
      <CardHeader className="pb-3">
        <div className="flex items-center justify-between">
          <CardTitle className="text-base font-semibold flex items-center gap-2">
            <Crosshair className="size-4 text-rose-500" />
            MITRE ATT&CK® TTP Alignment ({ttps.length} Identified)
          </CardTitle>
          <span className="text-[11px] font-mono text-muted-foreground">
            Enterprise Matrix v14
          </span>
        </div>
        <CardDescription>
          Automated TTP mapping derived deterministically from constituent packet anomalies and Snort 3 rule classifications.
        </CardDescription>
      </CardHeader>
      <CardContent>
        <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
          {ttps.map((ttp, idx) => {
            const styling = TACTIC_COLORS[ttp.tactic] || {
              bg: "bg-muted",
              text: "text-foreground",
              border: "border-border",
            };
            return (
              <div
                key={`${ttp.technique_id}-${idx}`}
                className={`rounded-lg border p-3.5 flex flex-col justify-between transition-all hover:shadow-sm ${styling.border} ${styling.bg}`}
              >
                <div>
                  <div className="flex items-center justify-between gap-1 mb-1.5">
                    <span
                      className={`inline-block rounded px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wider ${styling.text}`}
                    >
                      {ttp.tactic}
                    </span>
                    <span className="text-[10px] font-mono text-muted-foreground uppercase">
                      {ttp.confidence} Conf.
                    </span>
                  </div>

                  <div className="font-semibold text-xs text-foreground flex items-center gap-1.5 mt-1">
                    <span className="font-mono text-primary font-bold">{ttp.technique_id}</span>
                    <span>{ttp.technique_name}</span>
                  </div>

                  <p className="text-[11px] text-muted-foreground mt-2 line-clamp-3">
                    {ttp.description}
                  </p>
                </div>

                <div className="mt-3 pt-2 border-t border-border/50 flex items-center justify-between text-[10px]">
                  <span className="font-mono text-muted-foreground truncate max-w-[170px]" title={ttp.evidence_trigger}>
                    Trigger: {ttp.evidence_trigger}
                  </span>
                  <a
                    href={ttp.url}
                    target="_blank"
                    rel="noreferrer"
                    className="inline-flex items-center gap-0.5 text-primary hover:underline font-medium"
                  >
                    ATT&CK <ExternalLink className="size-2.5 ml-0.5" />
                  </a>
                </div>
              </div>
            );
          })}
        </div>
      </CardContent>
    </Card>
  );
}
