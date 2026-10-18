"use client";

import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { MitreTTP } from "@/types/backend";
import { Shield, ExternalLink, Crosshair } from "lucide-react";

interface MitreAttackCardProps {
  ttps?: MitreTTP[];
}

export function MitreAttackCard({ ttps }: MitreAttackCardProps) {
  if (!ttps || ttps.length === 0) {
    return (
      <Card>
        <CardHeader className="pb-2.5">
          <CardTitle className="text-sm font-semibold flex items-center gap-2">
            <Shield className="size-3.5 text-muted-foreground" />
            MITRE ATT&CK® TTP Alignment
          </CardTitle>
          <CardDescription className="text-xs">
            Tactics, Techniques, and Procedures mapped from correlated signatures and anomaly indicators.
          </CardDescription>
        </CardHeader>
        <CardContent className="pt-1">
          <p className="text-xs text-muted-foreground">
            No specific MITRE ATT&CK techniques identified for the constituent detections.
          </p>
        </CardContent>
      </Card>
    );
  }

  return (
    <Card>
      <CardHeader className="pb-2.5">
        <div className="flex items-center justify-between">
          <CardTitle className="text-sm font-semibold flex items-center gap-2">
            <Crosshair className="size-3.5 text-muted-foreground" />
            MITRE ATT&CK® TTP Alignment ({ttps.length} Identified)
          </CardTitle>
          <span className="text-[11px] font-mono text-muted-foreground">
            Enterprise Matrix v14
          </span>
        </div>
        <CardDescription className="text-xs">
          Automated TTP mapping derived deterministically from constituent packet anomalies and Snort 3 rule classifications.
        </CardDescription>
      </CardHeader>
      <CardContent className="pt-1">
        <div className="grid gap-2.5 sm:grid-cols-2 lg:grid-cols-3">
          {ttps.map((ttp, idx) => {
            return (
              <div
                key={`${ttp.technique_id}-${idx}`}
                className="rounded border border-border bg-card p-3 flex flex-col justify-between hover:bg-muted/30 transition-colors"
              >
                <div>
                  <div className="flex items-center justify-between gap-1 mb-1.5">
                    <span className="inline-block rounded border border-border bg-muted/40 px-1.5 py-0.5 text-[10px] font-mono text-muted-foreground uppercase tracking-wider">
                      {ttp.tactic}
                    </span>
                    <span className="text-[10px] font-mono text-muted-foreground uppercase">
                      {ttp.confidence} Conf.
                    </span>
                  </div>

                  <div className="font-medium text-xs text-foreground flex items-center gap-1.5 mt-1">
                    <span className="font-mono text-foreground font-semibold">{ttp.technique_id}</span>
                    <span>{ttp.technique_name}</span>
                  </div>

                  <p className="text-[11px] text-muted-foreground mt-1.5 line-clamp-3 leading-relaxed">
                    {ttp.description}
                  </p>
                </div>

                <div className="mt-3 pt-2 border-t border-border flex items-center justify-between text-[10px]">
                  <span className="font-mono text-muted-foreground truncate max-w-[170px]" title={ttp.evidence_trigger}>
                    Trigger: {ttp.evidence_trigger}
                  </span>
                  <a
                    href={ttp.url}
                    target="_blank"
                    rel="noreferrer"
                    className="inline-flex items-center gap-0.5 text-muted-foreground hover:text-foreground font-mono transition-colors"
                  >
                    <span>ATT&CK</span> <ExternalLink className="size-2.5 ml-0.5" />
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
