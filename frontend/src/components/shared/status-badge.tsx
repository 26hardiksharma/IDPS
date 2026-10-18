import { RunStatus } from "@/types/run";
import { IncidentStatus } from "@/types/incident";
import { ExplanationValidationStatus } from "@/types/provenance";
import { VALIDATION_STATUS_CONFIG } from "@/lib/constants";
import { cn } from "@/lib/utils";

export function RunStatusBadge({ status }: { status: RunStatus }) {
  const styles: Record<RunStatus, string> = {
    queued: "bg-muted text-muted-foreground border-border",
    running: "bg-primary/10 text-primary border-primary/25",
    completed: "bg-emerald-500/10 text-emerald-700 dark:text-emerald-400 border-emerald-500/25",
    failed: "bg-red-500/10 text-red-700 dark:text-red-400 border-red-500/25",
    cancelled: "bg-muted text-muted-foreground border-border",
  };

  return (
    <span
      className={cn(
        "inline-flex items-center rounded border px-2 py-0.5 text-[11px] font-mono capitalize",
        styles[status]
      )}
    >
      {status}
    </span>
  );
}

export function IncidentStatusBadge({ status }: { status: IncidentStatus }) {
  const styles: Record<IncidentStatus, string> = {
    new: "bg-primary/10 text-primary border-primary/20",
    triaged: "bg-muted text-muted-foreground border-border",
    in_review: "bg-amber-500/10 text-amber-700 dark:text-amber-400 border-amber-500/20",
    resolved: "bg-emerald-500/10 text-emerald-700 dark:text-emerald-400 border-emerald-500/20",
    dismissed: "bg-muted text-muted-foreground border-border",
  };

  return (
    <span
      className={cn(
        "inline-flex items-center rounded border px-2 py-0.5 text-[11px] font-medium capitalize",
        styles[status]
      )}
    >
      {status.replace("_", " ")}
    </span>
  );
}

export function ValidationStatusBadge({ status }: { status: ExplanationValidationStatus }) {
  const config = VALIDATION_STATUS_CONFIG[status] || VALIDATION_STATUS_CONFIG.pending;
  return (
    <span
      className={cn(
        "inline-flex items-center rounded-md border px-2 py-0.5 text-xs font-medium",
        config.badgeClass
      )}
    >
      {config.label}
    </span>
  );
}
