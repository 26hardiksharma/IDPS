import { RunStatus } from "@/types/run";
import { IncidentStatus } from "@/types/incident";
import { ExplanationValidationStatus } from "@/types/provenance";
import { VALIDATION_STATUS_CONFIG } from "@/lib/constants";
import { cn } from "@/lib/utils";

export function RunStatusBadge({ status }: { status: RunStatus }) {
  const styles: Record<RunStatus, string> = {
    queued: "bg-slate-500/15 text-slate-700 dark:text-slate-400 border-slate-500/30",
    running: "bg-blue-500/15 text-blue-700 dark:text-blue-400 border-blue-500/30 animate-pulse",
    completed: "bg-emerald-500/15 text-emerald-700 dark:text-emerald-400 border-emerald-500/30",
    failed: "bg-red-500/15 text-red-700 dark:text-red-400 border-red-500/30",
    cancelled: "bg-amber-500/15 text-amber-700 dark:text-amber-400 border-amber-500/30",
  };

  return (
    <span
      className={cn(
        "inline-flex items-center rounded-md border px-2 py-0.5 text-xs font-medium capitalize",
        styles[status]
      )}
    >
      {status}
    </span>
  );
}

export function IncidentStatusBadge({ status }: { status: IncidentStatus }) {
  const styles: Record<IncidentStatus, string> = {
    new: "bg-purple-500/15 text-purple-700 dark:text-purple-400 border-purple-500/30 font-semibold",
    triaged: "bg-blue-500/15 text-blue-700 dark:text-blue-400 border-blue-500/30",
    in_review: "bg-amber-500/15 text-amber-700 dark:text-amber-400 border-amber-500/30",
    resolved: "bg-emerald-500/15 text-emerald-700 dark:text-emerald-400 border-emerald-500/30",
    dismissed: "bg-slate-500/15 text-slate-700 dark:text-slate-400 border-slate-500/30",
  };

  return (
    <span
      className={cn(
        "inline-flex items-center rounded-md border px-2 py-0.5 text-xs font-medium capitalize",
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
