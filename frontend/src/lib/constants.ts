export const DEFAULT_API_BASE_URL = "http://127.0.0.1:8000";

export const SIMULATION_SAFETY_DISCLAIMER =
  "SIMULATION ONLY — NO NETWORK ACTION EXECUTED";

export const SIMULATION_SAFETY_DESCRIPTION =
  "In accordance with system safety constraints, all actions are recorded as audit simulations. The system does not modify host firewalls, routing tables, or active network controls.";

export const SEVERITY_CONFIG = {
  critical: {
    label: "Critical",
    badgeClass: "bg-red-500/10 text-red-700 dark:text-red-400 border-red-500/25",
    dotClass: "bg-red-500",
  },
  high: {
    label: "High",
    badgeClass: "bg-orange-500/10 text-orange-700 dark:text-orange-400 border-orange-500/25",
    dotClass: "bg-orange-500",
  },
  medium: {
    label: "Medium",
    badgeClass: "bg-amber-500/10 text-amber-700 dark:text-amber-400 border-amber-500/25",
    dotClass: "bg-amber-500",
  },
  low: {
    label: "Low",
    badgeClass: "bg-slate-500/10 text-slate-700 dark:text-slate-400 border-slate-500/20",
    dotClass: "bg-slate-400 dark:bg-slate-500",
  },
} as const;

export const VALIDATION_STATUS_CONFIG = {
  valid: {
    label: "Verified Grounded",
    badgeClass: "bg-emerald-500/10 text-emerald-700 dark:text-emerald-400 border-emerald-500/25",
  },
  partially_valid: {
    label: "Partially Valid",
    badgeClass: "bg-amber-500/10 text-amber-700 dark:text-amber-400 border-amber-500/25",
  },
  pending: {
    label: "Validation Pending",
    badgeClass: "bg-muted text-muted-foreground border-border",
  },
  invalid: {
    label: "Validation Failed",
    badgeClass: "bg-red-500/10 text-red-700 dark:text-red-400 border-red-500/25",
  },
  failed: {
    label: "Generation Error",
    badgeClass: "bg-red-500/10 text-red-700 dark:text-red-400 border-red-500/25",
  },
} as const;
