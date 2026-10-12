import { AlertTriangle } from "lucide-react";
import { SIMULATION_SAFETY_DISCLAIMER, SIMULATION_SAFETY_DESCRIPTION } from "@/lib/constants";
import { cn } from "@/lib/utils";

interface SimulationBannerProps {
  className?: string;
  variant?: "warning" | "compact";
}

export function SimulationBanner({ className, variant = "warning" }: SimulationBannerProps) {
  if (variant === "compact") {
    return (
      <div
        className={cn(
          "inline-flex items-center gap-1.5 rounded border border-amber-500/40 bg-amber-500/10 px-2 py-1 text-xs font-semibold text-amber-700 dark:text-amber-300",
          className
        )}
      >
        <AlertTriangle className="size-3.5 shrink-0 text-amber-600 dark:text-amber-400" />
        <span>{SIMULATION_SAFETY_DISCLAIMER}</span>
      </div>
    );
  }

  return (
    <div
      role="alert"
      className={cn(
        "relative flex flex-col gap-1 rounded-lg border border-amber-500/40 bg-amber-500/10 p-3.5 text-sm text-amber-800 dark:text-amber-200 md:flex-row md:items-center md:gap-3",
        className
      )}
    >
      <div className="flex shrink-0 items-center gap-2 font-bold tracking-tight">
        <AlertTriangle className="size-4 text-amber-600 dark:text-amber-400" />
        <span className="text-xs uppercase tracking-wider">{SIMULATION_SAFETY_DISCLAIMER}</span>
      </div>
      <span className="hidden text-amber-500/40 md:inline">|</span>
      <p className="text-xs text-amber-700 dark:text-amber-300/90 leading-relaxed">
        {SIMULATION_SAFETY_DESCRIPTION}
      </p>
    </div>
  );
}
