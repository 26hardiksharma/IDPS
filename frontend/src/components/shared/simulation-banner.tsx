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
          "inline-flex items-center gap-2 rounded border border-amber-500/25 bg-amber-500/5 px-2.5 py-1 text-xs text-amber-800 dark:text-amber-300",
          className
        )}
      >
        <AlertTriangle className="size-3.5 shrink-0 text-amber-600 dark:text-amber-400" />
        <span className="font-mono text-[11px] font-medium tracking-wide">{SIMULATION_SAFETY_DISCLAIMER}</span>
      </div>
    );
  }

  return (
    <div
      role="alert"
      className={cn(
        "flex flex-col gap-1 rounded border border-amber-500/25 bg-amber-500/5 px-3 py-2 text-xs text-amber-800 dark:text-amber-300 md:flex-row md:items-center md:gap-2.5",
        className
      )}
    >
      <div className="flex shrink-0 items-center gap-1.5 font-mono text-[11px] font-medium tracking-wide">
        <AlertTriangle className="size-3.5 text-amber-600 dark:text-amber-400" />
        <span>{SIMULATION_SAFETY_DISCLAIMER}</span>
      </div>
      <span className="hidden text-muted-foreground/40 md:inline">—</span>
      <p className="text-[11px] text-muted-foreground leading-normal">
        {SIMULATION_SAFETY_DESCRIPTION}
      </p>
    </div>
  );
}
