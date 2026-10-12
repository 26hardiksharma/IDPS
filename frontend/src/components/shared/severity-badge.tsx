import { SeverityLevel } from "@/types/detection";
import { SEVERITY_CONFIG } from "@/lib/constants";
import { cn } from "@/lib/utils";

interface SeverityBadgeProps {
  severity: SeverityLevel;
  className?: string;
  showDot?: boolean;
}

export function SeverityBadge({ severity, className, showDot = true }: SeverityBadgeProps) {
  const config = SEVERITY_CONFIG[severity] || SEVERITY_CONFIG.low;

  return (
    <span
      className={cn(
        "inline-flex items-center gap-1.5 rounded-md border px-2 py-0.5 text-xs font-semibold tracking-wide uppercase transition-colors",
        config.badgeClass,
        className
      )}
    >
      {showDot && <span className={cn("size-1.5 rounded-full", config.dotClass)} />}
      {config.label}
    </span>
  );
}
