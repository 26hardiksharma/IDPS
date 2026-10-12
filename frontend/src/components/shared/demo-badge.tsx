import { FlaskConical } from "lucide-react";
import { cn } from "@/lib/utils";

export function DemoDataBadge({ className }: { className?: string }) {
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1 rounded border border-blue-500/30 bg-blue-500/10 px-2 py-0.5 text-[11px] font-medium text-blue-700 dark:text-blue-300",
        className
      )}
      title="This data is a static development fixture and does not represent live network traffic."
    >
      <FlaskConical className="size-3 text-blue-600 dark:text-blue-400" />
      <span>DEMO FIXTURE</span>
    </span>
  );
}
