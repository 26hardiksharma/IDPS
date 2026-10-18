import { FlaskConical } from "lucide-react";
import { cn } from "@/lib/utils";

export function DemoDataBadge({ className }: { className?: string }) {
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1 rounded border border-border bg-muted/60 px-2 py-0.5 text-[10px] font-mono text-muted-foreground",
        className
      )}
      title="This data is a static development fixture and does not represent live network traffic."
    >
      <FlaskConical className="size-3 text-muted-foreground" />
      <span>DEMO FIXTURE</span>
    </span>
  );
}
