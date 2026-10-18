import { ReactNode } from "react";
import { cn } from "@/lib/utils";

interface PageContainerProps {
  title: string;
  description?: string;
  actions?: ReactNode;
  children: ReactNode;
  className?: string;
}

export function PageContainer({
  title,
  description,
  actions,
  children,
  className,
}: PageContainerProps) {
  return (
    <div className={cn("space-y-5 p-5 md:p-6 max-w-7xl mx-auto", className)}>
      <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between border-b border-border pb-3.5">
        <div>
          <h1 className="text-lg font-semibold tracking-tight text-foreground sm:text-xl">
            {title}
          </h1>
          {description && (
            <p className="mt-0.5 text-xs text-muted-foreground max-w-3xl leading-normal">
              {description}
            </p>
          )}
        </div>
        {actions && <div className="flex items-center gap-2 shrink-0">{actions}</div>}
      </div>
      <div>{children}</div>
    </div>
  );
}
