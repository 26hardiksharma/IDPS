"use client";

import { useQuery } from "@tanstack/react-query";
import { checkBackendHealth } from "@/lib/api/services/metrics";
import { WifiOff, RefreshCw } from "lucide-react";

export function ConnectionStatus() {
  const { data, isPending, isError } = useQuery({
    queryKey: ["backend-health"],
    queryFn: checkBackendHealth,
    refetchInterval: 10000, // 10s poll
    retry: 1,
  });

  if (isPending) {
    return (
      <div
        className="flex items-center gap-1.5 rounded border border-border bg-card/80 px-2 py-0.5 text-xs text-muted-foreground"
        title="Checking backend API connectivity"
      >
        <span className="size-1.5 rounded-full bg-amber-500" />
        <span className="font-mono text-[11px] text-muted-foreground hidden sm:inline">Backend: Checking</span>
      </div>
    );
  }

  if (isError || data?.status !== "ok") {
    return (
      <div
        className="flex items-center gap-1.5 rounded border border-border bg-card/80 px-2 py-0.5 text-xs text-muted-foreground"
        title="FastAPI backend offline (expected when backend is not running)"
      >
        <span className="size-1.5 rounded-full bg-red-500" />
        <span className="font-mono text-[11px] text-muted-foreground hidden sm:inline">Backend: Offline</span>
      </div>
    );
  }

  return (
    <div
      className="flex items-center gap-1.5 rounded border border-border bg-card/80 px-2 py-0.5 text-xs text-muted-foreground"
      title="Connected to FastAPI backend (localhost:8000)"
    >
      <span className="size-1.5 rounded-full bg-emerald-500" />
      <span className="font-mono text-[11px] text-foreground/80 hidden sm:inline">Backend: Live</span>
    </div>
  );
}
