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
        className="flex items-center gap-1.5 rounded-full border border-border px-2.5 py-1 text-xs text-muted-foreground"
        title="Checking backend API connectivity"
      >
        <RefreshCw className="size-3 animate-spin text-amber-500" />
        <span className="font-mono text-[11px] hidden sm:inline">Checking</span>
      </div>
    );
  }

  if (isError || data?.status !== "ok") {
    return (
      <div
        className="flex items-center gap-1.5 rounded-full border border-destructive/30 bg-destructive/10 px-2.5 py-1 text-xs text-destructive"
        title="FastAPI backend offline (expected when backend is not running)"
      >
        <WifiOff className="size-3" />
        <span className="font-mono text-[11px] font-semibold hidden sm:inline">API Offline</span>
      </div>
    );
  }

  return (
    <div
      className="flex items-center gap-1.5 rounded-full border border-emerald-500/30 bg-emerald-500/10 px-2.5 py-1 text-xs text-emerald-700 dark:text-emerald-400"
      title="Connected to FastAPI backend (localhost:8000)"
    >
      <span className="size-2 rounded-full bg-emerald-500 animate-pulse" />
      <span className="font-mono text-[11px] font-semibold hidden sm:inline">Connected</span>
    </div>
  );
}
