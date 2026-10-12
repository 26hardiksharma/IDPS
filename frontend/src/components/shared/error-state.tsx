"use client";

import { AlertCircle, RefreshCw } from "lucide-react";
import { Button } from "@/components/ui/button";

interface ErrorStateProps {
  title?: string;
  message?: string;
  onRetry?: () => void;
  isNetworkError?: boolean;
}

export function ErrorState({
  title = "Failed to load data",
  message = "An error occurred while connecting to the XAI-IDPS service.",
  onRetry,
  isNetworkError = false,
}: ErrorStateProps) {
  return (
    <div className="flex flex-col items-center justify-center rounded-lg border border-red-500/20 bg-red-500/5 p-8 text-center">
      <div className="flex size-12 items-center justify-center rounded-full bg-red-500/10 text-red-600 dark:text-red-400 mb-4">
        <AlertCircle className="size-6" />
      </div>
      <h3 className="text-base font-semibold text-foreground">
        {isNetworkError ? "Backend Connection Unavailable" : title}
      </h3>
      <p className="mt-1 text-sm text-muted-foreground max-w-md">{message}</p>
      {isNetworkError && (
        <p className="mt-2 text-xs font-mono text-muted-foreground/80 bg-muted px-2.5 py-1 rounded">
          Target: {process.env.NEXT_PUBLIC_API_BASE_URL || "http://127.0.0.1:8000"}
        </p>
      )}
      {onRetry && (
        <Button onClick={onRetry} variant="outline" size="sm" className="mt-4 gap-2">
          <RefreshCw className="size-3.5" />
          Retry Connection
        </Button>
      )}
    </div>
  );
}
