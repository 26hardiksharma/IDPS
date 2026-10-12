import Link from "next/link";
import { buttonVariants } from "@/components/ui/button";
import { ShieldAlert, ArrowLeft } from "lucide-react";
import { cn } from "@/lib/utils";

export default function NotFound() {
  return (
    <div className="flex min-h-screen flex-col items-center justify-center p-6 text-center">
      <div className="flex size-14 items-center justify-center rounded-full bg-muted text-muted-foreground mb-4">
        <ShieldAlert className="size-7" />
      </div>
      <h1 className="text-2xl font-bold tracking-tight text-foreground">404 - Page Not Found</h1>
      <p className="mt-2 text-sm text-muted-foreground max-w-sm">
        The requested dashboard route does not exist in the XAI-IDPS operations portal.
      </p>
      <Link
        href="/dashboard"
        className={cn(buttonVariants({ size: "sm" }), "mt-6 gap-2 text-xs")}
      >
        <ArrowLeft className="size-3.5" />
        Back to Overview
      </Link>
    </div>
  );
}
