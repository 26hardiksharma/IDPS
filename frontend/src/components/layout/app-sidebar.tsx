"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { navigationItems } from "@/config/navigation";
import { siteConfig } from "@/config/site";
import { Shield, Cpu } from "lucide-react";
import { cn } from "@/lib/utils";

export function AppSidebar({ className }: { className?: string }) {
  const pathname = usePathname();

  return (
    <aside
      className={cn(
        "flex flex-col w-64 border-r shrink-0 select-none",
        "bg-sidebar text-sidebar-foreground border-sidebar-border",
        className
      )}
    >
      {/* Brand & Identity */}
      <div className="flex items-center gap-2.5 px-4 py-3.5 border-b border-border">
        <div className="flex size-7 items-center justify-center rounded border border-border bg-muted/60 text-foreground">
          <Shield className="size-3.5 text-foreground/80" />
        </div>
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-1.5">
            <span className="font-semibold tracking-tight text-foreground text-xs font-mono">
              {siteConfig.name}
            </span>
            <span className="text-[10px] font-mono text-muted-foreground">
              v1.0
            </span>
          </div>
          <p className="text-[11px] text-muted-foreground truncate">
            SecOps Platform
          </p>
        </div>
      </div>

      {/* Navigation Links */}
      <nav className="flex-1 space-y-0.5 p-2 overflow-y-auto" aria-label="Main Navigation">
        {navigationItems.map((item) => {
          const isActive = pathname === item.href || pathname.startsWith(item.href + "/");
          const Icon = item.icon;

          return (
            <Link
              key={item.href}
              href={item.href}
              className={cn(
                "group relative flex items-center justify-between rounded px-2.5 py-1.5 text-xs transition-colors",
                isActive
                  ? "bg-accent/80 text-foreground font-medium before:absolute before:left-0 before:top-1.5 before:bottom-1.5 before:w-0.5 before:rounded-r before:bg-primary"
                  : "text-muted-foreground hover:bg-muted/50 hover:text-foreground"
              )}
            >
              <div className="flex items-center gap-2.5 min-w-0">
                <Icon
                  className={cn(
                    "size-3.5 shrink-0 transition-colors",
                    isActive
                      ? "text-foreground"
                      : "text-muted-foreground/80 group-hover:text-foreground"
                  )}
                />
                <span className="truncate">{item.title}</span>
              </div>
              {item.badge && (
                <span
                  className={cn(
                    "rounded border px-1 py-0.2 text-[9px] font-mono uppercase tracking-wider",
                    isActive
                      ? "border-primary/30 text-foreground bg-primary/10"
                      : "border-border text-muted-foreground bg-muted/40"
                  )}
                >
                  {item.badge}
                </span>
              )}
            </Link>
          );
        })}
      </nav>

      {/* Local Safety Context Footer */}
      <div className="border-t border-border p-3 space-y-1.5 text-[11px] text-muted-foreground">
        <div className="flex items-center gap-1.5 font-mono text-[10px] text-foreground/80 uppercase tracking-wider">
          <Cpu className="size-3" />
          <span>Local Engine</span>
        </div>
        <p className="leading-snug">
          Snort 3 + ML Anomaly + Ollama. Actions simulated only.
        </p>
      </div>
    </aside>
  );
}
