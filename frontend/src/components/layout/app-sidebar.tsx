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
      <div className="flex items-center gap-3 px-5 py-4 border-b border-border">
        <div className="flex size-9 items-center justify-center rounded-lg bg-blue-600 text-white shadow-sm">
          <Shield className="size-5" />
        </div>
        <div>
          <div className="flex items-center gap-2">
            <span className="font-bold tracking-tight text-foreground text-sm">
              {siteConfig.name}
            </span>
            <span className="rounded bg-muted px-1.5 py-0.5 text-[10px] font-mono text-muted-foreground">
              v1.0
            </span>
          </div>
          <p className="text-[11px] text-muted-foreground truncate max-w-[140px]">
            Security Operations
          </p>
        </div>
      </div>

      {/* Navigation Links */}
      <nav className="flex-1 space-y-1 p-3 overflow-y-auto" aria-label="Main Navigation">
        {navigationItems.map((item) => {
          const isActive = pathname === item.href || pathname.startsWith(item.href + "/");
          const Icon = item.icon;

          return (
            <Link
              key={item.href}
              href={item.href}
              className={cn(
                "group flex items-center justify-between rounded-md px-3 py-2 text-xs font-medium transition-colors",
                isActive
                  ? "bg-primary text-primary-foreground font-semibold shadow-xs"
                  : "text-muted-foreground hover:bg-muted hover:text-foreground"
              )}
            >
              <div className="flex items-center gap-2.5">
                <Icon
                  className={cn(
                    "size-4 shrink-0 transition-colors",
                    isActive
                      ? "text-primary-foreground"
                      : "text-muted-foreground group-hover:text-foreground"
                  )}
                />
                <span>{item.title}</span>
              </div>
              {item.badge && (
                <span
                  className={cn(
                    "rounded px-1.5 py-0.5 text-[10px] font-mono uppercase tracking-wider",
                    isActive
                      ? "bg-primary-foreground/20 text-primary-foreground"
                      : "bg-amber-500/15 text-amber-700 dark:text-amber-400"
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
      <div className="border-t border-border p-3 m-2 rounded-md bg-muted/40 space-y-2 text-xs">
        <div className="flex items-center gap-1.5 text-[11px] font-semibold text-muted-foreground uppercase tracking-wider">
          <Cpu className="size-3 text-blue-600 dark:text-blue-400" />
          <span>Local-First Pipeline</span>
        </div>
        <p className="text-[11px] text-muted-foreground leading-relaxed">
          Snort 3 + Python ML Anomaly + Ollama (Local LLM). Prevention strictly simulated.
        </p>
      </div>
    </aside>
  );
}
