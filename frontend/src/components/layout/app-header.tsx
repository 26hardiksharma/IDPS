"use client";

import { usePathname } from "next/navigation";
import { navigationItems } from "@/config/navigation";
import { ThemeToggle } from "./theme-toggle";
import { ConnectionStatus } from "@/components/shared/connection-status";
import { Menu } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Sheet, SheetContent, SheetTrigger } from "@/components/ui/sheet";
import { AppSidebar } from "./app-sidebar";
import { useState } from "react";

export function AppHeader() {
  const pathname = usePathname();
  const [mobileOpen, setMobileOpen] = useState(false);

  const currentNav = navigationItems.find(
    (item) => pathname === item.href || pathname.startsWith(item.href + "/")
  );

  return (
    <header className="sticky top-0 z-30 flex h-12 items-center justify-between border-b border-border bg-card px-4 md:px-6">
      <div className="flex items-center gap-2.5">
        {/* Mobile menu sheet trigger */}
        <Sheet open={mobileOpen} onOpenChange={setMobileOpen}>
          <SheetTrigger
            render={
              <Button
                variant="ghost"
                size="icon"
                className="md:hidden size-7"
                aria-label="Open Navigation Menu"
              >
                <Menu className="size-4 text-muted-foreground" />
              </Button>
            }
          />
          <SheetContent side="left" className="p-0 w-64">
            <AppSidebar className="w-full h-full border-r-0" />
          </SheetContent>
        </Sheet>

        {/* Current Area Indicator */}
        <div className="flex items-center gap-1.5 text-xs text-foreground">
          <span className="text-muted-foreground hidden sm:inline font-mono">XAI-IDPS</span>
          <span className="text-muted-foreground/40 hidden sm:inline font-mono">/</span>
          <span className="font-medium text-foreground">{currentNav?.title || "Dashboard"}</span>
        </div>
      </div>

      <div className="flex items-center gap-2">
        <ConnectionStatus />
        <ThemeToggle />
      </div>
    </header>
  );
}
