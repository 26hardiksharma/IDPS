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
    <header className="sticky top-0 z-30 flex h-14 items-center justify-between border-b border-border bg-card/95 px-4 md:px-6 backdrop-blur supports-[backdrop-filter]:bg-card/75">
      <div className="flex items-center gap-3">
        {/* Mobile menu sheet trigger */}
        <Sheet open={mobileOpen} onOpenChange={setMobileOpen}>
          <SheetTrigger
            render={
              <Button
                variant="ghost"
                size="icon"
                className="md:hidden size-8"
                aria-label="Open Navigation Menu"
              >
                <Menu className="size-4" />
              </Button>
            }
          />
          <SheetContent side="left" className="p-0 w-64">
            <AppSidebar className="w-full h-full border-r-0" />
          </SheetContent>
        </Sheet>

        {/* Current Area Indicator */}
        <div className="flex items-center gap-2 text-sm font-semibold text-foreground">
          <span className="text-muted-foreground hidden sm:inline">XAI-IDPS</span>
          <span className="text-muted-foreground hidden sm:inline">/</span>
          <span>{currentNav?.title || "Dashboard"}</span>
        </div>
      </div>

      <div className="flex items-center gap-3">
        <ConnectionStatus />

        <ThemeToggle />
      </div>
    </header>
  );
}
