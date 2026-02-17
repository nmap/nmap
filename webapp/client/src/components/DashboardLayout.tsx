/*
 * DashboardLayout — Spectra Command Dark Theme
 * Persistent left sidebar with icon-only collapsed mode on mobile
 * Top header bar with search/command palette and user avatar
 */
import { useState, useEffect, type ReactNode } from "react";
import { Link, useLocation } from "wouter";
import {
  LayoutDashboard,
  Radar,
  FileSearch,
  History,
  Shield,
  Settings,
  ChevronLeft,
  ChevronRight,
  Search,
  Bell,
  Menu,
  X,
  Terminal,
  Crosshair,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import { toast } from "sonner";

interface NavItem {
  icon: React.ElementType;
  label: string;
  href: string;
  badge?: number;
}

const navItems: NavItem[] = [
  { icon: LayoutDashboard, label: "Command Center", href: "/" },
  { icon: Crosshair, label: "New Scan", href: "/scan/new" },
  { icon: FileSearch, label: "Scan Results", href: "/scan/results" },
  { icon: History, label: "Scan History", href: "/history" },
  { icon: Shield, label: "Audit Log", href: "/audit" },
  { icon: Settings, label: "Settings", href: "/settings" },
];

export default function DashboardLayout({ children }: { children: ReactNode }) {
  const [location] = useLocation();
  const [collapsed, setCollapsed] = useState(false);
  const [mobileOpen, setMobileOpen] = useState(false);

  // Close mobile menu on route change
  useEffect(() => {
    setMobileOpen(false);
  }, [location]);

  // Keyboard shortcut: Ctrl+K for command palette placeholder
  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key === "k") {
        e.preventDefault();
        toast("Command palette coming soon", {
          description: "Press Ctrl+K to quick-navigate",
        });
      }
    };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, []);

  return (
    <div className="flex h-screen overflow-hidden bg-background">
      {/* Mobile overlay */}
      {mobileOpen && (
        <div
          className="fixed inset-0 z-40 bg-black/60 backdrop-blur-sm lg:hidden"
          onClick={() => setMobileOpen(false)}
        />
      )}

      {/* Sidebar */}
      <aside
        className={`
          fixed lg:relative z-50 h-full flex flex-col
          border-r border-border/50 bg-sidebar
          transition-all duration-300 ease-in-out
          ${collapsed ? "w-[68px]" : "w-[240px]"}
          ${mobileOpen ? "translate-x-0" : "-translate-x-full lg:translate-x-0"}
        `}
      >
        {/* Logo area */}
        <div className="flex items-center gap-3 px-4 h-16 border-b border-border/50">
          <div className="flex items-center justify-center w-9 h-9 rounded-lg bg-purple-600/20 shrink-0">
            <Radar className="w-5 h-5 text-purple-400" />
          </div>
          {!collapsed && (
            <div className="overflow-hidden">
              <h1 className="text-sm font-semibold text-foreground font-[Outfit] truncate leading-tight">
                Valentine RF
              </h1>
              <p className="text-[10px] text-muted-foreground tracking-wider uppercase">
                NMAP Command
              </p>
            </div>
          )}
          {/* Mobile close */}
          <button
            className="ml-auto lg:hidden text-muted-foreground hover:text-foreground"
            onClick={() => setMobileOpen(false)}
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Nav items */}
        <nav className="flex-1 py-4 px-2 space-y-1 overflow-y-auto">
          {navItems.map((item) => {
            const isActive = location === item.href || (item.href !== "/" && location.startsWith(item.href));
            const Icon = item.icon;

            const linkContent = (
              <Link
                key={item.href}
                href={item.href}
                className={`
                  flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium
                  transition-all duration-200
                  ${isActive
                    ? "bg-purple-600/15 text-purple-400 shadow-[inset_0_0_0_1px_rgba(139,92,246,0.2)]"
                    : "text-muted-foreground hover:text-foreground hover:bg-accent/50"
                  }
                `}
              >
                <Icon className={`w-[18px] h-[18px] shrink-0 ${isActive ? "text-purple-400" : ""}`} />
                {!collapsed && <span className="truncate">{item.label}</span>}
                {!collapsed && item.badge && (
                  <span className="ml-auto text-[10px] bg-purple-600/30 text-purple-300 px-1.5 py-0.5 rounded-full">
                    {item.badge}
                  </span>
                )}
              </Link>
            );

            if (collapsed) {
              return (
                <Tooltip key={item.href} delayDuration={0}>
                  <TooltipTrigger asChild>{linkContent}</TooltipTrigger>
                  <TooltipContent side="right" className="bg-popover text-popover-foreground">
                    {item.label}
                  </TooltipContent>
                </Tooltip>
              );
            }
            return linkContent;
          })}
        </nav>

        {/* Collapse toggle */}
        <div className="hidden lg:flex items-center justify-center p-3 border-t border-border/50">
          <button
            onClick={() => setCollapsed(!collapsed)}
            className="flex items-center justify-center w-8 h-8 rounded-md text-muted-foreground hover:text-foreground hover:bg-accent/50 transition-colors"
          >
            {collapsed ? <ChevronRight className="w-4 h-4" /> : <ChevronLeft className="w-4 h-4" />}
          </button>
        </div>
      </aside>

      {/* Main content area */}
      <div className="flex-1 flex flex-col overflow-hidden">
        {/* Top header */}
        <header className="flex items-center gap-4 h-16 px-4 lg:px-6 border-b border-border/50 bg-sidebar/50 backdrop-blur-sm shrink-0">
          {/* Mobile menu toggle */}
          <button
            className="lg:hidden text-muted-foreground hover:text-foreground"
            onClick={() => setMobileOpen(true)}
          >
            <Menu className="w-5 h-5" />
          </button>

          {/* Search bar */}
          <div className="flex-1 max-w-md">
            <div className="flex items-center gap-2 px-3 py-2 rounded-lg bg-input/50 border border-border/50 text-sm text-muted-foreground">
              <Search className="w-4 h-4 shrink-0" />
              <span className="hidden sm:inline">Search scans, hosts, ports...</span>
              <span className="sm:hidden">Search...</span>
              <kbd className="hidden md:inline-flex ml-auto text-[10px] bg-background/50 px-1.5 py-0.5 rounded border border-border/50 font-mono">
                ⌘K
              </kbd>
            </div>
          </div>

          {/* Right side actions */}
          <div className="flex items-center gap-2">
            <Tooltip>
              <TooltipTrigger asChild>
                <Button variant="ghost" size="icon" className="text-muted-foreground hover:text-foreground relative">
                  <Bell className="w-[18px] h-[18px]" />
                  <span className="absolute top-1.5 right-1.5 w-2 h-2 bg-red-500 rounded-full" />
                </Button>
              </TooltipTrigger>
              <TooltipContent>Notifications</TooltipContent>
            </Tooltip>

            <Tooltip>
              <TooltipTrigger asChild>
                <Button variant="ghost" size="icon" className="text-muted-foreground hover:text-foreground">
                  <Terminal className="w-[18px] h-[18px]" />
                </Button>
              </TooltipTrigger>
              <TooltipContent>Terminal</TooltipContent>
            </Tooltip>

            {/* User avatar */}
            <div className="flex items-center justify-center w-8 h-8 rounded-full bg-purple-600/20 text-purple-400 text-xs font-semibold ml-1">
              VR
            </div>
          </div>
        </header>

        {/* Page content */}
        <main className="flex-1 overflow-y-auto bg-grid">
          <div className="p-4 lg:p-6">
            {children}
          </div>
        </main>
      </div>
    </div>
  );
}
