import {
  LayoutDashboard,
  PlaySquare,
  ShieldAlert,
  FileCode2,
  BarChart3,
  TerminalSquare,
  type LucideIcon,
} from "lucide-react";

export interface NavItem {
  title: string;
  href: string;
  icon: LucideIcon;
  description: string;
  badge?: string;
}

export const navigationItems: NavItem[] = [
  {
    title: "Overview",
    href: "/dashboard",
    icon: LayoutDashboard,
    description: "System health, incident distribution, detector breakdown",
  },
  {
    title: "Analysis Runs",
    href: "/runs",
    icon: PlaySquare,
    description: "PCAP executions, detector configs, and run summaries",
  },
  {
    title: "Incident Queue",
    href: "/incidents",
    icon: ShieldAlert,
    description: "Correlated incidents, severity, provenance, and explanations",
  },
  {
    title: "Rule Registry",
    href: "/rules",
    icon: FileCode2,
    description: "Snort 3 signatures, ML models, and candidate rules",
  },
  {
    title: "Evaluation",
    href: "/evaluation",
    icon: BarChart3,
    description: "Detector benchmarks, precision/recall, and corpus results",
  },
  {
    title: "Response Simulation",
    href: "/response-simulation",
    icon: TerminalSquare,
    description: "Safe non-enforcing mitigation simulation and audit trails",
    badge: "Simulation",
  },
];
