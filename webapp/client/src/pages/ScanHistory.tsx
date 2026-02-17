/*
 * ScanHistory — Scan History & Filtering
 * Spectra Command Dark Theme
 */
import { useState } from "react";
import { Link } from "wouter";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  History,
  Search,
  Filter,
  ArrowUpRight,
  Clock,
  CheckCircle,
  XCircle,
  Loader2,
  Globe,
  Layers,
  Download,
} from "lucide-react";
import { motion } from "framer-motion";
import { toast } from "sonner";

const mockHistory = [
  {
    id: "scan-001",
    target: "192.168.1.0/24",
    profile: "Standard Scan",
    status: "completed",
    hostsUp: 12,
    openPorts: 342,
    startTime: "2026-02-17 06:30:00",
    duration: "2m 14s",
    initiatedBy: "admin",
  },
  {
    id: "scan-002",
    target: "10.0.0.0/16",
    profile: "Quick Scan",
    status: "completed",
    hostsUp: 45,
    openPorts: 128,
    startTime: "2026-02-16 14:22:00",
    duration: "5m 32s",
    initiatedBy: "admin",
  },
  {
    id: "scan-003",
    target: "172.16.0.1-50",
    profile: "Vulnerability Scan",
    status: "running",
    hostsUp: 8,
    openPorts: 67,
    startTime: "2026-02-17 07:15:00",
    duration: "—",
    initiatedBy: "analyst",
  },
  {
    id: "scan-004",
    target: "scanme.nmap.org",
    profile: "Intense Scan",
    status: "completed",
    hostsUp: 1,
    openPorts: 4,
    startTime: "2026-02-15 09:00:00",
    duration: "1m 05s",
    initiatedBy: "admin",
  },
  {
    id: "scan-005",
    target: "192.168.2.0/24",
    profile: "OS Detection",
    status: "failed",
    hostsUp: 0,
    openPorts: 0,
    startTime: "2026-02-14 18:45:00",
    duration: "0m 12s",
    initiatedBy: "analyst",
  },
  {
    id: "scan-006",
    target: "10.10.10.0/24",
    profile: "Stealth Scan",
    status: "completed",
    hostsUp: 23,
    openPorts: 89,
    startTime: "2026-02-13 11:30:00",
    duration: "8m 47s",
    initiatedBy: "admin",
  },
];

function StatusIcon({ status }: { status: string }) {
  switch (status) {
    case "completed":
      return <CheckCircle className="w-4 h-4 text-green-400" />;
    case "running":
      return <Loader2 className="w-4 h-4 text-purple-400 animate-spin" />;
    case "failed":
      return <XCircle className="w-4 h-4 text-red-400" />;
    default:
      return <Clock className="w-4 h-4 text-muted-foreground" />;
  }
}

function StatusBadge({ status }: { status: string }) {
  const styles: Record<string, string> = {
    completed: "bg-green-500/15 text-green-400 border-green-500/30",
    running: "bg-purple-500/15 text-purple-400 border-purple-500/30",
    failed: "bg-red-500/15 text-red-400 border-red-500/30",
  };
  return (
    <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded text-[11px] font-medium border ${styles[status] || ""}`}>
      <StatusIcon status={status} />
      {status}
    </span>
  );
}

export default function ScanHistory() {
  const [searchQuery, setSearchQuery] = useState("");
  const [statusFilter, setStatusFilter] = useState("all");

  const filtered = mockHistory.filter((scan) => {
    const matchesSearch = scan.target.toLowerCase().includes(searchQuery.toLowerCase()) ||
      scan.profile.toLowerCase().includes(searchQuery.toLowerCase());
    const matchesStatus = statusFilter === "all" || scan.status === statusFilter;
    return matchesSearch && matchesStatus;
  });

  return (
    <div className="space-y-6">
      {/* Header */}
      <motion.div
        initial={{ opacity: 0, y: 10 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.4 }}
      >
        <div className="flex items-center gap-2 mb-1">
          <History className="w-4 h-4 text-orange-400" />
          <span className="text-[11px] font-semibold tracking-[0.2em] uppercase text-orange-400">
            Scan Archive
          </span>
        </div>
        <h2 className="text-2xl font-bold text-foreground font-[Outfit]">Scan History</h2>
        <p className="text-sm text-muted-foreground mt-1">
          Browse, filter, and review all previous scan operations.
        </p>
      </motion.div>

      {/* Filters */}
      <motion.div
        initial={{ opacity: 0, y: 10 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.4, delay: 0.1 }}
      >
        <Card className="border-border/50 bg-card/80">
          <CardContent className="p-4">
            <div className="flex flex-col sm:flex-row gap-3">
              <div className="flex-1 relative">
                <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
                <Input
                  placeholder="Search by target or profile..."
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  className="pl-9 bg-input/50 border-border/50 text-sm"
                />
              </div>
              <Select value={statusFilter} onValueChange={setStatusFilter}>
                <SelectTrigger className="w-full sm:w-[160px] bg-input/50 border-border/50">
                  <Filter className="w-3.5 h-3.5 mr-2 text-muted-foreground" />
                  <SelectValue placeholder="Status" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">All Status</SelectItem>
                  <SelectItem value="completed">Completed</SelectItem>
                  <SelectItem value="running">Running</SelectItem>
                  <SelectItem value="failed">Failed</SelectItem>
                </SelectContent>
              </Select>
              <Button variant="outline" size="sm" className="border-border/50 gap-1.5" onClick={() => toast("Feature coming soon")}>
                <Download className="w-3.5 h-3.5" /> Export CSV
              </Button>
            </div>
          </CardContent>
        </Card>
      </motion.div>

      {/* Scan list */}
      <div className="space-y-3">
        {filtered.map((scan, i) => (
          <motion.div
            key={scan.id}
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.3, delay: 0.1 + i * 0.05 }}
          >
            <Card className="border-border/50 bg-card/80 card-hover">
              <CardContent className="p-4">
                <div className="flex flex-col sm:flex-row sm:items-center gap-3">
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 mb-1.5">
                      <code className="text-sm font-mono text-foreground font-medium">{scan.target}</code>
                      <StatusBadge status={scan.status} />
                    </div>
                    <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-[11px] text-muted-foreground">
                      <span className="flex items-center gap-1">
                        <Clock className="w-3 h-3" /> {scan.startTime}
                      </span>
                      <span>{scan.profile}</span>
                      <span>Duration: {scan.duration}</span>
                      <span>By: {scan.initiatedBy}</span>
                    </div>
                  </div>
                  <div className="flex items-center gap-4 sm:gap-6">
                    <div className="text-center">
                      <p className="text-lg font-bold text-foreground font-[Outfit]">{scan.hostsUp}</p>
                      <p className="text-[10px] text-muted-foreground">Hosts</p>
                    </div>
                    <div className="text-center">
                      <p className="text-lg font-bold text-foreground font-[Outfit]">{scan.openPorts}</p>
                      <p className="text-[10px] text-muted-foreground">Ports</p>
                    </div>
                    <Link href={`/scan/results/${scan.id}`}>
                      <Button variant="ghost" size="sm" className="text-xs text-muted-foreground hover:text-foreground gap-1">
                        View <ArrowUpRight className="w-3 h-3" />
                      </Button>
                    </Link>
                  </div>
                </div>
              </CardContent>
            </Card>
          </motion.div>
        ))}
      </div>

      {filtered.length === 0 && (
        <Card className="border-border/50 bg-card/80">
          <CardContent className="p-8 text-center">
            <Search className="w-8 h-8 text-muted-foreground mx-auto mb-3" />
            <p className="text-sm text-muted-foreground">No scans match your filters</p>
          </CardContent>
        </Card>
      )}
    </div>
  );
}
