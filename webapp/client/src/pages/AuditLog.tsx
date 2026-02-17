/*
 * AuditLog — Security Audit Trail
 * Spectra Command Dark Theme
 */
import { useState } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import {
  Shield,
  Search,
  Filter,
  Clock,
  User,
  Crosshair,
  Settings,
  LogIn,
  LogOut,
  AlertTriangle,
  Download,
  Eye,
} from "lucide-react";
import { motion } from "framer-motion";
import { toast } from "sonner";

const THREAT_MAP_IMAGE = "https://private-us-east-1.manuscdn.com/sessionFile/lPjfb29pgYeS2MTiIzmJY7/sandbox/nzEOAhVoSOSinYNAfaFTry-img-3_1771331600000_na1fn_dGhyZWF0LW1hcC12Mg.png?x-oss-process=image/resize,w_1920,h_1920/format,webp/quality,q_80&Expires=1798761600&Policy=eyJTdGF0ZW1lbnQiOlt7IlJlc291cmNlIjoiaHR0cHM6Ly9wcml2YXRlLXVzLWVhc3QtMS5tYW51c2Nkbi5jb20vc2Vzc2lvbkZpbGUvbFBqZmIyOXBnWWVTMk1UaUl6bUpZNy9zYW5kYm94L256RU9BaFZvU09TaW5ZTkFmYUZUcnktaW1nLTNfMTc3MTMzMTYwMDAwMF9uYTFmbl9kR2h5WldGMExXMWhjQzEyTWcucG5nP3gtb3NzLXByb2Nlc3M9aW1hZ2UvcmVzaXplLHdfMTkyMCxoXzE5MjAvZm9ybWF0LHdlYnAvcXVhbGl0eSxxXzgwIiwiQ29uZGl0aW9uIjp7IkRhdGVMZXNzVGhhbiI6eyJBV1M6RXBvY2hUaW1lIjoxNzk4NzYxNjAwfX19XX0_&Key-Pair-Id=K2HSFNDJXOU9YS&Signature=KtpOFEEmVnDywa0ZXR9K9MSqAprYKhV-N3dD2yohZC1McBINJv5SUf-YSRQrgksSJqZlDzwp2-HMtJdjMlfwRaJuToTndIuWIl~1qmwnvcv4A8JGkfNJfdaLpY803AxQzIHIQG9cuz2MC~vukuevKizdHkEr120z85PXAmHSVfxhQ~ObNaVMNBE9RW2KyBIE0HsRK5cpuIxHsbwQQHOD2H0NvEaN4rdO1LRkXWQjRnPF0W~sNN3UaB9JInGkmQ37KFh3oalycvQZ6r38VN7y26p6QRx86nnZdU145nxKv0NfRSSAbcKenUazfuXqeJVDvpwSY7i2bl0GcrTq5r7aiQ__";

type AuditAction = "scan_initiated" | "scan_completed" | "login" | "logout" | "settings_changed" | "alert_triggered" | "export_requested";

interface AuditEntry {
  id: string;
  timestamp: string;
  action: AuditAction;
  user: string;
  details: string;
  ip: string;
  severity: "info" | "warning" | "critical";
}

const mockAuditLog: AuditEntry[] = [
  { id: "a1", timestamp: "2026-02-17 07:35:12", action: "scan_initiated", user: "admin", details: "Initiated Standard Scan on 192.168.1.0/24", ip: "10.0.0.5", severity: "info" },
  { id: "a2", timestamp: "2026-02-17 07:32:14", action: "scan_completed", user: "system", details: "Scan scan-001 completed. 12 hosts up, 342 open ports.", ip: "—", severity: "info" },
  { id: "a3", timestamp: "2026-02-17 07:30:00", action: "scan_initiated", user: "admin", details: "Initiated Standard Scan on 192.168.1.0/24", ip: "10.0.0.5", severity: "info" },
  { id: "a4", timestamp: "2026-02-17 07:15:00", action: "alert_triggered", user: "system", details: "Critical: SMBv1 detected on 192.168.1.45:445", ip: "—", severity: "critical" },
  { id: "a5", timestamp: "2026-02-17 06:45:00", action: "login", user: "admin", details: "Successful login via SAML/Google Workspace", ip: "10.0.0.5", severity: "info" },
  { id: "a6", timestamp: "2026-02-16 22:30:00", action: "settings_changed", user: "admin", details: "Updated CIDR allowlist: added 172.16.0.0/12", ip: "10.0.0.5", severity: "warning" },
  { id: "a7", timestamp: "2026-02-16 18:00:00", action: "export_requested", user: "analyst", details: "Exported scan-002 results as JSON", ip: "10.0.0.8", severity: "info" },
  { id: "a8", timestamp: "2026-02-16 14:22:00", action: "scan_initiated", user: "admin", details: "Initiated Quick Scan on 10.0.0.0/16", ip: "10.0.0.5", severity: "info" },
  { id: "a9", timestamp: "2026-02-16 09:00:00", action: "login", user: "analyst", details: "Successful login via SAML/Google Workspace", ip: "10.0.0.8", severity: "info" },
  { id: "a10", timestamp: "2026-02-15 16:30:00", action: "logout", user: "admin", details: "Session ended", ip: "10.0.0.5", severity: "info" },
];

function ActionIcon({ action }: { action: AuditAction }) {
  const icons: Record<AuditAction, React.ReactNode> = {
    scan_initiated: <Crosshair className="w-3.5 h-3.5 text-purple-400" />,
    scan_completed: <Crosshair className="w-3.5 h-3.5 text-green-400" />,
    login: <LogIn className="w-3.5 h-3.5 text-cyan-400" />,
    logout: <LogOut className="w-3.5 h-3.5 text-muted-foreground" />,
    settings_changed: <Settings className="w-3.5 h-3.5 text-yellow-400" />,
    alert_triggered: <AlertTriangle className="w-3.5 h-3.5 text-red-400" />,
    export_requested: <Download className="w-3.5 h-3.5 text-cyan-400" />,
  };
  return <>{icons[action]}</>;
}

function SeverityDot({ severity }: { severity: string }) {
  const colors: Record<string, string> = {
    info: "bg-cyan-400",
    warning: "bg-yellow-400",
    critical: "bg-red-400",
  };
  return <span className={`w-1.5 h-1.5 rounded-full ${colors[severity] || "bg-muted-foreground"}`} />;
}

export default function AuditLog() {
  const [searchQuery, setSearchQuery] = useState("");

  const filtered = mockAuditLog.filter((entry) =>
    entry.details.toLowerCase().includes(searchQuery.toLowerCase()) ||
    entry.user.toLowerCase().includes(searchQuery.toLowerCase()) ||
    entry.action.toLowerCase().includes(searchQuery.toLowerCase())
  );

  return (
    <div className="space-y-6">
      {/* Header with threat map */}
      <motion.div
        initial={{ opacity: 0, y: 10 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.4 }}
        className="relative rounded-xl overflow-hidden"
      >
        <div className="absolute inset-0">
          <img src={THREAT_MAP_IMAGE} alt="" className="w-full h-full object-cover opacity-30" />
          <div className="absolute inset-0 bg-gradient-to-r from-background via-background/90 to-background/70" />
        </div>
        <div className="relative px-6 py-8">
          <div className="flex items-center gap-2 mb-1">
            <Shield className="w-4 h-4 text-green-400" />
            <span className="text-[11px] font-semibold tracking-[0.2em] uppercase text-green-400">
              Security Audit
            </span>
          </div>
          <h2 className="text-2xl font-bold text-foreground font-[Outfit]">Audit Log</h2>
          <p className="text-sm text-muted-foreground mt-1">
            Complete audit trail of all system actions. Who scanned what, when, and from where.
          </p>
        </div>
      </motion.div>

      {/* Search */}
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
                  placeholder="Search audit entries..."
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  className="pl-9 bg-input/50 border-border/50 text-sm"
                />
              </div>
              <Button variant="outline" size="sm" className="border-border/50 gap-1.5" onClick={() => toast("Feature coming soon")}>
                <Download className="w-3.5 h-3.5" /> Export Log
              </Button>
            </div>
          </CardContent>
        </Card>
      </motion.div>

      {/* Audit entries */}
      <div className="space-y-2">
        {filtered.map((entry, i) => (
          <motion.div
            key={entry.id}
            initial={{ opacity: 0, y: 8 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.25, delay: 0.05 + i * 0.03 }}
          >
            <Card className="border-border/50 bg-card/80 hover:bg-card transition-colors">
              <CardContent className="p-4">
                <div className="flex items-start gap-3">
                  <div className="flex items-center justify-center w-8 h-8 rounded-lg bg-accent/50 shrink-0 mt-0.5">
                    <ActionIcon action={entry.action} />
                  </div>
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 mb-1">
                      <SeverityDot severity={entry.severity} />
                      <span className="text-sm text-foreground">{entry.details}</span>
                    </div>
                    <div className="flex flex-wrap items-center gap-x-3 gap-y-1 text-[11px] text-muted-foreground">
                      <span className="flex items-center gap-1">
                        <Clock className="w-3 h-3" />
                        <span className="font-mono">{entry.timestamp}</span>
                      </span>
                      <span className="flex items-center gap-1">
                        <User className="w-3 h-3" />
                        {entry.user}
                      </span>
                      <span className="font-mono">{entry.ip}</span>
                    </div>
                  </div>
                </div>
              </CardContent>
            </Card>
          </motion.div>
        ))}
      </div>
    </div>
  );
}
