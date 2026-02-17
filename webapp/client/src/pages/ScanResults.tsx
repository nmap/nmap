/*
 * ScanResults — Results Explorer
 * Spectra Command Dark Theme
 * Shows scan results with hosts, ports, services, and script output
 */
import { useState } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Progress } from "@/components/ui/progress";
import {
  FileSearch,
  Globe,
  Layers,
  Shield,
  Clock,
  ChevronRight,
  Download,
  Terminal,
  Server,
  Wifi,
  AlertTriangle,
  CheckCircle,
  Copy,
} from "lucide-react";
import { toast } from "sonner";
import { motion } from "framer-motion";

const SCAN_VIZ_IMAGE = "https://private-us-east-1.manuscdn.com/sessionFile/lPjfb29pgYeS2MTiIzmJY7/sandbox/nzEOAhVoSOSinYNAfaFTry-img-2_1771331581000_na1fn_c2Nhbi12aXotdjI.png?x-oss-process=image/resize,w_1920,h_1920/format,webp/quality,q_80&Expires=1798761600&Policy=eyJTdGF0ZW1lbnQiOlt7IlJlc291cmNlIjoiaHR0cHM6Ly9wcml2YXRlLXVzLWVhc3QtMS5tYW51c2Nkbi5jb20vc2Vzc2lvbkZpbGUvbFBqZmIyOXBnWWVTMk1UaUl6bUpZNy9zYW5kYm94L256RU9BaFZvU09TaW5ZTkFmYUZUcnktaW1nLTJfMTc3MTMzMTU4MTAwMF9uYTFmbl9jMk5oYmkxMmFYb3RkakkucG5nP3gtb3NzLXByb2Nlc3M9aW1hZ2UvcmVzaXplLHdfMTkyMCxoXzE5MjAvZm9ybWF0LHdlYnAvcXVhbGl0eSxxXzgwIiwiQ29uZGl0aW9uIjp7IkRhdGVMZXNzVGhhbiI6eyJBV1M6RXBvY2hUaW1lIjoxNzk4NzYxNjAwfX19XX0_&Key-Pair-Id=K2HSFNDJXOU9YS&Signature=N6DG34g1CO77WeMymZTgKkjHHXOOQwjw0RrkW8mNIZoL4I4ZZ7P5mfjEbEC41dhZE9aLDdRpoXls8z0F3dUIdGq3BNV0NcYR0waxPIvUZj1KmoXayDanYFBGpGWy~j8lusRI2H-EY~BDHNDZbbv5Mt2OR3N4hfsfVAi4o6ufHcLx~ujP6yRPsWWYfgqQxjoNNIeZU7niSX43f03XqNjuBh~ZOe5TG5m8Lf9t3nOWIQOxkFKHYNDiuaUqarcKnQvkkTJVulKHR3wb92yisd-1CSJM0fS9VD9t9eFcnps9CdxxZ0UtjkcnbwoINfH6Hmibbf8HU32qWi3RPq-DPfbsSw__";

// Mock scan result data
const mockScan = {
  id: "scan-001",
  target: "192.168.1.0/24",
  profile: "Standard Scan",
  status: "Completed",
  startTime: "2026-02-17 06:30:00",
  endTime: "2026-02-17 06:32:14",
  duration: "2m 14s",
  hostsUp: 12,
  hostsDown: 243,
  totalPorts: 342,
  command: "nmap -sS -sV -T4 192.168.1.0/24",
};

const mockHosts = [
  {
    ip: "192.168.1.1",
    hostname: "gateway.local",
    os: "Linux 5.x",
    status: "up",
    ports: [
      { port: 22, protocol: "tcp", state: "open", service: "ssh", version: "OpenSSH 8.9p1", risk: "low" },
      { port: 80, protocol: "tcp", state: "open", service: "http", version: "nginx 1.24.0", risk: "info" },
      { port: 443, protocol: "tcp", state: "open", service: "https", version: "nginx 1.24.0", risk: "info" },
    ],
  },
  {
    ip: "192.168.1.10",
    hostname: "webserver.local",
    os: "Ubuntu 22.04",
    status: "up",
    ports: [
      { port: 22, protocol: "tcp", state: "open", service: "ssh", version: "OpenSSH 8.9p1", risk: "low" },
      { port: 80, protocol: "tcp", state: "open", service: "http", version: "Apache 2.4.29", risk: "high" },
      { port: 3306, protocol: "tcp", state: "open", service: "mysql", version: "MySQL 5.7.42", risk: "medium" },
      { port: 8080, protocol: "tcp", state: "open", service: "http-proxy", version: "Jetty 9.4", risk: "medium" },
    ],
  },
  {
    ip: "192.168.1.45",
    hostname: "fileserver.local",
    os: "Windows Server 2019",
    status: "up",
    ports: [
      { port: 135, protocol: "tcp", state: "open", service: "msrpc", version: "Microsoft Windows RPC", risk: "medium" },
      { port: 139, protocol: "tcp", state: "open", service: "netbios-ssn", version: "Microsoft Windows netbios-ssn", risk: "high" },
      { port: 445, protocol: "tcp", state: "open", service: "microsoft-ds", version: "Windows Server 2019", risk: "critical" },
      { port: 3389, protocol: "tcp", state: "open", service: "ms-wbt-server", version: "Microsoft Terminal Services", risk: "high" },
    ],
  },
  {
    ip: "192.168.1.100",
    hostname: "printer.local",
    os: "HP JetDirect",
    status: "up",
    ports: [
      { port: 80, protocol: "tcp", state: "open", service: "http", version: "HP HTTP Server", risk: "info" },
      { port: 515, protocol: "tcp", state: "open", service: "printer", version: "HP JetDirect", risk: "low" },
      { port: 9100, protocol: "tcp", state: "open", service: "jetdirect", version: "", risk: "low" },
    ],
  },
];

function RiskBadge({ risk }: { risk: string }) {
  const colors: Record<string, string> = {
    critical: "bg-red-500/20 text-red-400 border-red-500/30",
    high: "bg-orange-500/20 text-orange-400 border-orange-500/30",
    medium: "bg-yellow-500/20 text-yellow-400 border-yellow-500/30",
    low: "bg-green-500/20 text-green-400 border-green-500/30",
    info: "bg-cyan-500/20 text-cyan-400 border-cyan-500/30",
  };
  return (
    <span className={`inline-flex items-center px-1.5 py-0.5 rounded text-[10px] font-medium border ${colors[risk] || ""}`}>
      {risk}
    </span>
  );
}

export default function ScanResults() {
  const [selectedHost, setSelectedHost] = useState<string | null>(mockHosts[0].ip);
  const activeHost = mockHosts.find((h) => h.ip === selectedHost);

  return (
    <div className="space-y-6">
      {/* Header */}
      <motion.div
        initial={{ opacity: 0, y: 10 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.4 }}
      >
        <div className="flex items-center gap-2 mb-1">
          <FileSearch className="w-4 h-4 text-cyan-400" />
          <span className="text-[11px] font-semibold tracking-[0.2em] uppercase text-cyan-400">
            Results Explorer
          </span>
        </div>
        <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
          <div>
            <h2 className="text-2xl font-bold text-foreground font-[Outfit]">Scan Results</h2>
            <p className="text-sm text-muted-foreground mt-1">
              <code className="font-mono text-xs">{mockScan.target}</code> — {mockScan.profile}
            </p>
          </div>
          <div className="flex items-center gap-2">
            <Button variant="outline" size="sm" className="gap-1.5 text-xs border-border/50" onClick={() => toast("Feature coming soon")}>
              <Download className="w-3.5 h-3.5" /> Export
            </Button>
            <Button variant="outline" size="sm" className="gap-1.5 text-xs border-border/50" onClick={() => toast("Feature coming soon")}>
              <Terminal className="w-3.5 h-3.5" /> Raw XML
            </Button>
          </div>
        </div>
      </motion.div>

      {/* Scan Summary */}
      <motion.div
        initial={{ opacity: 0, y: 10 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.4, delay: 0.1 }}
      >
        <Card className="border-border/50 bg-card/80">
          <CardContent className="p-4">
            <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-6 gap-4">
              <div>
                <p className="text-[11px] text-muted-foreground mb-1">Status</p>
                <div className="flex items-center gap-1.5">
                  <CheckCircle className="w-3.5 h-3.5 text-green-400" />
                  <span className="text-sm font-medium text-green-400">{mockScan.status}</span>
                </div>
              </div>
              <div>
                <p className="text-[11px] text-muted-foreground mb-1">Duration</p>
                <p className="text-sm font-medium text-foreground">{mockScan.duration}</p>
              </div>
              <div>
                <p className="text-[11px] text-muted-foreground mb-1">Hosts Up</p>
                <p className="text-sm font-medium text-foreground">{mockScan.hostsUp}</p>
              </div>
              <div>
                <p className="text-[11px] text-muted-foreground mb-1">Hosts Down</p>
                <p className="text-sm font-medium text-foreground">{mockScan.hostsDown}</p>
              </div>
              <div>
                <p className="text-[11px] text-muted-foreground mb-1">Open Ports</p>
                <p className="text-sm font-medium text-foreground">{mockScan.totalPorts}</p>
              </div>
              <div>
                <p className="text-[11px] text-muted-foreground mb-1">Started</p>
                <p className="text-sm font-medium text-foreground font-mono text-xs">{mockScan.startTime}</p>
              </div>
            </div>
            <div className="mt-3 pt-3 border-t border-border/30">
              <div className="flex items-center gap-2">
                <Terminal className="w-3.5 h-3.5 text-green-400 shrink-0" />
                <code className="text-xs font-mono text-green-400/80 truncate">{mockScan.command}</code>
                <Button
                  variant="ghost"
                  size="icon"
                  className="h-6 w-6 shrink-0"
                  onClick={() => {
                    navigator.clipboard.writeText(mockScan.command);
                    toast.success("Command copied");
                  }}
                >
                  <Copy className="w-3 h-3" />
                </Button>
              </div>
            </div>
          </CardContent>
        </Card>
      </motion.div>

      {/* Network Topology Visualization */}
      <motion.div
        initial={{ opacity: 0, y: 10 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.4, delay: 0.15 }}
      >
        <Card className="border-border/50 bg-card/80 overflow-hidden">
          <div className="relative h-48 lg:h-64">
            <img src={SCAN_VIZ_IMAGE} alt="Network topology" className="w-full h-full object-cover opacity-50" />
            <div className="absolute inset-0 bg-gradient-to-t from-card via-card/50 to-transparent" />
            <div className="absolute bottom-4 left-4">
              <p className="text-xs text-muted-foreground">Network Topology — {mockScan.hostsUp} hosts discovered</p>
            </div>
          </div>
        </Card>
      </motion.div>

      {/* Host List + Detail */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        {/* Host list */}
        <motion.div
          initial={{ opacity: 0, y: 10 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.4, delay: 0.2 }}
        >
          <Card className="border-border/50 bg-card/80">
            <CardHeader className="pb-3">
              <CardTitle className="text-base font-semibold font-[Outfit] flex items-center gap-2">
                <Globe className="w-4 h-4 text-cyan-400" />
                Discovered Hosts
              </CardTitle>
            </CardHeader>
            <CardContent className="pt-0 space-y-1">
              {mockHosts.map((host) => (
                <button
                  key={host.ip}
                  onClick={() => setSelectedHost(host.ip)}
                  className={`
                    w-full flex items-center gap-3 p-3 rounded-lg text-left transition-all duration-200
                    ${selectedHost === host.ip
                      ? "bg-purple-500/10 border border-purple-500/20"
                      : "hover:bg-accent/30 border border-transparent"
                    }
                  `}
                >
                  <div className="flex items-center justify-center w-8 h-8 rounded-lg bg-cyan-500/10 shrink-0">
                    <Server className="w-4 h-4 text-cyan-400" />
                  </div>
                  <div className="flex-1 min-w-0">
                    <code className="text-xs font-mono text-foreground">{host.ip}</code>
                    <p className="text-[10px] text-muted-foreground truncate">{host.hostname}</p>
                  </div>
                  <div className="text-right shrink-0">
                    <p className="text-[11px] text-muted-foreground">{host.ports.length} ports</p>
                  </div>
                  <ChevronRight className="w-4 h-4 text-muted-foreground shrink-0" />
                </button>
              ))}
            </CardContent>
          </Card>
        </motion.div>

        {/* Host detail */}
        <motion.div
          className="lg:col-span-2"
          initial={{ opacity: 0, y: 10 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.4, delay: 0.3 }}
        >
          {activeHost ? (
            <Card className="border-border/50 bg-card/80">
              <CardHeader className="pb-3">
                <div className="flex items-center justify-between">
                  <div>
                    <CardTitle className="text-base font-semibold font-[Outfit]">
                      <code className="font-mono">{activeHost.ip}</code>
                    </CardTitle>
                    <p className="text-xs text-muted-foreground mt-0.5">
                      {activeHost.hostname} — {activeHost.os}
                    </p>
                  </div>
                  <Badge variant="outline" className="text-green-400 border-green-500/30 bg-green-500/10">
                    {activeHost.status}
                  </Badge>
                </div>
              </CardHeader>
              <CardContent className="pt-0">
                <Tabs defaultValue="ports">
                  <TabsList className="bg-secondary/50 mb-3">
                    <TabsTrigger value="ports">Ports & Services</TabsTrigger>
                    <TabsTrigger value="scripts">Scripts</TabsTrigger>
                    <TabsTrigger value="raw">Raw Output</TabsTrigger>
                  </TabsList>

                  <TabsContent value="ports">
                    <div className="overflow-x-auto">
                      <table className="w-full text-sm">
                        <thead>
                          <tr className="border-b border-border/30">
                            <th className="text-left py-2 px-3 text-[11px] text-muted-foreground font-medium">Port</th>
                            <th className="text-left py-2 px-3 text-[11px] text-muted-foreground font-medium">State</th>
                            <th className="text-left py-2 px-3 text-[11px] text-muted-foreground font-medium">Service</th>
                            <th className="text-left py-2 px-3 text-[11px] text-muted-foreground font-medium">Version</th>
                            <th className="text-left py-2 px-3 text-[11px] text-muted-foreground font-medium">Risk</th>
                          </tr>
                        </thead>
                        <tbody>
                          {activeHost.ports.map((port) => (
                            <tr key={port.port} className="border-b border-border/20 hover:bg-accent/20 transition-colors">
                              <td className="py-2.5 px-3">
                                <code className="text-xs font-mono text-foreground">{port.port}/{port.protocol}</code>
                              </td>
                              <td className="py-2.5 px-3">
                                <span className="flex items-center gap-1.5 text-xs">
                                  <span className="w-1.5 h-1.5 rounded-full bg-green-400" />
                                  {port.state}
                                </span>
                              </td>
                              <td className="py-2.5 px-3 text-xs text-foreground">{port.service}</td>
                              <td className="py-2.5 px-3 text-xs text-muted-foreground font-mono">{port.version || "—"}</td>
                              <td className="py-2.5 px-3"><RiskBadge risk={port.risk} /></td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  </TabsContent>

                  <TabsContent value="scripts">
                    <div className="bg-background/80 rounded-lg p-4 border border-border/30 font-mono text-xs text-green-400/80 space-y-2">
                      <p><span className="text-muted-foreground">| </span>ssh-hostkey:</p>
                      <p><span className="text-muted-foreground">|   </span>3072 SHA256:xyzABC... (RSA)</p>
                      <p><span className="text-muted-foreground">|   </span>256 SHA256:defGHI... (ECDSA)</p>
                      <p><span className="text-muted-foreground">|_  </span>256 SHA256:jklMNO... (ED25519)</p>
                      <p className="mt-2"><span className="text-muted-foreground">| </span>http-server-header: nginx/1.24.0</p>
                      <p><span className="text-muted-foreground">|_</span>http-title: Welcome to nginx!</p>
                    </div>
                  </TabsContent>

                  <TabsContent value="raw">
                    <div className="bg-background/80 rounded-lg p-4 border border-border/30 font-mono text-xs text-foreground/70 max-h-[300px] overflow-y-auto space-y-1">
                      <p>Nmap scan report for {activeHost.ip} ({activeHost.hostname})</p>
                      <p>Host is up (0.0012s latency).</p>
                      <p>Not shown: {1000 - activeHost.ports.length} closed ports</p>
                      <p>PORT     STATE SERVICE       VERSION</p>
                      {activeHost.ports.map((p) => (
                        <p key={p.port}>
                          {String(p.port).padEnd(5)}/{p.protocol.padEnd(4)} {p.state.padEnd(6)} {p.service.padEnd(14)} {p.version}
                        </p>
                      ))}
                      <p className="mt-2">OS details: {activeHost.os}</p>
                      <p>Network Distance: 1 hop</p>
                    </div>
                  </TabsContent>
                </Tabs>
              </CardContent>
            </Card>
          ) : (
            <Card className="border-border/50 bg-card/80 flex items-center justify-center h-64">
              <p className="text-sm text-muted-foreground">Select a host to view details</p>
            </Card>
          )}
        </motion.div>
      </div>
    </div>
  );
}
