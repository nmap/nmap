/*
 * Home — Command Center Dashboard
 * Spectra Command Dark Theme
 * Sections: Hero banner, Stat cards, Quick actions, Charts, Recent threats, Active investigations
 */
import { useState, useEffect } from "react";
import { Link } from "wouter";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import {
  Crosshair,
  Search,
  Globe,
  FileText,
  Layers,
  Zap,
  Shield,
  AlertTriangle,
  ArrowUpRight,
  Activity,
  Upload,
  Eye,
  Target,
  Cpu,
  Radio,
} from "lucide-react";
import {
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip as RechartsTooltip,
  ResponsiveContainer,
  Legend,
  PieChart,
  Pie,
  Cell,
} from "recharts";
import { motion } from "framer-motion";
import WorldMap from "@/components/WorldMap";

const HERO_IMAGE = "https://private-us-east-1.manuscdn.com/sessionFile/lPjfb29pgYeS2MTiIzmJY7/sandbox/nzEOAhVoSOSinYNAfaFTry-img-1_1771331593000_na1fn_aGVyby1iYW5uZXItdjI.png?x-oss-process=image/resize,w_1920,h_1920/format,webp/quality,q_80&Expires=1798761600&Policy=eyJTdGF0ZW1lbnQiOlt7IlJlc291cmNlIjoiaHR0cHM6Ly9wcml2YXRlLXVzLWVhc3QtMS5tYW51c2Nkbi5jb20vc2Vzc2lvbkZpbGUvbFBqZmIyOXBnWWVTMk1UaUl6bUpZNy9zYW5kYm94L256RU9BaFZvU09TaW5ZTkFmYUZUcnktaW1nLTFfMTc3MTMzMTU5MzAwMF9uYTFmbl9hR1Z5YnkxaVlXNXVaWEl0ZGpJLnBuZz94LW9zcy1wcm9jZXNzPWltYWdlL3Jlc2l6ZSx3XzE5MjAsaF8xOTIwL2Zvcm1hdCx3ZWJwL3F1YWxpdHkscV84MCIsIkNvbmRpdGlvbiI6eyJEYXRlTGVzc1RoYW4iOnsiQVdTOkVwb2NoVGltZSI6MTc5ODc2MTYwMH19fV19&Key-Pair-Id=K2HSFNDJXOU9YS&Signature=gsqZhDnT7BIbJFrxrNvV2lQTaJTPmxTc7cQHF68dlt0Qn5Ap2Iawzr1pay9BbQ4m~B7K3ctor2riwOzv26NVAJDRI~WLirp~QpHv6eWbvcYEZZk34YFShnrUZp5vSkM4m-WK1ZsJ~m8kUuo8-ItT4J4vPZbrL9iZHv9dDF~ZecwzfR1~X7t1rchjAkK9i6LsYKB~64mA1xOh4tbXyWx0spzy5GU8zmy1nZh1GRU9WCArnnhgAtzG76QPdRZB0NuXYgm0swo~pjmgI6gUQ8CDMsj8a8YX6F-tu0P0gjMLYgpid0gOtvPZIlznh5Qm3Lk1nrO-825lsH49CO0J5Lcs1A__";

// Mock data for charts
const detectionTrendData = [
  { date: "02-11", lookups: 2, scans: 1, threats: 0 },
  { date: "02-12", lookups: 3, scans: 2, threats: 0 },
  { date: "02-13", lookups: 1, scans: 3, threats: 1 },
  { date: "02-14", lookups: 4, scans: 2, threats: 0 },
  { date: "02-15", lookups: 2, scans: 4, threats: 0 },
  { date: "02-16", lookups: 3, scans: 1, threats: 0 },
  { date: "02-17", lookups: 1, scans: 3, threats: 0 },
];

const severityData = [
  { name: "Critical", value: 2, color: "#EF4444" },
  { name: "High", value: 5, color: "#F97316" },
  { name: "Medium", value: 12, color: "#EAB308" },
  { name: "Low", value: 23, color: "#10B981" },
  { name: "Info", value: 45, color: "#06B6D4" },
];

const statCards = [
  { label: "Scans (7d)", value: 14, sub: "3 active", icon: Crosshair, color: "text-purple-400", bgColor: "bg-purple-500/10" },
  { label: "Hosts Found", value: 87, sub: "12 new", icon: Globe, color: "text-cyan-400", bgColor: "bg-cyan-500/10" },
  { label: "Open Ports", value: 342, sub: "across all hosts", icon: Layers, color: "text-green-400", bgColor: "bg-green-500/10" },
  { label: "Vulnerabilities", value: 7, sub: "2 critical", icon: AlertTriangle, color: "text-orange-400", bgColor: "bg-orange-500/10" },
  { label: "Active Alerts", value: 3, sub: "", icon: Shield, color: "text-red-400", bgColor: "bg-red-500/10" },
];

const quickActions = [
  { label: "Quick Scan", icon: Crosshair, href: "/scan/new", color: "text-purple-400", borderColor: "border-purple-500/30", hoverBg: "hover:bg-purple-500/10" },
  { label: "Host Lookup", icon: Search, href: "/scan/new", color: "text-cyan-400", borderColor: "border-cyan-500/30", hoverBg: "hover:bg-cyan-500/10" },
  { label: "Port Discovery", icon: Target, href: "/scan/new", color: "text-green-400", borderColor: "border-green-500/30", hoverBg: "hover:bg-green-500/10" },
  { label: "OS Detection", icon: Cpu, href: "/scan/new", color: "text-orange-400", borderColor: "border-orange-500/30", hoverBg: "hover:bg-orange-500/10" },
  { label: "Service Scan", icon: Radio, href: "/scan/new", color: "text-yellow-400", borderColor: "border-yellow-500/30", hoverBg: "hover:bg-yellow-500/10" },
  { label: "Vuln Assessment", icon: Shield, href: "/scan/new", color: "text-red-400", borderColor: "border-red-500/30", hoverBg: "hover:bg-red-500/10" },
];

const recentThreats = [
  { host: "192.168.1.45", severity: "Critical", service: "SSH (22)", finding: "Weak cipher suites detected", time: "2m ago" },
  { host: "10.0.0.12", severity: "High", service: "HTTP (80)", finding: "Outdated Apache 2.4.29", time: "15m ago" },
  { host: "172.16.0.8", severity: "Medium", service: "SMB (445)", finding: "SMBv1 enabled", time: "1h ago" },
];

const activeInvestigations = [
  { name: "Subnet 192.168.1.0/24 Audit", status: "In Progress", scans: 4, findings: 12 },
  { name: "DMZ Perimeter Check", status: "Queued", scans: 0, findings: 0 },
  { name: "Production DB Servers", status: "Completed", scans: 3, findings: 7 },
];

function AnimatedCounter({ target, duration = 1500 }: { target: number; duration?: number }) {
  const [count, setCount] = useState(0);
  useEffect(() => {
    let start = 0;
    const step = target / (duration / 16);
    const timer = setInterval(() => {
      start += step;
      if (start >= target) {
        setCount(target);
        clearInterval(timer);
      } else {
        setCount(Math.floor(start));
      }
    }, 16);
    return () => clearInterval(timer);
  }, [target, duration]);
  return <>{count}</>;
}

function SeverityBadge({ severity }: { severity: string }) {
  const colors: Record<string, string> = {
    Critical: "bg-red-500/20 text-red-400 border-red-500/30",
    High: "bg-orange-500/20 text-orange-400 border-orange-500/30",
    Medium: "bg-yellow-500/20 text-yellow-400 border-yellow-500/30",
    Low: "bg-green-500/20 text-green-400 border-green-500/30",
  };
  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded text-[11px] font-medium border ${colors[severity] || "bg-muted text-muted-foreground"}`}>
      {severity}
    </span>
  );
}

function StatusBadge({ status }: { status: string }) {
  const colors: Record<string, string> = {
    "In Progress": "bg-purple-500/20 text-purple-400",
    Queued: "bg-yellow-500/20 text-yellow-400",
    Completed: "bg-green-500/20 text-green-400",
  };
  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded text-[11px] font-medium ${colors[status] || "bg-muted text-muted-foreground"}`}>
      {status}
    </span>
  );
}

export default function Home() {
  return (
    <div className="space-y-6">
      {/* Hero Banner */}
      <motion.div
        initial={{ opacity: 0, y: 10 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.5 }}
        className="relative rounded-xl overflow-hidden"
      >
        <div className="absolute inset-0">
          <img
            src={HERO_IMAGE}
            alt=""
            className="w-full h-full object-cover opacity-60"
          />
          <div className="absolute inset-0 bg-gradient-to-r from-background via-background/80 to-transparent" />
          <div className="absolute inset-0 bg-gradient-to-t from-background via-transparent to-transparent" />
        </div>
        <div className="relative px-6 py-8 lg:px-8 lg:py-10">
          <div className="flex items-center gap-2 mb-3">
            <Crosshair className="w-4 h-4 text-purple-400" />
            <span className="text-[11px] font-semibold tracking-[0.2em] uppercase text-purple-400">
              Analyst View
            </span>
          </div>
          <h2 className="text-2xl lg:text-3xl font-bold text-foreground font-[Outfit] mb-2">
            NMAP Command Center
          </h2>
          <p className="text-sm text-muted-foreground max-w-lg">
            Enterprise-grade network scanning, host discovery, and vulnerability assessment powered by Nmap.
            Safe by construction, auditable, and scalable.
          </p>
        </div>
      </motion.div>

      {/* Stat Cards */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-3 lg:gap-4">
        {statCards.map((stat, i) => {
          const Icon = stat.icon;
          return (
            <motion.div
              key={stat.label}
              initial={{ opacity: 0, y: 15 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.4, delay: i * 0.08 }}
            >
              <Card className="card-hover border-border/50 bg-card/80 backdrop-blur-sm">
                <CardContent className="p-4">
                  <div className="flex items-start justify-between mb-3">
                    <span className="text-xs text-muted-foreground">{stat.label}</span>
                    <div className={`flex items-center justify-center w-8 h-8 rounded-lg ${stat.bgColor}`}>
                      <Icon className={`w-4 h-4 ${stat.color}`} />
                    </div>
                  </div>
                  <div className="text-2xl font-bold text-foreground font-[Outfit]">
                    <AnimatedCounter target={stat.value} />
                  </div>
                  {stat.sub && (
                    <p className="text-[11px] text-muted-foreground mt-1">{stat.sub}</p>
                  )}
                </CardContent>
              </Card>
            </motion.div>
          );
        })}
      </div>

      {/* Quick Actions */}
      <motion.div
        initial={{ opacity: 0, y: 15 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.4, delay: 0.3 }}
      >
        <Card className="border-border/50 bg-card/80 backdrop-blur-sm">
          <CardHeader className="pb-3">
            <div className="flex items-center gap-2">
              <Zap className="w-4 h-4 text-yellow-400" />
              <div>
                <CardTitle className="text-base font-semibold font-[Outfit]">Quick Actions</CardTitle>
                <p className="text-xs text-muted-foreground mt-0.5">Common scanning workflows</p>
              </div>
            </div>
          </CardHeader>
          <CardContent className="pt-0">
            <div className="grid grid-cols-2 sm:grid-cols-3 gap-2">
              {quickActions.map((action) => {
                const Icon = action.icon;
                return (
                  <Link key={action.label} href={action.href}>
                    <div
                      className={`flex items-center gap-2.5 px-3 py-2.5 rounded-lg border ${action.borderColor} bg-transparent ${action.hoverBg} transition-all duration-200 cursor-pointer`}
                    >
                      <Icon className={`w-4 h-4 ${action.color} shrink-0`} />
                      <span className={`text-sm font-medium ${action.color}`}>{action.label}</span>
                    </div>
                  </Link>
                );
              })}
            </div>
          </CardContent>
        </Card>
      </motion.div>

      {/* World Map — Geographic Scan Targets */}
      <motion.div
        initial={{ opacity: 0, y: 15 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.4, delay: 0.35 }}
      >
        <Card className="border-border/50 bg-card/80 backdrop-blur-sm overflow-hidden">
          <CardHeader className="pb-2">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <Globe className="w-4 h-4 text-cyan-400" />
                <div>
                  <CardTitle className="text-base font-semibold font-[Outfit]">Global Scan Targets</CardTitle>
                  <p className="text-xs text-muted-foreground mt-0.5">Geographic distribution of scanned infrastructure</p>
                </div>
              </div>
              <div className="flex items-center gap-2 text-[11px] text-muted-foreground">
                <span className="flex items-center gap-1"><span className="w-1.5 h-1.5 rounded-full bg-green-400" />7 regions</span>
                <span className="flex items-center gap-1"><span className="w-1.5 h-1.5 rounded-full bg-cyan-400 animate-pulse" />1 scanning</span>
              </div>
            </div>
          </CardHeader>
          <CardContent className="pt-0 pb-2">
            <WorldMap />
          </CardContent>
        </Card>
      </motion.div>

      {/* Charts Row */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        {/* Detection Trend */}
        <motion.div
          className="lg:col-span-2"
          initial={{ opacity: 0, y: 15 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.4, delay: 0.4 }}
        >
          <Card className="border-border/50 bg-card/80 backdrop-blur-sm h-full">
            <CardHeader className="pb-2">
              <div className="flex items-center justify-between">
                <div>
                  <CardTitle className="text-base font-semibold font-[Outfit]">Detection Trend</CardTitle>
                  <p className="text-xs text-muted-foreground mt-0.5">Last 7 days</p>
                </div>
              </div>
            </CardHeader>
            <CardContent className="pt-0">
              <div className="h-[260px]">
                <ResponsiveContainer width="100%" height="100%">
                  <LineChart data={detectionTrendData}>
                    <CartesianGrid strokeDasharray="3 3" stroke="rgba(139,92,246,0.08)" />
                    <XAxis
                      dataKey="date"
                      tick={{ fill: "rgba(255,255,255,0.4)", fontSize: 11 }}
                      axisLine={{ stroke: "rgba(255,255,255,0.1)" }}
                      tickLine={false}
                    />
                    <YAxis
                      tick={{ fill: "rgba(255,255,255,0.4)", fontSize: 11 }}
                      axisLine={{ stroke: "rgba(255,255,255,0.1)" }}
                      tickLine={false}
                    />
                    <RechartsTooltip
                      contentStyle={{
                        backgroundColor: "rgba(18,20,31,0.95)",
                        border: "1px solid rgba(139,92,246,0.2)",
                        borderRadius: "8px",
                        fontSize: "12px",
                      }}
                    />
                    <Legend
                      iconType="circle"
                      iconSize={8}
                      wrapperStyle={{ fontSize: "12px", paddingTop: "8px" }}
                    />
                    <Line type="monotone" dataKey="lookups" stroke="#8B5CF6" strokeWidth={2} dot={{ r: 3, fill: "#8B5CF6" }} />
                    <Line type="monotone" dataKey="scans" stroke="#10B981" strokeWidth={2} dot={{ r: 3, fill: "#10B981" }} />
                    <Line type="monotone" dataKey="threats" stroke="#EF4444" strokeWidth={2} dot={{ r: 3, fill: "#EF4444" }} />
                  </LineChart>
                </ResponsiveContainer>
              </div>
            </CardContent>
          </Card>
        </motion.div>

        {/* Severity Distribution */}
        <motion.div
          initial={{ opacity: 0, y: 15 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.4, delay: 0.5 }}
        >
          <Card className="border-border/50 bg-card/80 backdrop-blur-sm h-full">
            <CardHeader className="pb-2">
              <CardTitle className="text-base font-semibold font-[Outfit]">Threat Severity</CardTitle>
              <p className="text-xs text-muted-foreground">Last 30 days across all scans</p>
            </CardHeader>
            <CardContent className="pt-0">
              <div className="h-[200px]">
                <ResponsiveContainer width="100%" height="100%">
                  <PieChart>
                    <Pie
                      data={severityData}
                      cx="50%"
                      cy="50%"
                      innerRadius={50}
                      outerRadius={80}
                      paddingAngle={3}
                      dataKey="value"
                    >
                      {severityData.map((entry, index) => (
                        <Cell key={`cell-${index}`} fill={entry.color} />
                      ))}
                    </Pie>
                    <RechartsTooltip
                      contentStyle={{
                        backgroundColor: "rgba(18,20,31,0.95)",
                        border: "1px solid rgba(139,92,246,0.2)",
                        borderRadius: "8px",
                        fontSize: "12px",
                      }}
                    />
                  </PieChart>
                </ResponsiveContainer>
              </div>
              <div className="flex flex-wrap gap-x-4 gap-y-1 justify-center mt-1">
                {severityData.map((item) => (
                  <div key={item.name} className="flex items-center gap-1.5 text-[11px] text-muted-foreground">
                    <span className="w-2 h-2 rounded-full" style={{ backgroundColor: item.color }} />
                    {item.name} ({item.value})
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        </motion.div>
      </div>

      {/* Bottom Row: Recent Threats + Active Investigations */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {/* Recent Threats */}
        <motion.div
          initial={{ opacity: 0, y: 15 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.4, delay: 0.6 }}
        >
          <Card className="border-border/50 bg-card/80 backdrop-blur-sm">
            <CardHeader className="pb-3">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <AlertTriangle className="w-4 h-4 text-red-400" />
                  <div>
                    <CardTitle className="text-base font-semibold font-[Outfit]">Recent Threats</CardTitle>
                    <p className="text-xs text-muted-foreground mt-0.5">High-severity detections</p>
                  </div>
                </div>
                <Link href="/scan/results">
                  <Button variant="ghost" size="sm" className="text-xs text-muted-foreground hover:text-foreground gap-1">
                    View All <ArrowUpRight className="w-3 h-3" />
                  </Button>
                </Link>
              </div>
            </CardHeader>
            <CardContent className="pt-0">
              <div className="space-y-3">
                {recentThreats.map((threat, i) => (
                  <div
                    key={i}
                    className="flex items-start gap-3 p-3 rounded-lg bg-background/50 border border-border/30 hover:border-border/60 transition-colors"
                  >
                    <div className="mt-0.5">
                      <AlertTriangle className={`w-4 h-4 ${threat.severity === "Critical" ? "text-red-400" : threat.severity === "High" ? "text-orange-400" : "text-yellow-400"}`} />
                    </div>
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2 mb-1">
                        <code className="text-xs font-mono text-foreground">{threat.host}</code>
                        <SeverityBadge severity={threat.severity} />
                      </div>
                      <p className="text-xs text-muted-foreground">{threat.finding}</p>
                      <div className="flex items-center gap-2 mt-1.5 text-[10px] text-muted-foreground">
                        <span>{threat.service}</span>
                        <span>·</span>
                        <span>{threat.time}</span>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        </motion.div>

        {/* Active Investigations */}
        <motion.div
          initial={{ opacity: 0, y: 15 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.4, delay: 0.7 }}
        >
          <Card className="border-border/50 bg-card/80 backdrop-blur-sm">
            <CardHeader className="pb-3">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <Shield className="w-4 h-4 text-purple-400" />
                  <div>
                    <CardTitle className="text-base font-semibold font-[Outfit]">Active Investigations</CardTitle>
                    <p className="text-xs text-muted-foreground mt-0.5">Ongoing scan campaigns</p>
                  </div>
                </div>
                <Link href="/history">
                  <Button variant="ghost" size="sm" className="text-xs text-muted-foreground hover:text-foreground gap-1">
                    View All <ArrowUpRight className="w-3 h-3" />
                  </Button>
                </Link>
              </div>
            </CardHeader>
            <CardContent className="pt-0">
              <div className="space-y-3">
                {activeInvestigations.map((inv, i) => (
                  <div
                    key={i}
                    className="flex items-center gap-3 p-3 rounded-lg bg-background/50 border border-border/30 hover:border-border/60 transition-colors"
                  >
                    <div className="flex items-center justify-center w-8 h-8 rounded-lg bg-purple-500/10 shrink-0">
                      <Activity className="w-4 h-4 text-purple-400" />
                    </div>
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2 mb-1">
                        <span className="text-sm font-medium text-foreground truncate">{inv.name}</span>
                        <StatusBadge status={inv.status} />
                      </div>
                      <div className="flex items-center gap-3 text-[11px] text-muted-foreground">
                        <span>{inv.scans} scans</span>
                        <span>·</span>
                        <span>{inv.findings} findings</span>
                      </div>
                    </div>
                    <ArrowUpRight className="w-4 h-4 text-muted-foreground shrink-0" />
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        </motion.div>
      </div>
    </div>
  );
}
