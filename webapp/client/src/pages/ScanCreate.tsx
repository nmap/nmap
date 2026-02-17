/*
 * ScanCreate — New Scan Configuration
 * Spectra Command Dark Theme
 * Guard-railed scan form with preset profiles and advanced options
 */
import { useState } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Label } from "@/components/ui/label";
import { Input } from "@/components/ui/input";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Switch } from "@/components/ui/switch";
import { Separator } from "@/components/ui/separator";
import {
  Crosshair,
  Play,
  Shield,
  Zap,
  Search,
  Cpu,
  Radio,
  AlertTriangle,
  Info,
  Terminal,
} from "lucide-react";
import { toast } from "sonner";
import { motion } from "framer-motion";

const scanProfiles = [
  {
    id: "quick",
    name: "Quick Scan",
    description: "Fast host discovery and common port check (-T4 -F)",
    icon: Zap,
    color: "text-green-400",
    borderColor: "border-green-500/30",
    flags: "-T4 -F",
  },
  {
    id: "standard",
    name: "Standard Scan",
    description: "SYN scan with service version detection (-sS -sV)",
    icon: Search,
    color: "text-cyan-400",
    borderColor: "border-cyan-500/30",
    flags: "-sS -sV",
  },
  {
    id: "intense",
    name: "Intense Scan",
    description: "Full TCP with OS detection and scripts (-sS -sV -O -A)",
    icon: Crosshair,
    color: "text-purple-400",
    borderColor: "border-purple-500/30",
    flags: "-sS -sV -O -A",
  },
  {
    id: "stealth",
    name: "Stealth Scan",
    description: "Low-profile SYN scan with timing control (-sS -T2)",
    icon: Shield,
    color: "text-yellow-400",
    borderColor: "border-yellow-500/30",
    flags: "-sS -T2",
  },
  {
    id: "vuln",
    name: "Vulnerability Scan",
    description: "Service detection with vuln scripts (--script vuln)",
    icon: AlertTriangle,
    color: "text-red-400",
    borderColor: "border-red-500/30",
    flags: "-sV --script vuln",
  },
  {
    id: "os",
    name: "OS Detection",
    description: "Operating system fingerprinting (-O --osscan-guess)",
    icon: Cpu,
    color: "text-orange-400",
    borderColor: "border-orange-500/30",
    flags: "-O --osscan-guess",
  },
];

const timingOptions = [
  { value: "T0", label: "T0 — Paranoid" },
  { value: "T1", label: "T1 — Sneaky" },
  { value: "T2", label: "T2 — Polite" },
  { value: "T3", label: "T3 — Normal" },
  { value: "T4", label: "T4 — Aggressive" },
  { value: "T5", label: "T5 — Insane" },
];

export default function ScanCreate() {
  const [selectedProfile, setSelectedProfile] = useState("quick");
  const [target, setTarget] = useState("");
  const [portRange, setPortRange] = useState("");
  const [timing, setTiming] = useState("T4");
  const [osDetection, setOsDetection] = useState(false);
  const [serviceVersion, setServiceVersion] = useState(true);
  const [scriptScan, setScriptScan] = useState(false);
  const [udpScan, setUdpScan] = useState(false);

  const selectedProfileData = scanProfiles.find((p) => p.id === selectedProfile);

  const buildCommand = () => {
    const parts = ["nmap"];
    if (selectedProfileData) parts.push(selectedProfileData.flags);
    if (portRange) parts.push(`-p ${portRange}`);
    if (osDetection && !selectedProfileData?.flags.includes("-O")) parts.push("-O");
    if (serviceVersion && !selectedProfileData?.flags.includes("-sV")) parts.push("-sV");
    if (scriptScan) parts.push("--script=default");
    if (udpScan) parts.push("-sU");
    parts.push(`-${timing}`);
    if (target) parts.push(target);
    return parts.join(" ");
  };

  const handleSubmit = () => {
    if (!target.trim()) {
      toast.error("Target required", { description: "Enter an IP address, hostname, or CIDR range" });
      return;
    }
    toast.success("Scan submitted", {
      description: `Scanning ${target} with ${selectedProfileData?.name} profile`,
    });
  };

  return (
    <div className="space-y-6 max-w-5xl">
      {/* Page header */}
      <motion.div
        initial={{ opacity: 0, y: 10 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.4 }}
      >
        <div className="flex items-center gap-2 mb-1">
          <Crosshair className="w-4 h-4 text-purple-400" />
          <span className="text-[11px] font-semibold tracking-[0.2em] uppercase text-purple-400">
            Scan Configuration
          </span>
        </div>
        <h2 className="text-2xl font-bold text-foreground font-[Outfit]">New Scan</h2>
        <p className="text-sm text-muted-foreground mt-1">
          Configure and launch a new network scan. All scans are validated, rate-limited, and audit-logged.
        </p>
      </motion.div>

      <Tabs defaultValue="guided" className="space-y-4">
        <TabsList className="bg-secondary/50">
          <TabsTrigger value="guided">Guided</TabsTrigger>
          <TabsTrigger value="advanced">Advanced</TabsTrigger>
        </TabsList>

        <TabsContent value="guided" className="space-y-4">
          {/* Target input */}
          <motion.div
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.4, delay: 0.1 }}
          >
            <Card className="border-border/50 bg-card/80">
              <CardContent className="p-5">
                <Label className="text-sm font-medium mb-2 block">Target</Label>
                <Input
                  placeholder="e.g., 192.168.1.0/24, scanme.nmap.org, 10.0.0.1-50"
                  value={target}
                  onChange={(e) => setTarget(e.target.value)}
                  className="bg-input/50 border-border/50 font-mono text-sm"
                />
                <p className="text-[11px] text-muted-foreground mt-2 flex items-center gap-1">
                  <Info className="w-3 h-3" />
                  Accepts IP addresses, hostnames, CIDR ranges, and IP ranges
                </p>
              </CardContent>
            </Card>
          </motion.div>

          {/* Scan Profiles */}
          <motion.div
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.4, delay: 0.2 }}
          >
            <Card className="border-border/50 bg-card/80">
              <CardHeader className="pb-3">
                <CardTitle className="text-base font-semibold font-[Outfit]">Scan Profile</CardTitle>
                <p className="text-xs text-muted-foreground">Select a pre-configured scan type</p>
              </CardHeader>
              <CardContent className="pt-0">
                <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-2">
                  {scanProfiles.map((profile) => {
                    const Icon = profile.icon;
                    const isSelected = selectedProfile === profile.id;
                    return (
                      <button
                        key={profile.id}
                        onClick={() => setSelectedProfile(profile.id)}
                        className={`
                          flex items-start gap-3 p-3 rounded-lg border text-left transition-all duration-200
                          ${isSelected
                            ? `${profile.borderColor} bg-purple-500/5 shadow-[inset_0_0_0_1px_rgba(139,92,246,0.15)]`
                            : "border-border/30 hover:border-border/60 hover:bg-accent/30"
                          }
                        `}
                      >
                        <div className={`mt-0.5 ${profile.color}`}>
                          <Icon className="w-4 h-4" />
                        </div>
                        <div>
                          <span className={`text-sm font-medium ${isSelected ? "text-foreground" : "text-muted-foreground"}`}>
                            {profile.name}
                          </span>
                          <p className="text-[11px] text-muted-foreground mt-0.5">{profile.description}</p>
                        </div>
                      </button>
                    );
                  })}
                </div>
              </CardContent>
            </Card>
          </motion.div>

          {/* Options */}
          <motion.div
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.4, delay: 0.3 }}
          >
            <Card className="border-border/50 bg-card/80">
              <CardHeader className="pb-3">
                <CardTitle className="text-base font-semibold font-[Outfit]">Options</CardTitle>
              </CardHeader>
              <CardContent className="pt-0 space-y-4">
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                  <div>
                    <Label className="text-sm mb-2 block">Port Range</Label>
                    <Input
                      placeholder="e.g., 1-1000, 22,80,443"
                      value={portRange}
                      onChange={(e) => setPortRange(e.target.value)}
                      className="bg-input/50 border-border/50 font-mono text-sm"
                    />
                  </div>
                  <div>
                    <Label className="text-sm mb-2 block">Timing Template</Label>
                    <Select value={timing} onValueChange={setTiming}>
                      <SelectTrigger className="bg-input/50 border-border/50">
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        {timingOptions.map((opt) => (
                          <SelectItem key={opt.value} value={opt.value}>
                            {opt.label}
                          </SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                  </div>
                </div>

                <Separator className="bg-border/30" />

                <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                  <div className="flex items-center justify-between">
                    <div>
                      <Label className="text-sm">OS Detection</Label>
                      <p className="text-[11px] text-muted-foreground">Fingerprint operating systems</p>
                    </div>
                    <Switch checked={osDetection} onCheckedChange={setOsDetection} />
                  </div>
                  <div className="flex items-center justify-between">
                    <div>
                      <Label className="text-sm">Service Version</Label>
                      <p className="text-[11px] text-muted-foreground">Detect service versions</p>
                    </div>
                    <Switch checked={serviceVersion} onCheckedChange={setServiceVersion} />
                  </div>
                  <div className="flex items-center justify-between">
                    <div>
                      <Label className="text-sm">Script Scan</Label>
                      <p className="text-[11px] text-muted-foreground">Run default NSE scripts</p>
                    </div>
                    <Switch checked={scriptScan} onCheckedChange={setScriptScan} />
                  </div>
                  <div className="flex items-center justify-between">
                    <div>
                      <Label className="text-sm">UDP Scan</Label>
                      <p className="text-[11px] text-muted-foreground">Include UDP port scanning</p>
                    </div>
                    <Switch checked={udpScan} onCheckedChange={setUdpScan} />
                  </div>
                </div>
              </CardContent>
            </Card>
          </motion.div>

          {/* Command Preview & Submit */}
          <motion.div
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.4, delay: 0.4 }}
          >
            <Card className="border-border/50 bg-card/80">
              <CardHeader className="pb-3">
                <div className="flex items-center gap-2">
                  <Terminal className="w-4 h-4 text-green-400" />
                  <CardTitle className="text-base font-semibold font-[Outfit]">Command Preview</CardTitle>
                </div>
              </CardHeader>
              <CardContent className="pt-0">
                <div className="bg-background/80 rounded-lg p-4 border border-border/30 font-mono text-sm text-green-400 overflow-x-auto">
                  <span className="text-muted-foreground">$ </span>
                  {buildCommand()}
                </div>
                <div className="flex items-center gap-3 mt-4">
                  <Button
                    onClick={handleSubmit}
                    className="bg-purple-600 hover:bg-purple-700 text-white gap-2"
                  >
                    <Play className="w-4 h-4" />
                    Launch Scan
                  </Button>
                  <p className="text-[11px] text-muted-foreground">
                    Scan will be validated against allowlist before execution
                  </p>
                </div>
              </CardContent>
            </Card>
          </motion.div>
        </TabsContent>

        <TabsContent value="advanced" className="space-y-4">
          <Card className="border-border/50 bg-card/80">
            <CardContent className="p-5">
              <Label className="text-sm font-medium mb-2 block">Target</Label>
              <Input
                placeholder="e.g., 192.168.1.0/24"
                value={target}
                onChange={(e) => setTarget(e.target.value)}
                className="bg-input/50 border-border/50 font-mono text-sm mb-4"
              />
              <Label className="text-sm font-medium mb-2 block">Raw Nmap Arguments</Label>
              <Input
                placeholder="e.g., -sS -sV -O -T4 -p 1-65535"
                className="bg-input/50 border-border/50 font-mono text-sm"
              />
              <p className="text-[11px] text-muted-foreground mt-2 flex items-center gap-1">
                <AlertTriangle className="w-3 h-3 text-yellow-400" />
                Arguments are validated against the allowlist. Disallowed flags will be rejected.
              </p>
              <div className="mt-4">
                <Button
                  onClick={handleSubmit}
                  className="bg-purple-600 hover:bg-purple-700 text-white gap-2"
                >
                  <Play className="w-4 h-4" />
                  Launch Scan
                </Button>
              </div>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
}
