/*
 * WorldMap — Geographic Scan Target Visualization
 * Spectra Command Dark Theme
 * Interactive SVG world map showing scanned target locations with
 * pulsing markers, connection lines, and severity-coded indicators.
 */
import { useState, useMemo } from "react";
import {
  ComposableMap,
  Geographies,
  Geography,
  Marker,
  Line,
  Graticule,
  Sphere,
  createCoordinates,
  createGraticuleStep,
} from "@vnedyalk0v/react19-simple-maps";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import { motion, AnimatePresence } from "framer-motion";

const GEO_URL = "https://cdn.jsdelivr.net/npm/world-atlas@2/countries-110m.json";

export interface ScanTarget {
  id: string;
  name: string;
  ip: string;
  coordinates: [number, number]; // [longitude, latitude]
  status: "active" | "completed" | "critical" | "scanning";
  hostsFound: number;
  openPorts: number;
  lastScan: string;
  region: string;
}

const defaultTargets: ScanTarget[] = [
  {
    id: "t1",
    name: "US-East DC",
    ip: "192.168.1.0/24",
    coordinates: [-74.006, 40.7128],
    status: "completed",
    hostsFound: 12,
    openPorts: 342,
    lastScan: "2m ago",
    region: "North America",
  },
  {
    id: "t2",
    name: "EU-West Gateway",
    ip: "10.0.0.0/16",
    coordinates: [-0.1276, 51.5074],
    status: "active",
    hostsFound: 45,
    openPorts: 128,
    lastScan: "15m ago",
    region: "Europe",
  },
  {
    id: "t3",
    name: "APAC-Tokyo Node",
    ip: "172.16.0.0/12",
    coordinates: [139.6917, 35.6895],
    status: "scanning",
    hostsFound: 8,
    openPorts: 67,
    lastScan: "now",
    region: "Asia Pacific",
  },
  {
    id: "t4",
    name: "SA-São Paulo Hub",
    ip: "10.10.10.0/24",
    coordinates: [-46.6333, -23.5505],
    status: "completed",
    hostsFound: 23,
    openPorts: 89,
    lastScan: "1h ago",
    region: "South America",
  },
  {
    id: "t5",
    name: "EU-Frankfurt Core",
    ip: "192.168.2.0/24",
    coordinates: [8.6821, 50.1109],
    status: "critical",
    hostsFound: 34,
    openPorts: 156,
    lastScan: "5m ago",
    region: "Europe",
  },
  {
    id: "t6",
    name: "APAC-Singapore Edge",
    ip: "172.20.0.0/16",
    coordinates: [103.8198, 1.3521],
    status: "active",
    hostsFound: 19,
    openPorts: 74,
    lastScan: "30m ago",
    region: "Asia Pacific",
  },
  {
    id: "t7",
    name: "AU-Sydney Perimeter",
    ip: "10.50.0.0/16",
    coordinates: [151.2093, -33.8688],
    status: "completed",
    hostsFound: 11,
    openPorts: 43,
    lastScan: "2h ago",
    region: "Oceania",
  },
];

const statusColors: Record<string, { fill: string; glow: string; ring: string }> = {
  active: { fill: "#10B981", glow: "rgba(16, 185, 129, 0.4)", ring: "rgba(16, 185, 129, 0.2)" },
  completed: { fill: "#8B5CF6", glow: "rgba(139, 92, 246, 0.4)", ring: "rgba(139, 92, 246, 0.2)" },
  critical: { fill: "#EF4444", glow: "rgba(239, 68, 68, 0.5)", ring: "rgba(239, 68, 68, 0.25)" },
  scanning: { fill: "#06B6D4", glow: "rgba(6, 182, 212, 0.4)", ring: "rgba(6, 182, 212, 0.2)" },
};

const statusLabels: Record<string, string> = {
  active: "Active",
  completed: "Completed",
  critical: "Critical",
  scanning: "Scanning...",
};

// Hub location (command center)
const HUB: [number, number] = [-96.7970, 32.7767]; // Dallas, TX

interface WorldMapProps {
  targets?: ScanTarget[];
  showConnections?: boolean;
  className?: string;
}

export default function WorldMap({
  targets = defaultTargets,
  showConnections = true,
  className = "",
}: WorldMapProps) {
  const [hoveredTarget, setHoveredTarget] = useState<string | null>(null);

  const activeTarget = useMemo(
    () => targets.find((t) => t.id === hoveredTarget),
    [hoveredTarget, targets]
  );

  return (
    <div className={`relative ${className}`}>
      {/* Map */}
      <ComposableMap
        projection="geoMercator"
        projectionConfig={{
          scale: 130,
          center: createCoordinates(15, 20),
        }}
        width={800}
        height={420}
        className="w-full h-auto"
      >
        <defs>
          {/* Glow filters for markers */}
          {Object.entries(statusColors).map(([status, colors]) => (
            <filter key={status} id={`glow-${status}`} x="-50%" y="-50%" width="200%" height="200%">
              <feGaussianBlur stdDeviation="3" result="blur" />
              <feFlood floodColor={colors.glow} result="color" />
              <feComposite in="color" in2="blur" operator="in" result="shadow" />
              <feMerge>
                <feMergeNode in="shadow" />
                <feMergeNode in="SourceGraphic" />
              </feMerge>
            </filter>
          ))}
          {/* Connection line gradient */}
          <linearGradient id="connection-gradient" x1="0%" y1="0%" x2="100%" y2="0%">
            <stop offset="0%" stopColor="rgba(139, 92, 246, 0.6)" />
            <stop offset="50%" stopColor="rgba(139, 92, 246, 0.15)" />
            <stop offset="100%" stopColor="rgba(139, 92, 246, 0.6)" />
          </linearGradient>
        </defs>

        {/* Ocean / Sphere background */}
        <Sphere
          id="sphere"
          fill="rgba(8, 10, 18, 0.5)"
          stroke="rgba(139, 92, 246, 0.12)"
          strokeWidth={0.6}
        />

        {/* Grid lines */}
        <Graticule
          stroke="rgba(139, 92, 246, 0.08)"
          strokeWidth={0.4}
          step={createGraticuleStep(20, 20)}
        />

        {/* Countries */}
        <Geographies geography={GEO_URL}>
          {({ geographies }) =>
            geographies.map((geo: any) => (
              <Geography
                key={geo.rsmKey}
                geography={geo}
                fill="rgba(35, 38, 60, 0.9)"
                stroke="rgba(139, 92, 246, 0.2)"
                strokeWidth={0.5}
                style={{
                  default: { outline: "none" },
                  hover: { fill: "rgba(55, 58, 85, 0.95)", outline: "none", stroke: "rgba(139, 92, 246, 0.35)" },
                  pressed: { outline: "none" },
                }}
              />
            ))
          }
        </Geographies>

        {/* Connection lines from hub to targets */}
        {showConnections &&
          targets.map((target) => (
            <Line
              key={`line-${target.id}`}
              from={createCoordinates(HUB[0], HUB[1])}
              to={createCoordinates(target.coordinates[0], target.coordinates[1])}
              stroke={
                hoveredTarget === target.id
                  ? statusColors[target.status]?.fill || "#8B5CF6"
                  : "rgba(139, 92, 246, 0.12)"
              }
              strokeWidth={hoveredTarget === target.id ? 1.5 : 0.6}
              strokeLinecap="round"
              strokeDasharray={hoveredTarget === target.id ? "none" : "4 4"}
              style={{
                transition: "all 0.3s ease",
              }}
            />
          ))}

        {/* Hub marker */}
        <Marker coordinates={createCoordinates(HUB[0], HUB[1])}>
          <circle r={4} fill="#8B5CF6" stroke="#fff" strokeWidth={1} opacity={0.9} />
          <circle r={8} fill="none" stroke="rgba(139, 92, 246, 0.3)" strokeWidth={0.5}>
            <animate attributeName="r" from="8" to="16" dur="2s" repeatCount="indefinite" />
            <animate attributeName="opacity" from="0.6" to="0" dur="2s" repeatCount="indefinite" />
          </circle>
        </Marker>

        {/* Target markers */}
        {targets.map((target) => {
          const colors = statusColors[target.status] || statusColors.active;
          const isHovered = hoveredTarget === target.id;

          return (
            <Marker
              key={target.id}
              coordinates={createCoordinates(target.coordinates[0], target.coordinates[1])}
              onMouseEnter={() => setHoveredTarget(target.id)}
              onMouseLeave={() => setHoveredTarget(null)}
            >
              {/* Outer pulse ring */}
              <circle r={12} fill="none" stroke={colors.ring} strokeWidth={0.5}>
                <animate attributeName="r" from="8" to="20" dur="3s" repeatCount="indefinite" />
                <animate attributeName="opacity" from="0.5" to="0" dur="3s" repeatCount="indefinite" />
              </circle>

              {/* Mid ring */}
              <circle
                r={isHovered ? 8 : 6}
                fill={colors.ring}
                stroke={colors.fill}
                strokeWidth={isHovered ? 1.5 : 0.8}
                style={{ transition: "all 0.2s ease", cursor: "pointer" }}
                filter={`url(#glow-${target.status})`}
              />

              {/* Inner dot */}
              <circle
                r={isHovered ? 3.5 : 2.5}
                fill={colors.fill}
                style={{ transition: "all 0.2s ease", cursor: "pointer" }}
              />

              {/* Scanning animation for active scans */}
              {target.status === "scanning" && (
                <>
                  <circle r={6} fill="none" stroke={colors.fill} strokeWidth={1} opacity={0.6}>
                    <animate attributeName="r" from="6" to="18" dur="1.5s" repeatCount="indefinite" />
                    <animate attributeName="opacity" from="0.6" to="0" dur="1.5s" repeatCount="indefinite" />
                  </circle>
                  <circle r={6} fill="none" stroke={colors.fill} strokeWidth={1} opacity={0.6}>
                    <animate attributeName="r" from="6" to="18" dur="1.5s" begin="0.75s" repeatCount="indefinite" />
                    <animate attributeName="opacity" from="0.6" to="0" dur="1.5s" begin="0.75s" repeatCount="indefinite" />
                  </circle>
                </>
              )}
            </Marker>
          );
        })}
      </ComposableMap>

      {/* Hover tooltip overlay */}
      <AnimatePresence>
        {activeTarget && (
          <motion.div
            initial={{ opacity: 0, y: 5 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: 5 }}
            transition={{ duration: 0.15 }}
            className="absolute top-3 right-3 bg-card/95 backdrop-blur-md border border-border/50 rounded-lg p-3 shadow-xl max-w-[220px] pointer-events-none z-10"
          >
            <div className="flex items-center gap-2 mb-2">
              <span
                className="w-2 h-2 rounded-full"
                style={{ backgroundColor: statusColors[activeTarget.status]?.fill }}
              />
              <span className="text-xs font-semibold text-foreground">{activeTarget.name}</span>
            </div>
            <div className="space-y-1.5 text-[11px]">
              <div className="flex justify-between">
                <span className="text-muted-foreground">Target</span>
                <code className="font-mono text-foreground">{activeTarget.ip}</code>
              </div>
              <div className="flex justify-between">
                <span className="text-muted-foreground">Status</span>
                <span
                  className="font-medium"
                  style={{ color: statusColors[activeTarget.status]?.fill }}
                >
                  {statusLabels[activeTarget.status]}
                </span>
              </div>
              <div className="flex justify-between">
                <span className="text-muted-foreground">Hosts</span>
                <span className="text-foreground">{activeTarget.hostsFound}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-muted-foreground">Open Ports</span>
                <span className="text-foreground">{activeTarget.openPorts}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-muted-foreground">Region</span>
                <span className="text-foreground">{activeTarget.region}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-muted-foreground">Last Scan</span>
                <span className="text-foreground">{activeTarget.lastScan}</span>
              </div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>

      {/* Legend */}
      <div className="absolute bottom-3 left-3 flex flex-wrap gap-x-4 gap-y-1">
        {Object.entries(statusLabels).map(([key, label]) => (
          <div key={key} className="flex items-center gap-1.5 text-[10px] text-muted-foreground">
            <span
              className="w-2 h-2 rounded-full"
              style={{ backgroundColor: statusColors[key]?.fill }}
            />
            {label}
          </div>
        ))}
        <div className="flex items-center gap-1.5 text-[10px] text-muted-foreground">
          <span className="w-2 h-2 rounded-full bg-purple-500" />
          Command Hub
        </div>
      </div>
    </div>
  );
}
