local datafiles = require "datafiles"
local nmap = require "nmap"
local shortport = require "shortport"
local snmp = require "snmp"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"
local target = require "target"

description = [[
Attempts to enumerate network interfaces through SNMP.

This script can also be run during Nmap's pre-scanning phase and can
attempt to add the SNMP server's interface addresses to the target
list.  The script argument <code>snmp-interfaces.host</code> is
required to know what host to probe.  To specify a port for the SNMP
server other than 161, use <code>snmp-interfaces.port</code>.  When
run in this way, the script's output tells how many new targets were
successfully added.
]]

---
-- @usage
-- nmap -sU -p 161 --script=snmp-interfaces <target>
-- @args snmp-interfaces.host  Specifies the SNMP server to probe when
--       running in the "pre-scanning phase".
-- @args snmp-interfaces.port  The optional port number corresponding
--       to the host script argument.  Defaults to 161.
--
-- @output
-- | snmp-interfaces:
-- |   eth0
-- |     IP address: 192.168.221.128
-- |     MAC address: 00:0c:29:01:e2:74 (VMware)
-- |     Type: ethernetCsmacd  Speed: 1 Gbps
-- |_    Traffic stats: 6.45 Mb sent, 15.01 Mb received
--

author = {"Thomas Buchanan", "Kris Katterjohn"}
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"default", "discovery", "safe"}
dependencies = {"snmp-brute"}

-- code borrowed heavily from Patrik Karlsson's excellent snmp scripts
-- Created 03/03/2010 - v0.1 - created by Thomas Buchanan <tbuchanan@thecompassgrp.net>
-- Revised 03/05/2010 - v0.2 - Reworked output slightly, moved iana_types to script scope. Suggested by David Fifield
-- Revised 04/11/2010 - v0.2 - moved snmp_walk to snmp library <patrik@cqure.net>
-- Revised 08/10/2010 - v0.3 - prerule; add interface addresses to Nmap's target list (Kris Katterjohn)
-- Revised 05/27/2011 - v0.4 - action; add MAC addresses to nmap.registry[host.ip]["mac-geolocation"] (Gorjan Petrovski)
-- Revised 07/31/2012 - v0.5 - action; remove mac-geolocation changes (script removed from trunk)




prerule = function()
  if not stdnse.get_script_args({"snmp-interfaces.host", "host"}) then
    stdnse.debug3("Skipping '%s' %s, 'snmp-interfaces.host' argument is missing.", SCRIPT_NAME, SCRIPT_TYPE)
    return false
  end

  return true
end

portrule = shortport.portnumber(161, "udp", {"open", "open|filtered"})

-- List of IANA-assigned network interface types
-- Taken from IANAifType-MIB
-- Available at http://www.iana.org/assignments/ianaiftype-mib
-- REVISION     "201703300000Z"  -- March 30, 2017
local iana_types = {
  [1] = "other",          -- none of the following
  [2] = "regular1822",
  [3] = "hdh1822",
  [4] = "ddnX25",
  [5] = "rfc877x25",
  [6] = "ethernetCsmacd", -- for all ethernet-like interfaces,
                                      -- regardless of speed, as per RFC3635
  [7] = "iso88023Csmacd", -- Deprecated via RFC3635
                                      -- ethernetCsmacd (6) should be used instead
  [8] = "iso88024TokenBus",
  [9] = "iso88025TokenRing",
  [10] = "iso88026Man",
  [11] = "starLan", -- Deprecated via RFC3635
                                -- ethernetCsmacd (6) should be used instead
  [12] = "proteon10Mbit",
  [13] = "proteon80Mbit",
  [14] = "hyperchannel",
  [15] = "fddi",
  [16] = "lapb",
  [17] = "sdlc",
  [18] = "ds1",            -- DS1-MIB
  [19] = "e1",             -- Obsolete see DS1-MIB
  [20] = "basicISDN",              -- no longer used
                                               -- see also RFC2127
  [21] = "primaryISDN",            -- no longer used
                                               -- see also RFC2127
  [22] = "propPointToPointSerial", -- proprietary serial
  [23] = "ppp",
  [24] = "softwareLoopback",
  [25] = "eon",            -- CLNP over IP
  [26] = "ethernet3Mbit",
  [27] = "nsip",           -- XNS over IP
  [28] = "slip",           -- generic SLIP
  [29] = "ultra",          -- ULTRA technologies
  [30] = "ds3",            -- DS3-MIB
  [31] = "sip",            -- SMDS, coffee
  [32] = "frameRelay",     -- DTE only.
  [33] = "rs232",
  [34] = "para",           -- parallel-port
  [35] = "arcnet",         -- arcnet
  [36] = "arcnetPlus",     -- arcnet plus
  [37] = "atm",            -- ATM cells
  [38] = "miox25",
  [39] = "sonet",          -- SONET or SDH
  [40] = "x25ple",
  [41] = "iso88022llc",
  [42] = "localTalk",
  [43] = "smdsDxi",
  [44] = "frameRelayService",  -- FRNETSERV-MIB
  [45] = "v35",
  [46] = "hssi",
  [47] = "hippi",
  [48] = "modem",          -- Generic modem
  [49] = "aal5",           -- AAL5 over ATM
  [50] = "sonetPath",
  [51] = "sonetVT",
  [52] = "smdsIcip",       -- SMDS InterCarrier Interface
  [53] = "propVirtual",    -- proprietary virtual/internal
  [54] = "propMultiplexor",-- proprietary multiplexing
  [55] = "ieee80212",      -- 100BaseVG
  [56] = "fibreChannel",   -- Fibre Channel
  [57] = "hippiInterface", -- HIPPI interfaces
  [58] = "frameRelayInterconnect", -- Obsolete, use either
                                       -- frameRelay(32) or
                                       -- frameRelayService(44).
  [59] = "aflane8023",     -- ATM Emulated LAN for 802.3
  [60] = "aflane8025",     -- ATM Emulated LAN for 802.5
  [61] = "cctEmul",        -- ATM Emulated circuit
  [62] = "fastEther",      -- Obsoleted via RFC3635
                                       -- ethernetCsmacd (6) should be used instead
  [63] = "isdn",           -- ISDN and X.25
  [64] = "v11",            -- CCITT V.11/X.21
  [65] = "v36",            -- CCITT V.36
  [66] = "g703at64k",      -- CCITT G703 at 64Kbps
  [67] = "g703at2mb",      -- Obsolete see DS1-MIB
  [68] = "qllc",           -- SNA QLLC
  [69] = "fastEtherFX",    -- Obsoleted via RFC3635
                                       -- ethernetCsmacd (6) should be used instead
  [70] = "channel",        -- channel
  [71] = "ieee80211",      -- radio spread spectrum
  [72] = "ibm370parChan",  -- IBM System 360/370 OEMI Channel
  [73] = "escon",          -- IBM Enterprise Systems Connection
  [74] = "dlsw",           -- Data Link Switching
  [75] = "isdns",          -- ISDN S/T interface
  [76] = "isdnu",          -- ISDN U interface
  [77] = "lapd",           -- Link Access Protocol D
  [78] = "ipSwitch",       -- IP Switching Objects
  [79] = "rsrb",           -- Remote Source Route Bridging
  [80] = "atmLogical",     -- ATM Logical Port
  [81] = "ds0",            -- Digital Signal Level 0
  [82] = "ds0Bundle",      -- group of ds0s on the same ds1
  [83] = "bsc",            -- Bisynchronous Protocol
  [84] = "async",          -- Asynchronous Protocol
  [85] = "cnr",            -- Combat Net Radio
  [86] = "iso88025Dtr",    -- ISO 802.5r DTR
  [87] = "eplrs",          -- Ext Pos Loc Report Sys
  [88] = "arap",           -- Appletalk Remote Access Protocol
  [89] = "propCnls",       -- Proprietary Connectionless Protocol
  [90] = "hostPad",        -- CCITT-ITU X.29 PAD Protocol
  [91] = "termPad",        -- CCITT-ITU X.3 PAD Facility
  [92] = "frameRelayMPI",  -- Multiproto Interconnect over FR
  [93] = "x213",           -- CCITT-ITU X213
  [94] = "adsl",           -- Asymmetric Digital Subscriber Loop
  [95] = "radsl",          -- Rate-Adapt. Digital Subscriber Loop
  [96] = "sdsl",           -- Symmetric Digital Subscriber Loop
  [97] = "vdsl",           -- Very H-Speed Digital Subscrib. Loop
  [98] = "iso88025CRFPInt", -- ISO 802.5 CRFP
  [99] = "myrinet",        -- Myricom Myrinet
  [100] = "voiceEM",       -- voice recEive and transMit
  [101] = "voiceFXO",      -- voice Foreign Exchange Office
  [102] = "voiceFXS",      -- voice Foreign Exchange Station
  [103] = "voiceEncap",    -- voice encapsulation
  [104] = "voiceOverIp",   -- voice over IP encapsulation
  [105] = "atmDxi",        -- ATM DXI
  [106] = "atmFuni",       -- ATM FUNI
  [107] = "atmIma",       -- ATM IMA
  [108] = "pppMultilinkBundle", -- PPP Multilink Bundle
  [109] = "ipOverCdlc",   -- IBM ipOverCdlc
  [110] = "ipOverClaw",   -- IBM Common Link Access to Workstn
  [111] = "stackToStack", -- IBM stackToStack
  [112] = "virtualIpAddress", -- IBM VIPA
  [113] = "mpc",          -- IBM multi-protocol channel support
  [114] = "ipOverAtm",    -- IBM ipOverAtm
  [115] = "iso88025Fiber", -- ISO 802.5j Fiber Token Ring
  [116] = "tdlc",         -- IBM twinaxial data link control
  [117] = "gigabitEthernet", -- Obsoleted via RFC3635
                                          -- ethernetCsmacd (6) should be used instead
  [118] = "hdlc",         -- HDLC
  [119] = "lapf",       -- LAP F
  [120] = "v37",       -- V.37
  [121] = "x25mlp",       -- Multi-Link Protocol
  [122] = "x25huntGroup", -- X25 Hunt Group
  [123] = "transpHdlc",   -- Transp HDLC
  [124] = "interleave",   -- Interleave channel
  [125] = "fast",         -- Fast channel
  [126] = "ip",       -- IP (for APPN HPR in IP networks)
  [127] = "docsCableMaclayer",  -- CATV Mac Layer
  [128] = "docsCableDownstream", -- CATV Downstream interface
  [129] = "docsCableUpstream",  -- CATV Upstream interface
  [130] = "a12MppSwitch", -- Avalon Parallel Processor
  [131] = "tunnel",       -- Encapsulation interface
  [132] = "coffee",       -- coffee pot
  [133] = "ces",          -- Circuit Emulation Service
  [134] = "atmSubInterface", -- ATM Sub Interface
  [135] = "l2vlan",       -- Layer 2 Virtual LAN using 802.1Q
  [136] = "l3ipvlan",     -- Layer 3 Virtual LAN using IP
  [137] = "l3ipxvlan",    -- Layer 3 Virtual LAN using IPX
  [138] = "digitalPowerline", -- IP over Power Lines
  [139] = "mediaMailOverIp", -- Multimedia Mail over IP
  [140] = "dtm",        -- Dynamic syncronous Transfer Mode
  [141] = "dcn",    -- Data Communications Network
  [142] = "ipForward",    -- IP Forwarding Interface
  [143] = "msdsl",       -- Multi-rate Symmetric DSL
  [144] = "ieee1394", -- IEEE1394 High Performance Serial Bus
  [145] = "if-gsn",       --   HIPPI-6400
  [146] = "dvbRccMacLayer", -- DVB-RCC MAC Layer
  [147] = "dvbRccDownstream",  -- DVB-RCC Downstream Channel
  [148] = "dvbRccUpstream",  -- DVB-RCC Upstream Channel
  [149] = "atmVirtual",   -- ATM Virtual Interface
  [150] = "mplsTunnel",   -- MPLS Tunnel Virtual Interface
  [151] = "srp", -- Spatial Reuse Protocol
  [152] = "voiceOverAtm",  -- Voice Over ATM
  [153] = "voiceOverFrameRelay",   -- Voice Over Frame Relay
  [154] = "idsl",  -- Digital Subscriber Loop over ISDN
  [155] = "compositeLink",  -- Avici Composite Link Interface
  [156] = "ss7SigLink",     -- SS7 Signaling Link
  [157] = "propWirelessP2P",  --  Prop. P2P wireless interface
  [158] = "frForward",    -- Frame Forward Interface
  [159] = "rfc1483", -- Multiprotocol over ATM AAL5
  [160] = "usb",  -- USB Interface
  [161] = "ieee8023adLag",  -- IEEE 802.3ad Link Aggregate
  [162] = "bgppolicyaccounting", -- BGP Policy Accounting
  [163] = "frf16MfrBundle", -- FRF .16 Multilink Frame Relay
  [164] = "h323Gatekeeper", -- H323 Gatekeeper
  [165] = "h323Proxy", -- H323 Voice and Video Proxy
  [166] = "mpls", -- MPLS
  [167] = "mfSigLink", -- Multi-frequency signaling link
  [168] = "hdsl2", -- High Bit-Rate DSL - 2nd generation
  [169] = "shdsl", -- Multirate HDSL2
  [170] = "ds1FDL", -- Facility Data Link 4Kbps on a DS1
  [171] = "pos", -- Packet over SONET/SDH Interface
  [172] = "dvbAsiIn", -- DVB-ASI Input
  [173] = "dvbAsiOut", -- DVB-ASI Output
  [174] = "plc", -- Power Line Communtications
  [175] = "nfas", -- Non Facility Associated Signaling
  [176] = "tr008", -- TR008
  [177] = "gr303RDT", -- Remote Digital Terminal
  [178] = "gr303IDT", -- Integrated Digital Terminal
  [179] = "isup", -- ISUP
  [180] = "propDocsWirelessMaclayer", -- Cisco proprietary Maclayer
  [181] = "propDocsWirelessDownstream", -- Cisco proprietary Downstream
  [182] = "propDocsWirelessUpstream", -- Cisco proprietary Upstream
  [183] = "hiperlan2", -- HIPERLAN Type 2 Radio Interface
  [184] = "propBWAp2Mp", -- PropBroadbandWirelessAccesspt2multipt
                             -- use of this iftype for IEEE 802.16 WMAN
                             -- interfaces as per IEEE Std 802.16f is
                             -- deprecated and ifType 237 should be used instead.
  [185] = "sonetOverheadChannel", -- SONET Overhead Channel
  [186] = "digitalWrapperOverheadChannel", -- Digital Wrapper
  [187] = "aal2", -- ATM adaptation layer 2
  [188] = "radioMAC", -- MAC layer over radio links
  [189] = "atmRadio", -- ATM over radio links
  [190] = "imt", -- Inter Machine Trunks
  [191] = "mvl", -- Multiple Virtual Lines DSL
  [192] = "reachDSL", -- Long Reach DSL
  [193] = "frDlciEndPt", -- Frame Relay DLCI End Point
  [194] = "atmVciEndPt", -- ATM VCI End Point
  [195] = "opticalChannel", -- Optical Channel
  [196] = "opticalTransport", -- Optical Transport
  [197] = "propAtm", --  Proprietary ATM
  [198] = "voiceOverCable", -- Voice Over Cable Interface
  [199] = "infiniband", -- Infiniband
  [200] = "teLink", -- TE Link
  [201] = "q2931", -- Q.2931
  [202] = "virtualTg", -- Virtual Trunk Group
  [203] = "sipTg", -- SIP Trunk Group
  [204] = "sipSig", -- SIP Signaling
  [205] = "docsCableUpstreamChannel", -- CATV Upstream Channel
  [206] = "econet", -- Acorn Econet
  [207] = "pon155", -- FSAN 155Mb Symetrical PON interface
  [208] = "pon622", -- FSAN622Mb Symetrical PON interface
  [209] = "bridge", -- Transparent bridge interface
  [210] = "linegroup", -- Interface common to multiple lines
  [211] = "voiceEMFGD", -- voice E&M Feature Group D
  [212] = "voiceFGDEANA", -- voice FGD Exchange Access North American
  [213] = "voiceDID", -- voice Direct Inward Dialing
  [214] = "mpegTransport", -- MPEG transport interface
  [215] = "sixToFour", -- 6to4 interface (DEPRECATED)
  [216] = "gtp", -- GTP (GPRS Tunneling Protocol)
  [217] = "pdnEtherLoop1", -- Paradyne EtherLoop 1
  [218] = "pdnEtherLoop2", -- Paradyne EtherLoop 2
  [219] = "opticalChannelGroup", -- Optical Channel Group
  [220] = "homepna", -- HomePNA ITU-T G.989
  [221] = "gfp", -- Generic Framing Procedure (GFP)
  [222] = "ciscoISLvlan", -- Layer 2 Virtual LAN using Cisco ISL
  [223] = "actelisMetaLOOP", -- Acteleis proprietary MetaLOOP High Speed Link
  [224] = "fcipLink", -- FCIP Link
  [225] = "rpr", -- Resilient Packet Ring Interface Type
  [226] = "qam", -- RF Qam Interface
  [227] = "lmp", -- Link Management Protocol
  [228] = "cblVectaStar", -- Cambridge Broadband Networks Limited VectaStar
  [229] = "docsCableMCmtsDownstream", -- CATV Modular CMTS Downstream Interface
  [230] = "adsl2", -- Asymmetric Digital Subscriber Loop Version 2
                                -- (DEPRECATED/OBSOLETED - please use adsl2plus 238 instead)
  [231] = "macSecControlledIF", -- MACSecControlled
  [232] = "macSecUncontrolledIF", -- MACSecUncontrolled
  [233] = "aviciOpticalEther", -- Avici Optical Ethernet Aggregate
  [234] = "atmbond", -- atmbond
  [235] = "voiceFGDOS", -- voice FGD Operator Services
  [236] = "mocaVersion1", -- MultiMedia over Coax Alliance (MoCA) Interface
                             -- as documented in information provided privately to IANA
  [237] = "ieee80216WMAN", -- IEEE 802.16 WMAN interface
  [238] = "adsl2plus", -- Asymmetric Digital Subscriber Loop Version 2,
                                   -- Version 2 Plus and all variants
  [239] = "dvbRcsMacLayer", -- DVB-RCS MAC Layer
  [240] = "dvbTdm", -- DVB Satellite TDM
  [241] = "dvbRcsTdma", -- DVB-RCS TDMA
  [242] = "x86Laps", -- LAPS based on ITU-T X.86/Y.1323
  [243] = "wwanPP", -- 3GPP WWAN
  [244] = "wwanPP2", -- 3GPP2 WWAN
  [245] = "voiceEBS", -- voice P-phone EBS physical interface
  [246] = "ifPwType", -- Pseudowire interface type
  [247] = "ilan", -- Internal LAN on a bridge per IEEE 802.1ap
  [248] = "pip", -- Provider Instance Port on a bridge per IEEE 802.1ah PBB
  [249] = "aluELP", -- Alcatel-Lucent Ethernet Link Protection
  [250] = "gpon", -- Gigabit-capable passive optical networks (G-PON) as per ITU-T G.948
  [251] = "vdsl2", -- Very high speed digital subscriber line Version 2 (as per ITU-T Recommendation G.993.2)
  [252] = "capwapDot11Profile", -- WLAN Profile Interface
  [253] = "capwapDot11Bss", -- WLAN BSS Interface
  [254] = "capwapWtpVirtualRadio", -- WTP Virtual Radio Interface
  [255] = "bits", -- bitsport
  [256] = "docsCableUpstreamRfPort", -- DOCSIS CATV Upstream RF Port
  [257] = "cableDownstreamRfPort", -- CATV downstream RF port
  [258] = "vmwareVirtualNic", -- VMware Virtual Network Interface
  [259] = "ieee802154", -- IEEE 802.15.4 WPAN interface
  [260] = "otnOdu", -- OTN Optical Data Unit
  [261] = "otnOtu", -- OTN Optical channel Transport Unit
  [262] = "ifVfiType", -- VPLS Forwarding Instance Interface Type
  [263] = "g9981", -- G.998.1 bonded interface
  [264] = "g9982", -- G.998.2 bonded interface
  [265] = "g9983", -- G.998.3 bonded interface
  [266] = "aluEpon", -- Ethernet Passive Optical Networks (E-PON)
  [267] = "aluEponOnu", -- EPON Optical Network Unit
  [268] = "aluEponPhysicalUni", -- EPON physical User to Network interface
  [269] = "aluEponLogicalLink", -- The emulation of a point-to-point link over the EPON layer
  [270] = "aluGponOnu", -- GPON Optical Network Unit
  [271] = "aluGponPhysicalUni", -- GPON physical User to Network interface
  [272] = "vmwareNicTeam", -- VMware NIC Team
  [277] = "docsOfdmDownstream", -- CATV Downstream OFDM interface
  [278] = "docsOfdmaUpstream", -- CATV Upstream OFDMA interface
  [279] = "gfast", -- G.fast port
  [280] = "sdci", -- SDCI (IO-Link)
  [281] = "xboxWireless", -- Xbox wireless
  [282] = "fastdsl", -- FastDSL
  [283] = "docsCableScte55d1FwdOob", -- Cable SCTE 55-1 OOB Forward Channel
  [284] = "docsCableScte55d1RetOob", -- Cable SCTE 55-1 OOB Return Channel
  [285] = "docsCableScte55d2DsOob", -- Cable SCTE 55-2 OOB Downstream Channel
  [286] = "docsCableScte55d2UsOob", -- Cable SCTE 55-2 OOB Upstream Channel
  [287] = "docsCableNdf", -- Cable Narrowband Digital Forward
  [288] = "docsCableNdr", -- Cable Narrowband Digital Return
  [289] = "ptm", -- Packet Transfer Mode
  [290] = "ghn" -- G.hn port
}

--- Gets a value for the specified oid
--
-- @param tbl table containing <code>oid</code> and <code>value</code>
-- @param oid string containing the object id for which the value should be extracted
-- @return value of relevant type or nil if oid was not found
function get_value_from_table( tbl, oid )

  for _, v in ipairs( tbl ) do
    if v.oid == oid then
      return v.value
    end
  end

  return nil
end

--- Gets the network interface type from a list of IANA approved types
--
-- @param iana integer interface type returned from snmp result
-- @return string description of interface type, or "Unknown" if type not found
function get_iana_type( iana )
  return iana_types[iana] or "Unknown"
end

--- Calculates the speed of the interface based on the snmp value
--
-- @param speed value from IF-MIB::ifSpeed
-- @return string description of speed
function get_if_speed( speed )
  local result

  -- GigE or 10GigE speeds
  if speed >= 1000000000 then
    result = string.format( "%.f Gbps", speed / 1000000000)
  -- Common for 10 or 100 Mbit ethernet
  elseif speed >= 1000000 then
    result = string.format( "%.f Mbps", speed / 1000000)
  -- Anything slower report in Kbps
  else
    result = string.format( "%.f Kbps", speed / 1000)
  end

  return result
end

--- Calculates the amount of traffic passed through an interface based on the snmp value
--
-- @param amount value from IF-MIB::ifInOctets or IF-MIB::ifOutOctets
-- @return string description of traffic amount
function get_traffic( amount )
  local result

  -- Gigabytes
  if amount >= 1000000000 then
    result = string.format( "%.2f Gb", amount / 1000000000)
  -- Megabytes
  elseif amount >= 1000000 then
    result = string.format( "%.2f Mb", amount / 1000000)
  -- Anything lower report in kb
  else
    result = string.format( "%.2f Kb", amount / 1000)
  end

  return result
end

--- Converts a 6 byte string into the familiar MAC address formatting
--
-- @param mac string containing the MAC address
-- @return formatted string suitable for printing
function get_mac_addr( mac )
  local catch = function() return end
  local try = nmap.new_try(catch)
  local mac_prefixes = try(datafiles.parse_mac_prefixes())

  if mac:len() ~= 6 then
    return "Unknown"
  else
    local prefix = string.upper(string.format("%02x%02x%02x", mac:byte(1), mac:byte(2), mac:byte(3)))
    local manuf = mac_prefixes[prefix] or "Unknown"
    return string.format("%s (%s)", stdnse.format_mac(mac:sub(1,6)), manuf )
  end
end

--- Processes the list of network interfaces
--
-- @param tbl table containing <code>oid</code> and <code>value</code>
-- @return table with network interfaces described in key / value pairs
function process_interfaces( tbl )

  -- Add the %. escape character to prevent matching the index on e.g. "1.3.6.1.2.1.2.2.1.10."
  local if_index = "1.3.6.1.2.1.2.2.1.1%."
  local if_descr = "1.3.6.1.2.1.2.2.1.2."
  local if_type = "1.3.6.1.2.1.2.2.1.3."
  local if_speed = "1.3.6.1.2.1.2.2.1.5."
  local if_phys_addr = "1.3.6.1.2.1.2.2.1.6."
  local if_status = "1.3.6.1.2.1.2.2.1.8."
  local if_in_octets = "1.3.6.1.2.1.2.2.1.10."
  local if_out_octets = "1.3.6.1.2.1.2.2.1.16."
  local new_tbl = {}

  -- Some operating systems (such as MS Windows) don't list interfaces with consecutive indexes
  -- Therefore we keep an index list so we can iterate over the indexes later on
  new_tbl.index_list = {}

  for _, v in ipairs( tbl ) do

    if ( v.oid:match("^" .. if_index) ) then
      local item = {}
      item.index = get_value_from_table( tbl, v.oid )

      local objid = v.oid:gsub( "^" .. if_index, if_descr)
      local value = get_value_from_table( tbl, objid )

      if value and value:len() > 0 then
        item.descr = value
      end

      objid = v.oid:gsub( "^" .. if_index, if_type )
      value = get_value_from_table( tbl, objid )

      if value then
        item.type = get_iana_type(value)
      end

      objid = v.oid:gsub( "^" .. if_index, if_speed )
      value = get_value_from_table( tbl, objid )

      if value then
        item.speed = get_if_speed( value )
      end

      objid = v.oid:gsub( "^" .. if_index, if_phys_addr )
      value = get_value_from_table( tbl, objid )

      if value and value:len() > 0 then
        item.phys_addr = get_mac_addr( value )
      end

      objid = v.oid:gsub( "^" .. if_index, if_status )
      value = get_value_from_table( tbl, objid )

      if value == 1 then
        item.status = "up"
      elseif value == 2 then
        item.status = "down"
      end

      objid = v.oid:gsub( "^" .. if_index, if_in_octets )
      value = get_value_from_table( tbl, objid )

      if value then
        item.received = get_traffic( value )
      end

      objid = v.oid:gsub( "^" .. if_index, if_out_octets )
      value = get_value_from_table( tbl, objid )

      if value then
        item.sent = get_traffic( value )
      end

      new_tbl[item.index] = item
      -- Add this interface index to our master list
      table.insert( new_tbl.index_list, item.index )

    end

  end

  return new_tbl

end

--- Processes the list of network interfaces and finds associated IP addresses
--
-- @param if_tbl table containing network interfaces
-- @param ip_tbl table containing <code>oid</code> and <code>value</code> pairs from IP::MIB
-- @return table with network interfaces described in key / value pairs
function process_ips( if_tbl, ip_tbl )
  local ip_index = "1.3.6.1.2.1.4.20.1.2."
  local ip_addr = "1.3.6.1.2.1.4.20.1.1."
  local ip_netmask = "1.3.6.1.2.1.4.20.1.3."
  local index
  local item

  for _, v in ipairs( ip_tbl ) do
    if ( v.oid:match("^" .. ip_index) ) then
      index = get_value_from_table( ip_tbl, v.oid )
      if not index then goto NEXT_PROCESS_IPS end
      item = if_tbl[index]
      if not item then
        stdnse.debug1("Unknown interface index %s", index)
        goto NEXT_PROCESS_IPS
      end

      local objid = v.oid:gsub( "^" .. ip_index, ip_addr )
      local value = get_value_from_table( ip_tbl, objid )

      if value then
        item.ip_addr = value
      end

      objid = v.oid:gsub( "^" .. ip_index, ip_netmask )
      value = get_value_from_table( ip_tbl, objid )

      if value then
        item.netmask = value
      end
      ::NEXT_PROCESS_IPS::
    end
  end

  return if_tbl
end

--- Creates a table of IP addresses from the table of network interfaces
--
-- @param tbl table containing network interfaces
-- @return table containing only IP addresses
function list_addrs( tbl )
  local new_tbl = {}

  for _, index in ipairs( tbl.index_list ) do
    local interface = tbl[index]
    if interface.ip_addr then
      table.insert( new_tbl, interface.ip_addr )
    end
  end

  return new_tbl
end

--- Process the table of network interfaces for reporting
--
-- @param tbl table containing network interfaces
-- @return table suitable for <code>stdnse.format_output</code>
function build_results( tbl )
  local new_tbl = {}
  local verbose = nmap.verbosity()

  -- For each interface index previously discovered, format the relevant information for output
  for _, index in ipairs( tbl.index_list ) do
    local interface = tbl[index]
    local item = {}
    local status = interface.status
    local if_type = interface.type

    if interface.descr then
      item.name = interface.descr
    else
      item.name = string.format("Interface %d", index)
    end

    if interface.ip_addr and interface.netmask then
      table.insert( item, ("IP address: %s  Netmask: %s"):format( interface.ip_addr, interface.netmask ) )
    end

    if interface.phys_addr then
      table.insert( item, ("MAC address: %s"):format( interface.phys_addr ) )
    end

    if interface.type and interface.speed then
      table.insert( item, ("Type: %s  Speed: %s"):format( interface.type, interface.speed ) )
    end

    if ( verbose > 0 ) and interface.status then
      table.insert( item, ("Status: %s"):format( interface.status ) )
    end

    if interface.sent and interface.received then
      table.insert( item, ("Traffic stats: %s sent, %s received"):format( interface.sent, interface.received ) )
    end

    if ( verbose > 0 ) or status == "up" then
      table.insert( new_tbl, item )
    end
  end

  return new_tbl
end

action = function(host, port)

  -- IF-MIB - used to look up network interfaces
  local if_oid = "1.3.6.1.2.1.2.2.1"
  -- IP-MIB - used to determine IP address information
  local ip_oid = "1.3.6.1.2.1.4.20"
  local interfaces = {}
  local ips = {}
  local status
  local srvhost, srvport

  if SCRIPT_TYPE == "prerule" then
    srvhost = stdnse.get_script_args({"snmp-interfaces.host", "host"})
    if not srvhost then
      -- Shouldn't happen; checked in prerule.
      return
    end

    srvport = stdnse.get_script_args({"snmp-interfaces.port", "port"})
    if srvport then
      srvport = { number=tonumber(srvport), protocol="udp" }
    else
      srvport = { number=tonumber(srvport), protocol="udp" }
    end
  else
    srvhost = host.ip
    srvport = port.number
  end

  local snmpHelper = snmp.Helper:new(host, port)
  snmpHelper:connect()

  -- retrieve network interface information from IF-MIB
  status, interfaces = snmpHelper:walk(if_oid)

  if (not(status)) or ( interfaces == nil ) or ( #interfaces == 0 ) then
    return
  end

  stdnse.debug1("SNMP walk of IF-MIB returned %d lines", #interfaces)

  -- build a table of network interfaces from the IF-MIB table
  interfaces = process_interfaces( interfaces )

  -- retrieve IP address information from IP-MIB
  status, ips = snmpHelper:walk( ip_oid )

  -- associate that IP address information with the correct interface
  if (not(status)) or ( ips ~= nil ) and ( #ips ~= 0 ) then
    interfaces = process_ips( interfaces, ips )
  end

  local output = stdnse.format_output( true, build_results(interfaces) )

  if SCRIPT_TYPE == "prerule" and target.ALLOW_NEW_TARGETS then
    local sum = 0

    ips = list_addrs(interfaces)

    -- Could add all of the addresses at once, but count
    -- successful additions instead for script output
    for _, i in ipairs(ips) do
      local st, err = target.add(i)
      if st then
        sum = sum + 1
      else
        stdnse.debug1("Couldn't add target " .. i .. ": " .. err)
      end
    end

    if sum ~= 0 then
      output = output .. "\nSuccessfully added " .. tostring(sum) .. " new targets"
    end
  elseif SCRIPT_TYPE == "portrule" then
    nmap.set_port_state(host, port, "open")
  end

  return output
end

