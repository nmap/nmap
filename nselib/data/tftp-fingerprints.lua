--[[
This is compiled list of known TFTP responses.
]]

author = {"Mak Kolybabi <mak@kolybabi.com>"}
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

-- Fingerprints by opcode
fingerprints = {

--------------------------------------------------------------------------------
-- Example Fingerprint
--------------------------------------------------------------------------------
-- Based on the format of the 'match' directive used in service probes.
-- https://nmap.org/book/vscan-fileformat.html#vscan-tbl-versioninfo
--------------------------------------------------------------------------------
-- {
-- -- Optional:
-- rport = REMOTE_PORT_NUMBER, -- some software uses same port, some uses a data port
-- length = number, -- length of entire TFTP packet
-- errcode = TFTP_ERRCODE, -- also interpreted as DATA.block
-- -- Very unlikely, response is a RRQ or WRQ
-- mode = "mode",
-- -- Mandatory:
-- errmsg = "TFTP_ERRMSG", -- also interpreted as DATA.data or RRQ/WRQ.filename
-- product = {
--   p   = "Product",
--   v   = "Version",
--   i   = "Extra Info",
--   h   = "Hostname",
--   o   = "Operating System",
--   d   = "Device Type",
--   cpe = {"CPE", ...},
-- }}

-- opcode RRQ
[1] = {},
-- opcode WRQ
[2] = {},
-- opcode DATA
[3] = {},
-- opcode ACK
[4] = {},
-- opcode ERROR
[5] = {
  -- SolarWinds
  { errcode = 2, errmsg = "The IP address is not in the range of allowable addresses.",
    product = {
      p   = "SolarWinds tftpd",
      e   = "IP disallowed",
      o   = "Windows",
      cpe = {"cpe:/a:solarwinds:tftp_server", "cpe:/o:microsoft:windows"},
  }},

  -- Cisco
  { errcode = 0, errmsg = "Invalid TFTP Opcode",
    product = {
      p   = "Cisco tftpd",
      cpe = {"cpe:/a:cisco:tftp_server"},
  }},

  -- Plan 9
  { errcode = 4, errmsg = "Illegal TFTP operation",
    product = {
      p   = "Plan 9 tftpd",
      o   = "Plan 9",
      cpe = {"cpe:/o:belllabs:plan_9"},
  }},

  -- Zoom X5 ADSL Modem
  { errcode = 4, errmsg = "Error: Illegal TFTP Operation",
    product = {
      p   = "Zoom X5 ADSL modem tftpd",
      d   = "broadband router",
      cpe = {"cpe:/h:zoom:x5"},
  }},

  -- Cisco Router
  { errcode = 4, errmsg = "Illegal operation",
    product = {
      p   = "Cisco router tftpd",
      o   = "IOS",
      d   = "router",
      cpe = {"cpe:/a:cisco:tftp_server", "cpe:/o:cisco:ios"},
  }},

  -- Microsoft Windows Deployment Services
  { errcode = 4, errmsg = "Illegal operation error.",
    product = {
      p   = "Microsoft Windows Deployment Services tftpd",
      o   = "Windows",
      cpe = {"cpe:/o:microsoft:windows"},
  }},

  -- SolarWinds Free
  { errcode = 4, errmsg = "Unknown operatation code: 0 received from",
    product = {
      p   = "SolarWinds Free tftpd",
      cpe = {"cpe:/a:solarwinds:tftp_server"},
  }},

  { errcode = 4, errmsg = "Could not find file '",
    product = {
      p   = "SolarWinds Free tftpd",
      cpe = {"cpe:/a:solarwinds:tftp_server"},
  }},

  -- Brother MFC-9340CDW
  { errcode = 4, errmsg = "illegal (unrecognized) tftp operation",
    product = {
      p   = "Brother printer tftpd",
      d   = "printer",
  }},

  -- HP Intelligent Management Center
  { errcode = 0, errmsg = "Not defined, see error message(if any).",
    product = {
      p   = "HP Intelligent Management Center tftpd",
      cpe = {"cpe:/a:hp:intelligent_management_center"},
  }},

  -- Windows 2003 Server Deployment Service
  { errcode = 4, errmsg = "Illegal TFTP operation",
    product = {
      p   = "Windows 2003 Server Deployment Service",
      o   = "Windows",
      cpe = {"cpe:/o:microsoft:windows_server_2003"},
  }},

  -- Enistic Zone Controller
  { errcode = 1, errmsg = "File not found.",
    product = {
      p   = "Enistic zone controller tftpd",
  }},

  -- Netkit
  { errcode = 1, errmsg = "File not found",
    product = {
      p   = "Netkit tftpd or atftpd",
      cpe = {"cpe:/a:netkit:netkit", "cpe:/a:lefebvre:atftpd"},
  }},
},

}

return fingerprints
