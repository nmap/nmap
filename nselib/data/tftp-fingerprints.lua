local table = require 'table'

--[[
This is compiled list of known TFTP responses.
]]

author = {"Mak Kolybabi <mak@kolybabi.com>"}
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

fingerprints = {};

--------------------------------------------------------------------------------
-- Example Fingerprint
--------------------------------------------------------------------------------
-- Based on the format of the 'match' directive used in service probes.
-- https://nmap.org/book/vscan-fileformat.html#vscan-tbl-versioninfo
--------------------------------------------------------------------------------
-- table.insert(fingerprints, {
--   TFTP_ERRCODE, "TFTP_ERRMSG", {
--   p   = "Product",
--   v   = "Version",
--   i   = "Extra Info",
--   h   = "Hostname",
--   o   = "Operating System",
--   d   = "Device Type",
--   cpe = {"CPE", ...},
-- }});

--------------------------------------------------------------------------------
-- SolarWinds
--------------------------------------------------------------------------------
table.insert(fingerprints, {
  2, "The IP address is not in the range of allowable addresses.", {
  p   = "SolarWinds tftpd",
  e   = "IP disallowed",
  o   = "Windows",
  cpe = {"a:solarwinds:tftp_server", "o:microsoft:windows/a"},
}});

--------------------------------------------------------------------------------
-- Cisco
--------------------------------------------------------------------------------
table.insert(fingerprints, {
  0, "Invalid TFTP Opcode", {
  p   = "Cisco tftpd",
  cpe = {"a:cisco:tftp_server"},
}});

--------------------------------------------------------------------------------
-- Plan 9
--------------------------------------------------------------------------------
table.insert(fingerprints, {
  4, "Illegal TFTP operation", {
  p   = "Plan 9 tftpd",
  o   = "Plan 9",
  cpe = {"o:belllabs:plan_9/a"},
}});

--------------------------------------------------------------------------------
-- Zoom X5 ADSL Modem
--------------------------------------------------------------------------------
table.insert(fingerprints, {
  4, "Error: Illegal TFTP Operation", {
  p   = "Zoom X5 ADSL modem tftpd",
  d   = "broadband router",
  cpe = {"h:zoom:x5/a"},
}});

--------------------------------------------------------------------------------
-- Cisco Router
--------------------------------------------------------------------------------
table.insert(fingerprints, {
  4, "Illegal operation", {
  p   = "Cisco router tftpd",
  o   = "IOS",
  d   = "router",
  cpe = {"a:cisco:tftp_server", "o:cisco:ios/a"},
}});

--------------------------------------------------------------------------------
-- Microsoft Windows Deployment Services
--------------------------------------------------------------------------------
table.insert(fingerprints, {
  4, "Illegal operation error.", {
  p   = "Microsoft Windows Deployment Services tftpd",
  o   = "Windows",
  cpe = {"o:microsoft:windows"},
}});

--------------------------------------------------------------------------------
-- SolarWinds Free
--------------------------------------------------------------------------------
table.insert(fingerprints, {
  4, "Unknown operatation code: 0 received from", {
  p   = "SolarWinds Free tftpd",
  cpe = {"a:solarwinds:tftp_server"},
}});

table.insert(fingerprints, {
  4, "Could not find file '", {
  p   = "SolarWinds Free tftpd",
  cpe = {"a:solarwinds:tftp_server"},
}});

--------------------------------------------------------------------------------
-- Brother MFC-9340CDW
--------------------------------------------------------------------------------
table.insert(fingerprints, {
  4, "illegal (unrecognized) tftp operation", {
  p   = "Brother printer tftpd",
  d   = "printer",
}});

--------------------------------------------------------------------------------
-- HP Intelligent Management Center
--------------------------------------------------------------------------------
table.insert(fingerprints, {
  0, "Not defined, see error message(if any).", {
  p   = "HP Intelligent Management Center tftpd",
  cpe = {"a:hp:intelligent_management_center"},
}});

--------------------------------------------------------------------------------
-- Windows 2003 Server Deployment Service
--------------------------------------------------------------------------------
table.insert(fingerprints, {
  4, "Illegal TFTP operation", {
  p   = "Windows 2003 Server Deployment Service",
  o   = "Windows",
  cpe = {"o:microsoft:windows_server_2003/a"},
}});

--------------------------------------------------------------------------------
-- Enistic Zone Controller
--------------------------------------------------------------------------------
table.insert(fingerprints, {
  1, "File not found.", {
  p   = "Enistic zone controller tftpd",
}});

--------------------------------------------------------------------------------
-- Netkit
--------------------------------------------------------------------------------
table.insert(fingerprints, {
  1, "File not found", {
  p   = "Netkit tftpd or atftpd",
  cpe = {"a:netkit:netkit", "a:lefebvre:atftpd"},
}})
