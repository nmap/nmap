local bit = require "bit"
local msrpc = require "msrpc"
local smb = require "smb"
local stdnse = require "stdnse"
local tab = require "tab"
local table = require "table"

description=[[
Queries information managed by the Windows Master Browser.
]]

---
-- @usage
-- nmap -p 445 <host> --script smb-mbenum
--
-- @output
-- | smb-mbenum:
-- |   Backup Browser
-- |     WIN2K3-EPI-1  5.2  EPiServer 2003 frontend server
-- |   DFS Root
-- |     WIN2K3-1      5.2  MSSQL Server backend
-- |     WIN2K3-EPI-1  5.2  EPiServer 2003 frontend server
-- |   Master Browser
-- |     WIN2K3-EPI-1  5.2  EPiServer 2003 frontend server
-- |   SQL Server
-- |     WIN2K3-EPI-1  5.2  EPiServer 2003 frontend server
-- |   Server
-- |     TIME-CAPSULE  4.32  Time Capsule
-- |     WIN2K3-1      5.2   MSSQL Server backend
-- |     WIN2K3-EPI-1  5.2   EPiServer 2003 frontend server
-- |   Server service
-- |     TIME-CAPSULE  4.32  Time Capsule
-- |     WIN2K3-1      5.2   MSSQL Server backend
-- |     WIN2K3-EPI-1  5.2   EPiServer 2003 frontend server
-- |   Windows NT/2000/XP/2003 server
-- |     TIME-CAPSULE  4.32  Time Capsule
-- |     WIN2K3-1      5.2   MSSQL Server backend
-- |     WIN2K3-EPI-1  5.2   EPiServer 2003 frontend server
-- |   Workstation
-- |     TIME-CAPSULE  4.32  Time Capsule
-- |     WIN2K3-1      5.2   MSSQL Server backend
-- |_    WIN2K3-EPI-1  5.2   EPiServer 2003 frontend server
--
-- @args smb-mbenum.format (optional) if set, changes the format of the result
--     returned by the script. There are three possible formats:
--     1. Ordered by type horizontally
--     2. Ordered by type vertically
--     3. Ordered by type vertically with details (default)
--
-- @args smb-mbenum.filter (optional) if set, queries the browser for a
--     specific type of server (@see ServerTypes)
--
-- @args smb-mbenum.domain (optional) if not specified, lists the domain of the queried browser
--

--
-- Version 0.1
-- Created 06/11/2011 - v0.1 - created by Patrik Karlsson <patrik@cqure.net>

author = "Patrik Karlsson"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}


hostrule = function(host) return smb.get_port(host) ~= nil end

local function log(msg) stdnse.debug3("%s", msg) end

ServerTypes = {
  SV_TYPE_WORKSTATION = 0x00000001,
  SV_TYPE_SERVER = 0x00000002,
  SV_TYPE_SQLSERVER = 0x00000004,
  SV_TYPE_DOMAIN_CTRL = 0x00000008,
  SV_TYPE_DOMAIN_BAKCTRL = 0x00000010,
  SV_TYPE_TIME_SOURCE = 0x00000020,
  SV_TYPE_AFP = 0x00000040,
  SV_TYPE_NOVELL = 0x00000080,
  SV_TYPE_DOMAIN_MEMBER = 0x00000100,
  SV_TYPE_PRINTQ_SERVER = 0x00000200,
  SV_TYPE_DIALIN_SERVER = 0x00000400,
  SV_TYPE_SERVER_UNIX = 0x00000800,
  SV_TYPE_NT = 0x00001000,
  SV_TYPE_WFW = 0x00002000,
  SV_TYPE_SERVER_MFPN = 0x00004000,
  SV_TYPE_SERVER_NT = 0x00008000,
  SV_TYPE_POTENTIAL_BROWSER = 0x00010000,
  SV_TYPE_BACKUP_BROWSER = 0x00020000,
  SV_TYPE_MASTER_BROWSER = 0x00040000,
  SV_TYPE_DOMAIN_MASTER = 0x00080000,
  SV_TYPE_WINDOWS = 0x00400000,
  SV_TYPE_DFS = 0x00800000,
  SV_TYPE_CLUSTER_NT = 0x01000000,
  SV_TYPE_TERMINALSERVER = 0x02000000,
  SV_TYPE_CLUSTER_VS_NT = 0x04000000,
  SV_TYPE_DCE = 0x10000000,
  SV_TYPE_ALTERNATE_XPORT = 0x20000000,
  SV_TYPE_LOCAL_LIST_ONLY = 0x40000000,
  SV_TYPE_DOMAIN_ENUM = 0x80000000,
  SV_TYPE_ALL = 0xFFFFFFFF
}

TypeNames = {
  SV_TYPE_WORKSTATION = { long = "Workstation", short = "WKS" },
  SV_TYPE_SERVER = { long = "Server service", short = "SRVSVC" },
  SV_TYPE_SQLSERVER = { long = "SQL Server", short = "MSSQL" },
  SV_TYPE_DOMAIN_CTRL = { long = "Domain Controller", short = "DC" },
  SV_TYPE_DOMAIN_BAKCTRL = { long = "Backup Domain Controller", short = "BDC" },
  SV_TYPE_TIME_SOURCE = { long = "Time Source", short = "TIME" },
  SV_TYPE_AFP = { long = "Apple File Protocol Server", short = "AFP" },
  SV_TYPE_NOVELL = { long = "Novell Server", short = "NOVELL" },
  SV_TYPE_DOMAIN_MEMBER = { long = "LAN Manager Domain Member", short = "MEMB" },
  SV_TYPE_PRINTQ_SERVER = { long = "Print server", short = "PRINT" },
  SV_TYPE_DIALIN_SERVER = { long = "Dial-in server", short = "DIALIN" },
  SV_TYPE_SERVER_UNIX = { long = "Unix server", short = "UNIX" },
  SV_TYPE_NT = { long = "Windows NT/2000/XP/2003 server", short = "NT" },
  SV_TYPE_WFW = { long = "Windows for workgroups", short = "WFW" },
  SV_TYPE_SERVER_MFPN = { long = "Microsoft File and Print for Netware", short="MFPN" },
  SV_TYPE_SERVER_NT = { long = "Server", short = "SRV" },
  SV_TYPE_POTENTIAL_BROWSER = { long = "Potential Browser", short = "POTBRWS" },
  SV_TYPE_BACKUP_BROWSER = { long = "Backup Browser", short = "BCKBRWS"},
  SV_TYPE_MASTER_BROWSER = { long = "Master Browser", short = "MBRWS"},
  SV_TYPE_DOMAIN_MASTER = { long = "Domain Master Browser", short = "DOMBRWS"},
  SV_TYPE_WINDOWS = { long = "Windows 95/98/ME", short="WIN95"},
  SV_TYPE_DFS = { long = "DFS Root", short = "DFS"},
  SV_TYPE_TERMINALSERVER = { long = "Terminal Server", short = "TS" },
}

OutputFormat = {
  BY_TYPE_H = 1,
  BY_TYPE_V = 2,
  BY_TYPE_V_DETAILED = 3,
}


action = function(host, port)

  local status, smbstate = smb.start(host)
  local err, entries
  local path = ("\\\\%s\\IPC$"):format(host.ip)
  local detail_level = 1
  local format = stdnse.get_script_args("smb-mbenum.format") or OutputFormat.BY_TYPE_V_DETAILED
  local filter = stdnse.get_script_args("smb-mbenum.filter") or ServerTypes.SV_TYPE_ALL
  local domain = stdnse.get_script_args("smb-mbenum.domain")

  filter = tonumber(filter) or ServerTypes[filter]
  format = tonumber(format)

  if ( not(filter) ) then
    return "\n The argument smb-mbenum.filter contained an invalid value."
  end

  if ( not(format) ) then
    return "\n  The argument smb-mbenum.format contained an invalid value."
  end

  local errstr = nil
  status, err = smb.negotiate_protocol(smbstate, {})
  if ( not(status) ) then
    log("ERROR: smb.negotiate_protocol failed")
    errstr = "\n  ERROR: Failed to connect to browser service: " .. err
  else

    status, err = smb.start_session(smbstate, {})
    if ( not(status) ) then
      log("ERROR: smb.start_session failed")
      errstr = "\n  ERROR: Failed to connect to browser service: " .. err
    else

      status, err = smb.tree_connect(smbstate, path, {})
      if ( not(status) ) then
        log("ERROR: smb.tree_connect failed")
        errstr = "\n  ERROR: Failed to connect to browser service: " .. err
      else

        status, entries = msrpc.rap_netserverenum2(smbstate, domain, filter, detail_level)
        if ( not(status) ) then
          log("ERROR: msrpc.rap_netserverenum2 failed")
          -- 71 == 0x00000047, ERROR_REQ_NOT_ACCEP
          -- http://msdn.microsoft.com/en-us/library/cc224501.aspx
          if entries:match("= 71$") then
            errstr = "Not a master or backup browser"
          else
            errstr = "\n  ERROR: " .. entries
          end
        end
      end

      status, err = smb.tree_disconnect(smbstate)
      if ( not(status) ) then log("ERROR: smb.tree_disconnect failed") end
    end

    status, err = smb.logoff(smbstate)
    if ( not(status) ) then log("ERROR: smb.logoff failed") end
  end

  status, err = smb.stop(smbstate)
  if ( not(status) ) then log("ERROR: smb.stop failed") end

  if errstr then
    return errstr
  end

  local results, output = {}, {}
  for k, _ in pairs(ServerTypes) do
    for _, server in ipairs(entries) do
      if ( TypeNames[k] and bit.band(server.type,ServerTypes[k]) == ServerTypes[k] ) then
        results[TypeNames[k].long] = results[TypeNames[k].long] or {}
        if ( format == OutputFormat.BY_TYPE_V_DETAILED ) then
          table.insert(results[TypeNames[k].long], server)
        else
          table.insert(results[TypeNames[k].long], server.name)
        end
      end
    end
  end

  if ( format == OutputFormat.BY_TYPE_H ) then
    for k, v in pairs(results) do
      local row = ("%s: %s"):format( k, stdnse.strjoin(",", v) )
      table.insert(output, row)
    end
    table.sort(output)
  elseif( format == OutputFormat.BY_TYPE_V ) then
    for k, v in pairs(results) do
      v.name = k
      table.insert(output, v)
    end
    table.sort(output, function(a,b) return a.name < b.name end)
  elseif( format == OutputFormat.BY_TYPE_V_DETAILED ) then
    for k, v in pairs(results) do
      local cat_tab = tab.new(3)
      table.sort(v, function(a,b) return a.name < b.name end )
      for _, server in pairs(v) do
        tab.addrow(
          cat_tab,
          server.name,
          ("%d.%d"):format(server.version.major,server.version.minor),
          server.comment
        )
      end
      table.insert(output, { name = k, tab.dump(cat_tab) } )
    end
    table.sort(output, function(a,b) return a.name < b.name end)
  end

  return stdnse.format_output(true, output)
end
