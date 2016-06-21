---
-- Functions for vulnerability management.
--
-- The vulnerabilities library may be used by scripts to report and
-- store vulnerabilities in a common format.
--
-- Reported vulnerabilities information must be stored in tables.
-- Each vulnerability must have its own state:
--  <code>NOT_VULN</code>: The program was confirmed to be not vulnerable.
--  <code>LIKELY_VULN</code>: The program is likely to be vulnerable,
--      this can be the case when we do a simple version comparison. This
--      state should cover possible false positive situations.
--  <code>VULN</code>: The program was confirmed to be vulnerable.
--  <code>EXPLOIT</code>: The program was confirmed to be vulnerable and
--      was exploited successfully. The <code>VULN</code> state will be
--      set automatically.
--  <code>DoS</code>: The program was confirmed to be vulnerable to Denial
--      of Service attack. The <code>VULN</code> state will be set
--      automatically.
--
-- To match different vulnerability states, like the <code>VULN</code>
-- and <code>EXPLOIT</code> states or the <code>VULN</code> and
-- <code>DoS</code> states, one can use the bitwise operations.
--
--
-- Vulnerability table:
-- --------------------
-- <code>
-- local vuln_table = {
--   title = "BSD ftpd Single Byte Buffer Overflow", -- mandatory field
--   state = vulns.STATE.EXPLOIT, -- mandatory field
--   -- Of course we must confirm the exploitation, otherwise just mark
--   -- it vulns.STATE.VULN if the vulnerability was confirmed.
--   -- states: 'NOT_VULN', 'LIKELY_VULN', 'VULN', 'DoS' and 'EXPLOIT'
--
--
--   -- The following fields are all optional
--
--   IDS = { -- Table of IDs
--      --  ID Type     ID (must be a string)
--          CVE       = 'CVE-2001-0053',
--          BID       = '2124',
--   },
--
--   risk_factor = "High", -- 'High', 'Medium' or 'Low'
--   scores = { -- A map of the different scores
--      CVSS = "10.0",
--      CVSSv2 = "...",
--   },
--
--   description = [[
-- One-byte buffer overflow in BSD-based ftpd allows remote attackers
-- to gain root privileges.]],
--
--   dates = {
--      disclosure = { year = 2000, month = 12, day = 18},
--   },
--
--   check_results = { -- A string or a list of strings
--      -- This field can store the results of the vulnerability check.
--      -- Did the server return anything ? some specialists can
--      -- investigate this and decide if the program is vulnerable.
--   },
--
--   exploit_results = { -- A string or a list of strings
--      -- This field can store the results of the exploitation.
--   },
--
--   extra_info = { -- A string or a list of strings
--      -- This field can be used to store and shown any useful
--      -- information about the vulnerability, server, etc.
--   },
--
--   references = { -- List of references
--      'http://www.openbsd.org/advisories/ftpd_replydirname.txt',
--
--       -- If some popular IDs like 'CVE' and 'OSVBD' are provided
--       -- then their links will be automatically constructed.
--   },
-- }
-- </code>
--
--
-- The following examples illustrates how to use the library.
--
-- Examples for <code>portrule</code> and <code>hostrule</code> scripts:
-- <code>
--  -- portrule and hostrule scripts must use the vulns.Report class
--  -- to report vulnerabilities
--  local vuln_table = {
--   title = "BSD ftpd Single Byte Buffer Overflow", -- mandatory field
--   references = { -- List of references
--      'http://www.openbsd.org/advisories/ftpd_replydirname.txt',
--   },
--   ...
--  }
--  ...
--  vuln_table.state = vulns.STATE.VULN
--  local report = vulns.Report:new(SCRIPT_NAME, host, port)
--  return report:make_output(vuln_table, ...)
-- </code>
--
-- <code>
--  local vuln_table = {
--   title = "BSD ftpd Single Byte Buffer Overflow", -- mandatory field
--   references = { -- List of references
--      'http://www.openbsd.org/advisories/ftpd_replydirname.txt',
--   },
--   ...
--  }
--  ...
--  vuln_table.state = vulns.STATE.VULN
--  local report = vulns.Report:new(SCRIPT_NAME, host, port)
--  report:add(vuln_table, ...)
--  return report:make_output()
-- </code>
--
--
-- Examples for <code>prerule</code> and <code>postrule</code> scripts:
-- <code>
--  local FID -- my script FILTER ID
--
--  prerule = function()
--    FID = vulns.save_reports()
--    if FID then
--      return true
--    end
--    return false
--  end
--
--  postrule = function()
--    if nmap.registry[SCRIPT_NAME] then
--      FID = nmap.registry[SCRIPT_NAME].FID
--      if vulns.get_ids(FID) then
--        return true
--      end
--    end
--    return false
--  end
--
--  prerule_action = function()
--    nmap.registry[SCRIPT_NAME] = nmap.registry[SCRIPT_NAME] or {}
--    nmap.registry[SCRIPT_NAME].FID = FID
--    return nil
--  end
--
--  postrule_action = function()
--    return vulns.make_output(FID) -- show all the vulnerabilities
--  end
--
--  local tactions = {
--    prerule = prerule_action,
--    postrule = postrule_action,
--  }
--
--  action = function(...) return tactions[SCRIPT_TYPE](...) end
-- </code>
--
-- @args vulns.showall  If set, the library will show and report all the
--   registered vulnerabilities which includes the
--   <code>NOT VULNERABLE</code> ones. By default the library will only
--   report the <code>VULNERABLE</code> entries: <code>VULNERABLE</code>,
--   <code>LIKELY VULNERABLE</code>, <code>VULNERABLE (DoS)</code>
--   and <code>VULNERABLE (Exploitable)</code>.
--   This argument affects the following functions:
--   vulns.Report.make_output(): the default output function for
--                               portule/hostrule scripts.
--   vulns.make_output(): the default output function for postrule scripts.
--   vulns.format_vuln() and vulns.format_vuln_table() functions.
--
-- Library debug messages:
--   Level 2: show the <code>NOT VULNERABLE</code> entries.
--   Level 3: show all the vulnerabilities that are saved into the registry.
--   Level 5: show all the other debug messages (useful for debugging).
--
-- Note: Vulnerability tables are always re-constructed before they are
-- saved in the registry. We do this to avoid using vulnerability tables
-- that are referenced by other objects to let the Lua garbage-collector
-- collect these last objects.
--
-- @author Djalal Harouni
-- @author Henri Doreau
-- @copyright Same as Nmap--See https://nmap.org/book/man-legal.html


local bit = require "bit"
local ipOps = require "ipOps"
local nmap = require "nmap"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"
local type    = type
local next    = next
local pairs   = pairs
local ipairs  = ipairs
local select  = select
local tostring = tostring
local insert  = table.insert
local concat  = table.concat
local sort    = table.sort
local setmetatable = setmetatable
local string_format = string.format
local string_upper = string.upper

local debug = stdnse.debug
local compare_ip = ipOps.compare_ip

_ENV = stdnse.module("vulns", stdnse.seeall)

-- This is the vulnerability database
-- (it will reference a table in the registry: nmap.registry.VULNS
-- see the save_reports() function).
local VULNS

-- Vulnerability Database (registry) internal data representation
--
-- -- VULNS = nmap.registry.VULNS
-- VULNS = {
--
--  -- Vulnerability entries
--  ENTRIES = {
--
--    HOSTS = {
--      -- Table of hosts
--      [host_a_ip] = {
--        -- list of vulnerabilities that affect the host A
--        { -- vuln_1
--          title = 'Program X vulnerability',
--          state = vulns.State.VULN,
--          IDS = {CVE = 'CVE-XXXX-XXXX', OSVDB = 'XXXXX'},
--
--          -- the following fields are all optional
--          risk_factor = 'High',
--          description = 'vulnerability description ...',
--
--          references = VULNS.SHARED.REFERENCES[x],
--        },
--
--        { -- vuln_2
--          ...
--        },
--        ...
--      },
--
--      [host_b_ip] = {
--        ...
--      },
--    },
--
--    NETWORKS = {
--      -- list of vulnerabilities that lacks the 'host' table
--      { -- vuln_1
--        ...
--      },
--      {
--        ...
--      },
--    },
--  },
--
--  -- Store shared data between vulnerabilities here (type of data: tables)
--  SHARED = {
--    -- List of references, members will be referenced by the previous
--    -- vulnerability entries.
--    REFERENCES = {
--      {
--        ["http://..."] = true,
--        ["http://..."] = true,
--        ...
--      },
--      {
--        ...
--      },
--    },
--  },
--
--  -- These are tables that are associated with the different filters.
--  -- This will help the vulnerabilities lookup mechanism.
--  --
--  -- Just caches to reference all the vulnerabilities information:
--  -- tables, maps etc. Only memory addresses are stored here.
--  FILTER_IDS = {
--
--    [fid_1] = { -- FILTER ID as it returned by vulns.save_reports()
--      'CVE' = {
--        'CVE-XXXX-XXXX' = {
--          ENTRIES = {
--            HOSTS = {
--              -- References to hosts and their vulnerabilities
--
--              -- The same IP address with multiple targetnames.
--              [host_a_ip] = {
--                [host_a_ip_targetname_x] =
--                  VULNS.ENTRIES.HOSTS[host_a_ip][vuln_x],
--                [host_a_ip_targetname_y] =
--                  VULNS.ENTRIES.HOSTS[host_a_ip][vuln_y],
--              }
--              [host_x_ip] = {
--                [host_x_targetname_x or host_x_ip] =
--                  VULNS.ENTRIES.HOSTS[host_x][vuln_x],
--              }
--              [host_y_ip] = {
--                [host_y_targetname_y or host_y_ip] =
--                  VULNS.ENTRIES.HOSTS[host_y][vuln_z],
--              }
--              ...
--            },
--            NETWORKS = {
--              VULNS.ENTRIES.NETWORKS[vuln_x],
--              ...
--            }
--          },
--        },
--
--        'CVE-YYYY-YYYY' = {
--
--        },
--      },
--
--      'OSVDB' = {
--        'XXXXX' = {
--
--          entries = {
--            ...
--          },
--        },
--        'YYYYY' = {
--          entries = {
--            ...
--          },
--        },
--      },
--
--      'YOUR_FAVORITE_ID' = {
--        'XXXXX' = {
--          ...
--        },
--      },
--
--      -- Entries without the vulnerability ID are stored here.
--      'NMAP_ID' = {
--        'XXXXX' = {
--          ...
--        },
--      },
--    },
--
--    [fid_2] = {
--      ...
--    },
--
--    [fid_3] = {
--      ...
--    },
--  },
--
--  -- List of the filters callbacks
--  FILTERS_FUNCS = {
--    [fid_1] = callback_filter_1,
--    [fid_2] = callback_filter_2,
--    ...
--  }
--
-- }  -- end of VULNS


-- This value is used to reference vulnerability entries
-- that lacks vulnerability IDs.
local NMAP_ID_NUM = 0

-- SHOW_ALL: if set the format and make_output() functions will
-- show the vulnerability entries with a state == NOT_VULN
local SHOW_ALL = stdnse.get_script_args('vulns.showall') or
                    stdnse.get_script_args('vuln.showall') or
                    stdnse.get_script_args('vulns.show-all') or
                    stdnse.get_script_args('vuln.show-all')

-- The different states of the vulnerability
STATE = {
  LIKELY_VULN = 0x01,
  NOT_VULN = 0x02,
  VULN = 0x04,
  DoS = 0x08,
  EXPLOIT = 0x10,
}

-- The vulnerability messages.
STATE_MSG = {
  [STATE.LIKELY_VULN] = 'LIKELY VULNERABLE',
  [STATE.NOT_VULN] = 'NOT VULNERABLE',
  [STATE.VULN] = 'VULNERABLE',
  [STATE.DoS] = 'VULNERABLE (DoS)',
  [STATE.EXPLOIT] = 'VULNERABLE (Exploitable)',
  [bit.bor(STATE.DoS,STATE.VULN)] = 'VUNERABLE (DoS)',
  [bit.bor(STATE.EXPLOIT,STATE.VULN)] = 'VULNERABLE (Exploitable)',
}

-- Scripts must provide the correct risk factor string.
local RISK_FACTORS = {
  ['HIGH'] = true,
  ['MEDIUM'] = true,
  ['LOW'] = true,
}

-- Use this function to copy a variable into another one.
-- If the src is an empty table then return nil.
-- Note: this is a special function for this library.
local function tcopy(src)
  if src and type(src) == "table" then
    if next(src) then
      local dst = {}
      for k,v in pairs(src) do
        if type(v) == "table" then
          dst[k] = tcopy(v)
        else
          dst[k] = v
        end
      end
      return dst
    else
      return nil
    end
  end
  return src
end

-- Use this function to push data from src list to dst list.
local function tadd(dst, src)
  if dst and type(dst) == "table" and src and type(src) == "table" then
    for _, v in ipairs(src) do
      dst[#dst + 1] = v
    end
  end
end

-- A list of popular vulnerability IDs with their callbacks to
-- construct and return the correct links.
local POPULAR_IDS_LINKS = {
  CVE = function(id)
          local link = 'https://cve.mitre.org/cgi-bin/cvename.cgi?name='
          return string_format("%s%s", link, id)
        end,
  OSVDB = function(id)
            local link = 'http://osvdb.org/'
            return string_format("%s%s", link, id)
          end,
  BID = function(id)
          local link = 'http://www.securityfocus.com/bid/'
          return string_format("%s%s", link, id)
        end,
}

--- Registers and associates a callback function with the popular ID
-- vulnerability type to construct and return popular links
-- automatically.
--
-- The callback function takes a vulnerability ID as a parameter
-- and must return a link. The library automatically supports three
-- different popular IDs:
-- <code>CVE</code>: cve.mitre.org
-- <code>OSVDB</code>: osvdb.org
-- <code>BID</code>: www.securityfocus.com/bid
--
-- @usage
-- function get_example_link(id)
--   return string.format("%s%s",
--            "http://example.com/example?name=", id)
-- end
-- vulns.register_popular_id('EXM-ID', get_example_link)
--
-- @param id_type  String representing the vulnerability ID type.
--        <code>'CVE'</code>, <code>'OSVDB'</code> ...
-- @param callback A function to construct and return links.
-- @return True on success or false if it can not register the callback.
register_popular_id = function(id_type, callback)
  if id_type and callback and type(id_type) == "string" and
    type(callback) == "function" then
      POPULAR_IDS_LINKS[string_upper(id_type)] = callback
      return true
  end
  return false
end

--- Calls the function associated with the popular ID vulnerability
-- type to construct and to return the appropriate reference link.
--
-- The library automatically supports three different popular IDs:
-- <code>CVE</code>: cve.mitre.org
-- <code>OSVDB</code>: osvdb.org
-- <code>BID</code>: www.securityfocus.com/bid
--
-- @usage
-- local link = vulns.get_popular_link('CVE', 'CVE-2001-0053')
--
-- @param id_type  String representing the vulnerability ID type.
--   <code>'CVE'</code>, <code>'OSVDB'</code> ...
-- @param id  String representing the vulnerability ID.
-- @return URI  The URI on success or nil if the library does not support
--   the specified <code>id_type</code>, and in this case you can register
--   new ID types by calling <code>vulns.register_popular_id()</code>.
get_popular_link = function(id_type, id)
  local id_vuln_type = string_upper(id_type)
  if POPULAR_IDS_LINKS[id_vuln_type] then
    return POPULAR_IDS_LINKS[id_vuln_type](id)
  end
end

--- Validate the vulnerability information
--
-- @param vuln_table The vulnerability information table.
-- @return True on success or false if some mandatory information is
--         missing.
local validate_vuln = function(vuln_table)
  local ret = false

  if type(vuln_table) == "table" and vuln_table.title and
  type(vuln_table.title) == "string" and vuln_table.state and
  STATE_MSG[vuln_table.state] then

    if vuln_table.risk_factor then
      if type(vuln_table.risk_factor) == "string" and
        vuln_table.risk_factor:len() > 0 then

        if RISK_FACTORS[string_upper(vuln_table.risk_factor)] then
          ret = true
        end
      end
    else
      ret = true
    end
  end

  return ret
end

--- Normalize the vulnerability information.
--
-- This function will modify the internal fields of the vulnerability.
--
-- @param vuln_table The vulnerability information table.
local normalize_vuln_info = function(vuln_table)
  if not vuln_table.IDS then
    vuln_table.IDS = vuln_table.ids or {}
  end

  if not next(vuln_table.IDS) then
    -- Use the internal NMAP_ID if vulnerability IDs are missing.
    NMAP_ID_NUM = NMAP_ID_NUM + 1
    -- Push IDs as strings instead of numbers to avoid
    -- dealing with array holes.
    vuln_table.IDS.NMAP_ID = string_format("NMAP-%d", NMAP_ID_NUM)
  else
    for id_type, id in pairs(vuln_table.IDS) do
      -- Push IDs as strings instead of numbers to avoid
      -- dealing with array holes.
      if type(id) == "number" then
        vuln_table.IDS[id_type] = tostring(id)
      end
    end
  end

  -- If the vulnerability state is 'DoS' or 'EXPLOIT' then set
  -- the 'VULN' state.
  if vuln_table.state == STATE.DoS or
  vuln_table.state == STATE.EXPLOIT then
    vuln_table.state = bit.bor(vuln_table.state, STATE.VULN)
  end

  -- Convert the following string fields to tables.
  if vuln_table.description and
  type(vuln_table.description) == "string" then
    vuln_table.description = {vuln_table.description}
  end

  if vuln_table.check_results and
  type(vuln_table.check_results) == "string" then
    vuln_table.check_results = {vuln_table.check_results}
  end

  if vuln_table.exploit_results and
  type(vuln_table.exploit_results) == "string" then
    vuln_table.exploit_results = {vuln_table.exploit_results}
  end

  if vuln_table.extra_info and
  type(vuln_table.extra_info) == "string" then
    vuln_table.extra_info = {vuln_table.extra_info}
  end

  if vuln_table.references and
  type(vuln_table.references) == "string" then
    vuln_table.references = {vuln_table.references}
  end
end

-- Default filter to use if the script did not provide one.
local default_filter = function(vuln_table) return true end

--- Register the callback filters.
--
-- This function just inserts the callback filters in the filters_db.
--
-- @param filters_db The filters database (a table in the registry).
-- @param filter_callback The callback function.
-- @return FID  The filter ID associated with the callback function.
local register_filter = function(filters_db, filter_callback)
  if filter_callback and type(filter_callback) == "function" then
    filters_db[#filters_db + 1] = filter_callback
  else
    filters_db[#filters_db + 1] = default_filter
  end
  return #filters_db
end

--- Call filter functions.
--
-- The callback filters will take a vulnerability table and inspect
-- it. The vulnerability will be stored in the registry if one of these
-- filters return true.
--
-- @param filters_db The filters database (a table in the registry).
-- @param vuln_table The vulnerability information table.
-- @return List  The list of filters that have returned True. If all the
--    Filters functions returned false then nil will be returned.
local filter_vulns = function(filters_db, vuln_table)
  local FIDS = {}
  for fid, callback in ipairs(filters_db) do
    if callback(vuln_table) == true then
      FIDS[#FIDS + 1] = fid
    end
  end
  return next(FIDS) and FIDS or nil
end

--- Add IDs to the ID table
--
-- IDs can be 'CVE', 'OSVDB', 'BID' ...
-- @usage
-- l_add_id_type(fid_table, 'CVE')
--
-- @param fid_table  The filter ID table.
-- @param id_type  String representing the vulnerability ID type.
local l_add_id_type = function(fid_table, id_type)
  fid_table[string_upper(id_type)] = fid_table[id_type] or {}
end

--- Get simple "targetname:port_number" keys
local l_get_host_port_key = function(vuln_table)
  local target = ""

  if vuln_table.host and next(vuln_table.host) then
    target = stdnse.get_hostname(vuln_table.host)

    if vuln_table.port and next(vuln_table.port) then
      target = target..string_format(":%d", vuln_table.port.number)
    end

  end

  return target
end

--- Update the FILTER ID table references.
--
-- When a new vulnerability table is stored in the registry in the
-- <code>nmap.registry.VULNS.ENTRIES</code> database, we will also update
-- the <code>nmap.registry.VULNS.FILTERS_IDS[fid_table]</code> to
-- reference the new saved vulnerability.
--
-- @usage
-- l_update_id(fid_table, 'CVE', 'CVE-2001-0053', vuln_table)
--
-- @param fid_table  The filter ID table.
-- @param id_type  String representing the vulnerability ID type.
--        <code>'CVE'</code>, <code>'OSVDB'</code> ...
-- @param id  String representing the vulnerability ID.
-- @param vuln_table  The vulnerability table reference that was stored
--        in the registry <code>nmap.registry.VULNS.ENTRIES</code>.
-- @return Table  A reference to the vulnerability table that was just
--        saved in the <code>FILTER ID</code> table.
local l_update_id = function(fid_table, id_type, id, vuln_table)
  local id_type = string_upper(id_type)

  -- Add the ID vulnerability type if it is missing
  l_add_id_type(fid_table, id_type)

  -- Make sure that we are referencing the correct tables
  fid_table[id_type][id] = fid_table[id_type][id] or {}
  fid_table[id_type][id]['ENTRIES'] = fid_table[id_type][id]['ENTRIES'] or {}
  local push_table = fid_table[id_type][id]['ENTRIES']

  if vuln_table.host and next(vuln_table.host) then
    local target_key = l_get_host_port_key(vuln_table)
    local host_info = string_format(" (host:%s %s)", vuln_table.host.ip, target_key)

    debug(5,
      "vulns.lua: Updating VULNS.FILTERS_IDS{} with '%s' ID:%s:%s %s",
      vuln_table.title, id_type, id, host_info)
    push_table.HOSTS = push_table.HOSTS or {}
    push_table.HOSTS[vuln_table.host.ip] =
        push_table.HOSTS[vuln_table.host.ip] or {}
    push_table.HOSTS[vuln_table.host.ip][target_key] = vuln_table
    return push_table.HOSTS[vuln_table.host.ip][target_key]
  else
    debug(5,
      "vulns.lua: Updating VULNS.FILTERS_IDS{} with '%s' ID:%s:%s",
      vuln_table.title, id_type, id)
    push_table.NETWORKS = push_table.NETWORKS or {}
    push_table.NETWORKS[#push_table.NETWORKS + 1] = vuln_table
    return push_table.NETWORKS[#push_table.NETWORKS]
  end
end

--- Lookup for vulnerability ID in the vulnerability database
-- associated with the <code>FILTER ID</code>, and return
-- a table of vulnerabilities identified by the provided ID.
--
-- @usage
-- local ids_table = l_lookup_id(fid_table, 'CVE', 'CVE-2001-0053')
--
-- @param fid_table  The filter ID table.
-- @param id_type  String representing the vulnerability ID type.
--        <code>'CVE'</code>, <code>'OSVDB'</code> ...
-- @param id  String representing the vulnerability ID.
-- @return Table  A table of vulnerabilities if there are entries
--         identified by the <code>id</code> parameter, otherwise nil.
local l_lookup_id = function(fid_table, id_type, id)
  local id_type = string_upper(id_type)
  if fid_table[id_type] then
    return fid_table[id_type][id]
  end
end

--- Save the references in the references_db
--
-- @param references_db The references_db which is a table in the registry
-- @param new_refs A list of references to save.
-- @return table The table of references in the references_db.
local l_push_references = function(references_db, new_refs)
  if new_refs and next(new_refs) then
    local refs = {}
    for _, l in ipairs(new_refs) do
      refs[l] = true
    end
    insert(references_db, refs)
    return references_db[#references_db]
  end
end

--- Re-construct the vulnerability table and save it in the vulnerability
-- database (vulndb: registry).
--
-- @param vulndb The vulnerability database which is a table in the
--   registry.
-- @param new_vuln  The vulnerability information table.
-- @return vuln_table  The vulnerability table in the vulndb.
local l_push_vuln = function(vulndb, new_vuln)
  -- Reconstruct the vulnerability table to avoid referencing
  -- any old external data.
  -- e.g: we can have other objects that reference the 'new_vuln'
  --      object, so we reconstruct the 'vuln' object to not reference
  --      the 'new_vuln' and to let the GC collect the 'new_vuln' and
  --      any other external object referencing it.

  local new_vuln = new_vuln

  local vuln = {
    title = new_vuln.title,
    state = new_vuln.state,
    _FIDS_MATCH = tcopy(new_vuln._FIDS_MATCH),
    IDS = {},
  }

  if new_vuln.IDS and next(new_vuln.IDS) then
    for id_type, id in pairs(new_vuln.IDS) do
      vuln.IDS[string_upper(id_type)] = id
    end
  end

  -- Save these fields only when the state is not 'NOT VULNERABLE'
  if bit.band(new_vuln.state, STATE.NOT_VULN) == 0 then
    if new_vuln.risk_factor then
      vuln.risk_factor = new_vuln.risk_factor
      vuln.scores = tcopy(new_vuln.scores)
    end

    vuln.description = tcopy(new_vuln.description)
    vuln.dates = tcopy(new_vuln.dates)

    -- Store the following information for the post-processing scripts
    --vuln.check_results = tcopy(new_vuln.check_results)
    --if vuln.check_results then
    --  insert(vuln.check_results, 1,
    --    string_format("Script %s checks:", new_vuln.script_name))
    --end

    --if bit.band(vuln.state, STATE.EXPLOIT) ~= 0 then
    --  vuln.exploit_results = tcopy(new_vuln.exploit_results)
    --  if vuln.exploit_results then
    --    insert(vuln.exploit_results, 1,
    --      string_format("Script %s exploits:", new_vuln.script_name))
    --  end
    --end

    --vuln.extra_info = tcopy(new_vuln.extra_info)
    --if vuln.extra_info then
    --  insert(vuln.extra_info, 1,
    --    string_format("Script %s info:", new_vuln.script_name))
    --end
  end

  vuln.references = l_push_references(vulndb.SHARED.REFERENCES,
                                      new_vuln.references)

  if new_vuln.script_name then
    vuln.scripts = {}
    insert(vuln.scripts, new_vuln.script_name)
  end

  local ref_vuln
  if new_vuln.host and next(new_vuln.host) then
    vuln.host = tcopy(new_vuln.host)
    vuln.port = tcopy(new_vuln.port)
    vulndb.ENTRIES.HOSTS[vuln.host.ip] = vulndb.ENTRIES.HOSTS[vuln.host.ip] or {}
    insert(vulndb.ENTRIES.HOSTS[vuln.host.ip], vuln)
    ref_vuln = vulndb.ENTRIES.HOSTS[vuln.host.ip][#vulndb.ENTRIES.HOSTS[vuln.host.ip]]
  else
    insert(vulndb.ENTRIES.NETWORKS, vuln)
    ref_vuln = vulndb.ENTRIES.NETWORKS[#vulndb.ENTRIES.NETWORKS]
  end

  -- Return a reference to the vulnerability table in the registry
  return ref_vuln
end

--- Update the references that are stored in the references_db
--
-- @param references_db The references_db which is a table in the registry
-- @param old_refs A table of the previously saved references.
-- @param new_refs A list of references to save.
-- @return table The table of updated references in the references_db.
local l_update_references = function(references_db, old_refs, new_refs)
  if old_refs and next(old_refs) and new_refs and next(new_refs) then
    for _, l in ipairs(new_refs) do
      old_refs[l] = true
    end
  end

  return next(old_refs) and old_refs or nil
end

--- Update the vulnerability information table that was stored in the
-- vulnerability database (vulndb: registry).
--
-- @param vulndb The vulnerability database which is a table in the registry.
-- @param old_vuln  The old vulnerability table stored in the vulndb.
-- @param new_vuln  The new vulnerability information table.
-- @return vuln_table  The updated vulnerability table in the vulndb.
local l_update_vuln = function(vulndb, old_vuln, new_vuln)
  local old_vuln, new_vuln = old_vuln, new_vuln

  -- Update vulnerability state
  if old_vuln.state < new_vuln.state then
    old_vuln.state = new_vuln.state
  end

  -- Update the FILTERS IDS MATCH
  for fid_table in pairs(new_vuln._FIDS_MATCH) do
    old_vuln[fid_table] = true
  end

  -- Add new IDs to the old vulnerability entry
  if new_vuln.IDS and next(new_vuln.IDS) then
    for id_type, id in pairs(new_vuln.IDS) do
      local id_vuln_type = string_upper(id_type)
      if not old_vuln.IDS[id_vuln_type] then
        old_vuln.IDS[id_vuln_type] = id
      end
    end
  end

  -- Remove these fields if the state is NOT VULNERABLE
  -- Note: At this level the old_vuln.state was already updated.
  if bit.band(old_vuln.state, STATE.NOT_VULN) ~= 0 then
    old_vuln.risk_factor = nil
    old_vuln.scores = nil
    old_vuln.description = nil
    old_vuln.dates = nil
    --old_vuln.check_results = nil
    --old_vuln.exploit_results = nil
    --old_vuln.extra_info = nil
  else
    if new_vuln.risk_factor then
      old_vuln.risk_factor = new_vuln.risk_factor
      if not old_vuln.scores and new_vuln.scores then
        old_vuln.scores = tcopy(new_vuln.scores)
      end
    end

    if not old_vuln.description and new_vuln.description then
      old_vuln.description = tcopy(new_vuln.description)
    end

    if not old_vuln.dates and new_vuln.dates then
      old_vuln.dates = tcopy(old_vuln.dates)
    end

    -- Store the following information for the post-processing scripts
    --if new_vuln.check_results then
    --  old_vuln.check_results = old_vuln.check_results or {}
    --  insert(old_vuln.check_results,
    --      string_format("Script %s checks:", new_vuln.script_name))
    --  tadd(old_vuln.check_results, new_vuln.check_results)
    --end

    --if new_vuln.exploit_results and
    --bit.band(old_vuln.state, STATE.EXPLOIT) ~= 0 then
    --  old_vuln.exploit_results = old_vuln.exploit_results or {}
    --  insert(old_vuln.exploit_results,
    --      string_format("Script %s exploits:", new_vuln.script_name))
    --  tadd(old_vuln.exploit_results, new_vuln.exploit_results)
    --end

    --if new_vuln.extra_info then
    --  old_vuln.extra_info = old_vuln.extra_info or {}
    --  insert(old_vuln.extra_info,
    --      string_format("Script %s info:", new_vuln.script_name))
    --  tadd(old_vuln.extra_info, new_vuln.extra_info)
    --end
  end

  -- Update the 'port' table if necessary
  if not old_vuln.port and new_vuln.port then
    old_vuln.port = tcopy(new_vuln.port)
  end

  -- Add the script name to the list of scripts that tested this
  -- vulnerability.
  if new_vuln.script_name then
    old_vuln.scripts = old_vuln.scripts or {}
    insert(old_vuln.scripts, new_vuln.script_name)
  end

  -- Update the references links
  if new_vuln.references and next(new_vuln.references) then
    old_vuln.references = l_update_references(vulndb.SHARED.REFERENCES,
                                              old_vuln.references,
                                              new_vuln.references)
  end

  return old_vuln
end

--- Adds the vulnerability table to the vulndb (registry).
--
-- @param vulndb The vulnerability database which is a table in the
--   registry.
-- @param vuln_table  The vulnerability information table.
-- @return True if the vulnerability information table was saved,
--    otherwise False.
local l_add = function(vulndb, vuln_table)
  local vuln_table = vuln_table

  -- Get the Filters IDs list
  local FIDS = filter_vulns(vulndb.FILTERS_FUNCS, vuln_table)

  -- All the Filters denied the vulnerability entry
  if not FIDS then
    return false
  else
    -- Store the Filters IDS that will reference this vulnerability
    -- This is a special field
    vuln_table._FIDS_MATCH = {}
    for _, fid in ipairs(FIDS) do
      vuln_table._FIDS_MATCH[vulndb.FILTERS_IDS[fid]] = true
    end
  end

  -- If we are here then the vulnerability entry has passed
  -- some filters. The list of passed filters is stored in the
  -- FIDS variable


  -- Store the new vulnerability IDS in this list:
  -- 1) If the vulnerability is new then store all the IDS.
  -- 2) If the vulnerability was already pushed, then we can have a
  --    situation when the current vulnerability table (which is the
  --    same vulnerability that was already pushed) have some new
  --    IDS entries, and in this case we will also save these new IDS,
  --    and make them reference the old vulnerability entry.
  local NEW_IDS = {}

  -- If the vulnerability was already saved in the registry, then
  -- store its references here.
  local old_entries = {}


  -- Count how many vuln_table.IDS entries should be and should reference
  -- the vulnerability table in the registry
  -- (in all the FILTERS_IDS tables).
  local ids_count = 0

  -- Count how many vuln_table.IDS entries are referencing an old
  -- vulnerability entry that was already saved in the registry.
  local ids_found = 0

  local host_info, target_key = "", ""
  if vuln_table.host and next(vuln_table.host) then
    target_key = l_get_host_port_key(vuln_table)
    host_info = string_format(" (host:%s %s)", vuln_table.host.ip, target_key)
  end

  -- Search the Filters IDS for the vulnerability
  for _, fid in ipairs(FIDS) do
    for id_type, id in pairs(vuln_table.IDS) do
      -- Count how many IDs should be referencing the vulnerability
      -- entry in all the FILTERS_IDS tables.
      ids_count = ids_count + 1

      -- If the IDs are referencing an old vulnerability entry
      -- that was saved previously in the registry then make this
      -- variable false.
      local id_not_found = true

      debug(5,
        "vulns.lua: Searching VULNS.FILTERS_IDS[%d] for '%s' ID:%s:%s",
        fid, vuln_table.title, id_type, id)

      local db = l_lookup_id(vulndb.FILTERS_IDS[fid], id_type, id)
      if db and db.ENTRIES and db.ENTRIES.HOSTS then

        if vuln_table.host and next(vuln_table.host) then
          local old_vuln_list = db.ENTRIES.HOSTS[vuln_table.host.ip]

          if old_vuln_list then
            -- Host IP is already affected by this vulnerability.
            -- Check the couple "targetname:port" now
            local tmp_vuln = old_vuln_list[target_key]

            if tmp_vuln then
              debug(5,
              "vulns.lua: VULNS.FILTERS_IDS[%d] '%s' ID:%s:%s%s: FOUND",
                fid, vuln_table.title, id_type, id, host_info)
              if old_entries[#old_entries] ~= tmp_vuln then
                old_entries[#old_entries + 1] = tmp_vuln
              end
              ids_found = ids_found + 1

              -- The ID couple is correctly referencing a vulnerability
              -- entry in the vulnerability database (registry).
              id_not_found = false
            end
          end

        end
      end

      -- If the ID couple (id_type, id) was not found then save it
      -- in order to make it later reference the saved vulnerability
      -- entry (vulnerability table in the registry).
      if id_not_found then
        debug(5,
          "vulns.lua: VULNS.FILTERS_IDS[%d] '%s' ID:%s:%s%s: NOT FOUND",
          fid, vuln_table.title, id_type, id, host_info)
        NEW_IDS[id_type] = {['id'] = id, ['fid'] = fid}
      end

    end
  end


  -- This will reference the vulnerability table that was saved
  -- in the registry.
  local vuln_ref

  -- Old entry, update the vulnerability information
  if ids_found > 0 then
    if #old_entries > 1 then
      debug(3, "vulns.lua: Warning at vuln '%s': "..
          "please check the vulnerability IDs field.", vuln_table.title)
      for _, old_vuln in ipairs(old_entries) do
        debug(3, "vulns: Warning at vuln '%s': "..
            "please check the vulnerability IDs field.", old_vuln.title)
      end
    end
    debug(3,
        "vulns.lua: Updating vulnerability entry: '%s'%s",
        vuln_table.title, host_info)
    debug(3,
        "vulns.lua: Vulnerability '%s' referenced by %d IDs from %d (%s)",
        vuln_table.title, ids_found, ids_count,
        ids_found < ids_count and "Bad" or "Good")

    -- Update the vulnerability entry with the first one found.
    -- Note: Script writers must provide correct IDs or things can
    --       go bad.
    vuln_ref = l_update_vuln(vulndb, old_entries[1], vuln_table)
  else
    -- New vulnerability entry
    debug(3,
        "vulns.lua: Adding new vulnerability entry: '%s'%s",
        vuln_table.title, host_info)

    -- Push the new vulnerability into the registry
    vuln_ref = l_push_vuln(vulndb, vuln_table)
  end

  -- Update the FILTERS IDS tables to reference the vulnerability entry
  -- This vulnerability entry is now saved in the registry.
  if ids_found < ids_count then

    for _, fid in ipairs(FIDS) do
      for id_type, new_entry in pairs(NEW_IDS) do
        if new_entry['fid'] == fid then
          -- Add the ID couple (id_type, id) to the
          -- VULNS.FILTERS_IDS[fid] table that lacks them
          debug(5,
            "vulns.lua: Updating VULNS.FILTERS_IDS[%d]", new_entry.fid)
          l_update_id(vulndb.FILTERS_IDS[new_entry['fid']],
                      id_type, new_entry.id, vuln_ref)
        end
      end
    end

  end

  return true
end

--- Check and normalize the selection filter fields.
--
-- @param Filter The selection filter table.
-- @return Table The new selection filter that should be used.
local l_normalize_selection_filter = function(filter)
  if filter and type(filter) == "table" and next(filter) then
    local ret = {}

    if filter.state and STATE_MSG[filter.state] then
      ret.state = filter.state
    end

    if filter.risk_factor and type(filter.risk_factor) == "string" and
    RISK_FACTORS[string_upper(filter.risk_factor)] then
      ret.risk_factor = string_upper(filter.risk_factor)
    end

    if filter.hosts_filter and
    type(filter.hosts_filter) == "function" then
      ret.hosts_filter = filter.hosts_filter
    end

    if filter.ports_filter and
    type(filter.ports_filter) == "function" then
      ret.ports_filter = filter.ports_filter
    end

    if filter.id_type and type(filter.id_type) == "string" then
      ret.id_type = string_upper(filter.id_type)
      ret.id = filter.id
    end

    return ret
  end
end

--- Checks the vulnerability table against the provided selection filter
--
-- @param vuln_table The vulnerability information table.
-- @param Filter  The filter table.
-- @return True if the vulnerability table passes the selection filter,
--    otherwise False.
local l_filter_vuln = function(vuln_table, filter)
  if filter and next(filter) then
    if filter.state and bit.band(vuln_table.state, filter.state) == 0 then
      return false
    end

    if filter.risk_factor then
      if not vuln_table.risk_factor or
      string_upper(vuln_table.risk_factor) ~= string_upper(filter.risk_factor) then
        return false
      end
    end

    if filter.hosts_filter then
      if not vuln_table.host or not next(vuln_table.host) or
      not filter.hosts_filter(vuln_table.host) then
        return false
      end
    end

    if filter.ports_filter then
      if not vuln_table.port or not next(vuln_table.port) or
      not filter.ports_filter(vuln_table.port) then
        return false
      end
    end

    if filter.id_type then
      if not vuln_table.IDS or not next(vuln_table.IDS) or
      not vuln_table.IDS[filter.id_type] then
        return false
      elseif filter.id then
        return (vuln_table.IDS[filter.id_type] == filter.id)
      end
    end
  end

  return true
end

--- Find vulnerabilities by ID
local l_find_by_id = function(fid_table, vuln_id_type, id)
  local out = {}

  local db = l_lookup_id(fid_table, vuln_id_type, id)
  if db then
    debug(5,
      "vulns.lua: Lookup VULNS.FILTERS_IDS{}  for ID:%s:%s:  FOUND",
      vuln_id_type, id)
    if db.ENTRIES and db.ENTRIES.HOSTS and next(db.ENTRIES.HOSTS) then
      for _, vuln_list in pairs(db.ENTRIES.HOSTS) do
        for _, vuln_table in pairs(vuln_list) do
          debug(5,
            "vulns.lua: Vulnerability '%s' (host:%s):  FOUND",
            vuln_table.title, vuln_table.host.ip)
          out[#out + 1] = vuln_table
        end
      end
    end

    if db.ENTRIES.NETWORKS and next(db.ENTRIES.NETWORKS) then
      for _, vuln_table in ipairs(db.ENTRIES.NETWOKRS) do
        debug(5,
          "vulns.lua: Vulnerability '%s':  FOUND", vuln_table.title)
        out[#out + 1] = vuln_table
      end
    end
  end

  return next(out) and out or nil
end

--- Find vulnerabilities.
local l_find_vulns = function(fid_table, entries, filter)
  local out, check_vuln = {}

  if filter then
    check_vuln = function(vuln_table, fid_table, filter)
      -- Check if this vulnerability entry is referenced by the fid_table
      return vuln_table._FIDS_MATCH[fid_table] and
             l_filter_vuln(vuln_table, filter)
    end
  else
    check_vuln = function(vuln_table, fid_table)
      return vuln_table._FIDS_MATCH[fid_table]
    end
  end

  for host_ip, vulns_list in pairs(entries.HOSTS) do
    for _, vuln_table in ipairs(vulns_list) do
      if check_vuln(vuln_table, fid_table, filter) then
        debug(5,
          "vulns.lua: Vulnerability '%s' (host: %s):  FOUND",
          vuln_table.title, vuln_table.host.ip)
        out[#out + 1] = vuln_table
      end
    end
  end

  for _, vuln_table in ipairs(entries.NETWORKS) do
    if check_vuln(vuln_table, fid_table, filter) then
      debug(5,
        "vulns.lua: Vulnerability '%s':  FOUND", vuln_table.title)
      out[#out + 1] = vuln_table
    end
  end

  return next(out) and out or nil
end

--- Format and push vulnerabilities into an output table.
local l_push_vuln_output = function(output, vlist, showall)
  local out, vuln_list = output, vlist
  for idx, vuln_table in ipairs(vuln_list) do
    local vuln_out = format_vuln_table(vuln_table, showall)
    if vuln_out then
      insert(out, concat(vuln_out, "\n"))
      if #vuln_list > 1 and idx ~= #vuln_list then
        insert(out, "")
      end
    end
  end
end

--- Report vulnerabilities.
local l_make_output = function(fid_table, entries, filter)
  local hosts, networks = {}, {vulns = {}, not_vulns = {}}

  local save_not_vulns = function(vulns, vuln_table)
  end
  if SHOW_ALL then
    save_not_vulns = function(vulns, vuln_table)
      vulns[#vulns + 1] = vuln_table
    end
  end

  local check_vuln
  if filter then
    check_vuln = function(vuln_table, fid_table, filter)
      -- Check if this vulnerability entry is referenced by the fid_table
      return vuln_table._FIDS_MATCH[fid_table] and
             l_filter_vuln(vuln_table, filter)
    end
  else
    check_vuln = function(vuln_table, fid_table)
      return vuln_table._FIDS_MATCH[fid_table]
    end
  end

  for ip, vulns_list in pairs(entries.HOSTS) do
    local host_entries = {
      ip = ip,
      vulns = {},
      not_vulns = {},
    }

    for _, vuln_table in ipairs(vulns_list) do
      if check_vuln(vuln_table, fid_table, filter) then
        debug(5,
          "vulns.lua: Vulnerability '%s' (host: %s):  FOUND",
          vuln_table.title, vuln_table.host.ip)

        if bit.band(vuln_table.state, STATE.NOT_VULN) == 0 then
          host_entries.vulns[#host_entries.vulns + 1] = vuln_table
        else
          save_not_vulns(host_entries.not_vulns, vuln_table)
        end
      end
    end

    host_entries.state = next(host_entries.vulns) and
                            STATE.VULN or STATE.NOT_VULN
    insert(hosts, host_entries)
  end

  for _, vuln_table in ipairs(entries.NETWORKS) do
    if check_vuln(vuln_table, fid_table, filter) then
      debug(5,
        "vulns.lua: Vulnerability '%s':  FOUND", vuln_table.title)
      if bit.band(vuln_table.state, STATE.NOT_VULN) == 0 then
        networks.vulns[#networks.vulns + 1] = vuln_table
      else
        save_not_vulns(networks.not_vulns, vuln_table)
      end
    end
  end

  local output = {}
  local function sort_hosts(a, b)
    return compare_ip(a.ip, "le", b.ip)
  end

  local function sort_ports(a, b)
    if a.port and b.port then
      return a.port.number < b.port.number
    end
    return false
  end

  if next(hosts) then
    debug(3,
      "vulns.lua: sorting vulnerability entries for %d host",
      #hosts)
    sort(hosts, sort_hosts)

    for hidx, host in ipairs(hosts) do
      insert(output, string_format("Vulnerability report for %s: %s",
                        host.ip, STATE_MSG[host.state]))

      if next(host.vulns) then
        sort(host.vulns, sort_ports)
        l_push_vuln_output(output, host.vulns)
      end

      if next(host.not_vulns) and SHOW_ALL then
        sort(host.vulns, sort_ports)
        if #host.vulns > 0 then
          insert(output, "")
        end
        l_push_vuln_output(output, host.not_vulns, SHOW_ALL)
      end

      if #hosts > 1 and hidx ~= #hosts then
        insert(output, "")
      end
    end
  end

  if next(networks.vulns) then
    if next(hosts) then
      insert(output, "")
    end
    insert(output, "VULNERABLE Entries:")
    l_push_vuln_output(output, networks.vulns)
  end

  if next(networks.not_vulns) and SHOW_ALL then
    if #networks.vulns or next(hosts) then
      insert(output, "")
    end
    insert(output, "NOT VULNERABLE Entries:")
    l_push_vuln_output(output, networks.not_vulns, SHOW_ALL)
  end

  return next(output) and output or nil
end

--- Add vulnerabilities IDs wrapper
local registry_add_ids = function(fid, ...)
  local t = {...}
  for _, v in ipairs(t) do
    local id_type = v
    l_add_id_type(VULNS.FILTERS_IDS[fid], id_type)
  end
end

--- Get vulnerabilities IDs wrapper
local registry_get_ids = function(fid)
  return VULNS.FILTERS_IDS[fid]
end

--- Lookup for a vulnerability wrapper
local registry_lookup_id = function(fid, vuln_id_type, id)
  if l_lookup_id(VULNS.FILTERS_IDS[fid], vuln_id_type, id) then
    return true
  end
  return false
end

--- Find vulnerabilities by ID wrapper
local registry_find_by_id = function(fid, vuln_id_type, id)
  if registry_lookup_id(fid, vuln_id_type, id) then
    debug(5,
      "vulns.lua: Lookup VULNS.FILTERS_IDS[%d]  for vulnerabilities",
      fid)

    return l_find_by_id(VULNS.FILTERS_IDS[fid], vuln_id_type, id)
  end
end

--- Find vulnerabilities wrapper
local registry_find_vulns = function(fid, selection_filter)
  local fid_table = VULNS.FILTERS_IDS[fid]

  if fid_table and next(fid_table) then
    -- Normalize the 'selection_filter' fields
    local filter = l_normalize_selection_filter(selection_filter)
    debug(5,
      "vulns.lua: Lookup VULNS.FILTERS_IDS[%d]  for vulnerabilities",
      fid)

    return l_find_vulns(VULNS.FILTERS_IDS[fid], VULNS.ENTRIES, filter)
  end
end

--- Report vulnerabilities wrapper
local registry_make_output = function(fid, selection_filter)
  local fid_table = VULNS.FILTERS_IDS[fid]

  if fid_table and next(fid_table) then
    local filter = l_normalize_selection_filter(selection_filter)
    debug(5,
      "vulns.lua: Lookup VULNS.FILTERS_IDS[%d]  for vulnerabilities",
      fid)

    local output = l_make_output(VULNS.FILTERS_IDS[fid],
                                 VULNS.ENTRIES, filter)
    return stdnse.format_output(true, output)
  end
end

--- Save vulnerabilities wrapper
local registry_add_vulns = function(script_name, ...)
  local vulns = {...}
  if not script_name or not next(vulns) then
    -- just ignore the entry
    return false
  end

  local count = 0
  for _, vuln_table in ipairs(vulns) do
    if validate_vuln(vuln_table) then
      normalize_vuln_info(vuln_table)
      vuln_table.script_name = script_name
      debug(3,
        "vulns.lua: ***  New Vuln '%s' %sreported by '%s' script  ***",
        vuln_table.title,
        vuln_table.host and
            string_format(" host:%s ", vuln_table.host.ip) or "",
        vuln_table.script_name)
      if l_add(VULNS, vuln_table) then
        count = count + 1
      end
    end
  end
  return count > 0 and true or false, count
end

--- Add vulnerability IDs type to the vulnerability database associated
-- with the <code>FILTER ID</code>.
--
-- This function will create a table for each specified vulnerability ID
-- into the vulnerability database to store the associated vulnerability
-- entries.
--
-- This function takes a <code>FILTER ID</code> as it is returned by
-- the <code>vulns.save_reports()</code> function and a variable number
-- of vulnerability IDs type as parameters.
--
-- Scripts must call <code>vulns.save_reports()</code> function first to
-- setup the vulnerability database.
--
-- @usage
-- vulns.add_ids(fid, 'CVE', 'OSVDB')
--
-- @param FILTER ID as it is returned by <code>vulns.save_reports()</code>
-- @param IDs A variable number of strings that represent the
--    vulnerability IDs type.
add_ids = function(fid, ...)
  -- Define this function in save_reports()
end

--- Gets the vulnerability database associated with the
-- <code>FILTER ID</code>.
--
-- This function can be used to check if there are vulnerability entries
-- that were saved in the vulnerability database.
-- The format of the vulnerability database associated with the
-- <code>FILTER ID</code> is specified as Lua comments in this library.
--
-- Scripts must call <code>vulns.save_reports()</code> function first to
-- setup the vulnerability database.
--
-- @usage
-- local vulndb = vulns.get_ids(fid)
-- if vulndb then
--    -- process vulnerability entries
-- end
--
-- @param FILTER ID as it is returned by <code>vulns.save_reports()</code>
-- @return vulndb The internal vulnerability database associated with the
--   <code>FILTER ID</code> if there are vulnerability entries that were
--   saved, otherwise nil.
get_ids = function(fid)
  -- Define this function in save_reports()
end

--- Lookup for a vulnerability entry in the vulnerability database
-- associated with the <code>FILTER ID</code>.
--
-- This function can be used to see if there are any references to the
-- specified vulnerability in the database, it will return
-- <code>True</code> if so which means that one of the scripts has
-- attempted to check this vulnerability.
--
-- Scripts must call <code>vulns.save_reports()</code> function first to
-- setup the vulnerability database.
--
-- @usage
-- local status = vulns.lookup(fid, 'CVE', 'CVE-XXXX-XXXX')
--
-- @param FILTER ID as it is returned by <code>vulns.save_reports()</code>
-- @param vuln_id_type  A string representing the vulnerability ID type.
-- @param id  The vulnerability ID.
-- @return True if there are references to this entry in the vulnerability
--   database, otherwise False.
lookup_id = function(fid, vuln_id_type, id)
  -- Define this function in save_reports()
end

--- Adds vulnerability tables into the vulnerability database
-- (registry).
--
-- This function takes a variable number of vulnerability tables and
-- stores them in the vulnerability database if they satisfy the callback
-- filters that were registered by the <code>vulns.save_reports()</code>
-- function.
--
-- Scripts must call <code>vulns.save_reports()</code> function first to
-- setup the vulnerability database.
--
-- @usage
-- local vuln_table = {
--  title = "Vulnerability X",
--  state = vulns.STATE.VULN,
--  ...,
--  -- take a look at the vulnerability table example at the beginning.
-- }
-- local status, ret = vulns.add(SCRIPT_NAME, vuln_table)
-- @param script_name The script name. The <code>SCRIPT_NAME</code>
--    environment variable will do the job.
-- @param vulnerabilities  A variable number of vulnerability tables.
-- @return True if the vulnerability tables were added, otherwise False.
-- @return Number of added vulnerabilities on success.
add = function(script_name, ...)
  -- Define this function in save_reports()
end

--- Search and return vulnerabilities in a list.
--
-- This function will return a list of the vulnerabilities that were
-- stored in the vulnerability database associated with the
-- <code>FILTER ID</code> that satisfy the <code>selection filter</code>.
-- It will take a <code>FILTER ID</code> as it is returned by the
-- <code>vulns.save_reports</code> function and a
-- <code>selection_filter</code> table as parameters.
--
-- Scripts must call <code>vulns.save_reports()</code> function first to
-- setup the vulnerability database.
--
-- This function is not affected by the <code>vulns.showall</code> script
-- argument. The <code>selection_filter</code> is an optional table
-- parameter of optional fields which can be used to select which
-- vulnerabilities to return, if it is not set then all vulnerability
-- entries will be returned.
--
-- @usage
-- -- All the following fields are optional.
-- local selection_filter = {
--   state = vulns.STATE.VULN, -- number
--   risk_factor = "High", -- string
--   hosts_filter = function(vuln_table.host)
--                  -- Function that returns a boolean
--                  -- True if it passes the filter, otherwise false.
--                  end,
--                  -- vuln_table.host = {ip, targetname, bin_ip}
--   ports_filter = function(vuln_table.port)
--                  -- Function that returns a boolean
--                  -- True if it passes the filter, otherwise false.
--                  end,
--                  -- vuln_table.port = {number, protocol, service
--                  --                    version}
--   id_type = 'CVE', -- Vulnerability type ID (string)
--   id = 'CVE-XXXX-XXXX', -- CVE id (string)
-- }
-- local list = vulns.find(fid, selection_filter)
--
-- @param FILTER ID as it is returned by <code>vulns.save_reports()</code>
-- @param selection An optional table to select which vulnerabilities to
--   list. The fields of the selection filter table are:
--    state:  The vulnerability state.
--    risk_factor:  The vulnerability <code>risk_factor</code> field, can
--                  be one of these values: <code>"High"</code>,
--                  <code>"Medium"</code> or <code>"Low"</code>.
--    hosts_filter:  A function to filter the <code>host</code> table of
--                   the vulnerability table. This function must return
--                   a boolean, true if it passes the filter otherwise
--                   false. The <code>host</code> table:
--                   host = {ip, targetname, bin_ip}
--    ports_filter:  A function to filter the <code>port</code> table of
--                   the vulnerability table. This function must return
--                   a boolean, true if it passes the filter, otherwise
--                   false. The <code>port</code> table:
--                   port = {number, protocol, service, version}
--    id_type: The vulnerability ID type, (e.g: 'CVE', 'OSVDB' ...)
--    id:  The vulnerability ID.
--   All these fields are optional.
-- @return List of vulnerability tables on success, or nil on failures.
find = function(fid, selection_filter)
  -- Define this function in save_reports()
end

--- Search vulnerability entries by ID and return the results in a list.
--
-- This function will return a list of the same vulnerability that affects
-- different hosts, each host will have its own vulnerability table.
--
-- Scripts must call <code>vulns.save_reports()</code> function first to
-- setup the vulnerability database.
--
-- @usage
-- local list = vulns.find_by_id(fid, 'CVE', 'CVE-XXXX-XXXX')
--
-- @param FILTER ID as it is returned by <code>vulns.save_reports()</code>
-- @param vuln_id_type A string representing the vulnerability ID type.
-- @param id The vulnerability ID.
-- @return List of vulnerability tables on success, or nil on failures.
find_by_id = function(fid, vuln_id_type, id)
  -- Define this function in save_reports()
end

--- Report vulnerabilities.
--
-- Format and report all the vulnerabilities that were stored in the
-- vulnerability database associated with the <code>FILTER ID</code> for
-- user display.
--
-- This function takes a <code>FILTER ID</code> as it is returned by the
-- <code>vulns.save_reports()</code> function and a
-- <code>selection_filter</code> as parameters.
--
-- Scripts must call <code>vulns.save_reports()</code> function first to
-- activate this function, then they can use it as a tail call to report
-- all vulnerabilities that were saved into the registry. Results will be
-- sorted by IP addresses and Port numbers.
--
-- To show the <code>NOT VULNERABLE</code> entries users must specify
-- the <code>vulns.showall</code> script argument.
--
-- The <code>selection_filter</code> is an optional table parameter of
-- optional fields which can be used to select which vulnerabilities to
-- report, if it is not set then all vulnerabilities entries will be
-- returned.
--
-- @usage
-- -- All the following fields are optional.
-- local selection_filter = {
--   state = vulns.STATE.VULN, -- number
--   risk_factor = "High", -- string
--   hosts_filter = function(vuln_table.host)
--                  -- Function that returns a boolean
--                  -- True if it passes the filter, otherwise false.
--                  end,
--                  -- vuln_table.host = {ip, targetname, bin_ip}
--   ports_filter = function(vuln_table.port)
--                  -- Function that returns a boolean
--                  -- True if it passes the filter, otherwise false.
--                  end,
--                  -- vuln_table.port = {number, protocol, service
--                  --                    version}
--   id_type = 'CVE', -- Vulnerability type ID (string)
--   id = 'CVE-XXXX-XXXX', -- CVE id (string)
-- }
-- return vulns.make_output(fid, selection_filter)
--
-- @param FILTER ID as it is returned by <code>vulns.save_reports()</code>
-- @param selection An optional table to select which vulnerabilities to
--   report. The fields of the selection filter table are:
--    state:  The vulnerability state.
--    risk_factor:  The vulnerability <code>risk_factor</code> field, can
--                  be one of these values: <code>"High"</code>,
--                  <code>"Medium"</code> or <code>"Low"</code>.
--    hosts_filter:  A function to filter the <code>host</code> table of
--                   the vulnerability table. This function must return
--                   a boolean, true if it passes the filter otherwise
--                   false. The <code>host</code> table:
--                   host = {ip, targetname, bin_ip}
--    ports_filter:  A function to filter the <code>port</code> table of
--                   the vulnerability table. This function must return
--                   a boolean, true if it passes the filter, otherwise
--                   false. The <code>port</code> table:
--                   port = {number, protocol, service, version}
--    id_type: The vulnerability ID type, (e.g: 'CVE', 'OSVDB' ...)
--    id:  The vulnerability ID.
--   All these fields are optional.
-- @return multiline string on success, or nil on failures.
make_output = function(fid, selection_filter)
  -- Define this function in save_reports()
end

--- Normalize and format some special vulnerability fields
--
-- @param vuln_field The vulnerability field
-- @return List  The contents of the vuln_field stored in a list.
local format_vuln_special_fields = function(vuln_field)
  local out = {}
  if vuln_field then
    if type(vuln_field) == "table" then
      for _, line in ipairs(vuln_field) do
				if type(line) == "string" then
          tadd(out, stdnse.strsplit("\r?\n", line))
				else
					insert(out, line)
				end
      end
    elseif type(vuln_field) == "string" then
      out = stdnse.strsplit("\r?\n", vuln_field)
    end
  end
  return next(out) and out or nil
end

--- Inspect and format the vulnerability information.
--
-- The result of this function must be checked, it will return a table
-- on success, or nil on failures.
--
-- @param Table The vulnerability information table.
-- @param showall  A string if set then show all the vulnerability
--    entries including the <code>NOT VULNERABLE</code> ones.
-- @return Table  The formatted vulnerability information stored in a
--    table on success. If one of the mandatory vulnerability fields is
--    missing or if the <code>'showall'</code> parameter is not set and
--    the vulnerability state is<code>NOT VULNERABLE</code> then it will
--    print a debug message about the vulnerability and return nil.
local format_vuln_base = function(vuln_table, showall)
  if not vuln_table.title or not type(vuln_table.title) == "string" or
  not vuln_table.state or not STATE_MSG[vuln_table.state] then
    return nil
  end

  if not showall and bit.band(vuln_table.state, STATE.NOT_VULN) ~= 0 then
    debug(2, "vulns.lua: vulnerability '%s'%s: %s.",
        vuln_table.title,
        vuln_table.host and
            string_format(" (host:%s%s)", vuln_table.host.ip,
            vuln_table.host.targetname and
              " "..vuln_table.host.targetname or "")
            or "", STATE_MSG[vuln_table.state])
    return nil
  end
  local output_table = stdnse.output_table()
  local out = {}
  output_table.title = vuln_table.title
  insert(out, vuln_table.title)
  output_table.state = STATE_MSG[vuln_table.state]
  insert(out,
      string_format("  State: %s", STATE_MSG[vuln_table.state]))

  if vuln_table.IDS and next(vuln_table.IDS) then
    local ids_t = {}
    for id_type, id in pairs(vuln_table.IDS) do
      -- ignore internal NMAP IDs
      if id_type ~= 'NMAP_ID' then
        table.insert(ids_t, string_format("%s:%s", id_type, id))
      end
    end

    if next(ids_t) then
      insert(out, string_format("  IDs:  %s", table.concat(ids_t, "  ")))
      output_table.ids = ids_t
    end
  end

  -- Show this information only if the program is vulnerable
  if bit.band(vuln_table.state, STATE.NOT_VULN) == 0 then
    if vuln_table.risk_factor then
      local risk_str = ""

      if vuln_table.scores and next(vuln_table.scores) then
        output_table.scores = vuln_table.scores
        for score_type, score in pairs(vuln_table.scores) do
          risk_str = risk_str .. string_format("  %s: %s", score_type, score)
        end
      end

      insert(out, string_format("  Risk factor: %s%s",
                      vuln_table.risk_factor, risk_str))
    end

    if vuln_table.description then
      local desc = format_vuln_special_fields(vuln_table.description)
      if desc then
        for _, line in ipairs(desc) do
          insert(out, string_format("    %s", line))
        end
        output_table.description = vuln_table.description
      end
    end

    if vuln_table.dates and next(vuln_table.dates) then
      output_table.dates = vuln_table.dates
      if vuln_table.dates.disclosure and
      next(vuln_table.dates.disclosure) then
        output_table.disclosure = string_format("%s-%s-%s",
          vuln_table.dates.disclosure.year,
          vuln_table.dates.disclosure.month,
          vuln_table.dates.disclosure.day)
        insert(out, string_format("  Disclosure date: %s-%s-%s",
                        vuln_table.dates.disclosure.year,
                        vuln_table.dates.disclosure.month,
                        vuln_table.dates.disclosure.day))
      end
    end

    if vuln_table.check_results then
      output_table.check_results = vuln_table.check_results
      local check = format_vuln_special_fields(vuln_table.check_results)
      if check then
        insert(out, "  Check results:")
        for _, line in ipairs(check) do
          insert(out, string_format("    %s", line))
        end
      end
    end

    if vuln_table.exploit_results then
      output_table.exploit_results = vuln_table.exploit_results
      local exploit = format_vuln_special_fields(vuln_table.exploit_results)
      if exploit then
        insert(out, "  Exploit results:")
        for _, v in ipairs(vuln_table.exploit_results) do
          insert(out, string_format("    %s", v))
        end
      end
    end

    if vuln_table.extra_info then
      output_table.extra_info = vuln_table.extra_info
      local extra = format_vuln_special_fields(vuln_table.extra_info)
      if extra then
        insert(out, "  Extra information:")
        for _, v in ipairs(vuln_table.extra_info) do
          insert(out, string_format("    %s", v))
        end
      end
    end
  end

  if vuln_table.IDS or vuln_table.references then
    local ref_set = {}

    -- Show popular references
    if vuln_table.IDS and next(vuln_table.IDS) then
      for id_type, id in pairs(vuln_table.IDS) do
        local id_type = string_upper(id_type)
        local link = get_popular_link(id_type, id)
        if link then ref_set[link] = true end
      end
    end

    -- Show other references
    if vuln_table.references and next(vuln_table.references) then
      for k, v in pairs(vuln_table.references) do
        local str = type(k) == "string" and k or v
        ref_set[str] = true
      end
    end

    if next(ref_set) then
      insert(out, "  References:")
      local ref_str = {}
      for link in pairs(ref_set) do
        insert(out, string_format("    %s", link))
        table.insert(ref_str, link)
      end
      output_table.refs = ref_str
    end
  end

  return out, output_table
end

--- Format the vulnerability information and return it in a table.
--
-- This function can return nil if the vulnerability mandatory fields
-- are missing or if the script argument <code>vulns.showall</code> and
-- the <code>'showall'</code> string parameter were not set and the state
-- of the vulnerability is <code>NOT VULNERABLE</code>.
--
-- Script writers must check the returned result.
--
-- If the vulnerability table contains the <code>host</code> and
-- <code>port</code> tables, then the following fields will be shown:
-- <code>vuln_table.host.targetname</code>,
-- <code>vuln_table.host.ip</code>, <code>vuln_table.port.number</code> and
-- <code>vuln_table.port.service</code>
--
-- @usage
-- local vuln_output = vulns.format_vuln_table(vuln_table)
-- if vuln_output then
--    -- process the vuln_output table
-- end
--
-- @param vuln_table The vulnerability information table.
-- @param showall  A string if set then show all the vulnerabilities
--    including the <code>NOT VULNERABLE</code> ones. This optional
--    parameter can be used to overwrite the <code>vulns.showall</code>
--    script argument value.
-- @return Multiline string on success. If one of the mandatory
--    vulnerability fields is missing or if the script argument
--    <code>vulns.showall</code> and the <code>'showall'</code> string
--    parameter were not specified and the vulnerability state is
--    <code>NOT VULNERABLE</code> then it will print a debug message
--    about the vulnerability and return nil.
format_vuln_table = function(vuln_table, showall)
  local out = format_vuln_base(vuln_table, showall)

  if out then
    -- Show the 'host' and 'port' tables information.
    if vuln_table.host and type(vuln_table.host) == "table" and
    vuln_table.host.ip then
      local run_info = "Target: "
      if vuln_table.host.targetname then
        run_info = run_info..vuln_table.host.targetname
      end
      run_info = run_info..string_format(" (%s)", vuln_table.host.ip)
      if vuln_table.port and type(vuln_table.port == "table") and
      vuln_table.port.number then
        run_info = run_info..string_format("  Port: %s%s",
                                vuln_table.port.number,
                                vuln_table.port.service and
                                "/"..vuln_table.port.service or "")
      end
      insert(out, 1, run_info)
    end

    -- Show the list of scripts that reported this vulnerability
    if vuln_table.scripts and next(vuln_table.scripts) then
      local script_list = string_format("  Reported by scripts: %s",
                              concat(vuln_table.scripts, " "))
      insert(out, script_list)
    end

    return out
  end
end

--- Format the vulnerability information and return it as a string.
--
-- This function can return nil if the vulnerability mandatory fields
-- are missing or if the script argument <code>vulns.showall</code> and
-- the <code>'showall'</code> string parameter were not set and the
-- state of the vulnerability is <code>NOT VULNERABLE</code>.
--
-- Script writers must check the returned result.
--
-- If the vulnerability table contains the <code>host</code> and
-- <code>port</code> tables, then the following fields will be shown:
-- <code>vuln_table.host.targetname</code>,
-- <code>vuln_table.host.ip</code>, <code>vuln_table.port.number</code> and
-- <code>vuln_table.port.service</code>
--
-- @usage
-- local vuln_str = vulns.format_vuln(vuln_table, 'showall')
-- if vuln_str then
--    return vuln_str
-- end
--
-- @param vuln_table The vulnerability information table.
-- @param showall  A string if set then show all the vulnerabilities
--    including the <code>NOT VULNERABLE</code> ones. This optional
--    parameter can be used to overwrite the <code>vulns.showall</code>
--    script argument value.
-- @return Multiline string on success. If one of the mandatory
--    vulnerability fields is missing or if the script argument
--    <code>vulns.showall</code> and the <code>'showall'</code> string
--    parameter were not specified and the vulnerability state is
--    <code>NOT VULNERABLE</code> then it will print a debug message
--    about the vulnerability and return nil.
format_vuln = function(vuln_table, showall)
  local out = format_vuln_table(vuln_table, showall or SHOW_ALL)

  if out then
    return concat(out, "\n")
  end
end

--- Initializes the vulnerability database and instructs the library
-- to save all the vulnerability tables reported by scripts into this
-- database (registry).
--
-- Usually this function should be called during a <code>prerule</code>
-- function so it can instructs the library to save vulnerability
-- entries that will be reported by the <code>vulns.Report</code> class
-- or by the <code>vulns.add()</code> function.
--
-- This function can take an optional callback filter parameter that can
-- help the library to decide if it should store the vulnerability table
-- in the registry or not. The callback function must return a boolean
-- value. If this parameter is not set then all vulnerability tables
-- will be saved.
-- This function will return a uniq <code>FILTER ID</code> for the scripts
-- to be used by the other library functions to reference the appropriate
-- vulnerability entries that were saved previously.
--
-- @usage
-- FID = vulns.save_reports() -- save all vulnerability reports.
--
-- -- Save only vulnerabilities with the <code>VULNERABLE</code> state.
-- local function save_only_vuln(vuln_table)
--   if bit.band(vuln_table.state, vulns.STATE.VULN) ~= 0 then
--     return true
--   end
--   return false
-- end
-- FID = vulns.save_reports(save_only_vuln)
--
-- @param filter_callback The callback function to filter vulnerabilities.
--    The function will receive a vulnerability table as a parameter in
--    order to inspect it, and must return a boolean value. True if the
--    the vulnerability table should be saved in the registry, otherwise
--    false. This parameter is optional.
-- @return Filter ID  A uniq ID to be used by the other library functions
--    to reference and identify the appropriate vulnerabilities.
save_reports = function(filter_callback)
  if not VULNS then
    nmap.registry.VULNS = nmap.registry.VULNS or {}
    VULNS = nmap.registry.VULNS
    VULNS.ENTRIES = VULNS.ENTRIES or {}
    VULNS.ENTRIES.HOSTS = VULNS.ENTRIES.HOSTS or {}
    VULNS.ENTRIES.NETWORKS = VULNS.ENTRIES.NETWORKS or {}
    VULNS.SHARED = VULNS.SHARED or {}
    VULNS.SHARED.REFERENCES = VULNS.SHARED.REFERENCES or {}
    VULNS.FILTERS_FUNCS = VULNS.FILTERS_FUNCS or {}
    VULNS.FILTERS_IDS = VULNS.FILTERS_IDS or {}

    -- Enable functions
    add_ids = registry_add_ids
    get_ids = registry_get_ids
    lookup_id = registry_lookup_id
    add = registry_add_vulns
    find_by_id = registry_find_by_id
    find = registry_find_vulns
    make_output = registry_make_output
  end

  local fid = register_filter(VULNS.FILTERS_FUNCS, filter_callback)
  VULNS.FILTERS_IDS[fid] = {}
  debug(3,
      "vulns.lua: New Filter table:  VULNS.FILTERS_IDS[%d]", fid)
  return fid
end

--- The Report class
--
-- Hostrule and Portrule scripts should use this class to store and
-- report vulnerabilities.
Report = {

  --- Creates a new Report object
  --
  -- @return report object
  new = function(self, script_name, host, port)
    local o = {}
    setmetatable(o, self)
    self.__index = self
    o.entries = {vulns = {}, not_vulns = {}}
    o.script_name = script_name
    if host then
      o.host = {}
      o.host.ip = host.ip
      o.host.targetname = host.targetname
      o.host.bin_ip = host.bin_ip
      if port then
        o.port = {}
        o.port.number = port.number
        o.port.protocol = port.protocol
        o.port.service = port.service
        -- Copy table
        o.port.version = tcopy(port.version)
      end
    end
    -- TODO: CPE support
    return o
  end,

  --- Registers and associates a callback function with the popular ID
  -- vulnerability type to construct and return popular links
  -- automatically.
  --
  -- The callback function takes a vulnerability ID as a parameter
  -- and must return a link. The library automatically supports three
  -- different popular IDs:
  -- <code>CVE</code>: cve.mitre.org
  -- <code>OSVDB</code>: osvdb.org
  -- <code>BID</code>: www.securityfocus.com/bid
  --
  -- @usage
  -- function get_example_link(id)
  --   return string.format("%s%s",
  --            "http://example.com/example?name=", id)
  -- end
  -- report:add_popular_id('EXM-ID', get_example_link)
  --
  -- @param id_type  String representing the vulnerability ID type.
  --        <code>'CVE'</code>, <code>'OSVDB'</code> ...
  -- @param callback A function to construct and return links.
  -- @return True on success or false if it can not register the callback.
  add_popular_id = function(self, id_type, callback)
    return register_popular_id(id_type, callback)
  end,

  --- Adds vulnerability tables to the report.
  --
  -- Takes a variable number of vulnerability tables and stores them
  -- in the internal db of the report so they can be reported later.
  --
  -- @usage
  -- local vuln_table = {
  --  title = "Vulnerability X",
  --  state = vulns.STATE.VULN,
  --  ...,
  --  -- take a look at the vulnerability table example at the beginning.
  -- }
  -- local status, ret = report:add_vulns(vuln_table)
  -- @param vulnerabilities A variable number of vulnerability tables.
  -- @return True if the vulnerability tables were added, otherwise
  --    False.
  -- @return Number of added vulnerabilities on success.
  add_vulns = function(self, ...)
    local count = 0
    for i = 1, select("#", ...) do
      local vuln_table = select(i, ...)
      if validate_vuln(vuln_table) then
        normalize_vuln_info(vuln_table)
        vuln_table.script_name = self.script_name
        vuln_table.host = self.host
        vuln_table.port = self.port
        if bit.band(vuln_table.state, STATE.NOT_VULN) ~= 0 then
          insert(self.entries.not_vulns, vuln_table)
        else
          insert(self.entries.vulns, vuln_table)
        end
        add(vuln_table.script_name, vuln_table)
        count = count + 1
      end
    end
    return count > 0 and true or false, count
  end,

  --- Report vulnerabilities.
  --
  -- Takes a variable number of vulnerability tables and stores them
  -- in the internal db of the report, then format all the
  -- vulnerabilities that are in this db for user display. Scripts should
  -- use this function as a tail call.
  --
  -- To show the <code>NOT VULNERABLE</code> entries users must specify
  -- the <code>vulns.showall</code> script argument.
  --
  -- @usage
  -- local vuln_table = {
  --  title = "Vulnerability X",
  --  state = vulns.STATE.VULN,
  --  ...,
  --  -- take a look at the vulnerability table example at the beginning.
  -- }
  -- return report:make_output(vuln_table)
  --
  -- @param vulnerabilities A variable number of vulnerability tables.
  -- @return multiline string on success, or nil on failures.
  make_output = function(self, ...)
    self:add_vulns(...)

    local vuln_count = #self.entries.vulns
    local not_vuln_count = #self.entries.not_vulns
    local output = {}
    local output_table = stdnse.output_table()
    local out_t = stdnse.output_table()
    local output_t2 = stdnse.output_table()
    -- VULNERABLE: LIKELY_VULN, VULN, DoS, EXPLOIT
    if vuln_count > 0 then
      output_table.state = "VULNERABLE"
      insert(output, "VULNERABLE:")
      for i, vuln_table in ipairs(self.entries.vulns) do
        local vuln_out, out_t = format_vuln_base(vuln_table)
        if type(out_t) == "table" then
          local ID = vuln_table.IDS.CVE or vuln_table.IDS[next(vuln_table.IDS)]
          output_t2[ID] = out_t
        end
        if vuln_out then
          output_table.report = concat(vuln_out, "\n")
          insert(output, concat(vuln_out, "\n"))
          if vuln_count > 1 and i ~= vuln_count then
            insert(output, "") -- separate several entries
          end
        end
      end
    end
    -- NOT VULNERABLE: NOT_VULN
    if not_vuln_count > 0 then
      if SHOW_ALL then
        if vuln_count > 0 then insert(output, "") end
        output_table.state = "NOT VULNERABLE"
        insert(output, "NOT VULNERABLE:")
      end
      for i, vuln_table in ipairs(self.entries.not_vulns) do
        local vuln_out, out_t = format_vuln_base(vuln_table, SHOW_ALL)
        if type(out_t) == "table" then
          local ID = vuln_table.IDS.CVE or vuln_table.IDS[next(vuln_table.IDS)]
          output_t2[ID] = out_t
        end
        if vuln_out then
          output_table.report = concat(vuln_out, "\n")
          insert(output, concat(vuln_out, "\n"))
          if not_vuln_count > 1 and i ~= not_vuln_count then
            insert(output, "") -- separate several entries
          end
        end
      end
    end
   if #output==0 and #output_t2==0 then
      return nil
    end
    return output_t2, stdnse.format_output(true, output)
  end,
}

return _ENV;
