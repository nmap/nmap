local datetime = require "datetime"
local msrpc = require "msrpc"
local smb = require "smb"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

description = [[
Enumerates the users logged into a system either locally or through an SMB share. The local users
can be logged on either physically on the machine, or through a terminal services session.
Connections to a SMB share are, for example, people connected to fileshares or making RPC calls.
Nmap's connection will also show up, and is generally identified by the one that connected "0
seconds ago".

From the perspective of a penetration tester, the SMB Sessions is probably the most useful
part of this program, especially because it doesn't require a high level of access. On, for
example, a file server, there might be a dozen or more users connected at the same time. Based
on the usernames, it might tell the tester what types of files are stored on the share.

Since the IP they're connected from and the account is revealed, the information here can also
provide extra targets to test, as well as a username that's likely valid on that target. Additionally,
since a strong username to ip correlation is given, it can be a boost to a social engineering
attack.

Enumerating the logged in users is done by reading the remote registry (and therefore won't
work against Vista, which disables it by default). Keys stored under <code>HKEY_USERS</code> are
SIDs that represent the connected users, and those SIDs can be converted to proper names by using
the <code>lsar.LsaLookupSids</code> function. Doing this requires any access higher than
anonymous; guests, users, or administrators are all able to perform this request on Windows 2000,
XP, 2003, and Vista.

Enumerating SMB connections is done using the <code>srvsvc.netsessenum</code> function, which
returns the usernames that are logged in, when they logged in, and how long they've been idle
for. The level of access required for this varies between Windows versions, but in Windows
2000 anybody (including the anonymous account) can access this, and in Windows 2003 a user
or administrator account is required.

I learned the idea and technique for this from Sysinternals' tool, <code>PsLoggedOn.exe</code>. I (Ron
Bowes) use similar function calls to what they use (although I didn't use their source),
so thanks go out to them. Thanks also to Matt Gardenghi, for requesting this script.

WARNING: I have experienced crashes in regsvc.exe while making registry calls
against a fully patched Windows 2000 system; I've fixed the issue that caused it,
but there's no guarantee that it (or a similar vuln in the same code) won't show
up again. Since the process automatically restarts, it doesn't negatively impact
the system, besides showing a message box to the user.
]]

---
--@usage
-- nmap --script smb-enum-sessions.nse -p445 <host>
-- sudo nmap -sU -sS --script smb-enum-sessions.nse -p U:137,T:139 <host>
--
--@output
-- Host script results:
-- |  smb-enum-sessions:
-- |  Users logged in:
-- |  |  TESTBOX\Administrator since 2008-10-21 08:17:14
-- |  |_ DOMAIN\rbowes since 2008-10-20 09:03:23
-- |  Active SMB Sessions:
-- |_ |_ ADMINISTRATOR is connected from 10.100.254.138 for [just logged in, it's probably you], idle for [not idle]
--
-- @see smb-enum-users.nse

author = "Ron Bowes"
copyright = "Ron Bowes"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery","intrusive"}
dependencies = {"smb-brute"}


hostrule = function(host)
  return smb.get_port(host) ~= nil
end

---Attempts to enumerate the sessions on a remote system using MSRPC calls. This will likely fail
-- against a modern system, but will succeed against Windows 2000.
--
--@param host The host object.
--@return Status (true or false).
--@return List of sessions (if status is true) or an an error string (if status is false).
local function srvsvc_enum_sessions(host)
  local i
  local status, smbstate
  local bind_result, netsessenum_result

  -- Create the SMB session
  status, smbstate = msrpc.start_smb(host, msrpc.SRVSVC_PATH)
  if(status == false) then
    return false, smbstate
  end

  -- Bind to SRVSVC service
  status, bind_result = msrpc.bind(smbstate, msrpc.SRVSVC_UUID, msrpc.SRVSVC_VERSION, nil)
  if(status == false) then
    msrpc.stop_smb(smbstate)
    return false, bind_result
  end

  -- Call netsessenum
  status, netsessenum_result = msrpc.srvsvc_netsessenum(smbstate, host.ip)
  if(status == false) then
    msrpc.stop_smb(smbstate)
    return false, netsessenum_result
  end

  -- Stop the SMB session
  msrpc.stop_smb(smbstate)

  return true, netsessenum_result['ctr']['array']
end

---Enumerates the users logged in locally (or through terminal services) by using functions
-- that access the registry. To perform this check, guest access or higher is required.
--
-- The way this works is based on the registry. HKEY_USERS is enumerated, and every key in it
-- that looks like a SID is converted to a username using the LSA lookup function lsa_lookupsids2().
--
--@param host The host object.
--@return An array of user tables, each with the keys <code>name</code>, <code>domain</code>, and <code>changed_date</code> (representing
--        when they logged in).
local function winreg_enum_rids(host)
  local i, j
  local elements = {}

  -- Create the SMB session
  local status, smbstate = msrpc.start_smb(host, msrpc.WINREG_PATH)
  if(status == false) then
    return false, smbstate
  end

  -- Bind to WINREG service
  local status, bind_result = msrpc.bind(smbstate, msrpc.WINREG_UUID, msrpc.WINREG_VERSION, nil)
  if(status == false) then
    msrpc.stop_smb(smbstate)
    return false, bind_result
  end

  local status, openhku_result = msrpc.winreg_openhku(smbstate)
  if(status == false) then
    msrpc.stop_smb(smbstate)
    return false, openhku_result
  end

  -- Loop through the keys under HKEY_USERS and grab the names
  i = 0
  repeat
    local status, enumkey_result = msrpc.winreg_enumkey(smbstate, openhku_result['handle'], i, "")

    if(status == true) then
      local status, openkey_result

      local element = {}
      element['name'] = enumkey_result['name']

      -- To get the time the user logged in, we check the 'Volatile Environment' key
      -- This can fail with the 'guest' account due to access restrictions
      local status, openkey_result = msrpc.winreg_openkey(smbstate, openhku_result['handle'], element['name'] .. "\\Volatile Environment")
      if(status ~= false) then
        local queryinfokey_result, closekey_result

        -- Query the info about this key. The response will tell us when the user logged into the server.
        local status, queryinfokey_result = msrpc.winreg_queryinfokey(smbstate, openkey_result['handle'])
        if(status == false) then
          msrpc.stop_smb(smbstate)
          return false, queryinfokey_result
        end

        local status, closekey_result = msrpc.winreg_closekey(smbstate, openkey_result['handle'])
        if(status == false) then
          msrpc.stop_smb(smbstate)
          return false, closekey_result
        end

        element['changed_date'] = queryinfokey_result['last_changed_date']
      else
        -- Getting extra details failed, but we can still handle this
        element['changed_date'] = "<unknown>"
      end
      elements[#elements + 1] = element
    end

    i = i + 1
  until status ~= true

  local status, closekey_result = msrpc.winreg_closekey(smbstate, openhku_result['handle'])
  if(status == false) then
    msrpc.stop_smb(smbstate)
    return false, closekey_result
  end

  msrpc.stop_smb(smbstate)

  -- Start a new SMB session
  local status, smbstate = msrpc.start_smb(host, msrpc.LSA_PATH)
  if(status == false) then
    return false, smbstate
  end

  -- Bind to LSA service
  local status, bind_result = msrpc.bind(smbstate, msrpc.LSA_UUID, msrpc.LSA_VERSION, nil)
  if(status == false) then
    msrpc.stop_smb(smbstate)
    return false, bind_result
  end

  -- Get a policy handle
  local status, openpolicy2_result = msrpc.lsa_openpolicy2(smbstate, host.ip)
  if(status == false) then
    msrpc.stop_smb(smbstate)
    return false, openpolicy2_result
  end

  -- Convert the SID to the name of the user
  local results = {}
  stdnse.debug3("MSRPC: Found %d SIDs that might be logged in", #elements)
  for i = 1, #elements, 1 do
    if(elements[i]['name'] ~= nil) then
      local sid = elements[i]['name']
      if(string.find(sid, "^S%-") ~= nil and string.find(sid, "%-%d+$") ~= nil) then
        -- The rid is the last digits before the end of the string
        local rid = string.sub(sid, string.find(sid, "%d+$"))

        local status, lookupsids2_result = msrpc.lsa_lookupsids2(smbstate, openpolicy2_result['policy_handle'], {elements[i]['name']})

        if(status == false) then
          -- It may not succeed, if it doesn't that's ok
          stdnse.debug3("MSRPC: Lookup failed")
        else
          -- Create the result array
          local result = {}
          result['changed_date'] = elements[i]['changed_date']
          result['rid'] = rid

          -- Fill in the result from the response
          if(lookupsids2_result['names']['names'][1] == nil) then
            result['name'] = "<unknown>"
            result['type'] = "<unknown>"
            result['domain'] = ""
          else
            result['name'] = lookupsids2_result['names']['names'][1]['name']
            result['type'] = lookupsids2_result['names']['names'][1]['sid_type']
            if(lookupsids2_result['domains'] ~= nil and lookupsids2_result['domains']['domains'] ~= nil and lookupsids2_result['domains']['domains'][1] ~= nil) then
              result['domain'] = lookupsids2_result['domains']['domains'][1]['name']
            else
              result['domain'] = ""
            end
          end

          if(result['type'] ~= "SID_NAME_WKN_GRP") then -- Don't show "well known" accounts
            -- Add it to the results
            results[#results + 1] = result
          end
        end
      end
    end
  end

  -- Close the policy
  msrpc.lsa_close(smbstate, openpolicy2_result['policy_handle'])

  -- Stop the session
  msrpc.stop_smb(smbstate)

  return true, results
end


--_G.TRACEBACK = TRACEBACK or {}
action = function(host)
  --    TRACEBACK[coroutine.running()] = true;

  local response = {}

  -- Enumerate the logged in users
  local logged_in = {}
  local status1, users = winreg_enum_rids(host)
  if(status1 == false) then
    logged_in['warning'] = "Couldn't enumerate login sessions: " .. users
  else
    logged_in['name'] = "Users logged in"
    if(#users == 0) then
      table.insert(response, "<nobody>")
    else
      for i = 1, #users, 1 do
        if(users[i]['name'] ~= nil) then
          table.insert(logged_in, string.format("%s\\%s since %s", users[i]['domain'], users[i]['name'], users[i]['changed_date']))
        end
      end
    end
  end
  table.insert(response, logged_in)

  -- Get the connected sessions
  local sessions_output = {}
  local status2, sessions = srvsvc_enum_sessions(host)
  if(status2 == false) then
    sessions_output['warning'] = "Couldn't enumerate SMB sessions: " .. sessions
  else
    sessions_output['name'] = "Active SMB sessions"
    if(#sessions == 0) then
      table.insert(sessions_output, "<none>")
    else
      -- Format the result
      for i = 1, #sessions, 1 do
        local time = sessions[i]['time']
        if(time == 0) then
          time = "[just logged in, it's probably you]"
        else
          time = datetime.format_time(time)
        end

        local idle_time = sessions[i]['idle_time']
        if(idle_time == 0) then
          idle_time = "[not idle]"
        else
          idle_time = datetime.format_time(idle_time)
        end

        table.insert(sessions_output, string.format("%s is connected from %s for %s, idle for %s", sessions[i]['user'], sessions[i]['client'], time, idle_time))
      end
    end
  end
  table.insert(response, sessions_output)

  return stdnse.format_output(true, response)
end



