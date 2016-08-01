local smb = require "smb"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

description = [[
Attempts to list shares using the <code>srvsvc.NetShareEnumAll</code> MSRPC function and
retrieve more information about them using <code>srvsvc.NetShareGetInfo</code>. If access
to those functions is denied, a list of common share names are checked.

Finding open shares is useful to a penetration tester because there may be private files
shared, or, if it's writable, it could be a good place to drop a Trojan or to infect a file
that's already there. Knowing where the share is could make those kinds of tests more useful,
except that determining where the share is requires administrative privileges already.

Running <code>NetShareEnumAll</code> will work anonymously against Windows 2000, and
requires a user-level account on any other Windows version. Calling <code>NetShareGetInfo</code>
requires an administrator account on all versions of Windows up to 2003, as well as Windows Vista
and Windows 7, if UAC is turned down.

Even if <code>NetShareEnumAll</code> is restricted, attempting to connect to a share will always
reveal its existence. So, if <code>NetShareEnumAll</code> fails, a pre-generated list of shares,
based on a large test network, are used. If any of those succeed, they are recorded.

After a list of shares is found, the script attempts to connect to each of them anonymously,
which divides them into "anonymous", for shares that the NULL user can connect to, or "restricted",
for shares that require a user account.
]]

---
--@usage
-- nmap --script smb-enum-shares.nse -p445 <host>
-- sudo nmap -sU -sS --script smb-enum-shares.nse -p U:137,T:139 <host>
--
--@output
-- Host script results:
-- | smb-enum-shares:
-- |  account_used: WORKGROUP\Administrator
-- |  ADMIN$
-- |    Type: STYPE_DISKTREE_HIDDEN
-- |    Comment: Remote Admin
-- |    Users: 0
-- |    Max Users: <unlimited>
-- |    Path: C:\WINNT
-- |    Anonymous access: <none>
-- |    Current user access: READ/WRITE
-- |  C$
-- |    Type: STYPE_DISKTREE_HIDDEN
-- |    Comment: Default share
-- |    Users: 0
-- |    Max Users: <unlimited>
-- |    Path: C:\
-- |    Anonymous access: <none>
-- |    Current user access: READ
-- |  IPC$
-- |    Type: STYPE_IPC_HIDDEN
-- |    Comment: Remote IPC
-- |    Users: 1
-- |    Max Users: <unlimited>
-- |    Path:
-- |    Anonymous access: READ
-- |_   Current user access: READ
--
-- @xmloutput
-- <elem key="account_used">WORKGROUP\Administrator</elem>
-- <table key="ADMIN$">
--   <elem key="Type">STYPE_DISKTREE_HIDDEN</elem>
--   <elem key="Comment">Remote Admin</elem>
--   <elem key="Users">0</elem>
--   <elem key="Max Users"><unlimited></elem>
--   <elem key="Path">C:\WINNT</elem>
--   <elem key="Anonymous access"><none></elem>
--   <elem key="Current user access">READ/WRITE</elem>
-- </table>
-- <table key="C$">
--   <elem key="Type">STYPE_DISKTREE_HIDDEN</elem>
--   <elem key="Comment">Default share</elem>
--   <elem key="Users">0</elem>
--   <elem key="Max Users"><unlimited></elem>
--   <elem key="Path">C:\</elem>
--   <elem key="Anonymous access"><none></elem>
--   <elem key="Current user access">READ</elem>
-- </table>
-- <table key="IPC$">
--   <elem key="Type">STYPE_IPC_HIDDEN</elem>
--   <elem key="Comment">Remote IPC</elem>
--   <elem key="Users">1</elem>
--   <elem key="Max Users"><unlimited></elem>
--   <elem key="Path"></elem>
--   <elem key="Anonymous access">READ</elem>
--   <elem key="Current user access">READ</elem>
-- </table>

author = "Ron Bowes"
copyright = "Ron Bowes"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery","intrusive"}
dependencies = {"smb-brute"}


hostrule = function(host)
  return smb.get_port(host) ~= nil
end

action = function(host)
  local status, shares, extra
  local response = stdnse.output_table()

  -- Get the list of shares
  status, shares, extra = smb.share_get_list(host)
  if(status == false) then
    return stdnse.format_output(false, string.format("Couldn't enumerate shares: %s", shares))
  end

  if(extra ~= nil and extra ~= '') then
    response.note = extra
  end

  -- Find out who the current user is
  local result, username, domain = smb.get_account(host)
  if(result == false) then
    username = "<unknown>"
    domain = ""
  end
  if domain and domain ~= "" then
    domain = domain .. "\\"
  end
  response.account_used = string.format("%s%s", domain, stdnse.string_or_blank(username, '<blank>'))

  if host.registry['smb_shares'] == nil then
     host.registry['smb_shares'] = {}
  end

  for i = 1, #shares, 1 do
    local share = shares[i]
    local share_output = stdnse.output_table()

    if(type(share['details']) ~= 'table') then
      share_output['warning'] = string.format("Couldn't get details for share: %s", share['details'])
      -- A share of 'NT_STATUS_OBJECT_NAME_NOT_FOUND' indicates this isn't a fileshare
      if(share['user_can_write'] == "NT_STATUS_OBJECT_NAME_NOT_FOUND") then
        share_output["Type"] = "Not a file share"
      else
        table.insert(host.registry['smb_shares'], share.name)
      end
    else
      local details = share['details']

      share_output["Type"] = details.sharetype
      share_output["Comment"] = details.comment
      share_output["Users"] = details.current_users
      share_output["Max Users"] = details.max_users
      share_output["Path"] = details.path

      if (share_output["Type"] == "STYPE_DISKTREE" or
          share_output["Type"] == "STYPE_DISKTREE_TEMPORARY" or
          share_output["Type"] == "STYPE_DISKTREE_HIDDEN") then
        table.insert(host.registry['smb_shares'], share.name)
      end
    end
    -- Print details for a file share
    if(share['anonymous_can_read'] and share['anonymous_can_write']) then
      share_output["Anonymous access"] = "READ/WRITE"
    elseif(share['anonymous_can_read'] and not(share['anonymous_can_write'])) then
      share_output["Anonymous access"] = "READ"
    elseif(not(share['anonymous_can_read']) and share['anonymous_can_write']) then
      share_output["Anonymous access"] = "WRITE"
    else
      share_output["Anonymous access"] = "<none>"
    end

    -- Don't bother printing this if we're already anonymous
    if(username ~= '') then
      if(share['user_can_read'] and share['user_can_write']) then
        share_output["Current user access"] = "READ/WRITE"
      elseif(share['user_can_read'] and not(share['user_can_write'])) then
        share_output["Current user access"] = "READ"
      elseif(not(share['user_can_read']) and share['user_can_write']) then
        share_output["Current user access"] = "WRITE"
      else
        share_output["Current user access"] = "<none>"
      end
    end

    response[share.name] = share_output
  end

  if next(host.registry['smb_shares']) == nil then
    host.registry['smb_shares'] = nil
  end

  return response
end

