local msrpc = require "msrpc"
local smb = require "smb"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"
local tableaux = require "tableaux"

description = [[
Obtains a list of groups from the remote Windows system, as well as a list of the group's users.
This works similarly to <code>enum.exe</code> with the <code>/G</code> switch.

The following MSRPC functions in SAMR are used to find a list of groups and the RIDs of their users. Keep
in mind that MSRPC refers to groups as "Aliases".

* <code>Bind</code>: bind to the SAMR service.
* <code>Connect4</code>: get a connect_handle.
* <code>EnumDomains</code>: get a list of the domains.
* <code>LookupDomain</code>: get the RID of the domains.
* <code>OpenDomain</code>: get a handle for each domain.
* <code>EnumDomainAliases</code>: get the list of groups in the domain.
* <code>OpenAlias</code>: get a handle to each group.
* <code>GetMembersInAlias</code>: get the RIDs of the members in the groups.
* <code>Close</code>: close the alias handle.
* <code>Close</code>: close the domain handle.
* <code>Close</code>: close the connect handle.

Once the RIDs have been termined, the
* <code>Bind</code>: bind to the LSA service.
* <code>OpenPolicy2</code>: get a policy handle.
* <code>LookupSids2</code>: convert SIDs to usernames.

I (Ron Bowes) originally looked into the possibility of using the SAMR function <code>LookupRids2</code>
to convert RIDs to usernames, but the function seemed to return a fault no matter what I tried. Since
enum.exe also switches to LSA to convert RIDs to usernames, I figured they had the same issue and I do
the same thing.
]]

---
-- @usage
-- nmap --script smb-enum-users.nse -p445 <host>
-- sudo nmap -sU -sS --script smb-enum-users.nse -p U:137,T:139 <host>
--
-- @output
-- Host script results:
-- | smb-enum-groups:
-- |   Builtin\Administrators (RID: 544): Administrator, Daniel
-- |   Builtin\Users (RID: 545): <empty>
-- |   Builtin\Guests (RID: 546): Guest
-- |   Builtin\Performance Monitor Users (RID: 558): <empty>
-- |   Builtin\Performance Log Users (RID: 559): Daniel
-- |   Builtin\Distributed COM Users (RID: 562): <empty>
-- |   Builtin\IIS_IUSRS (RID: 568): <empty>
-- |   Builtin\Event Log Readers (RID: 573): <empty>
-- |   azure\HomeUsers (RID: 1000): Administrator, Daniel, HomeGroupUser$
-- |_  azure\HelpLibraryUpdaters (RID: 1003): <empty>
--
-- @xmloutput
-- <table key="Builtin">
--   <table key="RID 544">
--     <table key="member_sids">
--       <elem>S-1-5-21-12345678-1234567890-0987654321-500</elem>
--       <elem>S-1-5-21-12345678-1234567890-0987654321-1001</elem>
--     </table>
--     <elem key="name">Administrators</elem>
--     <table key="members">
--       <elem>Administrator</elem>
--       <elem>Daniel</elem>
--     </table>
--   </table>
--   <table key="RID 545">
--     <table key="member_sids">
--       <elem>S-1-5-4</elem>
--       <elem>S-1-5-11</elem>
--     </table>
--     <elem key="name">Users</elem>
--     <table key="members"></table>
--   </table>
--   <table key="RID 546">
--     <table key="member_sids">
--       <elem>S-1-5-21-12345678-1234567890-0987654321-501</elem>
--     </table>
--     <elem key="name">Guests</elem>
--     <table key="members">
--       <elem>Guest</elem>
--     </table>
--   </table>
--   <table key="RID 559">
--     <table key="member_sids">
--       <elem>S-1-5-21-12345678-1234567890-0987654321-1001</elem>
--     </table>
--     <elem key="name">Performance Log Users</elem>
--     <table key="members">
--       <elem>Daniel</elem>
--     </table>
--   </table>
--   <table key="RID 562">
--     <table key="member_sids"></table>
--     <elem key="name">Distributed COM Users</elem>
--     <table key="members"></table>
--   </table>
--   <table key="RID 568">
--     <table key="member_sids">
--       <elem>S-1-5-17</elem>
--     </table>
--     <elem key="name">IIS_IUSRS</elem>
--     <table key="members"></table>
--   </table>
-- </table>
-- <table key="azure">
--   <table key="RID 1000">
--     <table key="member_sids">
--       <elem>S-1-5-21-12345678-1234567890-0987654321-500</elem>
--       <elem>S-1-5-21-12345678-1234567890-0987654321-1001</elem>
--       <elem>S-1-5-21-12345678-1234567890-0987654321-1002</elem>
--     </table>
--     <elem key="name">HomeUsers</elem>
--     <table key="members">
--       <elem>Administrator</elem>
--       <elem>Daniel</elem>
--       <elem>HomeGroupUser$</elem>
--     </table>
--   </table>
--   <table key="RID 1003">
--     <table key="member_sids"></table>
--     <elem key="name">HelpLibraryUpdaters</elem>
--     <table key="members"></table>
--   </table>
-- </table>

author = "Ron Bowes"
copyright = "Ron Bowes"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery","intrusive"}
dependencies = {"smb-brute"}


hostrule = function(host)
  return smb.get_port(host) ~= nil
end

local empty = {"<empty>"}

action = function(host)
  local status, groups = msrpc.samr_enum_groups(host)
  if(not(status)) then
    return stdnse.format_output(false, "Couldn't enumerate groups: " .. groups)
  end

  local response = stdnse.output_table()
  local response_str = {}

  local domains = tableaux.keys(groups)
  table.sort(domains)
  for _, domain_name in ipairs(domains) do
    local dom_groups = stdnse.output_table()
    response[domain_name] = dom_groups
    local domain_data = groups[domain_name]

    local rids = tableaux.keys(domain_data)
    table.sort(rids)
    for _, rid in ipairs(rids) do
      local group_data = domain_data[rid]
      -- TODO: Map SIDs to names, show non-named SIDs
      table.insert(response_str,
        string.format("\n  %s\\%s (RID: %s): %s", domain_name, group_data.name, rid,
          table.concat(#group_data.members > 0 and group_data.members or empty, ", "))
        )
      dom_groups[string.format("RID %d", rid)] = group_data
    end
  end

  return response, table.concat(response_str)
end

