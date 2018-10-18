local msrpc = require "msrpc"
local nmap = require "nmap"
local smb = require "smb"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

description = [[
Attempts to enumerate the users on a remote Windows system, with as much
information as possible, through two different techniques (both over MSRPC,
which uses port 445 or 139; see <code>smb.lua</code>). The goal of this script
is to discover all user accounts that exist on a remote system. This can be
helpful for administration, by seeing who has an account on a server, or for
penetration testing or network footprinting, by determining which accounts
exist on a system.

A penetration tester who is examining servers may wish to determine the
purpose of a server. By getting a list of who has access to it, the tester
might get a better idea (if financial people have accounts, it probably
relates to financial information). Additionally, knowing which accounts
exist on a system (or on multiple systems) allows the pen-tester to build a
dictionary of possible usernames for bruteforces, such as a SMB bruteforce
or a Telnet bruteforce. These accounts may be helpful for other purposes,
such as using the accounts in Web applications on this or other servers.

From a pen-testers perspective, retrieving the list of users on any
given server creates endless possibilities.

Users are enumerated in two different ways:  using SAMR enumeration or
LSA bruteforcing. By default, both are used, but they have specific
advantages and disadvantages. Using both is a great default, but in certain
circumstances it may be best to give preference to one.

Advantages of using SAMR enumeration:
* Stealthier (requires one packet/user account, whereas LSA uses at least 10 packets while SAMR uses half that; additionally, LSA makes a lot of noise in the Windows event log (LSA enumeration is the only script I (Ron Bowes) have been called on by the administrator of a box I was testing against).
* More information is returned (more than just the username).
* Every account will be found, since they're being enumerated with a function that's designed to enumerate users.

Advantages of using LSA bruteforcing:
* More accounts are returned (system accounts, groups, and aliases are returned, not just users).
* Requires a lower-level account to run on Windows XP and higher (a 'guest' account can be used, whereas SAMR enumeration requires a 'user' account; especially useful when only guest access is allowed, or when an account has a blank password (which effectively gives it guest access)).

SAMR enumeration is done with the  <code>QueryDisplayInfo</code> function.
If this succeeds, it will return a detailed list of users, along with descriptions,
types, and full names. This can be done anonymously against Windows 2000, and
with a user-level account on other Windows versions (but not with a guest-level account).

To perform this test, the following functions are used:
* <code>Bind</code>: bind to the SAMR service.
* <code>Connect4</code>: get a connect_handle.
* <code>EnumDomains</code>: get a list of the domains.
* <code>QueryDomain</code>: get the sid for the domain.
* <code>OpenDomain</code>: get a handle for each domain.
* <code>QueryDisplayInfo</code>: get the list of users in the domain.
* <code>Close</code>: Close the domain handle.
* <code>Close</code>: Close the connect handle.
The advantage of this technique is that a lot of details are returned, including
the full name and description; the disadvantage is that it requires a user-level
account on every system except for Windows 2000. Additionally, it only pulls actual
user accounts, not groups or aliases.

Regardless of whether this succeeds, a second technique is used to pull
user accounts, called LSA bruteforcing. LSA bruteforcing can be done anonymously
against Windows 2000, and requires a guest account or better on other systems.
It has the advantage of running with less permission, and will also find more
account types (i.e., groups, aliases, etc.). The disadvantages is that it returns
less information, and that, because it's a brute-force guess, it's possible to miss
accounts. It's also extremely noisy.

This isn't a brute-force technique in the common sense, however: it's a brute-forcing of users'
RIDs. A user's RID is a value (generally 500, 501, or 1000+) that uniquely identifies
a user on a domain or system. An LSA function is exposed which lets us convert the RID
(say, 1000) to the username (say, "Ron"). So, the technique will essentially try
converting 1000 to a name, then 1001, 1002, etc., until we think we're done.

To do this, the script breaks users into groups of RIDs based on the <code>LSA_GROUPSIZE</code>
constant. All members of this group are checked simultaneously, and the responses recorded.
When a series of empty groups are found (<code>LSA_MINEMPTY</code> groups, specifically),
the scan ends. As long as you are getting a few groups with active accounts, the scan will
continue.

Before attempting this conversion, the SID of the server has to be determined.
The SID is determined by doing the reverse operation; that is, by converting a name into
its RID. The name is determined by looking up any name present on the system.
We try:
* The computer name and domain name, returned in <code>SMB_COM_NEGOTIATE</code>;
* An nbstat query to get the server name and the user currently logged in; and
* Some common names: "administrator", "guest", and "test".

In theory, the computer name should be sufficient for this to always work, and
it has so far has in my tests, but I included the rest of the names for good measure. It
doesn't hurt to add more.

The names and details from both of these techniques are merged and displayed.
If the output is verbose, then extra details are shown. The output is ordered alphabetically.

Credit goes out to the <code>enum.exe</code>, <code>sid2user.exe</code>, and
<code>user2sid.exe</code> programs for pioneering some of the techniques used
in this script.
]]

---
-- @usage
-- nmap --script smb-enum-users.nse -p445 <host>
-- sudo nmap -sU -sS --script smb-enum-users.nse -p U:137,T:139 <host>
--
-- @output
-- Host script results:
-- |  smb-enum-users:
-- |_ |_ Domain: RON-WIN2K-TEST; Users: Administrator, Guest, IUSR_RON-WIN2K-TEST, IWAM_RON-WIN2K-TEST, test1234, TsInternetUser
--
-- Host script results:
-- |  smb-enum-users:
-- |  |  RON-WIN2K-TEST\Administrator (RID: 500)
-- |  |  |  Description: Built-in account for administering the computer/domain
-- |  |  |_ Flags:       Password does not expire, Normal user account
-- |  |  RON-WIN2K-TEST\Guest (RID: 501)
-- |  |  |  Description: Built-in account for guest access to the computer/domain
-- |  |  |_ Flags:       Password not required, Password does not expire, Normal user account
-- |  |  RON-WIN2K-TEST\IUSR_RON-WIN2K-TEST (RID: 1001)
-- |  |  |  Full name:   Internet Guest Account
-- |  |  |  Description: Built-in account for anonymous access to Internet Information Services
-- |  |  |_ Flags:       Password not required, Password does not expire, Normal user account
-- |  |  RON-WIN2K-TEST\IWAM_RON-WIN2K-TEST (RID: 1002)
-- |  |  |  Full name:   Launch IIS Process Account
-- |  |  |  Description: Built-in account for Internet Information Services to start out of process applications
-- |  |  |_ Flags:       Password not required, Password does not expire, Normal user account
-- |  |  RON-WIN2K-TEST\test1234 (RID: 1005)
-- |  |  |_ Flags:       Normal user account
-- |  |  RON-WIN2K-TEST\TsInternetUser (RID: 1000)
-- |  |  |  Full name:   TsInternetUser
-- |  |  |  Description: This user account is used by Terminal Services.
-- |_ |_ |_ Flags:       Password not required, Password does not expire, Normal user account
--
-- @args lsaonly If set, script will only enumerate using an LSA bruteforce (requires less
--       access than samr). Only set if you know what you're doing, you'll get better results
--       by using the default options.
-- @args samronly If set, script will only query a list of users using a SAMR lookup. This is
--       much quieter than LSA lookups, so enable this if you want stealth. Generally, however,
--       you'll get better results by using the default options.
-----------------------------------------------------------------------

author = "Ron Bowes"
copyright = "Ron Bowes"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"auth","intrusive"}
dependencies = {"smb-brute"}


hostrule = function(host)
  return smb.get_port(host) ~= nil
end

action = function(host)

  local i, j
  local samr_status = false
  local lsa_status  = false
  local samr_result = "Didn't run"
  local lsa_result  = "Didn't run"
  local names = {}
  local names_lookup = {}
  local response = {}
  local samronly = nmap.registry.args.samronly
  local lsaonly  = nmap.registry.args.lsaonly
  local do_samr  = samronly ~= nil or (samronly == nil and lsaonly == nil)
  local do_lsa   = lsaonly  ~= nil or (samronly == nil and lsaonly == nil)

  -- Try enumerating through SAMR. This is the better source of information, if we can get it.
  if(do_samr) then
    samr_status, samr_result = msrpc.samr_enum_users(host)

    if(samr_status) then
      -- Copy the returned array into the names[] table
      stdnse.debug2("EnumUsers: Received %d names from SAMR", #samr_result)
      for i = 1, #samr_result, 1 do
        -- Insert the full info into the names list
        table.insert(names, samr_result[i])
        -- Set the names_lookup value to 'true' to avoid duplicates
        names_lookup[samr_result[i]['name']] = true
      end
    end
  end

  -- Try enumerating through LSA.
  if(do_lsa) then
    lsa_status, lsa_result  = msrpc.lsa_enum_users(host)
    if(lsa_status) then
      -- Copy the returned array into the names[] table
      stdnse.debug2("EnumUsers: Received %d names from LSA", #lsa_result)
      for i = 1, #lsa_result, 1 do
        if(lsa_result[i]['name'] ~= nil) then
          -- Check if the name already exists
          if(not(names_lookup[lsa_result[i]['name']])) then
            table.insert(names, lsa_result[i])
          end
        end
      end
    end
  end

  -- Check if both failed
  if(samr_status == false and lsa_status == false) then
    if(string.find(lsa_result, 'ACCESS_DENIED')) then
      return stdnse.format_output(false, "Access denied while trying to enumerate users; except against Windows 2000, Guest or better is typically required")
    end

    return stdnse.format_output(false, {"Couldn't enumerate users", "SAMR returned " .. samr_result, "LSA returned " .. lsa_result})
  end

  -- Sort them
  table.sort(names, function (a, b) return string.lower(a.name) < string.lower(b.name) end)

  -- Break them out by domain
  local domains = {}
  for _, name in ipairs(names) do
    local domain    = name['domain']

    -- Make sure the entry in the domains table exists
    if(not(domains[domain])) then
      domains[domain] = {}
    end

    table.insert(domains[domain], name)
  end

  -- Check if we actually got any names back
  if(#names == 0) then
    table.insert(response, "Couldn't find any account names, sorry!")
  else
    -- If we're not verbose, just print out the names. Otherwise, print out everything we can
    if(nmap.verbosity() < 1) then
      for domain, domain_users in pairs(domains) do
        -- Make an impromptu list of users
        local names = {}
        for _, info in ipairs(domain_users) do
          table.insert(names, info['name'])
        end

        -- Add this domain to the response
        table.insert(response, string.format("Domain: %s; Users: %s", domain, table.concat(names, ", ")))
      end
    else
      for domain, domain_users in pairs(domains) do
        for _, info in ipairs(domain_users) do
          local response_part = {}
          response_part['name'] = string.format("%s\\%s (RID: %d)", domain, info['name'], info['rid'])

          if(info['fullname']) then
            table.insert(response_part, string.format("Full name:   %s", info['fullname']))
          end
          if(info['description']) then
            table.insert(response_part, string.format("Description: %s", info['description']))
          end
          if(info['flags']) then
            table.insert(response_part, string.format("Flags:       %s", table.concat(info['flags'], ", ")))
          end

          table.insert(response, response_part)
        end
      end
    end
  end

  return stdnse.format_output(true, response)
end

