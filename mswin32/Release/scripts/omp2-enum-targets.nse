local omp2 = require "omp2"
local shortport = require "shortport"
local stdnse = require "stdnse"
local tab = require "tab"
local table = require "table"
local target = require "target"

description = [[
Attempts to retrieve the list of target systems and networks from an OpenVAS Manager server.

The script authenticates on the manager using provided or previously cracked
credentials and gets the list of defined targets for each account.

These targets will be added to the scanning queue in case
<code>newtargets</code> global variable is set.
]]

---
-- @usage
-- nmap -p 9390 --script omp2-brute,omp2-enum-targets <target>
--
-- @usage
-- nmap -p 9390 --script omp2-enum-targets --script-args omp2.username=admin,omp2.password=secret <target>
--
-- @output
-- PORT     STATE SERVICE
-- 9390/tcp open  openvas
-- | omp2-enum-targets:
-- |  Targets for account admin:
-- |  TARGET              HOSTS
-- |  Sales network       192.168.20.0/24
-- |  Production network  192.168.30.0/24
-- |_ Firewall            192.168.1.254
--


author = "Henri Doreau"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}
dependencies = {"omp2-brute"}




portrule = shortport.port_or_service(9390, "openvas")


--- Return the list of targets defined for a given user
--
-- @param host the target host table
-- @param port the targetted OMP port
-- @param username the username to use to login
-- @param password the password to use to login
-- @return the list of targets for this user or nil
local function account_enum_targets(host, port, username, password)
  local targets
  local session = omp2.Session:new()

  local status, err = session:connect(host, port)

  if not status then
    stdnse.debug1("connection failure (%s)", err)
    return nil
  end

  if session:authenticate(username, password) then
    targets = session:ls_targets()
  else
    stdnse.debug1("authentication failure (%s:%s)", username, password)
  end

  session:close()

  return targets
end

--- Generate the output string representing the list of discovered targets
--
-- @param targets the list of targets as a name->hosts mapping
-- @return the array as a formatted string
local function report(targets)
  local outtab = tab.new()

  tab.add(outtab, 1, "TARGET")
  tab.add(outtab, 2, "HOSTS")
  tab.nextrow(outtab)

  for name, hosts in pairs(targets) do
    tab.addrow(outtab, name, hosts)
  end

  return tab.dump(outtab)
end

action = function(host, port)
  local results = {}
  local credentials = omp2.get_accounts(host)

  if not credentials then
    -- unable to authenticate on the server
    return "No valid account available!"
  end

  for _, account in pairs(credentials) do

    local username, password = account.username, account.password

    local targets = account_enum_targets(host, port, username, password)

    if targets ~= nil then
      table.insert(results, "Targets for account " .. username .. ":")
      table.insert(results, report(targets))
    else
      table.insert(results, "No targets found for account " .. username)
    end

    if target.ALLOW_NEW_TARGETS and targets ~= nil then
      stdnse.debug1("adding new targets %s", stdnse.strjoin(", ", targets))
      target.add(table.unpack(targets))
    end

  end

  return stdnse.format_output(true, results)
end

