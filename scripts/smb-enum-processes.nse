local msrpcperformance = require "msrpcperformance"
local nmap = require "nmap"
local smb = require "smb"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

description = [[
Pulls a list of processes from the remote server over SMB. This will determine
all running processes, their process IDs, and their parent processes. It is done
by querying the remote registry service, which is disabled by default on Vista;
on all other Windows versions, it requires Administrator privileges.

Since this requires administrator privileges, it isn't especially useful for a
penetration tester, since they can effectively do the same thing with metasploit
or other tools. It does, however, provide for a quick way to get process lists
for a bunch of systems at the same time.

WARNING: I have experienced crashes in <code>regsvc.exe</code> while making registry calls
against a fully patched Windows 2000 system; I've fixed the issue that caused
it, but there's no guarantee that it (or a similar vulnerability in the same code) won't
show up again. Since the process automatically restarts, it doesn't negatively
impact the system, besides showing a message box to the user.
]]

---
-- @usage
-- nmap --script smb-enum-processes.nse -p445 <host>
-- sudo nmap -sU -sS --script smb-enum-processes.nse -p U:137,T:139 <host>
--
---
-- @output
-- Host script results:
-- |  smb-enum-processes:
-- |_ |_ Idle, System, smss, csrss, winlogon, services, logon.scr, lsass, spoolsv, msdtc, VMwareService, svchost, alg, explorer, VMwareTray, VMwareUser, wmiprvse
--
-- --
-- Host script results:
-- |  smb-enum-processes:
-- |  `+-Idle
-- |   | `-System
-- |   |   `-smss
-- |   |     `+-csrss
-- |   |      `-winlogon
-- |   |        `+-services
-- |   |         | `+-spoolsv
-- |   |         |  +-msdtc
-- |   |         |  +-VMwareService
-- |   |         |  +-svchost
-- |   |         |  `-alg
-- |   |         +-logon.scr
-- |   |         `-lsass
-- |   +-explorer
-- |   | `+-VMwareTray
-- |   |  `-VMwareUser
-- |_  `-wmiprvse
--
-- --
-- Host script results:
-- |  smb-enum-processes:
-- |   PID  PPID  Priority Threads Handles
-- |  ----- ----- -------- ------- -------
-- |      0     0        0       1       0 `+-Idle
-- |      4     0        8      49     395  | `-System
-- |    252     4       11       3      19  |   `-smss
-- |    300   252       13      10     338  |     `+-csrss
-- |    324   252       13      18     513  |      `-winlogon
-- |    372   324        9      16     272  |        `+-services
-- |    872   372        8      12     121  |         | `+-spoolsv
-- |    896   372        8      13     151  |         |  +-msdtc
-- |   1172   372       13       3      53  |         |  +-VMwareService
-- |   1336   372        8      20     158  |         |  +-svchost
-- |   1476   372        8       6      90  |         |  `-alg
-- |    376   324        4       1      22  |         +-logon.scr
-- |    384   324        9      23     394  |         `-lsass
-- |   1720  1684        8       9     259  +-explorer
-- |   1796  1720        8       1      42  | `+-VMwareTray
-- |   1808  1720        8       1      44  |  `-VMwareUser
-- |_  1992   580        8       7     179  `-wmiprvse
-----------------------------------------------------------------------

author = "Ron Bowes"
copyright = "Ron Bowes"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "intrusive"}
dependencies = {"smb-brute"}


function psl_mode (list, i)
  local mode

  -- Decide connector for process.
  if #list == 1 then
    mode = "only"
  elseif i == 1 then
    mode = "first"
  elseif i < #list then
    mode = "middle"
  else
    mode = "last"
  end

  return mode
end

function psl_print (psl, lvl)
  -- Print out table header.
  local result = {}
  if lvl == 2 then
    result[#result+1] = " PID  PPID  Priority Threads Handles\n"
    result[#result+1] = "----- ----- -------- ------- -------\n"
  end

  -- Find how many root processes there are.
  local roots = {}
  for i, ps in pairs(psl) do
    if psl[ps.ppid] == nil or ps.ppid == ps.pid then
      table.insert(roots, i)
    end
  end
  table.sort(roots)

  -- Create vertical sibling bars.
  local bars = {}
  if #roots ~= 1 then
    table.insert(bars, 2)
  end

  -- Print out each root of the tree.
  for i, root in ipairs(roots) do
    local mode = psl_mode(roots, i)
    psl_tree(psl, root, 0, bars, mode, lvl, result)
  end

  return table.concat(result)
end

function psl_tree (psl, pid, column, bars, mode, lvl, result)
  local ps = psl[pid]

  -- Delete vertical sibling link.
  if mode == "last" then
    table.remove(bars)
  end

  -- Print information table.
  local info = ""
  if lvl == 2 then
    info = string.format("% 5d % 5d % 8d % 7d % 7d ", ps.pid, ps.ppid, ps.prio, ps.thrd, ps.hndl)
  end

  -- Print vertical sibling bars.
  local prefix = ""
  for i=1, #bars do
    prefix = prefix .. string.rep(" ", bars[i] - 1) .. "|"
  end

  -- Strings used to separate processes from one another.
  local separators = {
    first  = "`+-";
    last  = " `-";
    middle  = " +-";
    only  = "`-";
  }

  -- Format process itself.
  result[#result+1] = "\n" .. info .. prefix .. separators[mode] .. ps.name

  -- Find children of the process.
  local children = {}
  for child_pid, child in pairs(psl) do
    if child_pid ~= pid and child.ppid == pid then
      table.insert(children, child_pid)
    end
  end
  table.sort(children)

  -- Add vertical sibling link between children.
  column = column + #separators[mode]
  if #children > 1 then
    table.insert(bars, column + 2)
  end

  -- Format process's children.
  for i, pid in ipairs(children) do
    local mode = psl_mode(children, i)
    psl_tree(psl, pid, column, bars, mode, lvl, result)
  end

  return result
end

hostrule = function(host)
  return smb.get_port(host) ~= nil
end

action = function(host)
  -- Get the process list
  local status, result = msrpcperformance.get_performance_data(host, "230")
  if status == false then
    return stdnse.format_output(false, result)
  end

  -- Get the process table
  local process = result["Process"]

  -- Put the processes into an array, and sort them by pid.
  local names = {}
  for i, v in pairs(process) do
    if i ~= "_Total" then
      names[#names + 1] = i
    end
  end
  table.sort(names, function (a, b) return process[a]["ID Process"] < process[b]["ID Process"] end)

  -- Put the processes into an array indexed by pid and with a value equal
  -- to the name (so we can look it up easily when we need to).
  local process_id = {}
  for i, v in pairs(process) do
    process_id[v["ID Process"]] = i
  end

  -- Fill the process list table.
  --
  -- Used fields:
  --   Creating Process ID
  --   Handle Count
  --   ID Process
  --   Priority Base
  --   Thread Count
  --
  -- Unused fields:
  --   % Privileged Time
  --   % Processor Time
  --   % User Time
  --   Elapsed Time
  --   IO Data Bytes/sec
  --   IO Data Operations/sec
  --   IO Other Bytes/sec
  --   IO Other Operations/sec
  --   IO Read Bytes/sec
  --   IO Read Operations/sec
  --   IO Write Bytes/sec
  --   IO Write Operations/sec
  --   Page Faults/sec
  --   Page File Bytes
  --   Page File Bytes Peak
  --   Pool Nonpaged Bytes
  --   Pool Paged Bytes
  --   Private Bytes
  --   Virtual Bytes
  --   Virtual Bytes Peak
  --   Working Set
  --   Working Set Peak
  local psl = {}
  for i, name in ipairs(names) do
    if name ~= "_Total" then
      psl[process[name]["ID Process"]] = {
        name  = name;
        pid  = process[name]["ID Process"];
        ppid  = process[name]["Creating Process ID"];
        prio  = process[name]["Priority Base"];
        thrd  = process[name]["Thread Count"];
        hndl  = process[name]["Handle Count"];
      }
    end
  end

  -- Produce final output.
  local response
  if nmap.verbosity() == 0 then
    response = "|_ " .. table.concat(names, ", ")
  else
    response = "\n" .. psl_print(psl, nmap.verbosity())
  end

  return response
end
