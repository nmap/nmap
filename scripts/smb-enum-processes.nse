description = [[
Pulls a list of processes from the remote server over SMB. This will determine
all running processes, their process IDs, and their parent processes. It is done
by querying the remote registry service, which is disabled by default on Vista; on 
all other Windows versions, it requires Administrator privilges. 

Since this requires administrator privileges, it isn't especially useful for a 
penetration tester, since they can effectively do the same thing with metasploit
or other tools. It does, however, provide for a quick way to get process lists 
for a bunch of systems at the same time. 

WARNING: I have experienced crashes in regsvc.exe while making registry calls 
against a fully patched Windows 2000 system; I've fixed the issue that caused it,
but there's no guarantee that it (or a similar vuln in the same code) won't show 
up again. Since the process automatically restarts, it doesn't negatively impact 
the system, besides showing a message box to the user. 
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
-- |  -+-Idle(0)---System(8)---SMSS(140)-+-WINLOGON(160)-+-SERVICES(212)-+-spoolsv(432)
-- |   |                                 |               |               +-mstask(536)
-- |   |                                 |               |               +-WinMgmt(592)
-- |   |                                 |               |               +-svchost(620)
-- |   |                                 |               |               `-regsvc(1136)
-- |   |                                 |               `-LSASS(224)
-- |   |                                 `-CSRSS(164)
-- |   +-Unknown(296)---explorer(344)-+-firefox(636)---WinRAR(736)
-- |   |                              +-keyfinder(848)
-- |   |                              `-CMD(956)
-- |   +-Unknown(400)---IEXPLORE(1036)
-- |_  `-Unknown(840)---DRWTSN32(1192)
-- 
-- --
-- Host script results:
-- |  smb-enum-processes:  
-- |  Idle [0] (parent: 0, priority: 0, threads: 1, handles: 0)
-- |  System [8] (parent: 0, priority: 8, threads: 34, handles: 190)
-- |  smss [140] (parent: 8, priority: 11, threads: 6, handles: 33)
-- |  winlogon [160] (parent: 140, priority: 13, threads: 14, handles: 335)
-- |  csrss [164] (parent: 140, priority: 13, threads: 10, handles: 229)
-- |  services [212] (parent: 160, priority: 9, threads: 33, handles: 462)
-- |  lsass [224] (parent: 160, priority: 9, threads: 13, handles: 267)
-- |  SPOOLSV [412] (parent: 212, priority: 8, threads: 10, handles: 95)
-- |  svchost [448] (parent: 212, priority: 8, threads: 24, handles: 369)
-- |  mstask [516] (parent: 212, priority: 8, threads: 6, handles: 89)
-- |  VMwareService.e [572] (parent: 212, priority: 13, threads: 4, handles: 95)
-- |  winmgmt [648] (parent: 212, priority: 8, threads: 3, handles: 89)
-- |  cmd [700] (parent: 212, priority: 8, threads: 1, handles: 28)
-- |  explorer [720] (parent: 620, priority: 8, threads: 10, handles: 239)
-- |  VMwareUser [748] (parent: 720, priority: 8, threads: 1, handles: 30)
-- |  VMwareTray [764] (parent: 720, priority: 8, threads: 1, handles: 30)
-- |_ regsvc [868] (parent: 212, priority: 8, threads: 4, handles: 76)
-----------------------------------------------------------------------

author = "Ron Bowes"
copyright = "Ron Bowes"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"discovery","intrusive"}

require "bin"
require 'msrpc'
require 'msrpcperformance'
require 'smb'
require 'stdnse'

-- Strings used to separate processes from one another.
local separators = {
	first	= "-+-";
	last	= " `-";
	middle	= " +-";
	only 	= "---";
}

function psl_add (psl, ps)
	-- Add process.
	psl[ps.pid] = ps

	-- Add dummy parent if no real one exists.
	if psl[ps.ppid] == nil then
		psl[ps.ppid] = {
			name	= 'Unknown';
			pid	= ps.ppid;
			ppid	= ps.ppid;
		}
	end
end

function psl_mode (list, i)
	local mode

	-- Decide connector for process.
	if table.maxn(list) == 1 then
		mode = "only"
	elseif i == 1 then
		mode = "first"
	elseif i == table.maxn(list) then
		mode = "last"
	else
		mode = "middle"
	end

	return mode
end

function psl_print (psl)
	local result = ""

	-- Find how many root processes there are.
	local roots = {}
	for i,ps in pairs(psl) do
		if psl[ps.ppid] == nil or ps.ppid == ps.pid then
			table.insert(roots, i)
		end
	end
	table.sort(roots)

	-- Create vertical sibling link.
	local bars = {}
	if table.maxn(roots) ~= 1 then
		table.insert(bars, 2)
	end

	-- Print out each root of the tree.
	for i,root in ipairs(roots) do
		local mode = psl_mode(roots, i)
		result = result .. psl_tree(psl, root, 0, bars, mode)
	end

	return result
end

function psl_tree (psl, pid, column, bars, mode)
	local ps = psl[pid]

	-- Delete vertical sibling link.
	if mode == 'last' then
		table.remove(bars)
	end

	-- Print lead-in.
	local prefix = ''
	if mode == 'middle' or mode == 'last' then
		prefix = '\n'

		local i = 1
		for j = 1, column do
			if table.maxn(bars) >= i and
				bars[i] == j then
				prefix = prefix .. '|'
				i = i + 1
			else
				prefix = prefix .. ' '
			end
		end
	end

	-- Format process itself.
	output = separators[mode] .. ps.name .. '(' .. ps.pid .. ')'
	column = column + #output
	local result = prefix .. output

	-- Find process' children.
	local children = {}
	for child_pid,child in pairs(psl) do
		if child_pid ~= pid and child.ppid == pid then
			table.insert(children, child_pid)
		end
	end
	table.sort(children)

	-- Create vertical sibling link between children.
	if table.maxn(children) > 1 then
		table.insert(bars, column + 2)
	end

	-- Format process' children.
	for i,pid in ipairs(children) do
		local mode = psl_mode(children, i)
		result = result .. psl_tree(psl, pid, column, bars, mode)
	end

	return result
end

hostrule = function(host)
	return smb.get_port(host) ~= nil
end

action = function(host)

	local status, result
	local process
	local response = " \n"

	-- Get the process list
	status, result = msrpcperformance.get_performance_data(host, "230")
	if(status == false) then
		if(nmap.debugging() > 0) then
			return "ERROR: " .. result
		else
			return nil
		end
	end

	-- Get the process table
	process = result['Process']

--	for i, v in pairs(result['Processor']['_Total']) do
--		io.write(string.format("i = %s\n", i))
--	end

	-- Put the processes into an array, and sort them by process id
	local names = {}
	for i, v in pairs(process) do
		if(i ~= '_Total') then
			names[#names + 1] = i
		end
	end
	table.sort(names, function (a, b) return process[a]['ID Process'] < process[b]['ID Process'] end)

	-- Put the processes into an array indexed by process id and with a value equal to the name (so we can look it up 
	-- easily when we need to)
	local process_id = {}
	for i, v in pairs(process) do
		process_id[v['ID Process']] = i
	end


	if(nmap.verbosity() == 1) then
		local psl = {}
		for i,name in ipairs(names) do
			if(name ~= '_Total') then
				psl_add(psl, {
					name	= name;
					pid	= process[name]['ID Process'];
					ppid	= process[name]['Creating Process ID'];
				})
			end
		end
		response = ' \n' .. psl_print(psl)
	elseif(nmap.verbosity() > 1) then
		for i = 1, #names, 1 do
			local name = names[i]
			if(name ~= '_Total') then
				local parent = process_id[process[name]['Creating Process ID']]
				if(parent == nil) then
					parent = "n/a"
				end

--				response = response .. string.format("%6d %24s (Parent: %24s, Priority: %4d, Threads: %4d, Handles: %4d)\n", process[name]['ID Process'], name, parent, process[name]['Priority Base'], process[name]['Thread Count'], process[name]['Handle Count'])

				response = response .. string.format("%s [%d] (parent: %s, priority: %s, threads: %s, handles: %s)\n", name, process[name]['ID Process'], process[name]['Creating Process ID'], process[name]['Priority Base'], process[name]['Thread Count'], process[name]['Handle Count'])
			end
			
		end
	else
		response = stdnse.strjoin(", ", names)
	end

	return response
end


