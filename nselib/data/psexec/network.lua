---More verbose network scripts

-- Any variable in the 'config' table in smb-psexec.nse can be overriden in the
-- 'overrides' table. Most of them are not really recommended, such as the host,
-- key, etc.
overrides = {}
--overrides.timeout = 40

modules = {}
local mod

-- Grab the ip and mac address(es) from ipconfig. The output requires quite a bit of cleanup
-- to end up being usable and pretty.
mod = {}
mod.upload           = false
mod.name             = "IP Address and MAC Address from 'ipconfig.exe'"
mod.program          = "ipconfig.exe"
mod.args             = "/all"
mod.maxtime          = 1
mod.find             = {"IP Address", "Physical Address", "Ethernet adapter"}
mod.replace          = {{"%. ", ""}, {"-", ":"}, {"Physical Address", "MAC Address"}}
table.insert(modules, mod)

-- Dump the arp cache of the system.
mod = {}
mod.name             = "ARP Cache from arp.exe"
mod.program          = 'arp.exe'
mod.upload           = false
mod.args             = '-a'
mod.remove           = "Interface"
mod.noblank          = true
table.insert(modules, mod)

-- Get the listening/connected ports
mod = {}
mod.upload           = false
mod.name             = "List of listening and established connections (netstat -an)"
mod.program          = "netstat"
mod.args             = "-anb"
mod.maxtime          = 1
mod.remove           = {"Active"}
mod.noblank          = true
mod.env              = "SystemRoot=c:\\WINDOWS"
table.insert(modules, mod)

-- Get the routing table.
--
-- Like 'ver', this has to be run through cmd.exe. This also requires the 'PATH' variable to be
-- set properly, so it isn't going to work against systems with odd paths.
mod = {}
mod.upload           = false
mod.name             = "Full routing table from 'netstat -nr'"
mod.program          = "cmd.exe"
mod.args             = "/c \"netstat -nr\""
mod.env              = "PATH=C:\\WINDOWS\\system32;C:\\WINDOWS;C:\\WINNT;C:\\WINNT\\system32"
mod.maxtime          = 1
mod.noblank          = true
table.insert(modules, mod)

-- Try and ping back to our host. This helps check if there's a firewall in the way for connecting backwards.
-- Interestingly, in my tests against Windows 2003, ping gives weird output (but still, more or less, worked)
-- when the SystemRoot environmental variable wasn't set.
mod = {}
mod.upload           = false
mod.name             = "Can the host ping our address?"
mod.program          = "ping"
mod.args             = "-n 1 $lhost"
mod.maxtime          = 5
mod.remove           = {"statistics", "Packet", "Approximate", "Minimum"}
mod.noblank          = true
mod.env              = "SystemRoot=c:\\WINDOWS"
table.insert(modules, mod)

-- Try a traceroute back to our host. I limited it to the first 5 hops in the interest of saving time.
-- Like ping, if the SystemRoot variable isn't set, the output is a bit strange (but still works)
mod = {}
mod.upload           = false
mod.name             = "Traceroute back to the scanner"
mod.program          = "tracert"
mod.args             = "-d -h 5 $lhost"
mod.maxtime          = 20
mod.remove           = {"Tracing route", "Trace complete"}
mod.noblank          = true
mod.env              = "SystemRoot=c:\\WINDOWS"
table.insert(modules, mod)

-- Ping an arbitrary address given by the user
mod = {}
mod.upload           = false
mod.name             = "Can the host ping $address?"
mod.program          = "ping"
mod.args             = "-n 1 $address"
mod.req_args         = {'address'}
mod.maxtime          = 5
mod.remove           = {"statistics", "Packet", "Approximate", "Minimum"}
mod.noblank          = true
mod.env              = "SystemRoot=c:\\WINDOWS"
table.insert(modules, mod)

-- Try a traceroute to an address given by the user
mod = {}
mod.upload           = false
mod.name             = "Traceroute to $address (5 hops or less)"
mod.program          = "tracert"
mod.args             = "-d -h 5 $address"
mod.req_args         = {'address'}
mod.maxtime          = 20
mod.remove           = {"Tracing route", "Trace complete"}
mod.noblank          = true
mod.env              = "SystemRoot=c:\\WINDOWS"
table.insert(modules, mod)


