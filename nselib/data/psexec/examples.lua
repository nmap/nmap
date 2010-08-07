---This configuration file contains the examples given in smb-psexec.nse. 

-- Any variable in the 'config' table in smb-psexec.nse can be overriden in the 
-- 'overrides' table. Most of them are not really recommended, such as the host, 
-- key, etc.
overrides = {}
overrides.timeout = 40

modules = {}
local mod

mod = {}
mod.upload           = false
mod.name             = "Membership of 'administrators' from 'net localgroup administrators'"
mod.program          = "net.exe"
mod.args             = "localgroup administrators"
table.insert(modules, mod)

mod = {}
mod.upload           = false
mod.name             = "Example 2: Membership of 'administrators', cleaned"
mod.program          = "net.exe"
mod.args             = "localgroup administrators"
mod.remove           = {"The command completed", "%-%-%-%-%-%-%-%-%-%-%-", "Members", "Alias name", "Comment"}
mod.noblank          = true
table.insert(modules, mod)

mod = {}
mod.upload           = false
mod.name             = "Example 3: IP Address and MAC Address"
mod.program          = "ipconfig.exe"
mod.args             = "/all"
mod.maxtime          = 1
mod.find             = {"IP Address", "Physical Address", "Ethernet adapter"}
mod.replace          = {{"%. ", ""}, {"-", ":"}, {"Physical Address", "MAC Address"}}
table.insert(modules, mod)

mod = {}
mod.upload           = false
mod.name             = "Example 4: Can the host ping our address?"
mod.program          = "ping.exe"
mod.args             = "$lhost"
mod.remove           = {"statistics", "Packet", "Approximate", "Minimum"}
mod.noblank          = true
mod.env              = "SystemRoot=c:\\WINDOWS" 
table.insert(modules, mod)

mod = {}
mod.upload           = false
mod.name             = "Example 5: Can the host ping $host?"
mod.program          = "ping.exe"
mod.args             = "$host"
mod.remove           = {"statistics", "Packet", "Approximate", "Minimum"}
mod.noblank          = true
mod.env              = "SystemRoot=c:\\WINDOWS" 
mod.req_args         = {'host'}
table.insert(modules, mod)

mod = {}
mod.upload           = true
mod.name             = "Example 6: FgDump"
mod.program          = "fgdump.exe"
mod.args             = "-c -l fgdump.log"
mod.url              = "http://www.foofus.net/fizzgig/fgdump/"
mod.tempfiles        = {"fgdump.log"}
mod.outfile          = "127.0.0.1.pwdump"
table.insert(modules, mod)

