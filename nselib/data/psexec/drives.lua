---This configuration file pulls info about a given harddrive

-- Any variable in the 'config' table in smb-psexec.nse can be overriden in the
-- 'overrides' table. Most of them are not really recommended, such as the host,
-- key, etc.
overrides = {}
--overrides.timeout = 40

modules = {}
local mod

mod = {}
mod.upload           = false
mod.name             = "Drive type"
mod.program          = "fsutil"
mod.args             = "fsinfo drivetype $drive"
mod.req_args         = {"drive"}
mod.maxtime          = 1
table.insert(modules, mod)

mod = {}
mod.upload           = false
mod.name             = "Drive info"
mod.program          = "fsutil"
mod.args             = "fsinfo ntfsinfo $drive"
mod.req_args         = {"drive"}
mod.replace          = {{" :",":"}}
mod.maxtime          = 1
table.insert(modules, mod)

mod = {}
mod.upload           = false
mod.name             = "Drive type"
mod.program          = "fsutil"
mod.args             = "fsinfo statistics $drive"
mod.req_args         = {"drive"}
mod.replace          = {{" :",":"}}
mod.maxtime          = 1
table.insert(modules, mod)

mod = {}
mod.upload           = false
mod.name             = "Drive quota"
mod.program          = "fsutil"
mod.args             = "quota query $drive"
mod.req_args         = {"drive"}
mod.maxtime          = 1
table.insert(modules, mod)

