---This config file is designed for running password-dumping scripts. So far, 
-- it supports pwdump6 2.0.0 and fgdump.
--
-- Note that none of these modules are included with Nmap by default. 

-- Any variable in the 'config' table in smb-psexec.nse can be overriden in the
-- 'overrides' table. Most of them are not really recommended, such as the host,
-- key, etc.
overrides = {}
--overrides.timeout = 40

modules = {}
local mod

--mod = {}
--mod.upload           = true
--mod.name             = "PwDump6 2.0.0"
--mod.program          = "PwDump.exe"
--mod.args             = "localhost"
--mod.maxtime          = 10
--mod.include_stderr   = false
--mod.url              = "http://www.foofus.net/fizzgig/pwdump/"
--table.insert(modules, mod)

---Uncomment if you'd like to use PwDump6 1.7.2 (considered obsolete, but still works). 
-- Note that for some reason, this and 'fgdump' don't get along (fgdump only produces a blank
-- file if these are run together)
--mod = {}
--mod.upload           = true
--mod.name             = "PwDump6 1.7.2"
--mod.program          = "PwDump-1.7.2.exe"
--mod.args             = "localhost"
--mod.maxtime          = 10
--mod.include_stderr   = false
--mod.extrafiles       = {"servpw.exe", "lsremora.dll"}
--mod.url              = "http://www.foofus.net/fizzgig/pwdump/"
--table.insert(modules, mod)

-- Warning: the danger of using fgdump is that it always write the output to the harddrive unencrypted; 
-- this makes it more obvious that an attack has occurred. 
mod = {}
mod.upload           = true
mod.name             = "FgDump"
mod.program          = "fgdump.exe"
mod.args             = "-c -l fgdump.log"
mod.maxtime          = 10
mod.url              = "http://www.foofus.net/fizzgig/fgdump/"
mod.tempfiles        = {"fgdump.log"}
mod.outfile          = "127.0.0.1.pwdump"
table.insert(modules, mod)


