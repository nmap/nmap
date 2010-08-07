---This is the configuration file for modules that aren't quite ready for prime
-- time yet. 


-- Any variable in the 'config' table in smb-psexec.nse can be overriden in the 
-- 'overrides' table. Most of them are not really recommended, such as the host, 
-- key, etc.
overrides = {}
--overrides.timeout = 40

modules = {}
local mod


-- I can't get fport to work for me, so I'm going to leave this one in 'experimental' for now
--mod = {}
--mod.upload           = true
--mod.name             = "Fport"
--mod.program          = "Fport.exe"
--mod.url              = "http://www.foundstone.com/us/resources/proddesc/fport.htm"
--mod.maxtime          = 1
--mod.noblank          = true
--table.insert(modules, mod)

