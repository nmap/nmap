#!/usr/bin/lua

--Print the following NCAT_* variables and their values:
envs = {'REMOTE_ADDR', 'REMOTE_PORT', 'LOCAL_ADDR', 'LOCAL_PORT', 'PROTO'}

for _,v in pairs(envs) do
    v = 'NCAT_' .. v
    print(("%s=%s"):format(v, os.getenv(v)))
end
