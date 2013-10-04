#!/usr/bin/lua

function print_env(v)
    print(("%s=%s"):format(v, os.getenv(v)))
end

print_env("NCAT_REMOTE_ADDR")
print_env("NCAT_REMOTE_PORT")

print_env("NCAT_LOCAL_ADDR")
print_env("NCAT_LOCAL_PORT")

print_env("NCAT_PROTO")
