local creds = require "creds"
local shortport = require "shortport"
local stdnse = require "stdnse"
local vnc = require "vnc"

description = [[
Tries to log into a VNC server and get its desktop name. Uses credentials
discovered by vnc-brute, or None authentication types. If
<code>realvnc-auth-bypass</code> was run and returned VULNERABLE, this script
will use that vulnerability to bypass authentication.
]]

author = "Daniel Miller"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"intrusive", "discovery"}

---
-- @see vnc-brute.nse
-- @see realvnc-auth-bypass.nse
--
-- @output
-- | vnc-title:
-- |   name: LibVNCServer
-- |   geometry: 800 x 600
-- |_  color_depth: 24
--
-- @xmloutput
-- <elem key="name">QEMU (instance-00000002)</elem>
-- <elem key="geometry">1024 x 768</elem>
-- <elem key="color_depth">24</elem>

dependencies = {"vnc-brute", "realvnc-auth-bypass"}

portrule = shortport.port_or_service( {5900, 5901, 5902} , "vnc", "tcp", "open")

local function fail(err) return stdnse.format_output(false, err) end

action = function(host, port)

  local v = vnc.VNC:new( host, port )
  local status, data
  local result = stdnse.output_table()

  status, data = v:connect()
  if ( not(status) ) then return fail(data) end

  status, data = v:handshake()
  if ( not(status) ) then return fail(data) end

  -- If this doesn't work, start over.
  status = false
  local reg = host.registry["realvnc-auth-bypass"]
  if reg and reg[port.number] then
    stdnse.debug1("Trying RealVNC Auth Bypass")
    -- Force None auth type and try to init to exploit
    v:sendSecType(vnc.VNC.sectypes.NONE)
    status, data = v:login_none()
    if status then
      status, data = v:client_init(true)
      if not status then
        stdnse.debug1("RealVNC Auth Bypass failed.")
      end
    end
    if not status then
      -- clean up and start over
      v:disconnect()
      status, data = v:connect()
      if not status then return fail(data) end
      status, data = v:handshake()
      if not status then return fail(data) end
      -- Be sure to let the regular login stuff have a try
      status = false
    end
  end
  if not status then
    local c = creds.Credentials:new(creds.ALL_DATA, host, port)
    local tried = 0
    for cred in c:getCredentials(creds.State.VALID + creds.State.PARAM) do
      tried = tried + 1
      stdnse.debug1("Trying creds: %s:%s", cred.user, cred.pass)
      status, data = v:login(cred.user, cred.pass)
      if status then
        break
      end
    end
    if tried < 1 then
      --worth trying a None-type login
      stdnse.debug1("Trying empty creds, for None security type")
      status, data = v:login("", "")
    end
    if not status then
      return fail(("Couldn't log in: %s"):format(data))
    end
    status, data = v:client_init(true)
  end
  if status then
    local out = stdnse.output_table()
    out.name = data.name
    out.geometry = ("%d x %d"):format(data.width, data.height)
    out.color_depth = data.depth
    return out
  end

end
