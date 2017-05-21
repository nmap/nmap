local nmap = require "nmap"
local string = require "string"

-- NSE x11-access v1.3

description = [[
Checks if you're allowed to connect to the X server.

If the X server is listening on TCP port 6000+n (where n is the display
number), it is possible to check if you're able to get connected to the
remote display by sending a X11 initial connection request.

In reply, the success byte (0x00 or 0x01) will determine if you are in
the <code>xhost +</code> list. In this case, script will display the message:
<code>X server access is granted</code>.
]]

---
-- @output
-- Host script results:
-- |_ x11-access: X server access is granted
--
-- @xmloutput
-- true

author = "vladz"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"default", "safe", "auth"}

portrule = function(host, port)
  return ((port.number >= 6000 and port.number <= 6009)
    or (port.service and string.match(port.service, "^X11")))
  -- If port.version.product is not equal to nil, version
  -- detection "-sV" has already done this X server test.
  and port.version.product == nil
end

action = function(host, port)

  local result, socket, try, catch
  socket = nmap.new_socket()
  catch = function()
    socket:close()
  end

  try = nmap.new_try(catch)
  try(socket:connect(host, port))

  -- Sending the network dump of a x11 connection request (captured
  -- from the XOpenDisplay() function):
  --
  --    0x6c 0x00 0x0b 0x00 0x00 0x00 0x00
  --    0x00 0x00 0x00 0x00 0x00 0x00
  try(socket:send("\108\000\011\000\000\000\000\000\000\000\000\000"))

  -- According to the XOpenDisplay() sources, server answer is
  -- stored in a xConnSetupPrefix structure [1]. The function
  -- returns NULL if it does not succeed, and more precisely: When
  -- the success field of this structure (stored on 1 byte) is not
  -- equal to xTrue [2]. For more information, see the Xlib
  -- programming Manual [3].
  --
  -- [1] xConnSetupPrefix structure is defined in X11/Xproto.h.
  -- [2] xTrue = 0x01 according to X11/Xproto.h.
  -- [3] http://www.sbin.org/doc/Xlib

  result = try(socket:receive_bytes(1))
  socket:close()

  -- Check if first byte received is 0x01 (xTrue: succeed).
  if string.match(result, "^\001") then
    return true, "X server access is granted"
  end
end
