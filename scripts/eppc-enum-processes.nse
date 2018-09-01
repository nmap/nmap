local nmap      = require('nmap')
local shortport = require('shortport')
local stdnse    = require('stdnse')
local string    = require('string')
local tab       = require('tab')

description = [[
Attempts to enumerate process info over the Apple Remote Event protocol.
When accessing an application over the Apple Remote Event protocol the
service responds with the uid and pid of the application, if it is running,
prior to requesting authentication.
]]

---
-- @usage
-- nmap -p 3031 <ip> --script eppc-enum-processes
--
-- @output
-- PORT     STATE SERVICE
-- 3031/tcp open  eppc
-- | eppc-enum-processes:
-- | application       uid  pid
-- | Address Book      501  269
-- | Facetime          501  495
-- | Finder            501  274
-- | iPhoto            501  267
-- | Photo booth       501  471
-- | Remote Buddy      501  268
-- | Safari            501  270
-- | Terminal          501  266
-- | Transmission      501  265
-- |_VLC media player  501  367
--

author = "Patrik Karlsson"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

portrule = shortport.port_or_service(3031, "eppc", "tcp", "open")

action = function( host, port )

  local socket = nmap.new_socket()
  socket:set_timeout(5000)

  local try = nmap.new_try(
    function()
      stdnse.debug1("failed")
      socket:close()
    end
  )

  -- a list of application that may or may not be running on the target
  local apps = {
    "Address Book",
    "App Store",
    "Facetime",
    "Finder",
    "Firefox",
    "Google Chrome",
    "iChat",
    "iPhoto",
    "Keychain Access",
    "iTunes",
    "Photo booth",
    "QuickTime Player",
    "Remote Buddy",
    "Safari",
    "Spotify",
    "Terminal",
    "TextMate",
    "Transmission",
    "VLC",
    "VLC media player",
  }

  local results = tab.new(3)
  tab.addrow( results, "application", "uid", "pid" )

  for _, app in ipairs(apps) do
    try( socket:connect(host, port, "tcp") )
    local data

    local packets = {
      "PPCT\0\0\0\1\0\0\0\1",
      -- unfortunately I've found no packet specifications, so this has to do
      stdnse.fromhex("e44c50525401e101")
      .. string.pack("Bs1", 225 + #app, app)
      .. stdnse.fromhex("dfdbe302013ddfdfdfdfd500"),
    }

    for _, v in ipairs(packets) do
      try( socket:send(v) )
      data = try( socket:receive() )
    end

    local uid, pid = data:match("uid=(%d+)&pid=(%d+)")
    if ( uid and pid ) then tab.addrow( results, app, uid, pid ) end

    try( socket:close() )
  end

  return "\n" .. tab.dump(results)

end
