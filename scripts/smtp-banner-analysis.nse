local shortport = require "shortport"
local smtp = require "smtp"

description = [[
Captures and reports the initial greeting banner
returned by an SMTP server.
]]

author = "Aravind M"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

portrule = shortport.port_or_service(
  {25, 465, 587},
  {"smtp", "smtps", "submission"}
)

action = function(host, port)
  local options = {
    timeout = 10000,
    recv_before = true,
    ssl = (port.number == 465)
  }

  local socket, banner = smtp.connect(host, port, options)

  if not socket then
    return "Connection failed: " .. tostring(banner)
  end

  smtp.quit(socket)

  if banner and #banner > 0 then
    banner = banner:gsub("\r", ""):gsub("\n", " ")
    return "SMTP Greeting Banner: " .. banner
  end

  return "Connection established, but no greeting banner was captured."
end
