local shortport = require "shortport"
local smtp = require "smtp"
local nmap = require "nmap"

description = [[
Measures response times for selected SMTP commands
to characterize server response behavior.
]]

author = "Aravind M"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

portrule = shortport.port_or_service(
  {25, 587},
  {"smtp", "submission"}
)

action = function(host, port)
  local options = {
    timeout = 10000,
    recv_before = true,
    ssl = false
  }

  local socket, err = smtp.connect(host, port, options)

  if not socket then
    return "Connection failed: " .. tostring(err)
  end

  local status, response = smtp.ehlo(
    socket,
    smtp.get_domain(host)
  )

  if not status then
    return "EHLO failed: " .. tostring(response)
  end

  local results = {}

  for _, command in ipairs({"NOOP", "RSET"}) do
    local start_time = nmap.clock_ms()
    local ok, reply = smtp.query(socket, command)
    local elapsed = nmap.clock_ms() - start_time

    if ok then
      table.insert(results, string.format(
        "%s: %d ms; response: %s",
        command,
        elapsed,
        (reply or ""):gsub("[\r\n]+", " ")
      ))
    else
      table.insert(results, string.format(
        "%s failed: %s",
        command,
        tostring(reply)
      ))
    end
  end

  smtp.quit(socket)

  return table.concat(results, "\n")
end
