description = ""
categories = {}

prerule = function() return true end

action = function()
  local s, status, data

  s = nmap.new_socket()
  s:bind("255.255.255.255", 67)
  s:setup("ipv4", "udp")
  status, data = s:receive()

  return data
end
