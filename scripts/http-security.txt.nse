local http = require "http"
local shortport = require "shortport"
local strbuf = require "strbuf"
local table = require "table"

description = [[
Checks for Content in ".well-known/security.txt" on a web server.
]]

---
--@output
-- 80/tcp open  http
-- | http-security.txt: 
-- | # If you would like to report a security issue
-- | # you may report it to us on HackerOne.
-- | Contact: https://hackerone.com/ed
-- | Encryption: https://keybase.pub/edoverflow/pgp_key.asc
-- |_Acknowledgements: https://hackerone.com/ed/thanks

author = "Mario Riederer"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"default", "discovery", "safe"}

portrule = shortport.http

action = function(host, port)
 
  local answer = http.get(host, port, "/.well-known/security.txt" )

  if answer.status ~= 200 then
    return nil
  end

  local output = strbuf.new()
  local contact = strbuf.new()

  outout = output .. "Content:"
  contact = contact .. "Contact-Information:"
 
  for line in answer.body:gmatch("[^\r\n]+") do
      output = output .. (line)
      if string.match(line, "Contact:[^\r\n]+") then
	  contact = contact .. (line)
      end
  end
  
  output = output .. contact

  return  "\n" .. table.concat(output, '\n') 
end
