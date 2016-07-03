local http = require "http"
local io = require "io"
local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Uploads a local file to a remote web server using the HTTP PUT method. You must specify the filename and URL path with NSE arguments.
]]

---
-- @usage
-- nmap -p 80 <ip> --script http-put --script-args http-put.url='/uploads/rootme.php',http-put.file='/tmp/rootme.php'
--
-- @output
-- PORT     STATE SERVICE
-- PORT   STATE SERVICE
-- 80/tcp open  http
-- |_http-put: /uploads/rootme.php was successfully created
--
-- @args http-put.file - The full path to the local file that should be uploaded to the server
-- @args http-put.url  - The remote directory and filename to store the file to e.g. (/uploads/file.txt)
--
-- @xmloutput
-- <elem key="result">/uploads/rootme.php was successfully created</elem>
--
-- Version 0.1
-- Created 10/15/2011 - v0.1 - created by Patrik Karlsson <patrik@cqure.net>
-- Revised 10/20/2011 - v0.2 - changed coding style, fixed categories <patrik@cqure.net>
--

author = "Patrik Karlsson"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "intrusive"}


portrule = shortport.http

action = function( host, port )
  local output = stdnse.output_table()
  local fname, url = stdnse.get_script_args('http-put.file', 'http-put.url')
  if ( not(fname) or not(url) ) then
    return
  end

  local f = io.open(fname, "r")
  if ( not(f) ) then
    output.error = ("ERROR: Failed to open file: %s"):format(fname)
    return output, output.error
  end
  local content = f:read("a")
  f:close()

  local response = http.put(host, port, url,  nil, content)
  if ( 200 <= response.status and response.status < 210 ) then
    output.result = ("%s was successfully created"):format(url)
    return output, output.result
  end

  output.error = ("ERROR: %s could not be created"):format(url)
  return output, output.error
end
