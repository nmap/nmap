local http = require "http"
local nmap = require "nmap"
local stdnse = require "stdnse"
local table = require "table"
local shortport = require "shortport"

description = [[
Checks for Apple App Site Association file /.well-known/apple-app-site-association

This file can provide additional URLs, similar to robots.txt

]]

author = "NOPResearcher"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"default", "discovery", "safe"}

---
-- @usage
-- nmap --script http-apple-site-association -p 80,443 <host>
-- 
-- @output
-- 443/tcp  open   https    syn-ack
| http-apple-site-association: 
|   {
|       "applinks": {
|           "apps": [],
|           "details": [
|               {
|                   "appID": "example.app",
|                   "paths": [
|                       "/",

portrule = shortport.http
local last_len = 0


action = function(host, port)
  local path = "/.well-known/apple-app-site-association"
  local options = {header={}}
  options["redirect_ok"] = 3

  local answer = http.get(host, port, path, options)
  local response = {}

  if answer.status ~= 200 then
    return
  end

  if answer.body == 0 then
    return nil
  end
  
  table.insert(response, answer.body)
  return stdnse.format_output(true, response)
end