local dns = require "dns"
local http = require "http"
local ipOps = require "ipOps"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table  = require "table"
local url = require "url"

description = [[
Shows the title of the default page of a web server.

The script will follow no more than one HTTP redirect, and only if the
redirection leads to the same host. The script may send a DNS query to
determine whether the host the redirect leads to has the same IP address as the
original target.
]]

---
--@output
-- Nmap scan report for scanme.nmap.org (74.207.244.221)
-- PORT   STATE SERVICE
-- 80/tcp open  http
-- |_http-title: Go ahead and ScanMe!
--
-- @xmloutput
-- <elem key="title">Go ahead and ScanMe!</elem>
-- @xmloutput
-- <elem key="title">Wikipedia, the free encyclopedia</elem>
-- <elem key="redirect_url">http://en.wikipedia.org/wiki/Main_Page</elem>

author = "Diman Todorov"

license = "Same as Nmap--See http://nmap.org/book/man-legal.html"

categories = {"default", "discovery", "safe"}


portrule = shortport.http

local function getTitle(host, port, path)
  local resp = http.get( host, port, path )
  local redirect_url
  -- check for a redirect
  if resp.location then
    redirect_url = resp.location[#resp.location]
    if resp.status and tostring( resp.status ):match( "30%d" ) then
      return {redirect_url = redirect_url}, ("Did not follow redirect to %s"):format( redirect_url )
    end
  end

  -- try and match title tags
  local title
  if ( resp.body ) then
    title = string.match(resp.body, "<[Tt][Ii][Tt][Ll][Ee][^>]*>([^<]*)</[Tt][Ii][Tt][Ll][Ee]>")
  else
    title = "No reponse received from server"
  end

  local display_title = title
  if display_title and display_title ~= "" then
    display_title = string.gsub(display_title , "[\n\r\t]", "")
    if #display_title > 65 then
      display_title = string.sub(display_title, 1, 62) .. "..."
    end
  else
    display_title = "Site doesn't have a title"
    if ( resp.header and resp.header["content-type"] ) then
      display_title = display_title .. (" (%s)."):format( resp.header["content-type"] )
    else
      display_title = display_title .. "."
    end
  end

  return title, display_title, redirect_url
end

action = function(host, port)
  local path = stdnse.get_script_args(SCRIPT_NAME .. ".path") or "/"
  local str_res, xml_res = {}, stdnse.output_table()
  
  for _, p in ipairs(stdnse.strsplit(",", path)) do
    local title, display_title, redirect_url = getTitle(host, port, p)
    
    local result_part = { ("%s: %s"):format(p, display_title) }
    if redirect_url then
      table.insert(result_part, { ("Requested resource was %s"):format( redirect_url ) })
    end
    table.insert(str_res, result_part)

    xml_res.urls = xml_res.urls or {}
    table.insert(xml_res.urls, { path = p, title = title, redirect_url = redirect_url })
  end

  return xml_res, stdnse.format_output(true, str_res)
end
