local http = require "http"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"

description = [[
Find website backend behind reverse proxy like Cloudflare.

You need to set HTTP Host and html title of website that you looking for. 
Unicode title is working too.
Script looking at both HTTP and HTTPS servers.
]]

---
-- @usage
-- nmap --script=http-find-host.nse --script-args 'http-find-host.vhost=scanme.nmap.org,http-find-host.title="Go ahead and ScanMe"' <target>
-- @args http-find-host.vhost HTTP Host header
-- @args http-find-host.title HTML title on page that we looking for
--
-- @output
-- Nmap scan report for scanme.nmap.org (74.207.244.221)
-- PORT   STATE SERVICE
-- 80/tcp open  http
-- |_http-find-host: Title FOUND: Go ahead and ScanMe!
--


author = "Pavel Zhovner"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "intrusive"}

portrule = shortport.port_or_service( {80, 443}, {"http", "https"}, "tcp", "open")

local arg_vhost    = stdnse.get_script_args('http-find-host.vhost')
local wanted_title = stdnse.get_script_args('http-find-host.title')
local debug_output = stdnse.get_script_args('http-find-host.debug')
local arg_path = stdnse.get_script_args('http-find-host.path') or "/"

action = function(host, port)
  local resp, redirect_url, title

  -- TODO: i don't know why, but arg_vhost not passes to Host= if not do this:

  if not wanted_title or not arg_vhost then
    print ("")
    print("#################################")
    print("#################################")
    print("#################################")
    print ("")
    print ("Error: Host and Title needed.")
    print ("Use --script-args 'http-find-host.vhost=www.myhostname.com,http-find-host.title=MyTitle'")
    print ("Also try http-find-host.debug=true to debug unicode title issues")
    print ("")
    print("#################################")
    print("#################################")
    print("#################################")
    print ("")
    -- TODO: abort scanning with error code
    return
  end

  local resp = http.generic_request(host, port, "GET", arg_path, {header={Host=arg_vhost}})


  if ( not(resp.body) ) then
    return
  end

  -- try and match title tags
  title = string.match(resp.body, "<[Tt][Ii][Tt][Ll][Ee][^>]*>([^<]*)</[Tt][Ii][Tt][Ll][Ee]>")

  -- clear title from garbage
  local cleared_title = title

  if cleared_title and cleared_title ~= "" then
    cleared_title = string.gsub(cleared_title , "[\n\r\t]", "")
    if #cleared_title > 200 then
      cleared_title = string.sub(cleared_title, 1, 195) .. "..."
    end
  else
    return
  end

  -- try to find our string in title
  local title_found
  
  title_found = string.find(cleared_title, wanted_title)
  if title_found then
    cleared_title = "Title FOUND: " .. cleared_title
  elseif not debug_output then
    return
  end

  -- build output
  local output_tab = stdnse.output_table()
  output_tab.title = cleared_title

  local output_str = cleared_title

  return output_tab, output_str

end
