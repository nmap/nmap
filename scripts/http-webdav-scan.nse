local http = require "http"
local ipOps = require "ipOps"
local table = require "table"
local tableaux = require "tableaux"
local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
A script to detect WebDAV installations. Uses the OPTIONS and PROPFIND methods.

The script sends an OPTIONS request which lists the dav type, server type, date
and allowed methods. It then sends a PROPFIND request and tries to fetch exposed
directories and internal ip addresses by doing pattern matching in the response body.

This script takes inspiration from the various scripts listed here:
* http://carnal0wnage.attackresearch.com/2010/05/more-with-metasploit-and-webdav.html
* https://github.com/sussurro/Metasploit-Tools/blob/master/modules/auxiliary/scanner/http/webdav_test.rb
* http://code.google.com/p/davtest/
]]

---
-- @usage
-- nmap --script http-webdav-scan -p80,8080 <target>
--
-- @args http-webdav-scan.path The path to start in; e.g. <code>"/web/"</code>
--                             will try <code>"/web/xxx"</code>.
--
-- @output
-- PORT     STATE SERVICE
-- 8008/tcp open  http
-- | http-webdav-scan:
-- |   Allowed Methods: GET, HEAD, COPY, MOVE, POST, PUT, PROPFIND, PROPPATCH, OPTIONS, MKCOL, DELETE, TRACE, REPORT
-- |   Server Type: DAV/0.9.8 Python/2.7.6
-- |   Server Date: Fri, 22 May 2015 19:28:00 GMT
-- |   WebDAV type: Unknown
-- |   Directory Listing:
-- |     http://localhost
-- |     http://localhost:8008/WebDAVTest_b1tqTWeyRR
-- |     http://localhost:8008/WebDAVTest_A0QWJb7hcK
-- |     http://localhost:8008/WebDAVTest_hf9Mqqpi1M
-- |_    http://localhost:8008/WebDAVTest_Ds5KBFywDq
--
-- @xmloutput
-- <elem key="Allowed Methods">GET, HEAD, COPY, MOVE, POST, PUT,
-- PROPFIND, PROPPATCH, OPTIONS, MKCOL, DELETE, TRACE, REPORT</elem>
-- <elem key="Server Type">DAV/0.9.8 Python/2.7.6</elem>
-- <elem key="Server Date">Fri, 22 May 2015 19:28:00 GMT</elem>
-- <elem key="WebDAV type">Unknown</elem>
-- <table key="Directory Listing">
--   <elem>http://localhost</elem>
--   <elem>http://localhost:8008/WebDAVTest_b1tqTWeyRR</elem>
--   <elem>http://localhost:8008/WebDAVTest_A0QWJb7hcK</elem>
--   <elem>http://localhost:8008/WebDAVTest_hf9Mqqpi1M</elem>
--   <elem>http://localhost:8008/WebDAVTest_Ds5KBFywDq</elem>
-- </table>

author = "Gyanendra Mishra"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {
  "safe",
  "discovery",
  "default",
}


portrule = shortport.http

-- a function to test the OPTIONS method.
local function get_options (host, port, path)
  -- check if WebDAV is installed or not.
  local response = http.generic_request(host, port, "OPTIONS", path)
  if response and response.status == 200 then
    local ret = {}
    ret['Server Type'] = response.header['server']
    ret['Allowed Methods'] = response.header['allow']
    ret['Public Options'] = response.header['public']
    ret['WebDAV'] = false
    ret['Server Date'] = response.header['date']

    if response.header['dav'] and response.header['dav']:find('1') then
      ret['WebDAV'] = true
      ret['WebDAV type'] = 'Unknown'
      if response.header['X-MSDAVEXT'] then
        ret['WebDAV type'] = 'SHAREPOINT DAV'
      end
      if response.header['dav']:match 'apache' then
        ret['WebDAV type'] = 'Apache DAV'
      end
    end
    return ret

  else
    return false
  end
end

-- a function to extract internal ip addresses from PROPFIND response.
local function getIPs(body)
  local ip_pats = {'%f[%d]192%.168%.%d+%.%d+',
                   '%f[%d]10%.%d+%.%d+%.%d+',
                   '%f[%d]172%.1[6-9]%.%d+%.%d+',
                   '%f[%d]172%.2%d%.%d+%.%d+',
                   '%f[%d]172%.3[01]%.%d+%.%d+'}
  local result = {}
  for _, ip_pat in pairs(ip_pats) do
    for ip in body:gmatch(ip_pat) do
      if ipOps.expand_ip(ip) then
        result[ip] = true
      end
    end
  end
  return tableaux.keys(result)
end

-- a function to test the PROPFIND method.
local function check_propfind (host, port, path)
  local options = {
    header = {
      ["Depth"] = 1,
      ["Content-Length"] = 0,
    },
  }
  local response = http.generic_request(host, port, "PROPFIND", path, options)
  if response and response.status ~= 207 then
    return false
  end
  local ret = {}
  ret['WebDAV'] = false
  local dir_pat = '<.-[hH][rR][eE][fF][^>]->(.-)</.-[hH][rR][eE][fF]>'
  if response.body:find '<D:status>HTTP/1.1 200 OK</D:status>' then
    ret['WebDAV'] = true
  end
  ret['Server Type'] = response.header['server']
  ret['Server Date'] = response.header['date']
  local ips = getIPs(response.body)
  if next(ips) then ret['Exposed Internal IPs'] = getIPs(response.body) end
  if response.body:gmatch(dir_pat) then
    ret['Directory Listing'] = {}
    for dir in response.body:gmatch(dir_pat) do
      table.insert(ret['Directory Listing'], dir)
    end
  end
  return ret
end

function action (host, port)

  local path = stdnse.get_script_args(SCRIPT_NAME .. ".path") or '/'
  local enabled = false
  local output = stdnse.output_table()

  local info = get_options(host, port, path)
  if info then
    if info['WebDAV'] then
      enabled = true
      stdnse.debug1("Target has WebDAV enabled.")
      for name, data in pairs(info) do
        if name ~= 'WebDAV' then
          output[name] = data
        end
      end
    else
      stdnse.debug1 "Target isn't reporting WebDAV"
    end
  end

  local davinfo = check_propfind(host, port, path)
  if davinfo then
    if davinfo['WebDAV'] then
      for name, data in pairs(davinfo) do
        if not output[name] and name ~= 'WebDAV' then
          output[name] = data
        end
      end
      if not enabled then
        stdnse.debug1 "Target has WebDAV enabled."
      end
    end
  end

  if #output > 0 then return output else return nil end
end
