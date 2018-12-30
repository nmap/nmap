local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local httpspider = require "httpspider"
local table = require "table"
local httpcookies = require "httpcookies"
local nmap = require "nmap"

description = [[
The script allows users to quickly
check if web applications return any interesting cookie names/values and informs the user
regarding the same.

The cookie name (or value) must be meaningless to prevent information disclosure attacks,
where an attacker is able to decode the contents of the ID and extract details of the user,
the session, or the inner workings of the web application. The script calls the httpspider 
library with docookies argument enabled and it received all the cookies in a cookiejar. It 
then searches the cookiejar received for any interesting values.

]]	

---
-- @usage
-- nmap -p 80 --script http-cookie-alert <target>
--
-- @output
-- PORT   STATE SERVICE REASON
-- 80/tcp open  http    syn-ack
-- | http-cookie-alert: 
-- | The following interesting cookies were found: 
-- |_PHPSESSIONID	!o/BcH3Rvj1iaqD7220J9/DO4/a/fT0IotERS7sHae2NOCOCXAS/oDJPToaKcAy+/LB+Erqc3EQwt
-- 
--
-- @xmloutput
-- <table key="interesting-cookies">
-- <elem>/rest/contactsjp.php</elem>
-- </table>
-- 
-- @args http-cookie-alert.url The URL path to request. The default path is "/".
--- 

local sensitive = {"sessionid", "token", "admin", "session", "uid", "password", "pwd", "user", "guest"}

author = {"Vinamra Bhatia"}
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery"}

portrule = shortport.http

action = function(host, port)
  local path = stdnse.get_script_args(SCRIPT_NAME .. ".url") or "/"
  local output_xml = stdnse.output_table()
  output_xml = {}
  output_xml['interesting-cookies'] = {}
  local output_str = "\nThe following interesting cookies were found: " 

  -- crawl to put the cookies received in various web pages.
  local crawler = httpspider.Crawler:new(host, port, path, {scriptname = SCRIPT_NAME})

  if (not(crawler)) then
    return
  end

  crawler:set_enable_cookies(true)

  crawler:set_timeout(10000)

  while(true) do
    local status, r = crawler:crawl()
    if (not(status)) then
      if (r.err) then
        return stdnse.format_output(false, r.reason)
      else
        break
      end
    end

  end

  --Get sensitive values of cookies here from the cookiejar
  --Now, we have all the cookies received while spidering stored in the cookiejar!
  for index, cookie_table in pairs(crawler.httpcookies.cookies) do
    for _, p in ipairs(sensitive) do
      if string.find(cookie_table.name:lower(),p) or string.find(cookie_table.value:lower(),p) then
        output_str = string.format("%s\n%s\t%s", output_str, cookie_table.name, cookie_table.value)
        table.insert(output_xml['interesting-cookies'], cookie_table.name .. "\t" .. cookie_table.value)
      end
    end
  end

  --A way to print the output
  if next(output_xml['interesting-cookies']) then 
    return output_xml, output_str
  else
    if nmap.verbosity() > 1 then
      return "Couldn't find any interesting cookies"
    end
  end

end

