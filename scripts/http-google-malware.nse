local http = require "http"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"

description = [[
Checks if hosts are on Google's blacklist of suspected malware and phishing servers. These lists are constantly updated and are part of Google's Safe Browsing service.

To do this the script queries the Google's Safe Browsing service and you need to have your own API key to access Google's Safe Browsing Lookup services. Sign up for yours at http://code.google.com/apis/safebrowsing/key_signup.html

* To learn more about Google's Safe Browsing:
http://code.google.com/apis/safebrowsing/

* To register and get your personal API key: 
http://code.google.com/apis/safebrowsing/key_signup.html
]]

---
-- @usage
-- nmap -p80 --script http-google-malware <host>
--
-- @output
-- PORT   STATE SERVICE
-- 80/tcp open  http
-- |_http-google-malware.nse: Host is known for distributing malware.
--
-- @args http-google-malware.url URL to check. Default: <code>http/https</code>://<code>host</code> 
-- @args http-google-malware.api API key for Google's Safe Browsing Lookup service
---

author = "Paulino Calderon"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"malware", "discovery", "safe", "external"}


portrule = shortport.http

---#########################
--ENTER YOUR API KEY HERE  #
---#########################
local APIKEY = ""
---#########################

--Builds Google Safe Browsing query
--@param apikey Api key 
--@return Url 
local function build_qry(apikey, url)
  return string.format("https://sb-ssl.google.com/safebrowsing/api/lookup?client=%s&apikey=%s&appver=1.5.2&pver=3.0&url=%s", SCRIPT_NAME, apikey, url)
end

---
--MAIN
---
action = function(host, port)
  local apikey = stdnse.get_script_args("http-google-malware.api") or APIKEY
  local malware_found = false
  local target
  local output_lns = {}

  --Use the host IP if a hostname isn't available
  if not(host.targetname) then
    target = host.ip
  else
    target = host.targetname
  end

  local target_url = stdnse.get_script_args("http-google-malware.url") or string.format("%s://%s", port.service, target) 

  if string.len(apikey) < 25 then
    return string.format("[ERROR] No API key found. Update the variable APIKEY in %s or set it in the argument %s.api",
                         SCRIPT_NAME, SCRIPT_NAME) 
  end
 
  stdnse.print_debug(1, "%s: Checking host %s", SCRIPT_NAME, target_url) 
  local qry = build_qry(apikey, target_url)
  local req = http.get_url(qry)
  stdnse.print_debug(2, "%s", qry)

	if ( req.status > 400 ) then
		return "[ERROR] Request failed (invalid API key?)"
	end

  --The Safe Lookup API responds with a type when site is on the lists 
  if req.body then
    if http.response_contains(req, "malware") then
      output_lns[#output_lns+1] = "Host is known for distributing malware."
      malware_found = true
    end
    if http.response_contains(req, "phishing") then
      output_lns[#output_lns+1] = "Host is known for being used in phishing attacks."
      malware_found = true
    end
  end
  --For the verbose lovers
  if req.status == 204 and nmap.verbosity() >= 2 and not(malware_found) then
    output_lns[#output_lns+1] = "Host is safe to browse."
  end

  if #output_lns > 0 then
    return stdnse.strjoin("\n", output_lns)
  end
end
