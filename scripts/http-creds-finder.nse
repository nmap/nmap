local coroutine = require "coroutine"
local http = require "http"
local httpspider = require "httpspider"
local shortport = require "shortport"
local stdnse = require "stdnse"
local table = require "table"
local url = require "url"
local vulns = require "vulns"

description = [[
This script will spider a website and look for any sensitive API Keys or secrets

]]

---
-- @usage
-- nmap --script=http-creds-finder <TARGET> -p443
--
-- @output
-- PORT    STATE SERVICE REASON
---443/tcp open  https   syn-ack ttl 128
---| http-creds-finder:
---|   VULNERABLE:
---|   Sensitive Data: MYSQL_DATABASE_NAME
---|     State: VULNERABLE
---|       String Found: MYSQL_DEVELOPMENT_DATABASE_NAME: rtcdev
---|     Extra information:
---|       URI: https://demo.rtcfingroup.com:443/env.txt
---|
---|   Sensitive Data: SALESFORCE_CLIENT_SECRET
---|     State: VULNERABLE
---|       String Found: SALESFORCE_CLIENT_SECRET: WkpFFDDjTxZ3CagXEihmpe
---|     Extra information:
---|       URI: https://demo.rtcfingroup.com:443/env.txt
---|
--
-- @args http-creds-finder.maxdepth the maximum amount of directories beneath
--       the initial url to spider. A negative value disables the limit.
--       (default: 3)
-- @args http-creds-finder.maxpagecount the maximum amount of pages to visit.
--       A negative value disables the limit (default: 20)
-- @args http-creds-finder.url the url to start spidering. This is a URL
--       relative to the scanned host eg. /default.html (default: /)
-- @args http-creds-finder.withinhost only spider URLs within the same host.
--       (default: true)
-- @args http-creds-finder.withindomain only spider URLs within the same
--       domain. This widens the scope from <code>withinhost</code> and can
--       not be used in combination. (default: false)
--

author = "Jason Ostrom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

portrule = shortport.http

action = function(host, port)

    local report = vulns.Report:new(SCRIPT_NAME, host, port)

    --- helper function to check if data contains sensitive API keys or any credentials
    local function check_sensitive(response_body, key, value, rhost, ruri)

        local retval = ""
	retval = string.match(response_body, value)
	if retval == nil then
	     --- do nothing
	else
	    --- strip off the last '\n'
	    retval = retval:sub(1,-2)
	    ---print("Found: "..retval)

	    local tmp_vuln_table = {
	        title = "Sensitive Data: "..key,
	        state = vulns.STATE.VULN, --default
	        description = "String Found: "..retval,
	        ---extra_info = "URI: https://" .. rhost .. tostring(ruri)
	        extra_info = "URI: https://" .. tostring(ruri)
	    }

            ---Need to add this information to vulnerability table
            local status, ret = report:add_vulns(tmp_vuln_table)
	end

    end

    --- Define table for sensitive API key and data searches
    local sensitive = {}
    sensitive["MONGOID_HOST"] = "MONGOID_%u+_HOST.-\n"
    sensitive["MONGOID_USER"] = "MONGOID_%u+_USER:.-\n"
    sensitive["MONGOID_PASS"] = "MONGOID_%u+_PASS:.-\n"
    sensitive["MYSQL_USER"] = "MYSQL_%u+_USER:.-\n"
    sensitive["MYSQL_PASS"] = "MYSQL_%u+_PASS:.-\n"
    sensitive["MYSQL_DATABASE_NAME"] = "MYSQL_%u+_DATABASE_.-\n"
    sensitive["AWS_ACCESS_KEY_ID"] = "AWS_ACCESS_KEY_ID:.-\n"
    sensitive["S3_ACCESS_KEY_ID"] = "S3_ACCESS_KEY_ID:.-\n"
    sensitive["AWS_SECRET_ACCESS_KEY"] = "AWS_SECRET_ACCESS_KEY:.-\n"
    sensitive["S3_SECRET_ACCESS_KEY"] = "S3_SECRET_ACCESS_KEY:.-\n"
    sensitive["S3_BUCKET"] = "S3_BUCKET:.-\n"
    sensitive["LINKEDIN_APP_ID"] = "LINKEDIN_APP_ID:.-\n"
    sensitive["LINKEDIN_SECRET_KEY"] = "LINKEDIN_SECRET_KEY:.-\n"
    sensitive["FACEBOOK_APP_ID"] = "FACEBOOK_APP_ID:.-\n"
    sensitive["FACEBOOK_SECRET_KEY"] = "FACEBOOK_SECRET_KEY:.-\n"
    sensitive["TWITTER_APP_ID"] = "TWITTER_APP_ID:.-\n"
    sensitive["TWITTER_SECRET_KEY"] = "TWITTER_SECRET_KEY:.-\n"
    sensitive["GOOGLE_APP_ID"] = "GOOGLE_APP_ID:.-\n"
    sensitive["GOOGLE_SECRET_KEY"] = "GOOGLE_SECRET_KEY:.-\n"
    sensitive["GOOGLE_MAPS_API_KEY"] = "GOOGLE_MAPS_API_KEY:.-\n"
    sensitive["SALESFORCE_CLIENT_ID"] = "SALESFORCE_CLIENT_ID:.-\n"
    sensitive["SALESFORCE_CLIENT_SECRET"] = "SALESFORCE_CLIENT_SECRET:.-\n"
    sensitive["SALESFORCE_USERNAME"] = "SALESFORCE_USERNAME:.-\n"
    sensitive["SALESFORCE_PASSWORD_TOKEN"] = "SALESFORCE_PASSWORD_TOKEN:.-\n"
    sensitive["SALESFORCE_HOST"] = "SALESFORCE_HOST:.-\n"
    sensitive["EBAY_AUTH_TOKEN"] = "EBAY_AUTH_TOKEN:.-\n"
    sensitive["EBAY_DEV_ID"] = "EBAY_DEV_ID:.-\n"
    sensitive["EBAY_APP_ID"] = "EBAY_APP_ID:.-\n"
    sensitive["EBAY_CERT_ID"] = "EBAY_CERT_ID:.-\n"

    --- declaring the myhost variable
    local myhost = ""

    --- use hostname or IP address
    if host["targetname"] == nil then
	    myhost = host["ip"]
    else
	    myhost = host["targetname"]
    end

  local crawler = httpspider.Crawler:new(host, port, nil, { scriptname = SCRIPT_NAME } )
  crawler:set_timeout(10000)

  local status_404, result_404, known_404 = http.identify_404(host,port)
  if ( status_404 and result_404 == 200 ) then
    stdnse.debug1("Exiting due to ambiguous response from web server on %s:%s. All URIs return status 200.", host.ip, port.number)
    return nil
  end

  local result

  while(true) do
    local status, r = crawler:crawl()
    if ( not(status) ) then
      if ( r.err ) then
        return stdnse.format_output(false, r.reason)
      else
        break
      end
    end

    myuri = r.url

    for key, value in pairs(sensitive) do
      retval = check_sensitive(r.response.body, key, value, myhost, myuri)
    end

  end

  return report:make_output()

end
