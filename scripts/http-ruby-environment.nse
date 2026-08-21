-- The Head Section --
description = [[

Sample script to detect the presence of a Ruby on Rails rack-mini-profiler gem that is used to provide performance metrics 
for Rails applications.  This simple detection script finds the environment variables page and looks for exposed API keys 
and other sensitive data such as credentials at '?pp=env' appended to default host URL.  It is possible that Rails 
developers can expose environment variables through the gem without fully understanding their implications.  

The 'rack-mini-profiler' is a performance gem utilized by Ruby on Rails developers to better understand performance details
of Rails applications.  For more information:
[1] https://github.com/MiniProfiler/rack-mini-profiler
[2] https://www.speedshop.co/2015/08/05/rack-mini-profiler-the-secret-weapon.html
[3] https://stackify.com/rack-mini-profiler-a-complete-guide-on-rails-performance/

A demo project named 'Hammer' that demonstrates a mis-configured Rails app with this vulnerability:
[4] https://github.com/iknowjason/hammer

A gentle introduction to the 'Hammer' project:
[5] https://medium.com/@iknowjason/building-a-vulnerable-rails-application-for-learning-2a1de8cf98d5

]]

---
-- @usage
-- nmap --script http-ruby-environment <target>
-- @output
-- PORT    STATE SERVICE
-- 443/tcp open  https
-- | http-ruby-environment:
-- |   VULNERABLE:
-- |   Detected Rack-mini-profiler Environment Variables
-- |     State: LIKELY VULNERABLE
-- |       Manually investigate for issues
-- |     Extra information:
-- |       URI: https://preprod.rtcfingroup.com/?pp=env
-- |
-- |   Sensitive Data: S3_ACCESS_KEY_ID
-- |     State: VULNERABLE
-- |       String Found: S3_ACCESS_KEY_ID: kDgvmKEFKZsT9CAgJdKy
-- |     Extra information:
-- |       URI: https://preprod.rtcfingroup.com/?pp=env
-- |_


author = "Jason Ostrom"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"default", "safe", "vuln"}

--- Requirements
local shortport = require "shortport"
local http = require "http"
local string = require "string"
local stdnse = require "stdnse"
local vulns = require "vulns"

-- The Rule Section --
portrule = shortport.http

-- The Action Section --
action = function(host, port)

    local report = vulns.Report:new(SCRIPT_NAME, host, port)

    --- helper function to check if data contains sensitive API keys or any credentials
    local function check_sensitive(response_body, key, value, rhost, ruri)

	---print("Checking: "..key)
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
	        extra_info = "URI: https://" .. rhost .. ruri
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

    --- uri variable for rack-mini-profiler Ruby on Rails gem
    local uri = "/?pp=env"

    --- declaring the myhost variable
    local myhost = ""

    --- use hostname or IP address
    if host["targetname"] == nil then
	    myhost = host["ip"]
    else
	    myhost = host["targetname"]
    end

    --- Vuln Definition Table for presence of rack-mini-profiler gem---
    local vuln_table = {
	    title = "Detected Rack-mini-profiler Environment Variables",
	    state = vulns.STATE.NOT_VULN, --default
	    description = "Manually investigate for issues",
	    extra_info = "URI: https://" .. myhost .. uri
    }

    --- get the body response
    local response = http.get(host, port, uri)

    --- if this is True, then the URL exists of https://<HOST>/?pp=env and returns a 200 OK
    if ( response.status == 200) then
	vuln_table.state = vulns.STATE.LIKELY_VULN
        local status, ret = report:add_vulns(vuln_table)

	--- loop through and check for sensitive data in response.body
        for key, value in pairs(sensitive) do
	    retval = check_sensitive(response.body, key, value, myhost, uri)
        end

    else
	vuln_table.state = vulns.STATE.NOT_VULN
    end

    return report:make_output()
end
