description = [[
Discovers IoT devices in the network along with firmware security risk assessment

The script uses IoTVAS APIs (iotvas-api.firmalyzer.com/v1/docs) to identify manufacturer, model, device CVEs
and firmware security risks of IoT devices in the target IP range. It uses network service banners and 
optional MAC address of each host for device discovery.

This script requires an IoTVAS API key that can be obtained from https://iotvas-api.firmalyzer.com/portal/signup
]]

---
-- @usage
-- nmap -sSU -p U:161,T:- --top-ports 1000 --script iotvas.nse --script-args iotvas.api_key=<API_KEY> -Pn <target>
-- @args iotvas.api_key Provide your IoTVAS API key
-- @args iotvas.disco_only Perform device discovery scan without firmware security assessment
-- @output
--| iotvas:
--|   Detection Results:
--|     Manufacturer: Xerox Corporation
--|     Model: WorkCentre 7225
--|     Device Type: Printer/Scanner/Fax
--|     Firmware Version: 072.030.004.09101
--|     Discontinued: false
--|     Known Vulnerabilities:
--| CVE             CVSS
--| CVE-2016-11061  10.0
--| CVE-2018-20768  7.5
--| CVE-2018-20771  7.5
--| CVE-2018-20770  7.5
--| CVE-2018-20767  6.5
--| CVE-2018-20769  5.0
--| CVE-2020-36201  5.0
--| CVE-2020-9330   4.0
--|
--|     Firmware Info:
--|       version: 072.030.004.09101
--|       download_url: http://download.support.xerox.com/pub/drivers/WC7220_WC7225/firmware/_alloperatingsystems/en_GB/WorkCentre_7200-system-sw07203000409101.zip
--|       sha2: bf39acdf07eab75779fc30e979cf4e14643f49a55015eb8b708fe9c42c3bb2c4
--|       release_date: 2014-06-25
--|       name: WorkCentre 7220/7225 General Release v072.030.004.09101 (ConnectKey 1.5 Software)
--|     Latest Firmware Info:
--|       version: 073.030.075.34540
--|       download_url: http://download.support.xerox.com/pub/drivers/WC7220_WC7225/firmware/android/ar/WorkCentre_7220-25_Manual_Upgrade.zip
--|       sha2: b9804e0cb91f2c4cb030f3ea610434d318acd910f7f398f8696b480d6b653163
--|       release_date: 2016-06-16
--|       name: WorkCentre 7220/7225 Manual Upgrade 073.030.075.34540-Software for 2016 ConnectKey Technology
--|   Firmware Risk Report:
--|     Summary:
--|       client_tools_risk: None
--|       net_services_risk: Medium
--|       kernel_risk: None
--|       crypto_risk: Critical
--|     vulnerable_components:
--|   Name        Category        Version  CVSS_MAX  CVEs
--|   gnutls      Crypto Library  1.4.1    10.0      CVE-2008-1948,CVE-2008-1949,CVE-2009-2730,CVE-2012-1663,CVE-2015-3308,CVE-2017-5334,[...]
--|   cyrus-sasl  Crypto Library  2.1.23   4.3       CVE-2013-4122
--|   vsftpd      FTP Server      2.0.7    4.0       CVE-2011-0762
--|
--|   Default Accounts:
--|   name      pwd_hash                         hash_algorithm  shell       uid  gid  home_dir
--|   bin       x                                N/A                         1    1    /bin
--|   root                                       N/A             /bin/bash   0    0    /
--|   ftp       x                                N/A                         14   50   /
--|   daemon    x                                N/A                         2    2    /sbin
--|   nobody    x                                N/A                         99   99   /
--|   intFTP    $1$BbR.S$t22VMWcrVUOoTPoZwMlza.  1               /bin/false  51   51   /
--|   postgres  *                                N/A             /bin/bash   297  101  /
--|
--|   Private Crypto Keys:
--|   file_name   file_hash                                                         pem_type             algorithm            bits
--|   syncGW.pem  64a1d87467dbdafabe8e83988e56be241a20f24e92e3e04d251502888ff22e77  RSAPrivateKey        RSA                  1024
--|   cakey.pem   80ea9bea8fa63612890564de8d5ad846127c62d07bfd471c93d33c9c33d06735  EncryptedPrivateKey  EncryptedPrivateKey  N/A
--|
--|   Expired Certificates:
--|   file_name    algorithm  subject_name                                                         valid_from            valid_to
--|   cacerts.crt  RSA        C=US,O=Equifax,OU=Equifax Secure Certificate Authority      1998-08-22T16:41:51Z  2018-08-22T16:41:51Z
--|   cacerts.crt  RSA        C=US,O=Entrust.net,OU=www.entrust.net/CPS [...]             1999-05-25T16:09:40Z  2019-05-25T16:39:40Z
--|   [...]
--|
--|   Forgeable Certificates:
--|   file_name    algorithm             subject_name                                                     valid_from            valid_to
--|   cacerts.crt  md5WithRSAEncryption  C=US,O=Equifax Secure Inc.,CN=Equifax Secure eBusiness CA-1    1999-06-21T04:00:00Z  2020-06-21T04:00:00Z
--|   cacerts.crt  md5WithRSAEncryption  C=US,O=GTE Corporation,CN=GTE CyberTrust Root                  1996-02-23T23:01:00Z  2006-02-23T23:59:00Z
--|   cacerts.crt  md2WithRSAEncryption  C=US,O=RSA Data Security, Inc.,OU=Secure[...]                  1994-11-09T00:00:00Z  2010-01-07T23:59:59Z
--|   [...]
--|
--|   Config Issues:
--|   service_name  config_file           problems
--|_  SSH           /etc/ssh/sshd_config  Result: PermitRootLogin is enabled, root can login directly,Result: SSH has no specific user or group limitation. Most likely all valid users can SSH to this machine.

author = "Behrang Fouladi, Firmalyzer BV"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "vuln", "external", "safe"}

local http = require "http"
local json = require "json"
local snmp = require "snmp"
local comm = require "comm"
local stdnse = require "stdnse"
local ftp = require "ftp"
local strbuf = require "strbuf"
local tab = require "tab"
local upnp = require "upnp"

local arg_api_key = stdnse.get_script_args(SCRIPT_NAME .. ".api_key")
local arg_disco_only = stdnse.get_script_args(SCRIPT_NAME .. ".disco_only") or false
local API_HOST = "iotvas-api.firmalyzer.com"


prerule = function()
  if not arg_api_key then
    stdnse.verbose1("Error: Please specify your IoTVAS API key with %s.api_key argument", SCRIPT_NAME)
    return false
  end
  return true
end

hostrule = function(host)
  return (arg_api_key ~= nil)
end

local function remove_null_fields(obj)
  local new_obj = {}
  for key,val in pairs(obj) do
    if val == json.NULL or (type(val) == "table" and next(val) == nil) then 
      goto skip_to_next
    else
      new_obj[key] = val
    end
    ::skip_to_next::
  end
  return new_obj
end

local function set_unknown_fields(output)
  for key,val in pairs(output) do
    if val == json.NULL or (type(val) == "table" and next(val) == nil) then
      output[key] = "Unknown"
    end
  end
end

local function get_http_response(host, port)
  local options = { no_cache = true, bypass_cache = true, redirect_ok=function(host, port)
      local c = 3
      return function(url)
        if (c == 0) then return false end
        c = c - 1
        return true
      end
    end }

  local response = http.get(host, port, "/", options)
  if response.body then
    return response.body
  end
  return ""
end

local function get_https_response(host, port)
  local socket, result = comm.tryssl(host, port,("GET / HTTP/1.1\r\nHost: %s\r\n\r\n"):format(stdnse.get_hostname(host)))
  if socket then
    socket:close()
    return ""
  end
  if type(result) == "string" then
    return result
  else
    return ""
  end
end

local function get_ftp_banner(host, port)
  local socket, code, message, buffer = ftp.connect(host, port)
  if not socket then
    return
  end
  socket:close()
  return message
end

local function get_snmp_oid(host, port, oid)
  local snmpHelper = snmp.Helper:new(host, port)
  snmpHelper:connect()
  local status, response = snmpHelper:get({reqId=35426}, oid)
  if not status then
    return ("")
  end
  return (response and response[1] and response[1][1])
end

local function get_upnp_response(host)
  local port = { number = 1900, protocol = "udp" }
  local helper = upnp.Helper:new( host, port )
  helper:setOverride( true )
  local status, result = helper:queryServices()
  if (status) then
    result["name"] = nil
    return stdnse.format_output(true, result)
  end
end

local function parse_telnet_msg(msg)
  local len = msg:len()
  local opt_type, opt_code, loc
  local out_buf = strbuf.new()
  local got_data = false

  loc = 1
  while loc < (len - 3) do
    if string.byte(msg, loc) == 255 then
      opt_type = string.byte(msg, loc+1)
      opt_code = string.byte(msg, loc+2)
      stdnse.debug("telnet command code received " .. opt_type .. " " .. opt_code)
      if opt_type == 252 and (opt_code == 1 or opt_code == 3) then
        out_buf = out_buf .. string.char(255, 254, opt_code)
      elseif opt_type == 251 and (opt_code == 1 or opt_code == 3) then
        out_buf = out_buf .. string.char(255, 253, opt_code)
      elseif opt_type == 253 then
        out_buf = out_buf .. string.char(255, 252, opt_code)
      else
        stdnse.debug("unhandled telnet command " .. opt_type .. " " .. opt_code)
      end
    else 
      got_data = true
      break
    end
    loc = loc + 3
  end
  return got_data, loc, out_buf
end

local function negotiate_telnet(socket)
  local counter = 0
  local index = 0
  local data = ""
  local status, msg, opt_type, opt_code, data_loc
  local got_data = false

  while true do
    status, msg = socket:receive()
    if not status or msg:len() < 3 then
      stdnse.debug("telnet:no data received")
      break
    end
    got_data, data_loc, out_buf = parse_telnet_msg(msg)
    if got_data then
      data = string.sub(msg, data_loc)
      break
    else
      local reply = strbuf.dump(out_buf)
      if reply:len() > 0 then
        socket:send(reply)
        stdnse.debug("telnet reply size: " .. reply:len())
      end
    end
    counter = counter + 1
    if counter >= 10 then
      break
    end 
  end
  return data
end

local function get_telnet_banner(host, port)
  local socket = nmap.new_socket() 
  socket:set_timeout(2000)
  local st = socket:connect(host, port, 'tcp')
  if not st then
    return
  end
  local data = negotiate_telnet(socket)
  socket:close()
  return data
end

local function detect_device(features)
  local header = { }
  header['x-api-key'] = arg_api_key
  local body = json.generate(features)
  local response = http.post(API_HOST, 443, "/api/v1/device/detect",{any_af=true, header=header}, nil, body)
  if (not response) or response.status ~= 200 then
    return nil
  else
    stdnse.debug(response.body)
    status, detection = json.parse(response.body)
    return detection
  end
end

local function get_firmware_analysis(endpoint)
  local header = { }
  header['x-api-key'] = arg_api_key
  local response = http.get(API_HOST, 443, endpoint, {any_af=true, header=header})
  if (not response) or response.status ~= 200 then
    return nil
  else
    status, risk = json.parse(response.body)
    return risk
  end
end

local function should_call_detection(features)
  local count = 0
  local has_mac = false
  for key,val in pairs(features) do
    if val ~= '' then
      count = count + 1
      if key == 'nic_mac' then has_mac = true end
    end
  end
  return (has_mac and count > 1) or (not has_mac and count > 0)
end


local function format_detection(detection)
  local output = stdnse.output_table()
  output["Manufacturer"] = detection.manufacturer
  output["Model"] = detection.model_name 
  output["Device Type"] = detection.device_type
  output["Firmware Version"] = detection.firmware_version
  output["Discontinued"] = detection.is_discontinued
  if #detection.cve_list > 0 then
    local cve_tbl = tab.new(2)
    tab.addrow(cve_tbl, "CVE", "CVSS")
    for _, v in ipairs(detection.cve_list) do
      tab.addrow(cve_tbl, v.cve_id, v.cvss)
    end
    output["Known Vulnerabilities"] = "\n" .. tab.dump(cve_tbl)
  end
  output["Firmware Info"] = detection.firmware_info
  output["Latest Firmware Info"] = detection.latest_firmware_info
  -- remove keys with json.NULL values
  set_unknown_fields(output)
  return output
end

local function format_firmware_risk(risk)
  local output = stdnse.output_table()
  output["Summary"] = risk.risk_summary
  compo_tbl = tab.new(4)
  tab.addrow(compo_tbl, "Name", "Category", "Version", "CVSS_MAX", "CVEs")
  for _, c in ipairs(risk.vulnerable_components) do
    local cve_list = {}
    for i,vuln in pairs(c.vulnerabilities) do
      table.insert(cve_list, vuln.cve_id)
    end
      tab.addrow(compo_tbl, c.name, c.category, c.version, c.cvss_max, table.concat(cve_list,","))
  end
  output.vulnerable_components = stdnse.format_output(true,{tab.dump(compo_tbl)})
  return output
end

local function format_firmware_accounts(firmware_accounts)
  local tbl = tab.new(7)
  if #firmware_accounts == 0 then return nil end
  tab.addrow(tbl, "name", "pwd_hash", "hash_algorithm", "shell", "uid", "gid" , "home_dir")
  for _, a in ipairs(firmware_accounts) do
    tab.addrow(tbl, a.name, a.pwd_hash, (a.hash_algorithm == json.NULL) 
      and "N/A" or a.hash_algorithm, a.shell, a.uid, a.gid, a.home_dir)
  end
    return stdnse.format_output(true,{tab.dump(tbl)})
end

local function format_firmware_keys(keys)
  local tbl = tab.new(5)
  if #keys == 0 then return nil end
  tab.addrow(tbl, "file_name", "file_hash", "pem_type", "algorithm", "bits")
  for i, k in pairs(keys) do
    tab.addrow(tbl, k.file_name, k.file_hash, k.pem_type, k.algorithm, 
      (k.bits == json.NULL) and "N/A" or k.bits)
  end
  return stdnse.format_output(true,{tab.dump(tbl)})
end

local function format_certs(certs, is_expired)
  local tbl = tab.new(5)
  if #certs == 0 then return nil end
  tab.addrow(tbl, "file_name", "algorithm", "subject_name", "valid_from", "valid_to")
  for i, c in pairs(certs) do
    tab.addrow(tbl, c.file_name, (is_expired == true) and c.public_key.algorithm or c.sign_algorithm, 
      c.subject_name, c.valid_from,c.valid_to)
  end
  return stdnse.format_output(true,{tab.dump(tbl)})
end

local function format_config_issues(issues)
  local tbl = tab.new(4)
  if #issues == 0 then return nil end
  tab.addrow(tbl, "service_name", "config_file", "problems")
  for n, item in pairs(issues) do
    tab.addrow(tbl, item.service_name, item.config_file, table.concat(item.issues,","))
  end
  return stdnse.format_output(true,{tab.dump(tbl)})
end

local function is_http_service(name)
  web_services = {
    'http', 'websocket', 'daap',
    'hnap','ipp','soap', 'vnc-http',
    'xml-rpc', 'webdav', 'ws-discovery',
    'http-proxy-ctrl', 'http-proxy'
  }
  for _, item in ipairs(web_services) do
    if item == name then
      return true
    end
  end
  return false
end

host_action = function(host)
  local features = {
    http_response = "",
    https_response = "",
    ftp_banner = "",
    snmp_sysdescr = "",
    snmp_sysoid = "",
    telnet_banner = "",
    hostname = "",
    nic_mac = "",
    upnp_response = ""
  }
  local response = stdnse.output_table()
  local port = nmap.get_ports(host, nil, "tcp", "open")

  if host.mac_addr then
    features.nic_mac = stdnse.format_mac(host.mac_addr)
  end
  if host.name and not string.find(host.name, ".") then
    features.hostname = host.name
  end

  -- get tcp service banners
  while port do
    if port.service then
      if is_http_service(port.service) then
        features.http_response = get_http_response(host, port)

      elseif port.service == 'ssl/http' or port.service == 'https' then
        features.https_response = get_https_response(host, port)

      elseif port.service == 'ftp' or port.service == 'ftp-proxy' then
        features.ftp_banner = get_ftp_banner(host, port)

      elseif port.service == 'telnet' or port.service == 'telnet-proxy' then
        features.telnet_banner = get_telnet_banner(host, port)
      end

    else
        if port.number == 80 then
          features.http_response = get_http_response(host, port)

        elseif port.number == 443 then
          features.https_response = get_https_response(host, port)
        
        elseif port.number == 21 then
          features.ftp_banner = get_ftp_banner(host, port)

        elseif port.number == 23 then
          features.telnet_banner = get_telnet_banner(host, port)
        end
    end 
    port = nmap.get_ports(host, port, "tcp", "open")
  end

  -- get snmp strings
  local snmp_port = nmap.get_port_state(host, {number = 161, protocol = "udp"})
  if snmp_port ~= nil and (snmp_port.state == "open" or snmp_port.state == "open|filtered") then
    features.snmp_sysdescr = get_snmp_oid(host, snmp_port, "1.3.6.1.2.1.1.1.0")
    local oid = get_snmp_oid(host, snmp_port, "1.3.6.1.2.1.1.2.0")
    if oid ~= "" and oid ~=nil then features.snmp_sysoid = snmp.oid2str(oid) end
  end
  -- get upnp response
  features.upnp_response = get_upnp_response(host)

  if should_call_detection(features) then
    local detection = detect_device(features)
    if detection ~= nil then
      response['Detection Results'] = format_detection(detection)
      local firmware_hash = nil
      local firmware_found = false
      if detection.firmware_info ~= json.NULL and detection.firmware_info.sha2 ~= json.NULL then
        firmware_hash = detection.firmware_info.sha2
        firmware_found = true
      elseif detection.latest_firmware_info ~= json.NULL and detection.latest_firmware_info.sha2 ~= json.NULL then
        firmware_hash = detection.latest_firmware_info.sha2
      end
      if firmware_hash ~= nil and (not arg_disco_only) then
        local path = "/api/v1/firmware/" .. firmware_hash
        local firmware_risk = get_firmware_analysis(path .. "/risk")
        local label = (firmware_found == false) and 'Latest Firmware Risk Report' or 'Firmware Risk Report'
        response[label] = format_firmware_risk(firmware_risk)
        local firmware_accounts = get_firmware_analysis(path .. "/accounts")
        response["Default Accounts"] = format_firmware_accounts(firmware_accounts)
        local private_keys = get_firmware_analysis(path .. "/private-keys")
        response["Private Crypto Keys"] = format_firmware_keys(private_keys)
        local weak_keys = get_firmware_analysis(path .. "/weak-keys")
        response["Weak Crypto Keys"] = format_firmware_keys(weak_keys)
        local expired_certs = get_firmware_analysis(path .. "/expired-certs")
        response["Expired Certificates"] = format_certs(expired_certs, true)
        local weak_certs = get_firmware_analysis(path .. "/weak-certs")
        response["Forgeable Certificates"] = format_certs(weak_certs, false)
        local config_issues = get_firmware_analysis(path .. "/config-issues")
        response["Config Issues"] = format_config_issues(config_issues)
      end
    end
  else
    stdnse.debug("skipping detection for " .. host.ip)
  end
  return response
end


pre_action = function()
  if not arg_api_key then
    stdnse.verbose1("Error: api key not provided")
    return false
  else
    return true
  end
end

local action_table = {
  prerule = pre_action,
  hostrule = host_action,
}
action = function(...) return action_table[SCRIPT_TYPE](...) end

