local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

description = [[
Attempts to retrieve the model, firmware version, and enabled services from a
QNAP Network Attached Storage (NAS) device.
]]

---
-- @usage
-- nmap --script http-qnap-nas-info -p <port> <host>
--
-- @output
-- PORT   STATE SERVICE   REASON
-- 443/tcp open  https   syn-ack
-- | http-qnap-nas-info:
-- |   Device Model: TS-859
-- |   Firmware Version: 3.2.5
-- |   Firmware Build: 0410T
-- |   Force SSL: 0
-- |   SSL Port: 443
-- |   WebFS Enabled: 1
-- |   Multimedia Station Enabled: 0
-- |   Multimedia Station V2 Supported: 1
-- |   Multimedia Station V2 Web Enabled: 0
-- |   Download Station Enabled: 0
-- |   Network Video Recorder Enabled: 0
-- |   Web File Manager Enabled: 1
-- |   Music Station Enabled: 0
-- |   Video Station Enabled: 0
-- |   Photo Station Enabled: 1
-- |   QWeb Server Enabled: 1
-- |   QWeb Server Port: 80
-- |   Qweb Server SSL Enabled: 0
-- |_  Qweb Server SSL Port: 8081
--
-- @changelog
-- 2012-01-29 - created by Brendan Coles - itsecuritysolutions.org
-- 2020-05-19 - added Music, Video, and Photo Station detection - Clément Notin
--

author = "Brendan Coles"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe","discovery"}


portrule = shortport.port_or_service ({443,8080}, "https", "tcp")

action = function(host, port)

  local result = {}
  local path = "/cgi-bin/authLogin.cgi"
  local config_file = ""

  -- Retrieve file
  stdnse.debug1("Connecting to %s:%s", host.targetname or host.ip, port.number)
  local data = http.get(host, port, path)

  -- Check if file exists
  if data and data.status and data.status == 200 and data.body and data.body ~= "" then

    -- Check if the config file is valid
    stdnse.debug1("HTTP %s: %s", data.status, path)
    if string.match(data.body, '<QDocRoot version="[^"]+">') then
      config_file = data.body
    else
      stdnse.debug1("%s:%s uses an invalid config file.", host.targetname or host.ip, port.number)
      return
    end

  else
    stdnse.debug1("Failed to retrieve file: %s", path)
    return
  end

  -- Extract system info from config file
  stdnse.debug1("Extracting system info from %s", path)
  local vars = {

    -- System details --
    --{"Hostname","hostname"},
    {"Device Model", "internalModelName"},
    {"Firmware Version","version"},
    {"Firmware Build","build"},

    -- SSL --
    {"Force SSL","forceSSL"},
    {"SSL Port","stunnelPort"},

    -- Services --
    {"WebFS Enabled","webFSEnabled"},
    {"Multimedia Station Enabled","QMultimediaEnabled"},
    {"Multimedia Station V2 Supported","MSV2Supported"},
    {"Multimedia Station V2 Web Enabled","MSV2WebEnabled"},
    {"Download Station Enabled","QDownloadEnabled"},
    {"Network Video Recorder Enabled","NVREnabled"},
    {"Web File Manager Enabled","WFM2"},
    {"Music Station Enabled","QMusicsEnabled"},
    {"Video Station Enabled","QVideosEnabled"},
    {"Photo Station Enabled","QPhotosEnabled"},
    {"QWeb Server Enabled","QWebEnabled"},
    {"QWeb Server Port","QWebPort"},
    {"Qweb Server SSL Enabled","QWebSSLEnabled"},
    {"Qweb Server SSL Port","QWebSSLPort"},

  }
  for _, var in ipairs(vars) do
    local var_match = string.match(config_file, string.format('<%s><!.CDATA.(.+)..></%s>', var[2], var[2]))
    if var_match then table.insert(result, string.format("%s: %s", var[1], var_match)) end
  end

  -- Return results
  return stdnse.format_output(true, result)

end
