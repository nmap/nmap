local http = require "http"
local json = require "json"
local stdnse = require "stdnse"
local table = require "table"
_ENV = stdnse.module("mobileme", stdnse.seeall)

---
-- A MobileMe web service client that allows discovering Apple devices
-- using the "find my iPhone" functionality.
--
-- @author Patrik Karlsson <patrik@cqure.net>
--

MobileMe = {

  -- headers used in all requests
  headers = {
    ["Content-Type"] = "application/json; charset=utf-8",
    ["X-Apple-Find-Api-Ver"] = "2.0",
    ["X-Apple-Authscheme"] = "UserIdGuest",
    ["X-Apple-Realm-Support"] = "1.0",
    ["User-Agent"] = "Find iPhone/1.3 MeKit (iPad: iPhone OS/4.2.1)",
    ["X-Client-Name"] = "iPad",
    ["X-Client-UUID"] = "0cf3dc501ff812adb0b202baed4f37274b210853",
    ["Accept-Language"] = "en-us",
    ["Connection"] = "keep-alive"
  },

  -- Creates a MobileMe instance
  -- @param username string containing the Apple ID username
  -- @param password string containing the Apple ID password
  -- @return o new instance of MobileMe
  new = function(self, username, password)
    local o = {
      host = "fmipmobile.icloud.com",
      port = 443,
      username = username,
      password = password
    }
    setmetatable(o, self)
    self.__index = self
    return o
  end,

  -- Sends a message to an iOS device
  -- @param devid string containing the device id to which the message should
  --        be sent
  -- @param subject string containing the message subject
  -- @param message string containing the message body
  -- @param alarm boolean true if alarm should be sounded, false if not
  -- @return status true on success, false on failure
  -- @return err string containing the error message (if status is false)
  sendMessage = function(self, devid, subject, message, alarm)
    local data = '{"clientContext":{"appName":"FindMyiPhone","appVersion":\z
    "1.3","buildVersion":"145","deviceUDID":\z
    "0000000000000000000000000000000000000000","inactiveTime":5911,\z
    "osVersion":"3.2","productType":"iPad1,1","selectedDevice":"%s",\z
    "shouldLocate":false},"device":"%s","serverContext":{\z
    "callbackIntervalInMS":3000,"clientId":\z
    "0000000000000000000000000000000000000000","deviceLoadStatus":"203",\z
    "hasDevices":true,"lastSessionExtensionTime":null,"maxDeviceLoadTime":\z
    60000,"maxLocatingTime":90000,"preferredLanguage":"en","prefsUpdateTime":\z
    1276872996660,"sessionLifespan":900000,"timezone":{"currentOffset":\z
    -25200000,"previousOffset":-28800000,"previousTransition":1268560799999,\z
    "tzCurrentName":"Pacific Daylight Time","tzName":"America/Los_Angeles"},\z
    "validRegion":true},"sound":%s,"subject":"%s","text":"%s"}'
    data = data:format(devid, devid, tostring(alarm), subject, message)

    local url = ("/fmipservice/device/%s/sendMessage"):format(self.username)
    local auth = { username = self.username, password = self.password }

    local response = http.post(self.host, self.port, url, { header = self.headers, auth = auth, timeout = 10000 }, nil, data)

    if ( response.status == 200 ) then
      local status, resp = json.parse(response.body)
      if ( not(status) ) then
        stdnse.debug2("Failed to parse JSON response from server")
        return false, "Failed to parse JSON response from server"
      end

      if ( resp.statusCode ~= "200" ) then
        stdnse.debug2("Failed to send message to server")
        return false, "Failed to send message to server"
      end
    end
    return true
  end,

  -- Updates location information for all devices controlled by the Apple ID
  -- @return status true on success, false on failure
  -- @return json parsed json table or string containing an error message on
  --         failure
  update = function(self)

    local auth = {
      username = self.username,
      password = self.password
    }

    local url = ("/fmipservice/device/%s/initClient"):format(self.username)
    local data= '{"clientContext":{"appName":"FindMyiPhone","appVersion":\z
    "1.3","buildVersion":"145","deviceUDID":\z
    "0000000000000000000000000000000000000000","inactiveTime":2147483647,\z
    "osVersion":"4.2.1","personID":0,"productType":"iPad1,1"}}'

    local retries = 2

    local response
    repeat
      response = http.post(self.host, self.port, url, { header = self.headers, auth = auth }, nil, data)
      if ( response.header["x-apple-mme-host"] ) then
        self.host = response.header["x-apple-mme-host"]
      end

      if ( response.status == 401 ) then
        return false, "Authentication failed"
      elseif ( response.status ~= 200 and response.status ~= 330 ) then
        return false, "An unexpected error occurred"
      end

      retries = retries - 1
    until ( 200 == response.status or 0 == retries)

    if ( response.status ~= 200 ) then
      return false, "Received unexpected response from server"
    end

    local status, parsed_json = json.parse(response.body)

    if ( not(status) or parsed_json.statusCode ~= "200" ) then
      return false, "Failed to parse JSON response from server"
    end

    -- cache the parsed_json.content as devices
    self.devices = parsed_json.content

    return true, parsed_json
  end,

  -- Gets a list of devices
  -- @return devices table containing a list of devices
  getDevices = function(self)
    if ( not(self.devices) ) then
      self:update()
    end
    return self.devices
  end
}


Helper = {


  -- Creates a Helper instance
  -- @param username string containing the Apple ID username
  -- @param password string containing the Apple ID password
  -- @return o new instance of Helper
  new = function(self, username, password)
    local o = {
      mm = MobileMe:new(username, password)
    }
    setmetatable(o, self)
    self.__index = self
    o.mm:update()
    return o
  end,

  -- Gets the geolocation from each device
  --
  -- @return status true on success, false on failure
  -- @return result table containing a table of device locations
  --         the table is indexed based on the name of the device and
  --         contains a location table with the following fields:
  --         * <code>longitude</code> - the GPS longitude
  --         * <code>latitude</code>  - the GPS latitude
  --         * <code>accuracy</code>  - the location accuracy
  --         * <code>timestamp</code> - the time the location was acquired
  --         * <code>postype</code>   - the position type (GPS or WiFi)
  --         * <code>finished</code>  -
  --         or string containing an error message on failure
  getLocation = function(self)
    -- do 3 tries, with a 5 second timeout to allow the location to update
    -- there are two attributes, locationFinished and isLocating that seem
    -- to be good candidates to monitor, but so far, I haven't had any
    -- success with that.
    local tries, timeout = 3, 5
    local result = {}

    repeat
      local status, response = self.mm:update()

      if ( not(status) or not(response) ) then
        return false, "Failed to retrieve response from server"
      end
      for _, device in ipairs(response.content) do
        if ( device.location ) then
          result[device.name] = {
            longitude = device.location.longitude,
            latitude = device.location.latitude,
            accuracy = device.location.horizontalAccuracy,
            timestamp = device.location.timeStamp,
            postype   = device.location.positionType,
            finished = device.location.locationFinished,
          }
        end
      end
      tries = tries - 1
      if ( tries > 0 ) then
        stdnse.sleep(timeout)
      end
    until( tries == 0 )
    return true, result
  end,

  -- Gets a list of names and ids of devices associated with the Apple ID
  -- @return status true on success, false on failure
  -- @return table of devices containing the following fields:
  --         <code>name</code> and <code>id</code>
  getDevices = function(self)
    local devices = {}
    for _, dev in ipairs(self.mm:getDevices()) do
      table.insert(devices, { name = dev.name, id = dev.id })
    end
    return true, devices
  end,

  -- Send a message to an iOS Device
  --
  -- @param devid string containing the device id to which the message should
  --        be sent
  -- @param subject string containing the message subject
  -- @param message string containing the message body
  -- @param alarm boolean true if alarm should be sounded, false if not
  -- @return status true on success, false on failure
  -- @return err string containing the error message (if status is false)
  sendMessage = function(self, ...)
    return self.mm:sendMessage(...)
  end

}

return _ENV;
