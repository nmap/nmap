--- A UPNP library based on code from upnp-info initially written by
-- Thomas Buchanan. The code was factored out from upnp-info and partly
-- re-written by Patrik Karlsson <patrik@cqure.net> in order to support
-- multicast requests.
--
-- The library supports sending UPnP requests and decoding the responses
--
-- The library contains the following classes
-- * <code>Comm</code>
-- ** A class that handles communication with the UPnP service
-- * <code>Helper</code>
-- ** The helper class wraps the <code>Comm</code> class using functions with a more descriptive name.
-- * <code>Util</code>
-- ** The <code>Util</code> class contains a number of static functions mainly used to convert and sort data.
--
-- The following code snippet queries all UPnP services on the network:
-- <code>
--   local helper = upnp.Helper:new()
--   helper:setMulticast(true)
--   return stdnse.format_output(helper:queryServices())
-- </code>
--
-- This next snippet queries a specific host for the same information:
-- <code>
--   local helper = upnp.Helper:new(host, port)
--   return stdnse.format_output(helper:queryServices())
-- </code>
--
--
-- @author Thomas Buchanan
-- @author Patrik Karlsson <patrik@cqure.net>

--
-- Version 0.1
--

local http = require "http"
local ipOps = require "ipOps"
local nmap = require "nmap"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"
local target = require "target"
local slaxml = require "slaxml"
local url = require "url"
local outlib = require "outlib"
_ENV = stdnse.module("upnp", stdnse.seeall)

Util = {

  --- Compare function used for sorting IP-addresses
  --
  -- @param a table containing first item
  -- @param b table containing second item
  -- @return true if a is less than b
  ipCompare = function(a, b)
    return ipOps.compare_ip(a, "lt", b)
  end,

}

local device_elements = {
  deviceType = true,
  serviceType = true,
  friendlyName = true,
  manufacturer = true,
  modelDescription = true,
  modelName = true,
  modelNumber = true,
  UDN = true,
}

Comm = {

  --- Creates a new Comm instance
  --
  -- @param host string containing the host name or ip
  -- @param port number containing the port to connect to
  -- @return o a new instance of Comm
  new = function( self, host, port )
    local o = {}
    setmetatable(o, self)
    self.__index = self
    o.host = host
    o.port = port
    o.mcast = false
    return o
  end,

  --- Connect to the server
  --
  -- @return status true on success, false on failure
  connect = function( self )
    if ( self.mcast ) then
      self.socket = nmap.new_socket("udp")
      self.socket:set_timeout(5000)
    else
      self.socket = nmap.new_socket()
      self.socket:set_timeout(5000)
      local status, err = self.socket:connect(self.host, self.port, "udp" )
      if ( not(status) ) then return false, err end
    end

    return true
  end,

  --- Send the UPNP discovery request to the server
  --
  -- @return status true on success, false on failure
  sendRequest = function( self )

    -- for details about the UPnP message format, see http://upnp.org/resources/documents.asp
    local payload = 'M-SEARCH * HTTP/1.1\r\n\z
    Host:239.255.255.250:1900\r\n\z
    ST:upnp:rootdevice\r\n\z
    Man:"ssdp:discover"\r\n\z
    MX:3\r\n\r\n'

    local status, err

    if ( self.mcast ) then
      status, err = self.socket:sendto( self.host, self.port, payload )
    else
      status, err = self.socket:send( payload )
    end

    if ( not(status) ) then return false, err end

    return true
  end,

  --- Receives one or multiple UPNP responses depending on whether
  -- <code>setBroadcast</code> was enabled or not.
  --
  -- The function returns the
  -- status and a response containing:
  -- * an array (table) of responses if broadcast is used
  -- * a single response if broadcast is not in use
  -- * an error message if status was false
  --
  -- @return status true on success, false on failure
  -- @return result table or string containing results or error message
  --         on failure.
  receiveResponse = function( self )
    local status, response
    local result = {}

    repeat
      status, response = self.socket:receive()
      if ( not(status) and #response == 0 ) then
        return false, response
      elseif( not(status) ) then
        break
      end

      local status = self:decodeResponse( response, result )
      if ( not(status) ) then
        return false, "Failed to decode UPNP response"
      end
    until ( not( self.mcast ) )

    if ( self.mcast ) then
      return true, outlib.sorted_by_key(result, Util.ipCompare)
    end

    if status then
      local i, v = next(result)
      return (not not i), v
    else
      return false, "Received no responses"
    end
  end,

  --- Processes a response from a upnp device
  --
  -- @param response as received over the socket
  -- @return status boolean true on success, false on failure
  -- @return response table or string suitable for output or error message if status is false
  decodeResponse = function( self, response, results )
    local output = stdnse.output_table()
    local key

    -- We should get a response back that has contains one line for the server, and one line for the xml file location
    -- these match any combination of upper and lower case responses
    local usn = string.match(response, "\n[Uu][Ss][Nn]:%s*([Uu][Uu][Ii][Dd]:[%x-]+)")
    if usn then
      key = usn
      output.usn = usn
    end
    local location = string.match(response, "\n[Ll][Oo][Cc][Aa][Tt][Ii][Oo][Nn]:%s*(.-)\r?\n")
    if location then
      local loc_url = url.parse(location)
      if loc_url.host then
        key = loc_url.host
        if target.ALLOW_NEW_TARGETS then target.add(loc_url.host) end
      end
      output.location = location
    end

    if key and results[key] then
      return false, "Already recorded a response for this host"
    end

    local server = string.match(response, "\n[Ss][Ee][Rr][Vv][Ee][Rr]:%s*(.-)\r?\n")
    if server ~= nil then output.server = server end

    if location and nmap.verbosity() > 0 then
      -- the following check can output quite a lot of information, so we require at least one -v flag
      local status, result = self:retrieveXML( location )
      if status then
        if result.webserver ~= output.server then
          output.webserver = result.webserver
        end
        result.webserver = nil
        if usn and result[usn] then
          for k, v in pairs(result[usn]) do
            output[k] = v
          end
          result[usn] = nil
        end
        if #result > 0 then
          output.devices = result
        end
      end
    end

    if #output > 0 then
      results[key] = output
      return true
    else
      return false, "Could not decode response"
    end
  end,

  --- Retrieves the XML file that describes the UPNP device
  --
  -- @param location string containing the location of the XML file from the UPNP response
  -- @return status boolean true on success, false on failure
  -- @return response table or string suitable for output or error message if status is false
  retrieveXML = function( self, location )
    local response
    local options = {}
    options['header'] = {}
    options['header']['Accept'] = "text/xml, application/xml, text/html"

    -- if we're in multicast mode, or if the user doesn't want us to override the IP address,
    -- just use the HTTP library to grab the XML file
    if ( self.mcast or ( not self.override ) ) then
      response = http.get_url( location, options )
    else
      -- otherwise, split the location into an IP address, port, and path name for the xml file
      local loc_url = url.parse(location)
      options.scheme = loc_url.scheme
      local xhost = loc_url.host
      local xport = loc_url.port or url.get_default_port(loc_url.scheme) or 80
      local xfile = loc_url.path
      if loc_url.query then
        xfile = xfile .. "?" .. loc_url.query
      end

      -- check to see if the IP address returned matches the IP address we scanned
      if not ipOps.compare_ip(xhost, "eq", self.host.ip) then
        stdnse.debug1("IP addresses did not match! Found %s, using %s instead.", xhost, self.host.ip)
        xhost = self.host.ip
      end

      if xhost and xport and xfile then
        response = http.get( xhost, xport, xfile, options )
      end
    end

    if response.body then
      local output = stdnse.output_table()

      -- extract information about the webserver that is handling responses for the UPnP system
      local webserver = response['header']['server']
      if webserver then output.webserver = webserver end

      -- the schema for UPnP includes a number of <device> entries, which can a number of interesting fields
      local element
      local devices = {}
      local depth = 0
      local parser = slaxml.parser:new({
          startElement = function(name)
            if name == "device" then
              depth = depth + 1
              devices[depth] = stdnse.output_table()
            elseif devices[depth] and device_elements[name] then
              assert(not element, "nested element unexpected")
              element = name
            end
          end,
          closeElement = function(name)
            if element then
              assert(name == element, "close tag unexpected")
              element = nil
            elseif name == "device" then
              local dev = devices[depth]
              assert(dev and dev.UDN, "missing device or UDN")
              output[dev.UDN] = dev
              dev.UDN = nil
              devices[depth] = nil
              depth = depth - 1
            end
          end,
          text = function(content)
            if element then
              local dev = devices[depth]
              if element == "serviceType" then
                local services = dev.services or {}
                services[#services+1] = content
                dev.services = services
              else
                dev[element] = content
              end
            end
          end,
        })
      parser:parseSAX(response.body, {stripWhitespace=true})
      return true, output
    else
      return false, "Could not retrieve XML file"
    end
  end,

  --- Enables or disables multicast support
  --
  -- @param mcast boolean true if multicast is to be used, false otherwise
  setMulticast = function( self, mcast )
    assert( type(mcast)=="boolean", "mcast has to be either true or false")
    self.mcast = mcast
    local family = nmap.address_family()
    self.host = (family=="inet6" and "FF02::C" or "239.255.255.250")
    self.port = 1900
  end,

  --- Closes the socket
  close = function( self ) self.socket:close() end

}


Helper = {

  --- Creates a new helper instance
  --
  -- @param host string containing the host name or ip
  -- @param port number containing the port to connect to
  -- @return o a new instance of Helper
  new = function( self, host, port )
    local o = {}
    setmetatable(o, self)
    self.__index = self
    o.comm = Comm:new( host, port )
    return o
  end,

  --- Enables or disables multicast support
  --
  -- @param mcast boolean true if multicast is to be used, false otherwise
  setMulticast = function( self, mcast ) self.comm:setMulticast(mcast) end,

  --- Enables or disables whether the script will override the IP address is the Location URL
  --
  -- @param override boolean true if override is to be enabled, false otherwise
  setOverride = function( self, override )
    assert( type(override)=="boolean", "override has to be either true or false")
    self.comm.override = override
  end,

  --- Sends a UPnP queries and collects a single or multiple responses
  --
  -- @return status true on success, false on failure
  -- @return result table or string containing results or error message
  --         on failure.
  queryServices = function( self )
    local status, err = self.comm:connect()
    local response

    if ( not(status) ) then return false, err end

    status, err = self.comm:sendRequest()
    if ( not(status) ) then return false, err end

    status, response = self.comm:receiveResponse()
    self.comm:close()

    return status, response
  end,

}

return _ENV;
