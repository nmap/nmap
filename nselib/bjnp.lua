---
-- An implementation of the Canon BJNP protocol used to discover and query
-- Canon network printers and scanner devices.
--
-- The implementation is pretty much based on Wireshark decoded messages
-- the cups-bjnp implementation and the usual guesswork.
--
-- @author Patrik Karlsson <patrik [at] cqure.net>
--

local bin = require("bin")
local nmap = require("nmap")
local os = require("os")
local stdnse = require("stdnse")
local table = require("table")

_ENV = stdnse.module("bjnp", stdnse.seeall)

BJNP = {

  -- The common BJNP header
  Header = {

    new = function(self, o)
      o = o or {}
      o = {
        id = o.id or "BJNP",
        type = o.type or 1,
        code = o.code,
        seq = o.seq or 1,
        session = o.session or 0,
        length = o.length or 0,
      }
      assert(o.code, "code argument required")
      setmetatable(o, self)
      self.__index = self
      return o
    end,

    parse = function(data)
      local hdr = BJNP.Header:new({ code = -1 })
      local pos

      pos, hdr.id, hdr.type, hdr.code,
        hdr.seq, hdr.session, hdr.length = bin.unpack(">A4CCISI", data)
      return hdr
    end,

    __tostring = function(self)
      return bin.pack(">ACCISI",
      self.id,
      self.type,
      self.code,
      self.seq,
      self.session,
      self.length
      )
    end
  },

  -- Scanner related code
  Scanner = {

    Code = {
      DISCOVER = 1,
      IDENTITY = 48,
    },

    Request = {

      Discover = {

        new = function(self)
          local o = { header = BJNP.Header:new( { type = 2, code = BJNP.Scanner.Code.DISCOVER }) }
          setmetatable(o, self)
          self.__index = self
          return o
        end,

        __tostring = function(self)
          return tostring(self.header)
        end,
      },


      Identity = {

        new = function(self)
          local o = { header = BJNP.Header:new( { type = 2, code = BJNP.Scanner.Code.IDENTITY, length = 4 }), data = 0 }
          setmetatable(o, self)
          self.__index = self
          return o
        end,

        __tostring = function(self)
          return tostring(self.header) .. bin.pack(">I", self.data)
        end,
      }

    },

    Response = {

      Identity = {

        new = function(self)
          local o = {}
          setmetatable(o, self)
          self.__index = self
          return o
        end,

        parse = function(data)
          local identity = BJNP.Scanner.Response.Identity:new()
          identity.header = BJNP.Header.parse(data)

          local pos = #tostring(identity.header) + 1
          local pos, len = bin.unpack(">S", data, pos)
          if ( len ) then
            pos, identity.data = bin.unpack("A" .. len - 2, data, pos)
            return identity
          end
        end,


      }

    }

  },

  -- Printer related code
  Printer = {

    Code = {
      DISCOVER = 1,
      IDENTITY = 48,
    },

    Request = {

      Discover = {
        new = function(self)
          local o = { header = BJNP.Header:new( { code = BJNP.Printer.Code.DISCOVER }) }
          setmetatable(o, self)
          self.__index = self
          return o
        end,

        __tostring = function(self)
          return tostring(self.header)
        end,
      },

      Identity = {

        new = function(self)
          local o = { header = BJNP.Header:new( { code = BJNP.Printer.Code.IDENTITY }) }
          setmetatable(o, self)
          self.__index = self
          return o
        end,

        __tostring = function(self)
          return tostring(self.header)
        end,
      }

    },

    Response = {

      Identity = {

        new = function(self)
          local o = {}
          setmetatable(o, self)
          self.__index = self
          return o
        end,

        parse = function(data)
          local identity = BJNP.Printer.Response.Identity:new()
          identity.header = BJNP.Header.parse(data)

          local pos = #tostring(identity.header) + 1
          local pos, len = bin.unpack(">S", data, pos)
          if ( len ) then
            pos, identity.data = bin.unpack("A" .. len - 2, data, pos)
            return identity
          end
        end,


      }

    },

  }

}

-- Helper class, the main script writer interface
Helper = {

  -- Creates a new Helper instance
  -- @param host table
  -- @param port table
  -- @param options table containing one or more of the following fields;
  -- <code>timeout</code> - the timeout in milliseconds for socket communication
  -- <code>bcast</code> - instructs the library that the host is a broadcast
  --                      address
  -- @return o new instance of Helper
  new = function(self, host, port, options)
    local o = {
      host = host, port = port, options = options or {}
    }
    o.options.timeout = o.options.timeout or 5000
    setmetatable(o, self)
    self.__index = self
    return o
  end,

  -- Connects the socket to the device
  -- This should always be called, regardless if the broadcast option is set
  -- or not.
  --
  -- @return status, true on success, false on failure
  -- @return err string containing the error message if status is false
  connect = function(self)
    self.socket = nmap.new_socket(( self.options.bcast and "udp" ))
    self.socket:set_timeout(self.options.timeout)
    if ( not(self.options.bcast) ) then
      return self.socket:connect(self.host, self.port)
    end
    return true
  end,

  -- Discover network devices using either broadcast or unicast
  -- @param packet discovery packet (printer or scanner)
  -- @return status, true on success, false on failure
  -- @return devices table containing discovered devices when status is true
  --         errmsg string containing the error message when status is false
  discoverDevice = function(self, packet)
    if ( not(self.options.bcast) ) then
      if ( not(self.socket:send(tostring(packet))) ) then
        return false, "Failed to send request to server"
      end
    else
      if ( not(self.socket:sendto(self.host, self.port, tostring(packet))) ) then
        return false, "Failed to send request to server"
      end
    end
    -- discover run in loop
    local devices, tmp = {}, {}
    local start = os.time()
    while( true ) do
      local status, data = self.socket:receive()
      if ( not(status) or ( os.time() - start > ( self.options.timeout/1000 - 1 ) )) then
        break
      end
      local status, _, _, rhost = self.socket:get_info()
      tmp[rhost] = true
    end
    for host in pairs(tmp) do table.insert(devices, host) end
    return true, ( self.options.bcast and devices or ( #devices > 0 and devices[1] ))
  end,

  -- Discover BJNP supporting scanners
  discoverScanner = function(self)
    return self:discoverDevice(BJNP.Scanner.Request.Discover:new())
  end,

  -- Discover BJNP supporting printers
  discoverPrinter = function(self)
    return self:discoverDevice(BJNP.Printer.Request.Discover:new())
  end,

  -- Gets a printer identity (additional information)
  -- @param devtype string containing either the string printer or scanner
  -- @return status, true on success, false on failure
  -- @return attribs table containing device attributes when status is true
  --         errmsg string containing the error message when status is false
  getDeviceIdentity = function(self, devtype)
    -- Were currently only decoding this as I don't know what the other cruft is
    local attrib_names = {
      ["scanner"] = {
        { ['MFG'] = "Manufacturer" },
        { ['MDL'] = "Model" },
        { ['DES'] = "Description" },
        { ['CMD'] = "Command" },
      },
      ["printer"] = {
        { ['MFG'] = "Manufacturer" },
        { ['MDL'] = "Model" },
        { ['DES'] = "Description" },
        { ['VER'] = "Firmware version" },
        { ['CMD'] = "Command" },
      }
    }
    local identity
    if ( "printer" == devtype ) then
      identity = BJNP.Printer.Request.Identity:new()
    elseif ( "scanner" == devtype ) then
      identity = BJNP.Scanner.Request.Identity:new()
    end
    assert(not(self.options.bcast), "getIdentity is not supported for broadcast")
    if ( not(self.socket:send(tostring(identity))) ) then
      return false, "Failed to send request to server"
    end
    local status, data = self.socket:receive()
    if ( not(status) ) then
      return false, "Failed to receive response from server"
    end

    local identity
    if ( "printer" == devtype ) then
      identity = BJNP.Printer.Response.Identity.parse(data)
    elseif ( "scanner" == devtype ) then
      identity = BJNP.Scanner.Response.Identity.parse(data)
    end
    if ( not(identity) ) then
      return false, "Failed to parse identity"
    end
    local attrs, kvps = {}, {}

    for k, v in ipairs(stdnse.strsplit(";", identity.data)) do
      local nm, val = v:match("^([^:]*):(.*)$")
      if ( nm ) then kvps[nm] = val end
    end

    for _, attrib in ipairs(attrib_names[devtype]) do
      local short, long = next(attrib)
      if ( kvps[short] ) then
        table.insert(attrs, ("%s: %s"):format(long, kvps[short]))
      end
    end

    return true, attrs
  end,

  -- Retrieves information related to the printer
  getPrinterIdentity = function(self)
    return self:getDeviceIdentity("printer")
  end,

  -- Retrieves information related to the scanner
  getScannerIdentity = function(self)
    return self:getDeviceIdentity("scanner")
  end,

  -- Closes the connection
  -- @return status, true on success, false on failure
  -- @return errmsg string containing the error message when status is false
  close = function(self)
    return self.socket:close()
  end

}

return _ENV;
