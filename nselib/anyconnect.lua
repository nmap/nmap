---
-- This library implements HTTP requests used by the Cisco AnyConnect VPN Client
--
-- @author Patrik Karlsson <patrik@cqure.net>
--
-- @args anyconnect.group AnyConnect tunnel group (default: VPN)
-- @args anyconnect.mac MAC address of connecting client (default: random MAC)
-- @args anyconnect.version Version of connecting client (default: 3.1.05160)
-- @args anyconnect.ua User Agent of connecting client (default: AnyConnect Darwin_i386 3.1.05160)

local http = require('http')
local stdnse = require('stdnse')
local url = require('url')
local math = require('math')
local table = require('table')
local os = require('os')

local args_group= stdnse.get_script_args('anyconnect.group') or "VPN"
local args_mac= stdnse.get_script_args('anyconnect.mac')
local args_ver = stdnse.get_script_args('anyconnect.version') or "3.1.05160"
local args_ua = stdnse.get_script_args('anyconnect.ua') or ("AnyConnect Darwin_i386 %s"):format(args_ver)

_ENV = stdnse.module("anyconnect", stdnse.seeall)

Cisco = {

  Util = {

    generate_mac = function()
      math.randomseed(os.time())
      local mac = {}
      for i=1,6 do
        mac[#mac + 1] = (("%x"):format(math.random(255))):gsub(' ', '0');
      end
      return table.concat(mac,':')
    end,

  },

  AnyConnect = {

    new = function(self, host, port)
      local o = { host = host, port = port }
      setmetatable(o, self)
      self.__index = self
      return o
    end,

    -- generate a random hex-string of length 'length'
    --
    generate_random = function(length)
      return stdnse.generate_random_string(length * 2, '0123456789ABCDEF')
    end,

    connect = function(self)
      args_mac = args_mac or Cisco.Util.generate_mac()
      local headers = {
        ['User-Agent'] = args_ua,
        ['Accept'] = '*/*',
        ['Accept-Encoding'] = 'identity',
        ['X-Transcend-Version'] = 1,
        ['X-Aggregate-Auth'] = 1,
        ['X-AnyConnect-Platform'] = 'mac-intel'
      }

      local data = ([[<?xml version="1.0" encoding="UTF-8"?>
<config-auth client="vpn" type="init" aggregate-auth-version="2">
<version who="vpn">%s</version>
<device-id device-type="MacBookAir4,1" platform-version="10.9.2" unique-id="%s">mac-intel</device-id>
<mac-address-list>
<mac-address>%s</mac-address></mac-address-list>
<group-select>%s</group-select>
<group-access>https://%s:%s</group-access>
</config-auth>]]):format(args_ver, self.generate_random(64), args_mac, args_group, self.host.ip, self.port.number)

      local options = { header=headers , no_cache=true, redirect_ok = function(host,port)
          local c = 5
          return function(url)
            if ( c==0 ) then return false end
            c = c - 1
            return true
          end
        end
      }

      local path = '/'
      local response = http.head(self.host, self.port, path, options)
      -- account for redirects
      if response.status ~= 200 then
        return false, "Failed to connect to SSL VPN server"
      elseif response.location then
        local u = url.parse(response.location[#response.location])
        if u.host then
          self.host = u.host
        end
        if u.path then
          path = u.path
        end
      end

      response = http.post(self.host, self.port, path, options, nil, data)

      if response.status ~= 200 or response.body == nil then
        return false, "Not a Cisco ASA or unsupported version"
      end

      local xmltags = {
        'version',
        'tunnel-group',
        'group-alias',
        'config-hash',
        'host-scan-ticket',
        'host-scan-token',
        'host-scan-base-uri',
        'host-scan-wait-uri',
        'banner'
      }

      self.conn_attr = {}
      for _, tag in ipairs(xmltags) do
        local body = response.body:gsub('\r?\n', '')
        local filter = ("<%s.->(.*)</%s>"):format(tag:gsub('-', '%%-'), tag:gsub('-', '%%-'))
        local m = body:match(filter)
        if m then
          self.conn_attr[tag] = m
        end
      end

      if not self.conn_attr['version'] then
        return false, "Not a Cisco ASA or unsupported version"
      end

      -- in case we were redirected
      self.conn_attr['host'] = stdnse.get_hostname(self.host)
      return true
    end,

    ---
    -- Returns the version of the remote SSL VPN concentrator
    -- @return table containing major, minor and rev numeric values
    get_version = function(self)
      local ver = {}
      ver['major'], ver['minor'], ver['rev'] = self.conn_attr['version']:match('^(%d-)%.(%d-)%((.*)%)$')
      return ver
    end

  }
}

return _ENV
