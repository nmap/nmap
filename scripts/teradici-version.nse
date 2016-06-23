local nmap = require 'nmap'
local shortport = require 'shortport'
local stdnse = require 'stdnse'
local teradici = require 'teradici'

description = [[
Prints basic version information for Teradici PCoIP devices using the management port 50000.
]]

license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"version"}

dependencies = {'ssl-cert'}

portrule = shortport.version_port_or_service(50000)

action = function(host, port)
  local output = teradici.get_property(host, port, 'ProvisionedId')

  if output ~= nil then
    local firmware = output['firmwareVersion']
    local processor = output['pcoipProcessorRev']
    local hardware = output['version']

    if firmware ~= nil then
      port.version.name = "pcoipmgmt"
      port.version.name_confidence = 10
      port.version.product = "Teradici PCoIP management interface " .. firmware
      port.version.service_tunnel = "ssl"

      if processor ~= nil and hardware ~= nil then
        port.version.extrainfo = "processor '" .. processor .. "' hardware '" .. hardware .. "'"
      elseif processor ~= nil then
        port.version.extrainfo = "processor '" .. processor .. "'"
      elseif hardware ~= nil then
        port.version.extrainfo = "hardware '" .. hardware .. "'"
      end

      nmap.set_port_version(host, port)
    end
  end

end

