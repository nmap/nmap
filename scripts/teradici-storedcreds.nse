local nmap = require 'nmap'
local shortport = require 'shortport'
local stdnse = require 'stdnse'
local teradici = require 'teradici'

description = [[
Prints stored auto-login or kiosk creds on Teradici PCoIP devices.
]]

license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {'auth','intrusive'}

dependencies = {'teradici-version'}

portrule = shortport.service('pcoipmgmt')

action = function(host, port)
  local output = stdnse.output_table()

  local kiosk = teradici.get_property(host, port, 'VdmKioskMode')

  if kiosk ~= nil then
    output['kiosk mode username']=kiosk['vdmKioskModeCustomUsername']
    output['kiosk mode password']=kiosk['vdmKioskModePassword']
  end

  local logon = teradici.get_property(host, port, 'VdmLogon')

  if logon ~= nil then
    output['auto logon domain']=logon['vdmLogonDomainName']
    output['auto logon username']=logon['vdmLogonUsername']
    output['auto logon password']=logon['vdmLogonPassword']
  end

  return output
end

