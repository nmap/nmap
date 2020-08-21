description = [[
Attempts to brute force the Application Entity Title of a DICOM server (DICOM Service Provider).

Application Entity Titles (AET) are used to restrict responses only to clients knowing the title. Hence,
 the called AET is used as a form of password.
]]

---
-- @usage nmap -p4242 --script dicom-brute <target>
-- @usage nmap -sV --script dicom-brute <target>
-- @usage nmap --script dicom-brute --script-args passdb=aets.txt <target>
-- 
-- @output
-- PORT     STATE SERVICE        REASON
-- 4242/tcp open  vrml-multi-use syn-ack
-- | dicom-brute: 
-- |   Accounts: 
-- |     Called Application Entity Title:ORTHANC - Valid credentials
-- |_  Statistics: Performed 5 guesses in 1 seconds, average tps: 5.0
---

author = "Paulino Calderon <calderon()calderonpale.com>"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"auth", "brute"}

local shortport = require "shortport"
local dicom = require "dicom"
local stdnse = require "stdnse"
local nmap = require "nmap"
local brute = require "brute"
local creds = require "creds"

portrule = shortport.port_or_service({104, 2345, 2761, 2762, 4242, 11112}, "dicom", "tcp", "open")

Driver = {
  new = function(self, host, port)
  local o = {}
  setmetatable(o, self)
  self.__index = self
  o.host = host
  o.port = port
  o.passonly = true
  return o
  end,

  connect = function(self)
    return true
  end,

  disconnect = function(self)
  end,

  login = function(self, username, password)
    stdnse.debug2("Trying with called AE title:%s", password)
    local dcm_conn, err = dicom.associate(self.host, self.port, nil, password)
    if dcm_conn then
      return true, creds.Account:new("Called Application Entity Title", password, creds.State.VALID)
    else
      return false, brute.Error:new("Incorrect AET")
    end

  end,
  check = function(self)
    local dcm_conn, err = dicom.associate(self.host, self.port)
    if dcm_conn then
      return false, "DICOM SCU allows any AET"
    end
    return true
  end
}

action = function(host, port)
  local engine = brute.Engine:new(Driver, host, port)
  engine:setMaxThreads(5)
  engine.options.script_name = SCRIPT_NAME
  engine.options:setOption("passonly", true)
  local status, result = engine:start()

  return result
end
