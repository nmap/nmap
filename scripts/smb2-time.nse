local os = require "os"
local datetime = require "datetime"
local smb = require "smb"
local stdnse = require "stdnse"
local smb2 = require "smb2"

description = [[
Attempts to obtain the current system date and the start date of a SMB2 server.
]]

---
-- @usage nmap -p445 --script smb2-time <target>
--
-- @output
-- Host script results:
-- | smb2-time:
-- |   date: 2017-07-28 03:06:34
-- |_  start_date: 2017-07-20 09:29:49
--
-- @xmloutput
-- <elem key="date">2017-07-28 03:07:57</elem>
-- <elem key="start_date">2017-07-20 09:29:49</elem>
---

author = "Paulino Calderon <calderon()websec.mx>"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe", "default"}

hostrule = function(host)
  return smb.get_port(host) ~= nil
end

action = function(host,port)
  local smbstate, status, overrides
  local output = stdnse.output_table()
  overrides = {}
  status, smbstate = smb.start(host)
  status = smb2.negotiate_v2(smbstate, overrides)

  if status then
    datetime.record_skew(host, smbstate.time, os.time())
    stdnse.debug2("SMB2: Date: %s (%s) Start date:%s (%s)",
                        smbstate['date'], smbstate['time'],
            smbstate['start_date'], smbstate['start_time'])
    output.date = smbstate['date']
    output.start_date = smbstate['start_date']
    return output
  else
    stdnse.debug2("Negotiation failed")
    return "Protocol negotiation failed (SMB2)"
  end
end
