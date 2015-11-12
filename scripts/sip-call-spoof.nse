local nmap = require "nmap"
local shortport = require "shortport"
local sip = require "sip"
local stdnse = require "stdnse"

description = [[
Spoofs a call to a SIP phone and detects the action taken by the target (busy, declined, hung up, etc.)

This works by sending a fake sip invite request to the target phone and checking
the responses. A response with status code 180 means that the phone is ringing.
The script waits for the next responses until timeout is reached or a special
response is received.  Special responses include:  Busy (486), Decline (603),
Timeout (408) or Hang up (200).
]]

---
--@args sip-call-spoof.ua Source application's user agent. Defaults to
-- <code>Ekiga</code>.
--
--@args sip-call-spoof.from Caller user ID. Defaults to <code>Home</code>.
--
--@args sip-call-spoof.extension SIP Extension to send request from. Defaults to
-- <code>100</code>.
--
--@args sip-call-spoof.src Source address to spoof.
--
--@args sip-call-spoof.timeout Time to wait for a response. Defaults to
-- <code>5s</code>
--
-- @usage
-- nmap --script=sip-call-spoof -sU -p 5060 <targets>
-- nmap --script=sip-call-spoof -sU -p 5060 --script-args
-- 'sip-call-spoof.ua=Nmap, sip-call-spoof.from=Boss' <targets>
--
--@output
-- 5060/udp open  sip
-- | sip-call-spoof:
-- |_  Target hung up. (After 10.9 seconds)


author = "Hani Benhabiles"

license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

categories = {"discovery", "intrusive"}


portrule = shortport.port_or_service(5060, "sip", {"tcp", "udp"})


--- Function that sends an invite request with given parameters.
-- @arg session SIP Session to use.
-- @arg ua User Agent to use.
-- @arg from SIP From field.
-- @arg src Request source address to spoof.
-- @arg extension Request SIP extension.
-- @return status True if we got a response, false else.
-- @return resp Response table if status is true, error string else.
local sendinvite = function(session, ua, from, src, extension)
  local request = sip.Request:new(sip.Method.INVITE)

  request:setUri("sip:" ..  session.sessdata:getServer())
  request:setUA(ua)
  if src then
    session.sessdata:setDomain(src)
  end
  session.sessdata:setUsername(extension)
  session.sessdata:setName(from)
  request:setSessionData(session.sessdata)

  return session:exch(request)
end

--- Function that waits for certain responses for an amount of time.
-- @arg session SIP Session to use.
-- @arg timeout Max time to wait for responses other than ringing.
-- @return ringing True if we got a ringing response, false else.
-- @return responsecode Code for the latest meaningful response.
--  could be 180, 200, 486, 408 or 603
local waitresponses = function(session,timeout)
  local response, status, data, responsecode, ringing, waittime
  local start = nmap.clock_ms()

  while (nmap.clock_ms() - start) < timeout do
    status, data = session.conn:recv()
    if status then
      response = sip.Response:new(data)
      responsecode = response:getErrorCode()
      waittime = nmap.clock_ms() - start
      if responsecode == sip.Error.RING then
        ringing = true
      elseif responsecode == sip.Error.BUSY then
        return ringing, sip.Error.BUSY
      elseif responsecode == sip.Error.DECLINE then
        return ringing, sip.Error.DECLINE, waittime
      elseif responsecode == sip.Error.OK then
        return ringing, sip.Error.OK, waittime
      elseif responsecode == sip.Error.TIMEOUT then
        return ringing, sip.Error.OK
      end
    end
  end
  if ringing then
    return ringing, sip.Error.RING
  end
end

--- Function that spoofs an invite request and listens for responses.
-- @arg session SIP Session to use.
-- @arg ua User Agent to use.
-- @arg from SIP From field.
-- @arg src Request source address to spoof.
-- @arg extension Request SIP extension.
-- @arg timeout Max time to wait for responses other than ringing.
-- @return ringing True if we got a ringing response, false else.
-- @return responsecode Code for the latest meaningful response.
--  could be 180, 200, 486, 408 or 603
local invitespoof = function(session, ua, from, src, extension, timeout)

  local status, response = sendinvite(session, ua, from, src,  extension)
  -- check if we got a 100 Trying response.
  if status and response:getErrorCode() == 100 then
    -- wait for responses
    return waitresponses(session, timeout)
  end
end

action = function(host, port)
  local status, session

  local ua = stdnse.get_script_args(SCRIPT_NAME .. ".ua") or "Ekiga"
  local from = stdnse.get_script_args(SCRIPT_NAME .. ".from") or "Home"
  local src = stdnse.get_script_args(SCRIPT_NAME .. ".src")
  local extension = stdnse.get_script_args(SCRIPT_NAME .. ".extension") or 100
  local timeout = stdnse.parse_timespec(stdnse.get_script_args(SCRIPT_NAME .. ".timeout"))

  -- Default timeout value = 5 seconds.
  timeout = (timeout or 5) * 1000

  session = sip.Session:new(host, port)
  status = session:connect()
  if not status then
    return stdnse.format_output(false, "Failed to connect to the SIP server.")
  end

  local ringing, result, waittime = invitespoof(session, ua, from, src, extension, timeout)
  -- If we get a response, we set the port to open.
  if result then
    if nmap.get_port_state(host, port) ~= "open" then
      nmap.set_port_state(host, port, "open")
    end
  end

  -- We check for ringing to skip false positives.
  if ringing then
    if result == sip.Error.BUSY then
      return stdnse.format_output(true, "Target line is busy.")
    elseif result == sip.Error.DECLINE then
      return stdnse.format_output(true, ("Target declined the call. (After %.1f seconds)"):format(waittime / 1000))
    elseif result == sip.Error.OK then
      return stdnse.format_output(true, ("Target hung up. (After %.1f seconds)"):format(waittime / 1000))
    elseif result == sip.Error.TIMEOUT then
      return stdnse.format_output(true, "Ringing, no answer.")
    elseif result == sip.Error.RING then
      return stdnse.format_output(true, "Ringing, got no answer. (script timeout)")
    end
  else
    stdnse.debug1("Target phone didn't ring.")
  end
end
