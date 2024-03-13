local shortport = require "shortport"
local stdnse = require "stdnse"
local math = require "math"
local nmap = require "nmap"
local os = require "os"
local string = require "string"
local sslcert = require "sslcert"
local tls = require "tls"
local datetime = require "datetime"

description = [[
Retrieves a target host's time and date from its TLS ServerHello response.


In many TLS implementations, the first four bytes of server randomness
are a Unix timestamp. The script will test whether this is indeed true
and report the time only if it passes this test.

Original idea by Jacob Appelbaum and his TeaTime and tlsdate tools:
* https://github.com/ioerror/TeaTime
* https://github.com/ioerror/tlsdate
]]

---
-- @usage
-- nmap <target> --script=ssl-date
--
-- @output
-- PORT    STATE SERVICE REASON
-- 5222/tcp open  xmpp-client syn-ack
-- |_ssl-date: 2012-08-02T18:29:31Z; +4s from local time.
--
-- @xmloutput
-- <elem key="date">2012-08-02T18:29:31+00:00</elem>
-- <elem key="delta">4</elem>

author = {"Aleksandar Nikolic", "nnposter"}
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe", "default"}
dependencies = {"https-redirect"}

portrule = function(host, port)
  return shortport.ssl(host, port) or sslcert.getPrepareTLSWithoutReconnect(port)
end

-- Miscellaneous script-wide constants
local conn_timeout = 5         -- connection timeout (seconds)
local max_clock_skew = 90*60   -- maximum acceptable difference between target
                               --   and scanner clocks to avoid additional
                               --   testing (seconds)
local max_clock_jitter = 5     -- maximum acceptable target clock jitter
                               --   Logically should be 50-100% of conn_timeout
                               --   (seconds)
local detail_debug = 2         -- debug level for printing detailed steps


--- Function that sends a client hello packet
-- target host and returns the response
--@args host The target host table.
--@args port The target port table.
--@return status true if response, false else.
--@return response if status is true.
local client_hello = function(host, port)
  local sock, status, response, err, cli_h

  -- Craft Client Hello
  cli_h = tls.client_hello()

  -- Connect to the target server
  local specialized_function = sslcert.getPrepareTLSWithoutReconnect(port)

  if not specialized_function then
    sock = nmap.new_socket()
    sock:set_timeout(1000 * conn_timeout)
    status, err = sock:connect(host, port)
    if not status then
      sock:close()
      stdnse.debug("Can't connect: %s", err)
      return false
    end
  else
    status,sock = specialized_function(host,port)
    if not status then
      return false
    end
  end


  repeat -- only once
    -- Send Client Hello to the target server
    status, err = sock:send(cli_h)
    if not status then
      stdnse.debug("Couldn't send: %s", err)
      break
    end

    -- Read response
    status, response, err = tls.record_buffer(sock)
    if not status then
      stdnse.debug("Couldn't receive: %s", err)
      break
    end
  until true

  sock:close()
  return status, response
end

-- extract time from ServerHello response
local extract_time = function(response)
  local i, record = tls.record_read(response, 1)
  if record == nil then
    stdnse.debug("Unknown response from server")
    return nil
  end

  if record.type == "handshake" then
    for _, body in ipairs(record.body) do
      if body.type == "server_hello" then
        return true, body.time
      end
    end
  end
  stdnse.debug("Server response was not server_hello")
  return nil
end


---
-- Retrieve a timestamp from a TLS port and compare it to the scanner clock
--
-- @param host TLS host
-- @param port TLS port
-- @return Timestamp sample object or nil (if the operation failed)
local get_time_sample = function (host, port)
  -- Send crafted client hello
  local rstatus, response = client_hello(host, port)
  local stm = os.time()
  if not (rstatus and response) then return nil end
  -- extract time from response
  local tstatus, ttm = extract_time(response)
  if not tstatus then return nil end
  stdnse.debug(detail_debug, "TLS sample: %s", datetime.format_timestamp(ttm, 0))
  return {target=ttm, scanner=stm, delta=os.difftime(ttm, stm)}
end


local result = { STAGNANT = "stagnant",
                 ACCEPTED = "accepted",
                 REJECTED = "rejected" }

---
-- Obtain a new timestamp sample and validate it against a reference sample
--
-- @param host TLS host
-- @param port TLS port
-- @param reftm Reference timestamp sample
-- @return Result code
-- @return New timestamp sample object or nil (if the operation failed)
local test_time_sample = function (host, port, reftm)
  local tm = get_time_sample(host, port)
  if not tm then return nil end
  local tchange = os.difftime(tm.target, reftm.target)
  local schange = os.difftime(tm.scanner, reftm.scanner)
  local status =
           -- clock cannot run backwards or drift rapidly
           (tchange < 0 or math.abs(tchange - schange) > max_clock_jitter)
             and result.REJECTED
           -- the clock did not advance
           or tchange == 0
             and result.STAGNANT
           -- plausible enough
           or result.ACCEPTED
  stdnse.debug(detail_debug, "TLS sample verdict: %s", status)
  return status, tm
end


action = function(host, port)
  local tm = get_time_sample(host, port)
  if not tm then
    return stdnse.format_output(false, "Unable to obtain data from the target")
  end
  if math.abs(tm.delta) > max_clock_skew then
    -- The target clock differs substantially from the scanner
    -- Let's take another sample to eliminate cases where the TLS field
    -- contains either random or fixed data instead of the timestamp
    local reftm = tm
    local status
    status, tm = test_time_sample(host, port, reftm)
    if status and status == result.STAGNANT then
      -- The target clock did not advance between the two samples (reftm, tm)
      -- Let's wait long enough for the target clock to advance
      -- and then re-take the second sample
      stdnse.sleep(1.1)
      status, tm = test_time_sample(host, port, reftm)
    end
    if not status then
      return nil
    end
    if status ~= result.ACCEPTED then
      return {}, "TLS randomness does not represent time"
    end
  end

  datetime.record_skew(host, tm.target, tm.scanner)
  local output = {
                 date = datetime.format_timestamp(tm.target, 0),
                 delta = tm.delta,
                 }
  return output,
         string.format("%s; %s from scanner time.", output.date,
                 datetime.format_difftime(os.date("!*t", tm.target),
                                        os.date("!*t", tm.scanner)))
end
