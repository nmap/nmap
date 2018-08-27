local datetime = require "datetime"
local http = require "http"
local os = require "os"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local datetime = require "datetime"

description = [[
Gets the date from HTTP-like services. Also prints how much the date
differs from local time. Local time is the time the HTTP request was
sent, so the difference includes at least the duration of one RTT.
]]

---
-- @output
-- 80/tcp open  http
-- |_http-date: Thu, 02 Aug 2012 22:11:03 GMT; 0s from local time.
-- 80/tcp open  http
-- |_http-date: Thu, 02 Aug 2012 22:07:12 GMT; -3m51s from local time.
--
-- @xmloutput
-- <elem key="date">2012-08-02T23:07:12+00:00</elem>
-- <elem key="delta">-231</elem>

author = "David Fifield"

license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

categories = {"discovery", "safe"}


portrule = shortport.http

action = function(host, port)
  local response = http.get(host, port, "/")
  local request_time = os.time()
  if not response.status or not response.header["date"] then
    return
  end

  local response_date = http.parse_date(response.header["date"])
  if not response_date then
    return
  end
  local response_time = datetime.date_to_timestamp(response_date)

  local output_tab = stdnse.output_table()
  output_tab.date = datetime.format_timestamp(response_time, 0)
  output_tab.delta = os.difftime(response_time, request_time)

  datetime.record_skew(host, response_time, request_time)

  local output_str = string.format("%s; %s from local time.",
    response.header["date"], datetime.format_difftime(os.date("!*t", response_time), os.date("!*t", request_time)))

  return output_tab, output_str
end
