local coroutine = require "coroutine"
local io = require "io"
local nmap = require "nmap"
local rtsp = require "rtsp"
local shortport = require "shortport"
local stdnse = require "stdnse"
local table = require "table"

description = [[
Attempts to enumerate RTSP media URLS by testing for common paths on devices such as surveillance IP cameras.

The script attempts to discover valid RTSP URLs by sending a DESCRIBE
request for each URL in the dictionary. It then parses the response, based
on which it determines whether the URL is valid or not.

]]

---
-- @usage
-- nmap --script rtsp-url-brute -p 554 <ip>
--
-- @output
-- PORT    STATE SERVICE
-- 554/tcp open  rtsp
-- | rtsp-url-brute:
-- |   discovered:
-- |     rtsp://camera.example.com/mpeg4
-- |   other responses:
-- |     401:
-- |_      rtsp://camera.example.com/live/mpeg4
-- @xmloutput
-- <table key="discovered">
--   <elem>rtsp://camera.example.com/mpeg4</elem>
-- </table>
-- <table key="other responses">
--   <table key="401">
--     <elem>rtsp://camera.example.com/live/mpeg4</elem>
--   </table>
-- </table>
--
-- @args rtsp-url-brute.urlfile sets an alternate URL dictionary file
-- @args rtsp-url-brute.threads sets the maximum number of parallel threads to run

--
-- Version 0.1
-- Created 23/10/2011 - v0.1 - created by Patrik Karlsson <patrik@cqure.net>
--

author = "Patrik Karlsson"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"brute", "intrusive"}


portrule = shortport.port_or_service(554, "rtsp", "tcp", "open")

--- Retrieves the next RTSP relative URL from the datafile
-- @param filename string containing the name of the file to read from
-- @return url string containing the relative RTSP url
urlIterator = function(fd)
  local function getNextUrl ()
    repeat
      local line = fd:read()
      if ( line and not(line:match('^#!comment:')) ) then
        coroutine.yield(line)
      end
    until(not(line))
    fd:close()
    while(true) do coroutine.yield(nil) end
  end
  return coroutine.wrap( getNextUrl )
end

local function fetch_url(host, port, url)
  local helper = rtsp.Helper:new(host, port)
  local status = helper:connect()

  if not status then
    stdnse.debug2("ERROR: Connecting to RTSP server url: %s", url)
    return nil
  end

  local response
  status, response = helper:describe(url)
  if not status then
    stdnse.debug2("ERROR: Sending DESCRIBE request to url: %s", url)
    return nil, response
  end

  helper:close()
  return true, response
end

-- Fetches the next url from the iterator, creates an absolute url and tries
-- to fetch it from the RTSP service.
-- @param host table containing the host table as received by action
-- @param port table containing the port table as received by action
-- @param url_iter function containing the url iterator
-- @param result table containing the urls that were successfully retrieved
local function processURL(host, port, url_iter, result)
  local condvar = nmap.condvar(result)
  local name = stdnse.get_hostname(host)
  for u in url_iter do
    local url = ("rtsp://%s%s"):format(name, u)
    local status, response = fetch_url(host, port, url)
    if not status then
      table.insert(result, { url = url, status = -1 } )
      break
    else
      table.insert(result, { url = url, status = response.status } )
    end
  end
  condvar "signal"
end

action = function(host, port)

  local response
  local result = {}
  local condvar = nmap.condvar(result)
  local threadcount = stdnse.get_script_args('rtsp-url-brute.threads') or 10
  local filename = stdnse.get_script_args('rtsp-url-brute.urlfile') or
    nmap.fetchfile("nselib/data/rtsp-urls.txt")

  threadcount = tonumber(threadcount)

  if ( not(filename) ) then
    return stdnse.format_output(false, "No dictionary could be loaded")
  end

  local f = io.open(filename)
  if ( not(f) ) then
    return stdnse.format_output(false, ("Failed to open dictionary file: %s"):format(filename))
  end

  local url_iter = urlIterator(f)
  if ( not(url_iter) ) then
    return stdnse.format_output(false, ("Could not open the URL dictionary: %s"):format(f))
  end

  -- Try to see what a nonexistent URL looks like
  local status, response = fetch_url(
    host, port, ("rtsp://%s/%s"):format(
      stdnse.get_hostname(host), stdnse.generate_random_string(14))
    )
  local status_404 = 404
  if status then
    local status_404 = response.status
  end

  local threads = {}
  for t=1, threadcount do
    local co = stdnse.new_thread(processURL, host, port, url_iter, result)
    threads[co] = true
  end

  repeat
    for t in pairs(threads) do
      if ( coroutine.status(t) == "dead" ) then threads[t] = nil end
    end
    if ( next(threads) ) then
      condvar "wait"
    end
  until( next(threads) == nil )

  -- urls that could not be retrieved due to low level errors, such as
  -- failure in socket send or receive
  local failure_urls = {}

  -- urls that elicited a 200 OK response
  local success_urls = {}

  -- urls that got some non-404-type response
  local urls_by_code = {}

  for _, r in ipairs(result) do
    if ( r.status == -1 ) then
      table.insert(failure_urls, r.url)
    elseif ( r.status == 200 ) then
      table.insert(success_urls, r.url)
    elseif r.status ~= status_404 then
      local s = tostring(r.status)
      urls_by_code[s] = urls_by_code[s] or {}
      table.insert(urls_by_code[s], r.url)
    end
  end

  local output = stdnse.output_table()
  if next(failure_urls) then
    output.errors = failure_urls
  end
  if next(success_urls) then
    output.discovered = success_urls
  end
  if next(urls_by_code) then
    output["other responses"] = urls_by_code
  end

  if #output > 0 then
    return output
  end
end
