local http = require "http"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local table = require "table"

description = [[
Exploits the Max-Forwards HTTP header to detect the presence of reverse proxies.

The script works by sending HTTP requests with values of the Max-Forwards HTTP
header varying from 0 to 2 and checking for any anomalies in certain response
values such as the status code, Server, Content-Type and Content-Length HTTP
headers and body values such as the HTML title.

Based on the work of:
* Nicolas Gregoire (nicolas.gregoire@agarri.fr)
* Julien Cayssol (tools@aqwz.com)

For more information, see:
* http://www.agarri.fr/kom/archives/2011/11/12/traceroute-like_http_scanner/index.html
]]

---
-- @args http-traceroute.path The path to send requests to. Defaults to <code>/</code>.
-- @args http-traceroute.method HTTP request method to use. Defaults to <code>GET</code>.
-- Among other values, TRACE is probably the most interesting.
--
-- @usage
-- nmap --script=http-traceroute <targets>
--
--@output
-- PORT   STATE SERVICE REASON
-- 80/tcp open  http    syn-ack
-- | http-traceroute:
-- |   HTML title
-- |     Hop #1: Twitter / Over capacity
-- |     Hop #2: t.co / Twitter
-- |     Hop #3: t.co / Twitter
-- |   Status Code
-- |     Hop #1: 502
-- |     Hop #2: 200
-- |     Hop #3: 200
-- |   server
-- |     Hop #1: Apache
-- |     Hop #2: hi
-- |     Hop #3: hi
-- |   content-type
-- |     Hop #1: text/html; charset=UTF-8
-- |     Hop #2: text/html; charset=utf-8
-- |     Hop #3: text/html; charset=utf-8
-- |   content-length
-- |     Hop #1: 4833
-- |     Hop #2: 3280
-- |     Hop #3: 3280
-- |   last-modified
-- |     Hop #1: Thu, 05 Apr 2012 00:19:40 GMT
-- |     Hop #2
-- |_    Hop #3

author = "Hani Benhabiles"

license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

categories = {"discovery", "safe"}


portrule = shortport.service("http")

--- Attempts to extract the html title
-- from an HTTP response body.
--@param responsebody Response's body.
local function extract_title (responsebody)
  return responsebody:match "<title>(.-)</title>"
end

--- Attempts to extract the X-Forwarded-For header
-- from an HTTP response body in case of TRACE requests.
--@param responsebody Response's body.
local function extract_xfwd (responsebody)
  return responsebody:match "X-Forwarded-For: [^\r\n]*"
end

---  Check for differences in response headers, status code
-- and html title between responses.
--@param responses Responses to compare.
--@param method Used HTTP method.
local compare_responses = function(responses, method)
  local response, key
  local results = {}
  local result = {}
  local titles = {}
  local interesting_headers = {
      'server',
      'via',
      'x-via',
      'x-forwarded-for',
      'content-type',
      'content-length',
      'last-modified',
      'location',
  }

  -- Check page title
  for key,response in pairs(responses) do
      titles[key] = extract_title(response.body)
  end
  if titles[1] ~= titles[2] or
     titles[1] ~= titles[3] then

     table.insert(results, 'HTML title')
     for key,response in pairs(responses) do
       table.insert(result, "Hop #" .. key .. ": " .. titles[key])
     end
     table.insert(results, result)
  end

  -- Check status code
  if responses[1].status == 502 or
    responses[1].status == 483 or
    responses[1].status ~= responses[2].status or
    responses[1].status ~= responses[3].status then

    result = {}
    table.insert(results, 'Status Code')
    for key,response in pairs(responses) do
      table.insert(result, "Hop #" .. key .. ": " .. tostring(response.status))
    end
    table.insert(results, result)
  end

   -- Check headers
  for _,header in pairs(interesting_headers) do
    -- Compare header of different responses
    if responses[1].header[header] ~= responses[2].header[header] or
       responses[1].header[header] ~= responses[3].header[header] then

      result = {}
      table.insert(results, header)
      for key,response in pairs(responses) do
        if response.header[header] ~= nil then
          table.insert(result, "Hop #" .. key .. ": " .. tostring(response.header[header]))
        else
          table.insert(result, "Hop #" .. key)
        end
      end
      table.insert(results, result)
    end
  end

  -- Check for X-Forwarded-For in the response body
  -- when using TRACE method
  if method == "TRACE" then
     local xfwd  = extract_xfwd(responses[1].body)
     if xfwd ~= nil then
         table.insert(results, xfwd)
     end
  end

  return results
end

action = function(host, port)
  local path = stdnse.get_script_args(SCRIPT_NAME .. '.path') or "/"
  local method = stdnse.get_script_args(SCRIPT_NAME .. '.method') or "GET"
  local responses = {}
  local detected = "Possible reverse proxy detected."

  for i = 0,2 do
    local response = http.generic_request(host, port, method, path, { ['header'] = { ['Max-Forwards'] = i }, ['no_cache'] = true})
    table.insert(responses, response)
  end

  -- Check results
  local results = compare_responses(responses, method)
  if results ~= nil and nmap.verbosity() == 1 then
      return stdnse.format_output(true,detected)
  else
      return stdnse.format_output(true,results)
  end
end
