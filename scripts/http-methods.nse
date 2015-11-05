local http = require "http"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

description = [[
Finds out what options are supported by an HTTP server by sending an
OPTIONS request. Lists potentially risky methods. It tests those methods
not mentioned in the OPTIONS headers individually and sees if they are
implemented. Any output other than 501/405 suggests that the method is
if not in the range 400 to 600. If the response falls under that range then
it is compared to the response from a randomly generated method.

In this script, "potentially risky" methods are anything except GET,
HEAD, POST, and OPTIONS. If the script reports potentially risky
methods, they may not all be security risks, but you should check to
make sure. This page lists the dangers of some common methods:

http://www.owasp.org/index.php/Testing_for_HTTP_Methods_and_XST_%28OWASP-CM-008%29

The list of supported methods comes from the contents of the Allow and
Public header fields. In verbose mode, a list of all methods is printed,
followed by the list of potentially risky methods. Without verbose mode,
only the potentially risky methods are shown.
]]

---
-- @args http.url-path The path to request. Defaults to
-- <code>/</code>.
-- @args http.retest If defined, do a request using each method
-- individually and show the response code. Use of this argument can
-- make this script unsafe; for example <code>DELETE /</code> is
-- possible. All methods received through options are tested with generic
-- requests. Saved status lines are shown for rest.
-- @args http.test-all If set true tries all the unsafe methods as well.
--
-- @output
-- PORT   STATE SERVICE REASON
-- 80/tcp open  http    syn-ack
-- | http-methods:
-- |_  Supported Methods: GET HEAD POST OPTIONS
--
-- @usage
-- nmap --script http-methods --script-args <target>
-- nmap --script http-methods --script-args http.url-path='/website' <target>
--
-- @xmloutput
-- <table key="Supported Methods">
--   <elem>GET</elem>
--   <elem>HEAD</elem>
--   <elem>POST</elem>
--   <elem>OPTIONS</elem>
-- </table>


author = {"Bernd Stroessenreuther <berny1@users.sourceforge.net>", "Gyanendra Mishra"}

license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

categories = {"default", "safe"}

local function check_allowed(random_resp, response)
  if response.status == 405 or response.status == 501 then
    return false
  end
  if response.status < 600 and response.status >= 400 and response.status == random_resp.status then
    return false
  end
  return true
end

local function filter_out(t, filter)
  local result = {}
  local _, e, f
  for _, e in ipairs(t) do
    if not stdnse.contains(filter, e) then
      result[#result + 1] = e
    end
  end
  return result
end


-- Split header field contents on commas and return a table without duplicates.
local function merge_headers(headers, names)
  local seen = {}
  local result = {}

  for _, name in ipairs(names) do
    name = string.lower(name)
    if headers[name] then
      for _, v in ipairs(stdnse.strsplit(",%s*", headers[name])) do
        if not seen[v] then
          result[#result + 1] = v
        end
        seen[v] = true
      end
    end
  end

  return result
end

-- We don't report these methods except with verbosity.
local SAFE_METHODS = {
  "GET", "HEAD", "POST", "OPTIONS"
}

local UNSAFE_METHODS = {
"DELETE", "PUT", "CONNECT", "TRACE"
}

portrule = shortport.http

action = function(host, port)

  local path, retest_http_methods, test_all_unsafe
  local response, methods, options_status_line
  local output = stdnse.output_table()
  local options_status = true

  local spacesep = {
    __tostring = function(t)
      return table.concat(t, " ")
    end
  }

  -- default values for script-args
  path = stdnse.get_script_args(SCRIPT_NAME .. ".url-path") or '/'
  retest_http_methods = stdnse.get_script_args(SCRIPT_NAME .. ".retest") or false
  test_all_unsafe = stdnse.get_script_args(SCRIPT_NAME .. ".test-all") or false

  response = http.generic_request(host, port, "OPTIONS", path)
  if not response.status then
    options_status = false
    stdnse.debug1("OPTIONS %s failed.", path)
  end
  -- Cache in case retest is requested.
  if options_status then
    options_status_line = response["status-line"]
    stdnse.debug1("HTTP Status for OPTIONS is " .. response.status)
    if not(response.header["allow"] or response.header["public"]) then
      stdnse.debug1("No Allow or Public header in OPTIONS response (status code %d)", response.status)
    end
  end

  -- The Public header is defined in RFC 2068, but was removed in its
  -- successor RFC 2616. It is implemented by at least IIS 6.0.
  methods = merge_headers(response.header, {"Allow", "Public"})

  local to_test = {}
  local status_lines = {}

  for _, method in pairs(SAFE_METHODS) do
    if not stdnse.contains(methods, method) then
      table.insert(to_test, method)
    end
  end

  if test_all_unsafe then
    for _, method in pairs(UNSAFE_METHODS) do
      if not stdnse.contains(methods, method) then
        table.insert(to_test, method)
      end
    end
  end

  local random_resp = http.generic_request(host, port, stdnse.generate_random_string(4), path)

  if random_resp.status then
    stdnse.debug1("Response Code to Random Method is %d", random_resp.status)
  else
    stdnse.debug1("Random Method %s failed.", path)
  end

  for _, method in pairs(to_test) do
    response = http.generic_request(host, port, method, path)
    if response.status and check_allowed(random_resp, response) then
      stdnse.debug2("Method %s not in OPTIONS found to exist. STATUS %d", method, response.status)
      table.insert(methods, method)
      status_lines[method] = response['status-line']
    end
  end

  if nmap.verbosity() > 0 and #methods > 0 then
    output["Supported Methods"] = methods
    setmetatable(output["Supported Methods"], spacesep)
  end

  local interesting = filter_out(methods, SAFE_METHODS)
  if #interesting > 0 then
    output["Potentially risky methods"] = interesting
    setmetatable(output["Potentially risky methods"], spacesep)
  end

  if path ~= '/' then
    output["Path tested"] = path
  end

  -- retest http methods if requested
  if retest_http_methods then
    output["Status Lines"] = {}
    for _, method in ipairs(methods) do
      local str
      if method == "OPTIONS" then
        -- Use the saved value.
        str = options_status_line
      elseif stdnse.contains(to_test, method) then
        -- use the value saved earlier.
        str = status_lines[method]
      -- this case arises when methods in the Public or Allow headers are retested.
      else
        response = http.generic_request(host, port, method, path)
        if not response.status then
          str = "Error getting response"
        else
          str = response["status-line"]
        end
      end
      str = str:gsub('\r?\n?', "")
      output["Status Lines"][method] = str
    end
  end
  if #output > 0 then return output else return nil end
end

