local http = require "http"
local ipOps = require "ipOps"
local json = require "json"
local nmap = require "nmap"
local stdnse = require "stdnse"
local table = require "table"
local url = require "url"

description = [[
Looks up the likely owner of a scanned host and its responsible vulnerability-
disclosure routes using lookup.disclose.io.

The script sends the selected target hostname or IP address to an external
service. It skips non-public addresses, makes no requests to the scanned
service, and is not included in Nmap's default script set. Confirm reporting
scope and current program instructions before submitting a vulnerability
report.
]]

---
-- @usage
-- nmap -Pn -sn --script lookup-disclose example.com
-- nmap -sV --script lookup-disclose 1.1.1.1
--
-- @args lookup-disclose.endpoint Lookup API URL. Defaults to
--       <code>https://lookup.disclose.io/api/lookup</code>. Overrides are
--       restricted to literal loopback addresses for local development.
-- @args lookup-disclose.input Input selection: <code>target</code> prefers the
--       hostname supplied to Nmap and falls back to the IP; <code>ip</code>
--       always uses the resolved IP. Defaults to <code>target</code>.
-- @args lookup-disclose.max-contacts Maximum reporting routes displayed for
--       each host, from 1 to 20. Defaults to 3.
-- @args lookup-disclose.max-lookups Maximum external lookups across the scan,
--       from 1 to 1000. Defaults to 50.
-- @args lookup-disclose.timeout HTTP timeout in milliseconds, from 1000 to
--       60000. Defaults to 15000.
--
-- @output
-- Host script results:
-- | lookup-disclose:
-- |   input: example.com
-- |   status: complete
-- |   asset_type: domain
-- |   organization: Example Corporation
-- |   attribution_confidence: high
-- |   route: First-party security reporting route found.
-- |   reporting_routes:
-- |     https://example.com/.well-known/security.txt
-- |       [security_txt, first_party, verified]
-- |     security@example.com [email, first_party, verified]
-- |   request_id: req_...
-- |_  source: https://lookup.disclose.io
--
-- @xmloutput
-- <elem key="input">example.com</elem>
-- <elem key="status">complete</elem>
-- <elem key="asset_type">domain</elem>
-- <elem key="organization">Example Corporation</elem>
-- <elem key="attribution_confidence">high</elem>
-- <elem key="route">First-party security reporting route found.</elem>
-- <table key="reporting_routes">
--   <elem>security@example.com [email, first_party, verified]</elem>
-- </table>
-- <elem key="request_id">req_...</elem>
-- <elem key="source">https://lookup.disclose.io</elem>

author = "disclose.io"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "external", "safe"}

local DEFAULT_ENDPOINT = "https://lookup.disclose.io/api/lookup"
local DEFAULT_HOST = "lookup.disclose.io"
local DEFAULT_PATH = "/api/lookup"
local DEFAULT_MAX_CONTACTS = 3
local DEFAULT_MAX_LOOKUPS = 50
local DEFAULT_TIMEOUT = 15000
local MAX_RESPONSE_BYTES = 262144
local MAX_OUTPUT_FIELD_BYTES = 512
local MAX_ERROR_BYTES = 256

-- ipOps.isPrivate omits some IANA special-purpose ranges. These additions
-- make the external-service boundary fail closed for non-public targets.
local IPV4_NON_PUBLIC_RANGES = {
  "0.0.0.0/8",
  "100.64.0.0/10",
  "192.88.99.0/24",
  "224.0.0.0/4",
}
local IPV6_NON_PUBLIC_RANGES = {
  "::ffff:0:0/96",
  "64:ff9b:1::/48",
  "100::/64",
  "100:0:0:1::/64",
  "2001::/23",
  "2001:db8::/32",
  "2002::/16",
  "3fff::/20",
  "5f00::/16",
  "ff00::/8",
}

local function single_line(value, maximum_bytes)
  local value_type = type(value)
  if value_type ~= "string"
    and value_type ~= "number"
    and value_type ~= "boolean"
  then
    return nil
  end

  local text = tostring(value)
    :gsub("\194[\128-\159]", " ")
    :gsub("\226\128[\168\169]", " ")
    :gsub("%c", " ")
    :gsub("%s+", " ")
  text = text:match("^%s*(.-)%s*$")
  if text == "" then
    return nil
  end
  if #text <= maximum_bytes then
    return text
  end

  local cut = maximum_bytes - 3
  -- Do not leave a partial UTF-8 codepoint at the end of a truncated value.
  while cut > 0 do
    local next_byte = text:byte(cut + 1)
    if not next_byte or next_byte < 0x80 or next_byte > 0xBF then
      break
    end
    cut = cut - 1
  end
  return text:sub(1, cut) .. "..."
end

local function bounded_number(value, default, minimum, maximum)
  local number = tonumber(value)
  if not number then
    return default
  end
  number = math.floor(number)
  if number < minimum then
    return minimum
  end
  if number > maximum then
    return maximum
  end
  return number
end

local function selected_input(host)
  local mode = stdnse.get_script_args(SCRIPT_NAME .. ".input") or "target"
  if mode == "ip" then
    return host.ip
  end
  if mode ~= "target" then
    return nil, "lookup-disclose.input must be 'target' or 'ip'"
  end

  local targetname = host.targetname
  if targetname and targetname ~= "" then
    return targetname
  end
  return host.ip
end

local function parse_endpoint(raw_endpoint)
  if type(raw_endpoint) ~= "string" or raw_endpoint == "" then
    return nil, "lookup-disclose.endpoint must be a non-empty URL"
  end
  local parsed = url.parse(raw_endpoint)
  if parsed.scheme ~= "https" and parsed.scheme ~= "http" then
    return nil, "lookup-disclose.endpoint must use http or https"
  end
  if not parsed.host or parsed.host == "" or parsed.userinfo then
    return nil, "lookup-disclose.endpoint must contain a host and no userinfo"
  end
  if parsed.host:find("[%c%s]") then
    return nil, "lookup-disclose.endpoint contains an invalid host"
  end
  if parsed.fragment then
    return nil, "lookup-disclose.endpoint must not contain a fragment"
  end
  if parsed.query then
    return nil, "lookup-disclose.endpoint must not contain a query string"
  end

  local path = parsed.path
  if not path or path == "" then
    path = DEFAULT_PATH
  end
  if path:sub(1, 1) ~= "/" or path:find("[%c%s]") then
    return nil, "lookup-disclose.endpoint contains an invalid path"
  end
  local port_number = parsed.port or url.get_default_port(parsed.scheme)
  if not port_number or port_number < 1 or port_number > 65535 then
    return nil, "lookup-disclose.endpoint contains an invalid port"
  end
  return {
    host = parsed.ascii_host or parsed.host,
    port = {
      number = port_number,
      protocol = "tcp",
      service = parsed.scheme,
    },
    path = path,
    scheme = parsed.scheme,
  }
end

local function registry()
  local mutex = nmap.mutex("lookup-disclose-registry")
  mutex "lock"
  if not nmap.registry.lookup_disclose then
    nmap.registry.lookup_disclose = {
      cache = {},
      limit_reported = false,
      lookups = 0,
    }
  end
  local state = nmap.registry.lookup_disclose
  mutex "done"
  return state
end

local function reserve_lookup(state, max_lookups)
  local mutex = nmap.mutex("lookup-disclose-quota")
  mutex "lock"
  if state.lookups >= max_lookups then
    local report_limit = not state.limit_reported
    state.limit_reported = true
    mutex "done"
    return false, report_limit
  end
  state.lookups = state.lookups + 1
  mutex "done"
  return true
end

local function is_loopback_endpoint(host)
  local normalized = host:lower():gsub("^%[(.*)%]$", "%1")
  return normalized == "127.0.0.1" or normalized == "::1"
end

local function is_production_endpoint(endpoint)
  return endpoint.scheme == "https"
    and endpoint.host:lower() == DEFAULT_HOST
    and endpoint.port.number == 443
    and endpoint.path == DEFAULT_PATH
end

local function api_request(input)
  local raw_endpoint = stdnse.get_script_args(SCRIPT_NAME .. ".endpoint")
    or DEFAULT_ENDPOINT
  local endpoint, endpoint_error = parse_endpoint(raw_endpoint)
  if not endpoint then
    return nil, endpoint_error
  end
  if not is_production_endpoint(endpoint)
    and not is_loopback_endpoint(endpoint.host)
  then
    return nil, "lookup-disclose.endpoint must use the default API "
      .. "or a literal loopback address"
  end

  local headers = {
    ["Accept"] = "application/json",
    ["Content-Type"] = "application/json",
    ["User-Agent"] = "lookup-disclose-nmap/1.0",
  }
  local timeout = bounded_number(
    stdnse.get_script_args(SCRIPT_NAME .. ".timeout"),
    DEFAULT_TIMEOUT,
    1000,
    60000
  )
  local response = http.post(
    endpoint.host,
    endpoint.port,
    endpoint.path,
    {
      bypass_cache = true,
      header = headers,
      max_body_size = MAX_RESPONSE_BYTES,
      no_cache = true,
      redirect_ok = false,
      scheme = endpoint.scheme,
      timeout = timeout,
      truncated_ok = true,
    },
    nil,
    json.generate({ input = input })
  )

  if not response or not response.status then
    return nil, "lookup API connection failed"
  end

  if response.truncated then
    return nil, "lookup API response exceeded "
      .. tostring(MAX_RESPONSE_BYTES) .. " bytes"
  end

  local parsed_ok, body = json.parse(response.body or "")
  if response.status ~= 200 then
    local message = "lookup API returned HTTP " .. tostring(response.status)
    if parsed_ok and type(body) == "table" and body.errorMessage then
      local error_message = single_line(body.errorMessage, MAX_ERROR_BYTES)
      if error_message then
        message = message .. ": " .. error_message
      end
    end
    return nil, message
  end
  if not parsed_ok or type(body) ~= "table" then
    return nil, "lookup API returned invalid JSON"
  end
  return body
end

local function is_public_address(address)
  local is_private, private_error = ipOps.isPrivate(address)
  if is_private == nil then
    return nil, private_error
  end
  if is_private then
    return false
  end

  local ranges = IPV4_NON_PUBLIC_RANGES
  if address:find(":", 1, true) then
    ranges = IPV6_NON_PUBLIC_RANGES
  end
  for _, range in ipairs(ranges) do
    local in_range, range_error = ipOps.ip_in_range(address, range)
    if in_range == nil then
      return nil, range_error
    end
    if in_range then
      return false
    end
  end
  return true
end

local function route_text(contact)
  local value = single_line(contact.value, MAX_OUTPUT_FIELD_BYTES)
    or single_line(contact.label, MAX_OUTPUT_FIELD_BYTES)
    or "unnamed route"
  local attributes = {}
  local contact_type = single_line(contact.type, 64)
  if contact_type then
    table.insert(attributes, contact_type)
  end
  local route_class = single_line(contact.routeClass, 64)
  if route_class then
    table.insert(attributes, route_class)
  end
  if contact.verified == true then
    table.insert(attributes, "verified")
  else
    local confidence = single_line(contact.confidence, 32)
    if confidence then
      table.insert(attributes, confidence .. " confidence")
    end
  end
  if #attributes == 0 then
    return value
  end
  return value .. " [" .. table.concat(attributes, ", ") .. "]"
end

local function format_result(body, input)
  local output = stdnse.output_table()
  output.input = single_line(body.input, MAX_OUTPUT_FIELD_BYTES)
    or single_line(input, MAX_OUTPUT_FIELD_BYTES)
  output.status = single_line(body.status, 32) or "unknown"
  output.asset_type = single_line(body.assetType, 64)

  local attribution = body.attribution
  if type(attribution) == "table" then
    output.organization = single_line(
      attribution.organization,
      MAX_OUTPUT_FIELD_BYTES
    )
    output.parent_company = single_line(
      attribution.parentCompany,
      MAX_OUTPUT_FIELD_BYTES
    )
    output.jurisdiction = single_line(attribution.jurisdiction, 64)
    output.attribution_confidence = single_line(attribution.confidence, 32)
  end

  if type(body.routeSummary) == "table" then
    output.route = single_line(
      body.routeSummary.headline,
      MAX_OUTPUT_FIELD_BYTES
    )
  end

  local max_contacts = bounded_number(
    stdnse.get_script_args(SCRIPT_NAME .. ".max-contacts"),
    DEFAULT_MAX_CONTACTS,
    1,
    20
  )
  if type(body.contacts) == "table" and #body.contacts > 0 then
    local routes = {}
    local valid_contacts = 0
    for _, contact in ipairs(body.contacts) do
      if type(contact) == "table" then
        valid_contacts = valid_contacts + 1
        if #routes < max_contacts then
          table.insert(routes, route_text(contact))
        end
      end
    end
    if #routes > 0 then
      output.reporting_routes = routes
    end
    if valid_contacts > #routes then
      output.routes_omitted = valid_contacts - #routes
    end
  end

  if body.hasErrors == true then
    output.warning = "Some attribution sources failed during resolution"
  elseif body.status == "partial" then
    output.warning = "No strong owner-qualified route; treat routes as leads"
  elseif body.status == "failed" then
    output.warning = "No reporting route was found"
  end
  output.request_id = single_line(body.requestId, 128)
  output.source = "https://lookup.disclose.io"
  return output
end

hostrule = function(host)
  local is_public, public_error = is_public_address(host.ip)
  if is_public == nil then
    stdnse.debug1(
      "lookup-disclose could not classify %s: %s",
      host.ip,
      public_error
    )
    return false
  end
  return is_public
end

action = function(host)
  local input, input_error = selected_input(host)
  if not input then
    return "ERROR: " .. input_error
  end

  local state = registry()
  local input_mutex = nmap.mutex("lookup-disclose-input:" .. input)
  input_mutex "lock"
  if state.cache[input] then
    local cached = state.cache[input]
    input_mutex "done"
    return cached
  end

  local max_lookups = bounded_number(
    stdnse.get_script_args(SCRIPT_NAME .. ".max-lookups"),
    DEFAULT_MAX_LOOKUPS,
    1,
    1000
  )
  local reserved, report_limit = reserve_lookup(state, max_lookups)
  if not reserved then
    input_mutex "done"
    if report_limit then
      return "SKIPPED: scan-wide lookup limit reached "
        .. "(lookup-disclose.max-lookups=" .. tostring(max_lookups) .. ")"
    end
    return nil
  end

  local completed, output = pcall(function()
    local body, request_error = api_request(input)
    if body then
      return format_result(body, input)
    end
    return "ERROR: " .. request_error
  end)
  if not completed then
    stdnse.debug1("lookup-disclose failed while processing %s", input)
    output = "ERROR: lookup API processing failed"
  end
  state.cache[input] = output
  input_mutex "done"
  return output
end
