local coap = require "coap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local stringaux = require "stringaux"
local table = require "table"

description = [[
Dumps list of available resources from CoAP endpoints.

This script establishes a connection to a CoAP endpoint and performs a
GET request on a resource. The default resource for our request is
<code>/.well-known/core</core>, which should contain a list of
resources provided by the endpoint.

For additional information:
* https://en.wikipedia.org/wiki/Constrained_Application_Protocol
* https://tools.ietf.org/html/rfc7252
* https://tools.ietf.org/html/rfc6690
]]

---
-- @usage nmap -p U:5683 -sU --script coap-resources <target>
--
-- @output
-- PORT     STATE SERVICE REASON
-- 5683/udp open  coap    udp-response ttl 36
-- | coap-resources:
-- |   /large:
-- |     rt: block
-- |     sz: 1280
-- |     title: Large resource
-- |   /large-update:
-- |     ct: 0
-- |     rt: block
-- |     sz: 55
-- |     title: Large resource that can be updated using PUT method
-- |   /link1:
-- |     if: If1
-- |     rt: Type1 Type2
-- |_    title: Link test resource
--
-- @args coap-resources.uri URI to request via the GET method,
--       <code>/.well-known/core</code> by default.
--
-- @xmloutput
-- <table key="/">
--   <elem key="ct">0</elem>
--   <elem key="title">General Info</elem>
-- </table>
-- <table key="/ft">
--   <elem key="ct">0</elem>
--   <elem key="title">Faults Reporting</elem>
-- </table>
-- <table key="/mn">
--   <elem key="ct">0</elem>
--   <elem key="title">Monitor Reporting</elem>
-- </table>
-- <table key="/st">
--   <elem key="ct">0</elem>
--   <elem key="title">Status Reporting</elem>
-- </table>
-- <table key="/time">
--   <elem key="ct">0</elem>
--   <elem key="obs,&lt;/devices/block&gt;;title">Devices Block</elem>
--   <elem key="title">Internal Clock</elem>
-- </table>
-- <table key="/wn">
--   <elem key="ct">0</elem>
--   <elem key="title">Warnings Reporting</elem>
-- </table>

author = "Mak Kolybabi <mak@kolybabi.com>"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery"}

-- TODO: Add 5684 "coaps" if DTLS support is added
portrule = shortport.port_or_service(5683, "coap", "udp")

format_payload = function(payload)
  -- Leave strings alone.
  if type(payload) == "string" then
    return payload
  end

  local tbl = stdnse.output_table()

  -- We want to go through all of the links in alphabetical order.
  table.sort(payload, function(a,b) return a.name < b.name end)

  for _, link in ipairs(payload) do
    -- We want to go through all of the parameters in alphabetical
    -- order.
    table.sort(link.parameters, function(a,b) return a.name < b.name end)

    local row = stdnse.output_table()
    for _, param in ipairs(link.parameters) do
      row[param.name] = param.value
    end

    tbl[link.name] = row
  end

  return tbl
end

get_blocks = function(helper, options, b2opt, payload, max_reqs)
  -- Initialize the block table to store all of our received blocks.
  local blocks = {}
  blocks[b2opt.number] = payload

  -- If we don't know the number of the last block, we'll need to use
  -- the largest number we've seen as the maxumum.
  local max = b2opt.number

  -- If the first block we received happens to be the last one, either
  -- by being a one-block sequence or by the endpoint sending us the
  -- last block in the sequence first, we want to record the final
  -- number in the sequence.
  local last = nil
  if b2opt.more == false then
    last = b2opt.number
    max = b2opt.number
  end

  -- We'll continue to request blocks that are the same size as the
  -- original block, since the endpoint likely prefers that.
  local length = b2opt.length

  -- We want to track the number of requests we make so that a
  -- malicious endpoint can't keep us on the hook forever.
  for req = 1, max_reqs do
    -- Determine if there are any blocks in the sequence that we have
    -- not yet received.
    local top = max + 1
    if last then
      top = last
    end

    local num = top
    for i = 0, top do
      if not blocks[i] then
        num = i
        break
      end
    end

    -- If the block we think we're missing is at the end of the
    -- sequence, we've got them all.
    if last and num >= last then
      stdnse.debug3("All %d blocks have been retrieved.", last)
      break
    end

    -- Create the request.
    local opts = {
      ["code"] = "get",
      ["type"] = "confirmable",
      ["options"] = {
        {["name"] = "block2", ["value"] = {
          ["number"] = num,
          ["more"] = false,
          ["length"] = length
        }}
      }
    }

    local components = stringaux.strsplit("/", options.uri)
    for _, component in ipairs(components) do
      if component ~= "" then
        table.insert(opts.options, {["name"] = "uri_path", ["value"] = component})
      end
    end

    -- Send the request and receive the response.
    stdnse.debug3("Requesting block %d of size %d.", num, length)
    local status, response = helper:request(opts)
    if not status then
      return false, response
    end

    if not response.payload then
      return false, "Response did not contain a payload."
    end

    -- Check for the presence of the block2 option, and if it's
    -- missing then we're going to stop.
    b2opt = coap.COAP.header.find_option(response, "block2")
    if not b2opt then
      stdnse.debug1("Stopped requesting more blocks, response found without block2 option.")
      break
    end

    stdnse.debug3("Received block %d of size %d.", b2opt.number, b2opt.length)
    blocks[b2opt.number] = response.payload

    if b2opt.more == false then
      stdnse.debug3("Block %d indicates it is the end of the sequence.", b2opt.number, b2opt.length)
      last = b2opt.number
      max = b2opt.number
    elseif b2opt.number > max then
      max = b2opt.number
    end
  end

  -- Reassemble payload, handling potentially missing blocks.
  local result = ""
  for i = 1, max do
    if not blocks[i] then
      stdnse.debug3("Block %d is missing, replacing with dummy data.", i)
      result = result .. ("<! missing block %d!>"):format(i)
    else
      result = result .. blocks[i]
    end
  end

  return true, result
end

local function parse_args ()
  local args = {}

  local uri = stdnse.get_script_args(SCRIPT_NAME .. '.uri')
  if not uri then
    uri = "/.well-known/core"
  end
  args.uri = uri

  return true, args
end

action = function(host, port)
  local output = stdnse.output_table()

  -- Parse and sanity check the command line arguments.
  local status, options = parse_args()
  if not status then
    output.ERROR = options
    return output, output.ERROR
  end

  -- Create an instance of the CoAP library's client object.
  local helper = coap.Helper:new(host, port)

  -- Connect to the CoAP endpoint.
  local status, response = helper:connect({["uri"] = options.uri})
  if not status then
    -- Erros at this stage indicate we're probably not talking to a CoAP server,
    -- so we exit silently.
    return nil
  end

  -- Check that the response is a 2.05, otherwise we don't know how to
  -- continue.
  if response.code ~= "content" then
    -- If the port runs an echo service, we'll see an unexpected 'get' code.
    if response.code == "get" then
      -- Exit silently, this has all been a mistake.
      return nil
    end

    -- If the requested resource wasn't found, that's okay.
    if response.code == "not_found" then
      stdnse.debug1("The target reports that the resource '%s' was not found.", options.uri)
      return nil
    end

    -- Otherwise, we assume that we're getting a legitimate CoAP response.
    output.ERROR = ("Server responded with '%s' code where 'content' was expected."):format(response.code)
    return output, output.ERROR
  end

  local result = response.payload
  if not result then
    output.ERROR = "Payload for initial response was not part of the packet."
    return output, output.ERROR
  end

  -- Check for the presence of the block2 option, which indicates that
  -- we'll need to perform more requests.
  local b2opt = coap.COAP.header.find_option(response, "block2")
  if b2opt then
    -- Since the block2 option was used, the payload should be an unparsed string.
    assert(type(result) == "string")

    local status, payload = get_blocks(helper, options, b2opt, result, 64)
    if not status then
      output.ERROR = result
      return output, output.ERROR
    end
    result = result .. payload

    -- Parse the payload.
    local status, parsed = coap.COAP.payload.parse(response, result)
    if not status then
      stdnse.debug1("Failed to parse payload: %s", parsed)
      stdnse.debug1("Falling back to returning raw payload as last resort.")
      output["Raw CoAP response"] = result
      return output, stdnse.format_output(true, output)
    end

    result = parsed
  end

  -- Regardless of whether the block2 option was used, we should now have a
  -- parsed payload in some format or another. For now, they should all be
  -- strings or tables.
  assert(type(result) == "string" or type(result) == "table")

  -- If the payload has been parsed, and we requested the default
  -- resource, then we know how to format it nicely.
  local formatted = result
  if true then
    formatted = format_payload(result)
  end

  return formatted
end
