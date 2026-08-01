local http = require "http"
local json = require "json"
local nmap = require "nmap"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

description = [[
Discovers HTTP-exposed Model Context Protocol (MCP) servers and lists advertised
tools. The script only performs MCP discovery/list operations and does not call
tools/call.

It supports modern Streamable HTTP discovery, legacy Streamable HTTP
initialize/tools-list, and HexStrike AI REST backend fingerprinting on /health.
HexStrike's default :8888 service is a REST backend used by hexstrike_mcp.py
over stdio, not a direct Streamable HTTP MCP endpoint.
]]

---
-- @usage
-- nmap -p 8888 --script ./nse/mcp-info.nse 127.0.0.1
-- nmap -p 3000,6274,8000-8010 --script ./nse/mcp-info.nse --script-args mcp-info.paths=/mcp,/sse,/ <target>
--
-- @args mcp-info.paths Comma-separated paths to probe. Default: /mcp,/sse,/,/health
-- @args mcp-info.max-pages Maximum tools/list pages to request. Default: 20
-- @args mcp-info.modern-version MCP version to use for server/discover. Default: 2026-07-28
--
-- @output
-- PORT     STATE SERVICE
-- 8888/tcp open  sun-answerbook
-- | mcp-info:
-- |   url: http://127.0.0.1:8888/health
-- |   transport: hexstrike-rest-backend
-- |   server: hexstrike-ai/6.0.0
-- |   tools:
-- |     nmap: available on HexStrike backend
-- |     sqlmap: available on HexStrike backend
-- |_  note: Tools are derived from health.tools_status, not from MCP tools/list.

author = "mcp-scanner contributors"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

local CLIENT_NAME = "nmap-mcp-info"
local CLIENT_VERSION = "0.1.0"
local DEFAULT_MODERN_VERSION = "2026-07-28"
local LEGACY_VERSIONS = {"2025-11-25", "2025-06-18", "2025-03-26"}
local SSE_VERSIONS = {"2025-06-18", "2025-03-26", "2024-11-05"}
local DEFAULT_PATHS = {"/mcp", "/sse", "/", "/health"}
local DEFAULT_MAX_PAGES = 20

local function get_arg(name)
  return stdnse.get_script_args(SCRIPT_NAME .. "." .. name)
    or stdnse.get_script_args("mcp-info." .. name)
    or stdnse.get_script_args("mcp-info.nse." .. name)
    or stdnse.get_script_args(name)
end

portrule = function(host, port)
  return port.protocol == "tcp" and (port.state == "open" or port.state == "open|filtered")
end

local function split_csv(value)
  local result = {}
  if not value or value == "" then
    return result
  end
  for item in string.gmatch(value, "([^,]+)") do
    item = string.match(item, "^%s*(.-)%s*$")
    if item ~= "" then
      table.insert(result, item)
    end
  end
  return result
end

local function normalize_path(path)
  if not path or path == "" then
    return "/"
  end
  if string.sub(path, 1, 1) ~= "/" then
    return "/" .. path
  end
  return path
end

local function get_paths()
  local raw = get_arg("paths")
  local paths = split_csv(raw)
  if #paths == 0 then
    return DEFAULT_PATHS
  end
  for index, path in ipairs(paths) do
    paths[index] = normalize_path(path)
  end
  return paths
end

local function get_max_pages()
  local raw = get_arg("max-pages")
  local value = tonumber(raw or DEFAULT_MAX_PAGES)
  if not value or value < 1 then
    return DEFAULT_MAX_PAGES
  end
  return math.floor(value)
end

local function is_health_path(path)
  local normalized = string.lower(path)
  normalized = string.gsub(normalized, "/+$", "")
  return normalized == "/health"
end

local function decode_json(body)
  if not body or body == "" then
    return nil
  end
  local ok, decoded = json.parse(body)
  if ok then
    return decoded
  end
  return nil
end

local function post_json(host, port, path, payload, extra_headers)
  local headers = {
    ["Accept"] = "application/json, text/event-stream",
    ["Content-Type"] = "application/json",
    ["User-Agent"] = CLIENT_NAME .. "/" .. CLIENT_VERSION,
  }
  if extra_headers then
    for key, value in pairs(extra_headers) do
      headers[key] = value
    end
  end
  return http.post(host, port, path, {header = headers}, nil, json.generate(payload))
end

local function get_json(host, port, path)
  local response = http.get(host, port, path, {
    header = {
      ["Accept"] = "application/json",
      ["User-Agent"] = CLIENT_NAME .. "/" .. CLIENT_VERSION,
    }
  })
  if response and response.body then
    response.json = decode_json(response.body)
  end
  return response
end

local function jsonrpc_result(data)
  return type(data) == "table" and data["jsonrpc"] == "2.0" and data["result"] ~= nil
end

local function jsonrpc_error_code(data)
  if type(data) ~= "table" or type(data["error"]) ~= "table" then
    return nil
  end
  return data["error"]["code"]
end

local function optional_string(value)
  if type(value) == "string" and value ~= "" then
    return value
  end
  return nil
end

local function modern_headers(method, version)
  return {
    ["MCP-Protocol-Version"] = version,
    ["Mcp-Method"] = method,
  }
end

local function modern_payload(method, id, version, params)
  params = params or {}
  params["_meta"] = {
    ["io.modelcontextprotocol/protocolVersion"] = version,
    ["io.modelcontextprotocol/clientInfo"] = {
      name = CLIENT_NAME,
      version = CLIENT_VERSION,
    },
    ["io.modelcontextprotocol/clientCapabilities"] = {},
  }
  return {
    jsonrpc = "2.0",
    id = id,
    method = method,
    params = params,
  }
end

local function extract_tools(result)
  local tools = {}
  if type(result) ~= "table" or type(result["tools"]) ~= "table" then
    return tools
  end
  for _, tool in ipairs(result["tools"]) do
    if type(tool) == "table" and type(tool["name"]) == "string" then
      table.insert(tools, {
        name = tool["name"],
        title = optional_string(tool["title"]),
        description = optional_string(tool["description"]),
      })
    end
  end
  return tools
end

local function append_tools(dst, src)
  for _, tool in ipairs(src) do
    table.insert(dst, tool)
  end
end

local function strip_line(line)
  if not line then
    return nil
  end
  return (string.gsub(line, "[\r\n]+$", ""))
end

local function host_header(host, port)
  return ("%s:%d"):format(host.targetname or host.ip, port.number)
end

local function new_raw_reader(socket)
  return {socket = socket, buffer = ""}
end

local function read_byte(reader)
  if #reader.buffer == 0 then
    local status, data = reader.socket:receive_bytes(1)
    if not status then
      return nil, data
    end
    reader.buffer = data or ""
  end
  if #reader.buffer == 0 then
    return nil, "empty read"
  end
  local byte = string.sub(reader.buffer, 1, 1)
  reader.buffer = string.sub(reader.buffer, 2)
  return byte, nil
end

local function read_until(reader, marker, max_bytes)
  local data = ""
  while #data < max_bytes do
    local byte, err = read_byte(reader)
    if not byte then
      return nil, err
    end
    data = data .. byte
    if string.sub(data, -#marker) == marker then
      return data, nil
    end
  end
  return nil, "read limit exceeded"
end

local function parse_headers(raw)
  local lines = {}
  for line in string.gmatch(raw, "([^\r\n]+)") do
    table.insert(lines, line)
  end
  local status_line = lines[1] or ""
  local headers = {}
  for index = 2, #lines do
    local key, value = string.match(lines[index], "^([^:]+):%s*(.*)$")
    if key then
      headers[string.lower(key)] = value or ""
    end
  end
  return status_line, headers
end

local function new_sse_reader(raw_reader, headers)
  return {
    socket = raw_reader.socket,
    raw = raw_reader,
    chunked = string.lower(headers["transfer-encoding"] or "") == "chunked",
    chunk_remaining = 0,
  }
end

local function read_chunk_size(reader)
  local line = ""
  while true do
    local byte, err = read_byte(reader.raw)
    if not byte then
      return nil, err
    end
    line = line .. byte
    if string.sub(line, -2) == "\r\n" then
      local size_text = string.match(line, "^%s*([0-9a-fA-F]+)")
      if not size_text then
        return nil, "invalid chunk size"
      end
      return tonumber(size_text, 16), nil
    end
  end
end

local function reader_read_byte(reader)
  if not reader.chunked then
    return read_byte(reader.raw)
  end

  if reader.chunk_remaining == 0 then
    local size, err = read_chunk_size(reader)
    if not size then
      return nil, err
    end
    if size == 0 then
      return nil, "end of chunked stream"
    end
    reader.chunk_remaining = size
  end

  local byte, err = read_byte(reader.raw)
  if not byte then
    return nil, err
  end
  reader.chunk_remaining = reader.chunk_remaining - 1
  if reader.chunk_remaining == 0 then
    -- Consume the CRLF after the chunk body.
    read_byte(reader.raw)
    read_byte(reader.raw)
  end
  return byte, nil
end

local function reader_read_line(reader)
  local line = ""
  while true do
    local byte, err = reader_read_byte(reader)
    if not byte then
      return nil, err
    end
    line = line .. byte
    if byte == "\n" then
      return line, nil
    end
  end
end

local function open_sse(host, port, path)
  local socket = nmap.new_socket()
  socket:set_timeout(3000)
  local status, err = socket:connect(host, port)
  if not status then
    return nil, err
  end

  local request = table.concat({
    ("GET %s HTTP/1.1"):format(path),
    ("Host: %s"):format(host_header(host, port)),
    "Accept: text/event-stream",
    ("User-Agent: %s/%s"):format(CLIENT_NAME, CLIENT_VERSION),
    "Connection: keep-alive",
    "",
    "",
  }, "\r\n")
  status, err = socket:send(request)
  if not status then
    socket:close()
    return nil, err
  end

  local raw = new_raw_reader(socket)
  local raw_headers
  raw_headers, err = read_until(raw, "\r\n\r\n", 8192)
  if not raw_headers then
    socket:close()
    return nil, err or "failed reading SSE headers"
  end

  local status_line, headers = parse_headers(raw_headers)
  if not string.find(status_line or "", "^HTTP/%d%.%d 200") then
    socket:close()
    return nil, status_line or "SSE endpoint did not return HTTP 200"
  end
  local content_type = string.lower(headers["content-type"] or "")
  if not string.find(content_type, "text/event%-stream") then
    socket:close()
    return nil, "endpoint is not text/event-stream"
  end

  return new_sse_reader(raw, headers), nil
end

local function read_sse_event(reader)
  local event_name = "message"
  local data_lines = {}
  while true do
    local line, err = reader_read_line(reader)
    if not line then
      return nil, err
    end
    line = strip_line(line)
    if line == "" then
      if #data_lines > 0 then
        return {
          event = event_name,
          data = table.concat(data_lines, "\n"),
        }
      end
      event_name = "message"
      data_lines = {}
    elseif string.sub(line, 1, 1) ~= ":" then
      local field, value = string.match(line, "^([^:]+):%s?(.*)$")
      if field == "event" then
        event_name = value
      elseif field == "data" then
        table.insert(data_lines, value or "")
      end
    end
  end
end

local function endpoint_path(endpoint)
  if type(endpoint) ~= "string" or endpoint == "" then
    return nil
  end
  local path = string.match(endpoint, "^https?://[^/]+(.*)$") or endpoint
  if path == "" then
    path = "/"
  end
  if string.sub(path, 1, 1) ~= "/" then
    path = "/" .. path
  end
  return path
end

local function read_sse_endpoint(socket)
  for _ = 1, 20 do
    local event = read_sse_event(socket)
    if not event then
      return nil
    end
    if event.event == "endpoint" then
      return endpoint_path(event.data)
    end
  end
  return nil
end

local function read_sse_json_response(socket, id)
  for _ = 1, 80 do
    local event = read_sse_event(socket)
    if not event then
      return nil
    end
    local data = decode_json(event.data)
    if type(data) == "table" and data["id"] == id then
      return data
    end
  end
  return nil
end

local function list_modern_tools(host, port, path, version, max_pages)
  local tools = {}
  local cursor = nil
  for page = 1, max_pages do
    local params = {}
    if cursor then
      params["cursor"] = cursor
    end
    local response = post_json(
      host,
      port,
      path,
      modern_payload("tools/list", "tools-" .. page, version, params),
      modern_headers("tools/list", version)
    )
    if not response then
      return tools, "tools/list request failed"
    end
    local data = decode_json(response.body)
    if jsonrpc_error_code(data) == -32601 then
      return tools, "server does not implement tools/list"
    end
    if not jsonrpc_result(data) or type(data["result"]) ~= "table" then
      return tools, ("tools/list failed with HTTP status %s"):format(response.status or "unknown")
    end
    append_tools(tools, extract_tools(data["result"]))
    cursor = data["result"]["nextCursor"]
    if type(cursor) ~= "string" or cursor == "" then
      return tools, nil
    end
  end
  return tools, "tools/list stopped after max-pages"
end

local function list_legacy_tools(host, port, path, version, session_id, max_pages)
  local headers = {["MCP-Protocol-Version"] = version}
  if session_id then
    headers["Mcp-Session-Id"] = session_id
  end

  local tools = {}
  local cursor = nil
  for page = 1, max_pages do
    local params = {}
    if cursor then
      params["cursor"] = cursor
    end
    local response = post_json(host, port, path, {
      jsonrpc = "2.0",
      id = "tools-" .. page,
      method = "tools/list",
      params = params,
    }, headers)
    if not response then
      return tools, "tools/list request failed"
    end
    local data = decode_json(response.body)
    if jsonrpc_error_code(data) == -32601 then
      return tools, "server does not implement tools/list"
    end
    if not jsonrpc_result(data) or type(data["result"]) ~= "table" then
      return tools, ("tools/list failed with HTTP status %s"):format(response.status or "unknown")
    end
    append_tools(tools, extract_tools(data["result"]))
    cursor = data["result"]["nextCursor"]
    if type(cursor) ~= "string" or cursor == "" then
      return tools, nil
    end
  end
  return tools, "tools/list stopped after max-pages"
end

local function list_sse_tools(host, port, socket, endpoint, max_pages)
  local tools = {}
  local cursor = nil
  for page = 1, max_pages do
    local params = {}
    if cursor then
      params["cursor"] = cursor
    end
    local request_id = "tools-" .. page
    local response = post_json(host, port, endpoint, {
      jsonrpc = "2.0",
      id = request_id,
      method = "tools/list",
      params = params,
    })
    if not response then
      return tools, "tools/list POST failed"
    end
    local data = read_sse_json_response(socket, request_id)
    if jsonrpc_error_code(data) == -32601 then
      return tools, "server does not implement tools/list"
    end
    if not jsonrpc_result(data) or type(data["result"]) ~= "table" then
      return tools, "tools/list response was not readable from SSE stream"
    end
    append_tools(tools, extract_tools(data["result"]))
    cursor = data["result"]["nextCursor"]
    if type(cursor) ~= "string" or cursor == "" then
      return tools, nil
    end
  end
  return tools, "tools/list stopped after max-pages"
end

local function choose_version(supported, preferred)
  if type(supported) ~= "table" then
    return preferred
  end
  for _, version in ipairs(supported) do
    if version == preferred then
      return preferred
    end
  end
  for _, version in ipairs(supported) do
    if type(version) == "string" then
      return version
    end
  end
  return preferred
end

local function probe_modern(host, port, path, max_pages)
  local preferred = get_arg("modern-version") or DEFAULT_MODERN_VERSION
  local response = post_json(
    host,
    port,
    path,
    modern_payload("server/discover", "discover-1", preferred),
    modern_headers("server/discover", preferred)
  )
  if not response then
    return nil
  end

  local data = decode_json(response.body)
  if not jsonrpc_result(data) then
    return nil
  end

  local result = data["result"]
  if type(result) ~= "table" then
    return nil
  end

  local version = choose_version(result["supportedVersions"], preferred)
  local tools, note = list_modern_tools(host, port, path, version, max_pages)
  local server_info = nil
  if type(result["_meta"]) == "table" then
    server_info = result["_meta"]["io.modelcontextprotocol/serverInfo"]
  end
  return {
    transport = "streamable-http-modern",
    protocol_version = version,
    server_info = server_info,
    capabilities = result["capabilities"],
    tools = tools,
    note = note,
  }
end

local function probe_legacy(host, port, path, max_pages)
  for _, requested_version in ipairs(LEGACY_VERSIONS) do
    local response = post_json(host, port, path, {
      jsonrpc = "2.0",
      id = "init-1",
      method = "initialize",
      params = {
        protocolVersion = requested_version,
        capabilities = {},
        clientInfo = {name = CLIENT_NAME, version = CLIENT_VERSION},
      },
    })
    if response then
      local data = decode_json(response.body)
      if jsonrpc_result(data) and type(data["result"]) == "table" then
        local result = data["result"]
        local version = optional_string(result["protocolVersion"]) or requested_version
        local session_id = response.header and response.header["mcp-session-id"]
        local headers = {["MCP-Protocol-Version"] = version}
        if session_id then
          headers["Mcp-Session-Id"] = session_id
        end
        post_json(host, port, path, {
          jsonrpc = "2.0",
          method = "notifications/initialized",
        }, headers)
        local tools, note = list_legacy_tools(host, port, path, version, session_id, max_pages)
        return {
          transport = "streamable-http-legacy",
          protocol_version = version,
          server_info = result["serverInfo"],
          capabilities = result["capabilities"],
          tools = tools,
          note = note,
        }
      end
    end
  end
  return nil
end

local function probe_sse_once(host, port, path, requested_version, max_pages)
  local reader = nil
  local endpoint = nil
  reader = open_sse(host, port, path)
  if not reader then
    return nil
  end

  endpoint = read_sse_endpoint(reader)
  if not endpoint then
    reader.socket:close()
    return nil
  end

  post_json(host, port, endpoint, {
    jsonrpc = "2.0",
    id = "init-1",
    method = "initialize",
    params = {
      protocolVersion = requested_version,
      capabilities = {},
      clientInfo = {name = CLIENT_NAME, version = CLIENT_VERSION},
    },
  })
  local init_response = read_sse_json_response(reader, "init-1")
  if not jsonrpc_result(init_response) or type(init_response["result"]) ~= "table" then
    reader.socket:close()
    return nil
  end

  local result = init_response["result"]
  local protocol_version = optional_string(result["protocolVersion"]) or requested_version
  post_json(host, port, endpoint, {
    jsonrpc = "2.0",
    method = "notifications/initialized",
  })

  local tools, note = list_sse_tools(host, port, reader, endpoint, max_pages)
  reader.socket:close()
  return {
    transport = "http+sse-legacy",
    protocol_version = protocol_version,
    server_info = result["serverInfo"],
    capabilities = result["capabilities"],
    tools = tools,
    note = note,
  }
end

local function probe_sse(host, port, path, max_pages)
  for _, requested_version in ipairs(SSE_VERSIONS) do
    local finding = probe_sse_once(host, port, path, requested_version, max_pages)
    if finding then
      return finding
    end
  end
  return nil
end

local function looks_like_hexstrike_health(data)
  if type(data) ~= "table" then
    return false
  end
  local haystack = string.lower(
    tostring(data["message"] or "") .. " " ..
    tostring(data["name"] or "") .. " " ..
    tostring(data["service"] or "")
  )
  if string.find(haystack, "hexstrike", 1, true) then
    return true
  end
  return type(data["tools_status"]) == "table" and data["total_tools_count"] ~= nil and data["category_stats"] ~= nil
end

local function tools_from_hexstrike_status(tools_status)
  local tools = {}
  if type(tools_status) ~= "table" then
    return tools
  end
  local names = {}
  for name, _ in pairs(tools_status) do
    table.insert(names, name)
  end
  table.sort(names)
  for _, name in ipairs(names) do
    local available = tools_status[name] and true or false
    table.insert(tools, {
      name = name,
      description = available and "available on HexStrike backend" or "missing on HexStrike backend",
    })
  end
  return tools
end

local function probe_health(host, port, path)
  local response = get_json(host, port, path)
  if not response or not response.status or response.status < 200 or response.status >= 300 then
    return nil
  end

  if looks_like_hexstrike_health(response.json) then
    return {
      transport = "hexstrike-rest-backend",
      server_info = {
        name = "hexstrike-ai",
        version = optional_string(response.json["version"]),
      },
      tools = tools_from_hexstrike_status(response.json["tools_status"]),
      note = "Tools are derived from health.tools_status, not from MCP tools/list.",
    }
  end

  local body = string.lower(response.body or "")
  if port.number == 8888 or string.find(body, "hexstrike", 1, true) then
    return {
      transport = "possible-hexstrike-rest-backend",
      server_info = {name = "hexstrike-ai"},
      tools = {},
      note = "Port 8888 /health returned HTTP 2xx but did not expose tools_status; low-confidence backend fingerprint.",
    }
  end

  return nil
end

local function probe_path(host, port, path, max_pages)
  if is_health_path(path) then
    return probe_health(host, port, path)
  end
  return probe_modern(host, port, path, max_pages)
    or probe_legacy(host, port, path, max_pages)
    or probe_sse(host, port, path, max_pages)
end

local function server_label(server_info)
  if type(server_info) ~= "table" then
    return nil
  end
  if server_info["name"] and server_info["version"] then
    return ("%s/%s"):format(server_info["name"], server_info["version"])
  end
  return server_info["name"]
end

local function finding_to_output(host, port, path, finding)
  local scheme = port.service == "https" and "https" or "http"
  local url = ("%s://%s:%d%s"):format(scheme, host.targetname or host.ip, port.number, path)
  local output = stdnse.output_table()
  output["url"] = url
  output["transport"] = finding.transport
  if finding.protocol_version then
    output["protocol"] = finding.protocol_version
  end
  local label = server_label(finding.server_info)
  if label then
    output["server"] = label
  end
  if finding.tools and #finding.tools > 0 then
    local tools = stdnse.output_table()
    for _, tool in ipairs(finding.tools) do
      tools[tool.name] = tool.description or tool.title or ""
    end
    output["tools"] = tools
  else
    output["tools"] = "none listed"
  end
  if finding.note then
    output["note"] = finding.note
  end
  return output
end

local function finding_to_lines(host, port, path, finding)
  local scheme = port.service == "https" and "https" or "http"
  local url = ("%s://%s:%d%s"):format(scheme, host.targetname or host.ip, port.number, path)
  local lines = {
    "url: " .. url,
    "transport: " .. finding.transport,
  }
  if finding.protocol_version then
    table.insert(lines, "protocol: " .. finding.protocol_version)
  end
  local label = server_label(finding.server_info)
  if label then
    table.insert(lines, "server: " .. label)
  end
  if finding.tools and #finding.tools > 0 then
    table.insert(lines, "tools:")
    for _, tool in ipairs(finding.tools) do
      local value = tool.description or tool.title or ""
      if value ~= "" then
        table.insert(lines, ("  %s: %s"):format(tool.name, value))
      else
        table.insert(lines, "  " .. tool.name)
      end
    end
  else
    table.insert(lines, "tools: none listed")
  end
  if finding.note then
    table.insert(lines, "note: " .. finding.note)
  end
  return lines
end

action = function(host, port)
  local paths = get_paths()
  local max_pages = get_max_pages()
  local findings = {}
  local lines = {}

  for _, path in ipairs(paths) do
    local finding = probe_path(host, port, path, max_pages)
    if finding then
      table.insert(findings, finding_to_output(host, port, path, finding))
      for _, line in ipairs(finding_to_lines(host, port, path, finding)) do
        table.insert(lines, line)
      end
    end
  end

  if #findings == 0 then
    return nil
  end
  return findings, stdnse.format_output(true, lines)
end
