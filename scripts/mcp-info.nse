local mcp = require "mcp"
local nmap = require "nmap"
local stdnse = require "stdnse"
local table = require "table"

description = [[
Detects and fingerprints Model Context Protocol (MCP) servers exposed over HTTP(S).

The script attempts an MCP JSON-RPC `initialize` handshake (Streamable HTTP transport)
against a list of candidate endpoint paths, sending the spec-required
`Accept: application/json, text/event-stream` header. A response carrying a JSON-RPC
`initialize` result (serverInfo / protocolVersion / capabilities) is treated as a
high-confidence MCP match. The script also falls back to the legacy HTTP+SSE transport
and, for auth-gated servers, parses the OAuth 2.1 protected-resource metadata
(RFC 9728) to reveal the authorization server(s) and scopes.

On a match it reports the transport, endpoint path, server implementation name/version,
negotiated protocol version, advertised capabilities, session statefulness, and
authentication posture. It augments service/version detection via `-sV`.

This script is read-only: it issues only the protocol `initialize` handshake and never
invokes tools (`tools/call`). For attack-surface enumeration (tools/resources/prompts)
see the companion script `mcp-enum`. Shared logic lives in the `mcp` nselib.
]]

---
-- @usage nmap -p 8000,3000,8080 --script mcp-info <target>
-- @usage nmap -sV --script mcp-info -p- <target>
-- @usage nmap --script mcp-info --script-args mcp.paths=/custom,mcp.ua=curl/8 <target>
--
-- @args mcp.paths   Comma-separated list of endpoint paths to probe.
-- @args mcp.timeout HTTP timeout in ms (default 7000).
-- @args mcp.ua      User-Agent to send (default a neutral browser UA; a UA containing
--                   "nmap" is blocked by common WAFs).
--
-- @output
-- PORT     STATE SERVICE
-- 8000/tcp open  mcp
-- | mcp-info:
-- |   transport: streamable-http
-- |   endpoint: /mcp
-- |   protocolVersion: 2025-06-18
-- |   server: acme-toolserver 1.4.2
-- |   capabilities: logging, prompts, resources, tools
-- |   session: stateful (Mcp-Session-Id issued)
-- |_  auth: NONE (unauthenticated)
--
-- @xmloutput
-- <elem key="transport">streamable-http</elem>
-- <elem key="endpoint">/mcp</elem>
-- <elem key="protocolVersion">2025-06-18</elem>
-- <elem key="server">acme-toolserver 1.4.2</elem>
-- <elem key="auth">NONE (unauthenticated)</elem>

author = "Ben Williams <ben.williams@nccgroup.com>"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe", "version"}

portrule = mcp.portrule

action = function(host, port)
  local opts = mcp.args()
  local out = stdnse.output_table()

  local transport, auth = mcp.connect(host, port, opts)

  if transport then
    out.transport = transport.name
    out.endpoint = transport.endpoint
    if transport.protocol then out.protocolVersion = transport.protocol end
    local si = transport.server_info or {}
    if si.name then
      out.server = si.version and (si.name .. " " .. si.version) or si.name
    end
    if type(transport.capabilities) == "table" then
      local names = {}
      for k in pairs(transport.capabilities) do names[#names + 1] = tostring(k) end
      table.sort(names)
      if #names > 0 then out.capabilities = table.concat(names, ", ") end
    end
    out.session = transport.session_stateful and "stateful (Mcp-Session-Id issued)" or "stateless"
    local authed = opts.token ~= nil
    out.auth = authed and "PROVIDED (Bearer token accepted)" or "NONE (unauthenticated)"

    -- Feed -sV.
    local legacy = transport.name:find("legacy") ~= nil
    port.version.name = "mcp"
    port.version.product = si.name or (legacy and "MCP server (legacy SSE)" or "MCP server")
    if si.version then port.version.version = si.version end
    port.version.extrainfo = "MCP " .. (transport.protocol or "?") ..
      (authed and ", authenticated (token)" or ", unauthenticated")
    nmap.set_port_version(host, port, "hardmatched")

    if transport.close then transport:close() end
    return out
  end

  if auth then
    out.transport = "streamable-http"
    out.endpoint = auth.path
    out.auth = "REQUIRED (OAuth/Bearer)"
    out.www_authenticate = auth.www
    local meta = mcp.fetch_oauth_metadata(host, port, auth.www, opts)
    if meta then
      if meta.resource then out.oauth_resource = meta.resource end
      if meta.authorization_servers then out.oauth_authorization_servers = meta.authorization_servers end
      if meta.scopes then out.oauth_scopes = meta.scopes end
      if meta.bearer_methods then out.oauth_bearer_methods = meta.bearer_methods end
      if meta.metadata_url then out.oauth_metadata_url = meta.metadata_url end
    end
    port.version.name = "mcp"
    port.version.product = "MCP server (auth required)"
    port.version.extrainfo = "OAuth-protected"
    nmap.set_port_version(host, port, "hardmatched")
    return out
  end

  return nil
end
