local mcp = require "mcp"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

description = [[
Enumerates the attack surface of a Model Context Protocol (MCP) server over HTTP(S),
across both the current Streamable HTTP transport and the legacy HTTP+SSE transport.

After completing the MCP `initialize` handshake the script invokes the read-only listing
methods `tools/list`, `resources/list`, `resources/templates/list`, and `prompts/list`.
It reports each tool's name, description, and input-parameter names; resource URIs; and
prompt names. Each tool is risk-assessed across its name, description, AND its JSON input
schema -- free-form parameters (string/array/object without an enum) named or described
like commands, file paths, URLs/hosts, SQL, or secrets are flagged even when the tool's
name and description look benign. Findings are bucketed into categories (code-exec,
file-access, network/ssrf, sql/db, secrets, privileged); risk-contributing parameters are
marked with a trailing `*`. If the server answered the handshake with no authentication,
an unauthenticated-exposure security finding is emitted.

Transport handling (shared with the `mcp` nselib):
* Streamable HTTP - carries any issued `Mcp-Session-Id` and the negotiated
  `MCP-Protocol-Version` header; parses both application/json and text/event-stream.
* Legacy HTTP+SSE (2024-11-05) - opens the SSE stream with a raw socket, reads the
  `endpoint` event, POSTs JSON-RPC to the message endpoint, and correlates the
  asynchronous responses delivered back on the SSE stream by JSON-RPC id.

This script is read-only: it never calls `tools/call`, so no server-side tool is actually
executed. Run `mcp-info` first/alongside for transport and version fingerprinting.
]]

---
-- @usage nmap -p 8000 --script mcp-enum <target>
-- @usage nmap -sV --script "mcp-info,mcp-enum" -p- <target>
-- @usage nmap --script mcp-enum --script-args mcp.paths=/mcp,mcp-enum.schemas=true <target>
--
-- @args mcp.paths          Comma-separated endpoint paths to probe.
-- @args mcp.timeout        HTTP/socket timeout in ms (default 7000).
-- @args mcp.ua             User-Agent to send (default a neutral browser UA).
-- @args mcp.sse_path       Legacy SSE path to probe (default /sse).
-- @args mcp-enum.schemas   If true, dump each tool's full JSON input schema.
--
-- @output
-- | mcp-enum:
-- |   transport: streamable-http
-- |   server: acme-toolserver 1.4.2 (protocol 2025-06-18)
-- |   tools (4):
-- |     run_command [RISK: code-exec] - Execute a shell command on the host  (params: cmd*)
-- |     read_file [RISK: file-access] - Read a file from disk  (params: path*)
-- |     search_web - Search the web  (params: q)
-- |     get_weather - Get the weather for a city  (params: city)
-- |   resources (2): file:///etc/, db://customers
-- |   prompts (1): summarize
-- |_  SECURITY: unauthenticated server exposes 2 risky tool(s) [code-exec, file-access]: run_command, read_file
--
-- @xmloutput
-- <elem key="transport">streamable-http</elem>
-- <elem key="server">acme-toolserver 1.4.2 (protocol 2025-06-18)</elem>
-- <table key="tools (4)">
--   <elem>run_command [RISK: code-exec] - Execute a shell command on the host  (params: cmd*)</elem>
--   <elem>read_file [RISK: file-access] - Read a file from disk  (params: path*)</elem>
--   <elem>search_web - Search the web  (params: q)</elem>
--   <elem>get_weather - Get the weather for a city  (params: city)</elem>
-- </table>
-- <table key="resources (2)">
--   <elem>file:///etc/</elem>
--   <elem>db://customers</elem>
-- </table>
-- <table key="prompts (1)">
--   <elem>summarize</elem>
-- </table>
-- <elem key="SECURITY">unauthenticated server exposes 2 risky tool(s) [code-exec, file-access]: run_command, read_file</elem>

author = "Ben Williams <ben.williams@nccgroup.com>"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

portrule = mcp.portrule

action = function(host, port)
  local opts = mcp.args()
  local transport = (mcp.connect(host, port, opts))
  if not transport then
    return nil
  end

  local data = mcp.enumerate(transport, opts)
  if transport.close then transport:close() end

  local out = stdnse.output_table()
  out.transport = data.transport
  local si = data.server_info or {}
  if si.name then
    out.server = (si.version and (si.name .. " " .. si.version) or si.name) ..
      " (protocol " .. (data.protocol or "?") .. ")"
  end

  if #data.tools > 0 then
    local lines = {}
    for _, t in ipairs(data.tools) do
      local line = t.name
      if t.dangerous then
        line = line .. " [RISK: " .. table.concat(t.categories, ", ") .. "]"
      end
      if t.description ~= "" then line = line .. " - " .. t.description:gsub("%s+", " ") end
      if opts.schemas and t.schema then
        line = line .. "  schema=" .. (mcp.gen(t.schema) or "?")
      elseif #t.params > 0 then
        -- mark risk-contributing params with a trailing *
        local marked = {}
        for _, p in ipairs(t.params) do
          marked[#marked + 1] = (t.risky_params and t.risky_params[p]) and (p .. "*") or p
        end
        line = line .. "  (params: " .. table.concat(marked, ", ") .. ")"
      end
      lines[#lines + 1] = line
    end
    out["tools (" .. #data.tools .. ")"] = lines
  end

  if #data.resources > 0 then
    out["resources (" .. #data.resources .. ")"] = data.resources
  end
  if #data.prompts > 0 then
    out["prompts (" .. #data.prompts .. ")"] = data.prompts
  end

  if not data.authenticated then
    if #data.dangerous > 0 then
      local cats = (data.categories and #data.categories > 0)
        and (" [" .. table.concat(data.categories, ", ") .. "]") or ""
      out.SECURITY = string.format(
        "unauthenticated server exposes %d risky tool(s)%s: %s",
        #data.dangerous, cats, table.concat(data.dangerous, ", "))
    else
      out.SECURITY = "unauthenticated MCP server (no credentials required to enumerate)"
    end
  end

  return out
end
