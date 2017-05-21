local http = require "http"
local nmap = require "nmap"
local shortport = require "shortport"
local slaxml = require "slaxml"
local stdnse = require "stdnse"
local strbuf = require "strbuf"
local string = require "string"
local table = require "table"

description = [[
Performs XMLRPC Introspection via the system.listMethods method.

If the verbosity is > 1 then the script fetches the response
of system.methodHelp for each method returned by listMethods.
]]

---
-- @args xmlrpc-methods.url The URI path to request.
--
-- @output
-- | xmlrpc-methods:
-- |   Supported Methods:
-- |     list
-- |     system.listMethods
-- |     system.methodHelp
-- |_    system.methodSignature
--
-- @xmloutput
-- <table key="Supported Methods">
--   <elem>list</elem>
--   <elem>system.listMethods</elem>
--   <elem>system.methodHelp</elem>
--   <elem>system.methodSignature</elem>
-- </table>

author = "Gyanendra Mishra"

license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

categories = {"default", "safe", "discovery"}

portrule = shortport.http

local function set_80_columns(t)
  local buffer = strbuf.new()
  for method, description in pairs(t) do
    buffer = (buffer ..  string.format("    %s:\n\n", method))
    local line, ll  = {}, 0
    local add_word = function(word)
      if #word + ll + 1 < 78 then
        table.insert(line, word)
        ll = ll + #word + 1
      else
        buffer = buffer .. stdnse.strjoin(" ", line) .. "\n"
        ll =  #word + 1
        line = {word}
      end
    end
    string.gsub(description, "(%S+)", add_word)
    buffer = buffer .. stdnse.strjoin(" ", line) .. "\n\n"
  end
  return "\n" .. strbuf.dump(buffer)
end

action = function(host, port)

  local url = stdnse.get_script_args(SCRIPT_NAME .. ".url") or "/"
  local data = '<methodCall> <methodName>system.listMethods</methodName> <params></params> </methodCall>'
  local response = http.post(host, port, url, {header = {["Content-Type"] = "application/x-www-form-urlencoded"}}, nil, data )
  if not (response and response.status and response.body) then
    stdnse.debug1("HTTP POST failed")
    return nil
  end
  local output = stdnse.output_table()
  local parser = slaxml.parser:new()

  local under_80 = {
  __tostring = set_80_columns
  }

  if response.status == 200 and response.body:find("<value><string>system.listMethods</string></value>", nil, true)  then

    parser._call = {startElement = function(name)
        parser._call.text = name == "string" and function(content) output["Supported Methods"] = output["Supported Methods"] or {} table.insert(output["Supported Methods"], content)  end end,
        closeElement = function(name) parser._call.text = function() return nil end end
      }
    parser:parseSAX(response.body, {stripWhitespace=true})

    if  nmap.verbosity() > 1 and stdnse.contains(output["Supported Methods"], "system.methodHelp") then
      for i, method in ipairs(output["Supported Methods"]) do
        data = '<methodCall> <methodName>system.methodHelp</methodName> <params> <param><value> <string>' .. method .. '</string> </value></param> </params> </methodCall>'
        response = http.post(host, port, url, {header = {["Content-Type"] = "application/x-www-form-urlencoded"}}, nil, data)
        if response and response.status == 200 then
          parser._call.startElement = function(name)
            parser._call.text = name == "string" and function(content)
              content = parser.unescape(content)
              output["Supported Methods"][i] = nil
              output["Supported Methods"][method] = content
            end
          end
          parser:parseSAX(response.body, {stripWhitespace=true})
        end
        -- useful in cases when the output returned by the above request is empty
        -- or the <value><string></string></value> has no text in the string
        -- element.
        if output["Supported Methods"][i] then
          output["Supported Methods"][i] = nil
          output["Supported Methods"][method] = "Empty system.methodHelp output."
        end
      end
      setmetatable(output["Supported Methods"], under_80)
    end
    return output
  elseif response.body:find("<name>faultCode</name>", nil, true) then
    output.error = "XMLRPC instance doesn't support introspection."
    return output, output.error
  end
end

