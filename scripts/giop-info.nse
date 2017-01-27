local giop = require "giop"
local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Queries a CORBA naming server for a list of objects.
]]

author = "Patrik Karlsson"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"default", "discovery", "safe"}

---
-- @output
-- PORT     STATE SERVICE              REASON
-- 1050/tcp open  java-or-OTGfileshare syn-ack
-- | giop-info:
-- |   Object: Hello
-- |   Context: Test
-- |_  Object: GoodBye
--
-- @xmloutput
-- <table>
--   <enum key="enum">0</enum>
--   <enum key="id">Hello</enum>
--   <enum key="kind">18</enum>
-- </table>
-- <table>
--   <enum key="enum">1</enum>
--   <enum key="id">Test</enum>
--   <enum key="kind">0</enum>
-- </table>
-- <table>
--   <enum key="enum">0</enum>
--   <enum key="id">Goodbye</enum>
--   <enum key="kind">18</enum>
-- </table>


-- Version 0.1

-- Created 07/08/2010 - v0.1 - created by Patrik Karlsson <patrik@cqure.net>


portrule = shortport.port_or_service( {2809,1050,1049} , "giop", "tcp", "open")

local fmt_meta = {
  __tostring = function (t)
    local tmp = "Unknown"
    if ( t.enum == 0 ) then
      tmp = "Object"
    elseif( t.enum == 1 ) then
      tmp = "Context"
    end

    -- TODO: Handle t.kind? May require IDL.
    return ("%s: %s"):format(tmp, t.id)
  end
}

local function fail (err) return stdnse.format_output(false, err) end
action = function(host, port)

  local helper = giop.Helper:new( host, port )
  local ctx, objs, status, err

  status, err = helper:Connect()
  if ( not(status) ) then return err end

  status, ctx = helper:GetNamingContext()
  if ( not(status) ) then return fail(ctx) end

  status, objs = helper:ListObjects(ctx)
  if ( not(status) ) then return fail(objs) end

  for _, obj in ipairs( objs ) do
    setmetatable(obj, fmt_meta)
  end

  return objs
end
