local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

description = [[
Lists files and directories at the root of a gopher service.
]]

---
-- @usage
-- nmap -p 70 --script gopher-ls --script-args gopher-ls.maxfiles=100 <target>
--
-- @output
-- 70/tcp open  gopher
-- | gopher-ls:
-- | [txt] /gresearch.txt "Gopher, the next big thing?"
-- | [dir] /taxf "Tax Forms"
-- |_Only 2 shown. Use --script-args gopher-ls.maxfiles=-1 to see all.
--
-- @args gopher-ls.maxfiles If set, limits the amount of files returned by
--       the script. If set to 0 or less, all files are shown. The default
--       value is 10.


author = "Toni Ruottu"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"default", "discovery", "safe"}


portrule = shortport.port_or_service (70, "gopher", {"tcp"})

local function typelabel(gtype)
  if gtype == "0" then
    return "[txt]"
  end
  if gtype == "1" then
    return "[dir]"
  end
  return string.format("[%s]", gtype)

end

action = function( host, port )

  local INFO = "i"
  local maxfiles = stdnse.get_script_args(SCRIPT_NAME..".maxfiles")
  if not maxfiles then
    maxfiles = 10
  else
    maxfiles = tonumber(maxfiles)
  end
  if maxfiles < 1 then
    maxfiles = nil
  end

  local socket = nmap.new_socket()
  local status, err = socket:connect(host, port)
  if not status then
    return
  end

  socket:send("\r\n")

  local buffer, _ = stdnse.make_buffer(socket, "\r\n")
  local line = buffer()
  local files = {}

  while line ~= nil do
    if #line > 1 then
      local gtype = string.sub(line, 1, 1)
      local fields = stdnse.strsplit("\t", string.sub(line, 2))
      if #fields > 1 then
        local label = fields[1]
        local filename = fields[2]
        if gtype ~= INFO then
          if maxfiles and #files >= maxfiles then
            table.insert(files, string.format('Only %d shown. Use --script-args %s.maxfiles=-1 to see all.', maxfiles, SCRIPT_NAME))
            break
          else
            table.insert(files, string.format('%s %s "%s"', typelabel(gtype), filename, label))
          end
        end
      end
    end
    line = buffer()
  end
  return "\n" .. stdnse.strjoin("\n", files)
end

