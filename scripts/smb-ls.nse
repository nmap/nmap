local bit    = require 'bit'
local smb    = require 'smb'
local stdnse = require 'stdnse'
local tab    = require 'tab'
local table = require "table"
local openssl= stdnse.silent_require 'openssl'

description = [[
Attempts to retrieve useful information about files shared on SMB volumes.
The output is intended to resemble the output of the UNIX <code>ls</code> command.
]]

---
-- @usage
-- nmap -p 445 <ip> --script smb-ls --script-args 'share=c$,path=\temp'
--
-- @output
-- Host script results:
-- | smb-ls:
-- |   Directory of \\192.168.56.101\c$\
-- |     2007-12-02 00:20:09  0      AUTOEXEC.BAT
-- |     2007-12-02 00:20:09  0      CONFIG.SYS
-- |     2007-12-02 00:53:39  <DIR>  Documents and Settings
-- |     2009-09-08 13:26:10  <DIR>  e5a6b742d36facb19c5192852c43
-- |     2008-12-01 02:06:29  <DIR>  Inetpub
-- |     2007-02-18 00:31:38  94720  msizap.exe
-- |     2007-12-02 00:55:01  <DIR>  Program Files
-- |     2008-12-01 02:05:52  <DIR>  temp
-- |     2011-12-16 14:40:18  <DIR>  usr
-- |     2007-12-02 00:42:40  <DIR>  WINDOWS
-- |_    2007-12-02 00:22:38  <DIR>  wmpub
--
-- @args smb-ls.share [optional] the share to connect to
-- @args smb-ls.shares [optional] a colon-separated list of shares to connect to
-- @args smb-ls.path [optional] the path, relative to the share to list the contents from
-- @args smb-ls.pattern [optional] the search pattern to execute (default: *)
-- @args smb-ls.maxdepth [optional] the maximum depth to recurse into a directory (default: no recursion)
-- @args smb-ls.maxfiles [optional] return only a certain amount of files
-- @args smb-ls.checksum [optional] download each file and calculate a SHA1 checksum
-- @args smb-ls.errors [optional] report connection errors
--

author = "Patrik Karlsson"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}
dependencies = {"smb-enum-shares"}

local arg_shares   = stdnse.get_script_args(SCRIPT_NAME .. '.shares')
local arg_share    = stdnse.get_script_args(SCRIPT_NAME .. '.share')
local arg_path     = stdnse.get_script_args(SCRIPT_NAME .. '.path') or '\\'
local arg_pattern  = stdnse.get_script_args(SCRIPT_NAME .. '.pattern') or '*'
local arg_maxfiles = tonumber(stdnse.get_script_args(SCRIPT_NAME .. '.maxfiles'))
local arg_maxdepth = stdnse.get_script_args(SCRIPT_NAME .. '.maxdepth')
local arg_checksum = stdnse.get_script_args(SCRIPT_NAME .. '.checksum')
local arg_errors   = stdnse.get_script_args(SCRIPT_NAME .. '.errors')

hostrule = function(host)
  return ( smb.get_port(host) ~= nil and
    (arg_shares or arg_share
    or host.registry['smb_shares'] ~= nil) )
end

-- checks whether the file entry is a directory
local function is_dir(fe)
  return ( bit.band(fe.attrs, 16) == 16 )
end

local function fail(err) return ("\n  ERROR: %s"):format(err or "") end

action = function(host)

  -- give priority to specified shares if specified
  if arg_shares ~= nil then
    arg_shares = stdnse.strsplit(":", arg_shares)
  elseif arg_share ~= nil then
    arg_shares = {arg_share}
  else
    arg_shares = host.registry['smb_shares']
  end

  -- arg_maxdepth defaults to 1 (no recursion)
  if arg_maxdepth == nil then
    arg_maxdepth = 1
  else
    arg_maxdepth = tonumber(arg_maxdepth)
  end

  local output = {}

  for _, share in ipairs(arg_shares) do
    local status, smbstate = smb.start_ex(host, true, true, share,
      nil, nil, nil)
    if ( not(status) ) then
      if arg_errors then
        table.insert(
          output,
          ("Failed to authenticate to server (%s) for directory of \\\\%s\\%s%s"):format(smbstate, stdnse.get_hostname(host), share, arg_path))
        table.insert(output, "")
      end
    else

      table.insert(output, "")

      -- remove leading slash
      arg_path = ( arg_path:sub(1,2) == '\\' and arg_path:sub(2) or arg_path )

      -- fixup checksum argument
      arg_checksum = ( arg_checksum == 'true' or arg_checksum == '1' ) and true or false

      local options = { max_depth = arg_maxdepth, max_files = arg_maxfiles }
      local depth, path, dirs = 0, arg_path, {}
      local file_count, dir_count, total_bytes = 0, 0, 0

      repeat
        -- we need three columns per row, plus one for checksum if
        -- requested
        local lstab = tab.new((arg_checksum and 4 or 3))

        for fe in smb.find_files(smbstate, path .. '\\' .. arg_pattern, options ) do
          if ( arg_checksum and not(is_dir(fe)) ) then
            local status, content = smb.file_read(host, share, path .. '\\' .. fe.fname, nil, {file_create_disposition=1})
            local sha1 = ( status and stdnse.tohex(openssl.sha1(content)) or "" )
            tab.addrow(lstab, fe.created, (is_dir(fe) and '<DIR>' or fe.eof), fe.fname, sha1)
          else
            tab.addrow(lstab, fe.created, (is_dir(fe) and '<DIR>' or fe.eof), fe.fname)
          end

          arg_maxfiles = ( arg_maxfiles and arg_maxfiles - 1 )
          if ( arg_maxfiles == 0 ) then
            break
          end

          if ( is_dir(fe) ) then
            dir_count = dir_count + 1
            if ( fe.fname ~= '.' and fe.fname ~= '..' ) then
              table.insert(dirs, { depth = depth + 1, path = path .. '\\' .. fe.fname } )
            end
          else
            total_bytes = total_bytes + fe.eof
            file_count = file_count + 1
          end
        end
        table.insert(output, { name = ("Directory of %s"):format( '\\\\' .. stdnse.get_hostname(host) .. '\\' .. share .. path), tab.dump(lstab) })

        path = nil
        if ( #dirs ~= 0 ) then
          local dir = table.remove(dirs, 1)
          depth = dir.depth
          if ( not(arg_maxdepth) or ( dir.depth < arg_maxdepth ) ) then
            path = dir.path
            table.insert(output, "")
          end
        end
      until(not(path) or arg_maxfiles == 0)

      smb.stop(smbstate)

      local summary = { name = "Total Files Listed:",
        ("%8d File(s)\t%d bytes"):format(file_count, total_bytes),
      ("%8d Dir(s)"):format(dir_count) }
      table.insert(output, "")
      table.insert(output, summary)
      table.insert(output, "")
    end
  end

  return stdnse.format_output(true, output)
end
