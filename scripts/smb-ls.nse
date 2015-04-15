local bit    = require 'bit'
local smb    = require 'smb'
local stdnse = require 'stdnse'
local ls     = require 'ls'

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

local function list_files(smbstate, path, options, output, maxdepth, basedir)
  basedir = basedir or ""
  local continue

  for fe in smb.find_files(smbstate, path .. '\\' .. ls.config("pattern"),
                           options) do
    if basedir == "" or (fe.fname ~= "." and fe.fname ~= "..") then
      if ls.config('checksum') and not(is_dir(fe)) then
        local status, content = smb.file_read(host, share,
                                              path .. '\\' .. fe.fname,
                                              nil, {file_create_disposition=1})
        local sha1 = status and stdnse.tohex(openssl.sha1(content)) or ""
        continue = ls.add_file(output, {is_dir(fe) and '<DIR>' or fe.eof,
                                        fe.created, basedir .. fe.fname, sha1})
      else
        continue = ls.add_file(output, {is_dir(fe) and '<DIR>' or fe.eof,
                                        fe.created, basedir .. fe.fname})
      end
      if not continue then
        return false
      end
      if is_dir(fe) then
        continue = true
        if maxdepth > 1 then
          stdnse.debug1("YYY " .. tostring(maxdepth))
          continue = list_files(smbstate, path .. '\\' .. fe.fname, options,
                                output, maxdepth - 1,
                                basedir .. fe.fname .. '\\')
        elseif maxdepth == 0 then
          continue = list_files(smbstate, path .. '\\' .. fe.fname, options,
                                output, 0,
                                basedir .. fe.fname .. '\\')
        end
        if not continue then
          return false
        end
      end
    end
  end
  return true
end

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

  local output = ls.new_listing()

  for _, share in ipairs(arg_shares) do
     local status, smbstate = smb.start_ex(host, true, true, share,
                                           nil, nil, nil)
     if ( not(status) ) then
        if arg_errors then
           ls.report_error(
              output,
              ("Failed to authenticate to server (%s) for directory of \\\\%s\\%s%s"):format(smbstate, stdnse.get_hostname(host), share, arg_path))
        end
     else

        -- remove leading slash
        arg_path = ( arg_path:sub(1,2) == '\\' and arg_path:sub(2) or arg_path )

        -- local options = { max_depth = arg_maxdepth, max_files = arg_maxfiles }
        local options = {}
        local depth, path, dirs = 0, arg_path, {}
        local file_count, dir_count, total_bytes = 0, 0, 0
        local continue = true

        ls.new_vol(
          output,
          '\\\\' .. stdnse.get_hostname(host) .. '\\' .. share .. path,
          false)
        continue = list_files(smbstate, path, options,
                              output, ls.config('maxdepth'))
        if not continue then
          ls.report_info(
            output,
            string.format("maxfiles limit reached (%d)", ls.config('maxfiles')))
        end
        ls.end_vol(output)
        smb.stop(smbstate)
     end
  end

  ls.end_listing(output)
  return output
end
