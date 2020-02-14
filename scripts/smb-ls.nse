local smb    = require 'smb'
local string = require 'string'
local stringaux = require "stringaux"
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
-- nmap -p 445 <ip> --script smb-enum-shares,smb-ls
--
-- @args smb-ls.share (or smb-ls.shares) the share (or a colon-separated list
--       of shares) to connect to (default: use shares found by smb-enum-shares)
-- @args smb-ls.path the path, relative to the share to list the contents from
--       (default: root of the share)
-- @args smb-ls.pattern the search pattern to execute (default: *)
-- @args smb-ls.checksum download each file and calculate a checksum
--       (default: false)
--
-- @output
-- Host script results:
-- | smb-ls:
-- |   Volume \\192.168.56.101\c$\
-- |   SIZE   TIME                 FILENAME
-- |   0      2007-12-02 00:20:09  AUTOEXEC.BAT
-- |   0      2007-12-02 00:20:09  CONFIG.SYS
-- |   <DIR>  2007-12-02 00:53:39  Documents and Settings
-- |   <DIR>  2009-09-08 13:26:10  e5a6b742d36facb19c5192852c43
-- |   <DIR>  2008-12-01 02:06:29  Inetpub
-- |   94720  2007-02-18 00:31:38  msizap.exe
-- |   <DIR>  2007-12-02 00:55:01  Program Files
-- |   <DIR>  2008-12-01 02:05:52  temp
-- |   <DIR>  2011-12-16 14:40:18  usr
-- |   <DIR>  2007-12-02 00:42:40  WINDOWS
-- |   <DIR>  2007-12-02 00:22:38  wmpub
-- |_
--
-- @xmloutput
-- <table key="volumes">
--   <table>
--     <table key="files">
--       <table>
--         <elem key="size">0</elem>
--         <elem key="time">2007-12-02 00:20:09</elem>
--         <elem key="filename">AUTOEXEC.BAT</elem>
--       </table>
--       <table>
--         <elem key="size">0</elem>
--         <elem key="time">2007-12-02 00:20:09</elem>
--         <elem key="filename">CONFIG.SYS</elem>
--       </table>
--       <table>
--         <elem key="size">&lt;DIR&gt;</elem>
--         <elem key="time">2007-12-02 00:53:39</elem>
--         <elem key="filename">Documents and Settings</elem>
--       </table>
--       <table>
--         <elem key="size">&lt;DIR&gt;</elem>
--         <elem key="time">2009-09-08 13:26:10</elem>
--         <elem key="filename">e5a6b742d36facb19c5192852c43</elem>
--       </table>
--       <table>
--         <elem key="size">&lt;DIR&gt;</elem>
--         <elem key="time">2008-12-01 02:06:29</elem>
--         <elem key="filename">Inetpub</elem>
--       </table>
--       <table>
--         <elem key="size">94720</elem>
--         <elem key="time">2007-02-18 00:31:38</elem>
--         <elem key="filename">msizap.exe</elem>
--       </table>
--       <table>
--         <elem key="size">&lt;DIR&gt;</elem>
--         <elem key="time">2007-12-02 00:55:01</elem>
--         <elem key="filename">Program Files</elem>
--       </table>
--       <table>
--         <elem key="size">&lt;DIR&gt;</elem>
--         <elem key="time">2008-12-01 02:05:52</elem>
--         <elem key="filename">temp</elem>
--       </table>
--       <table>
--         <elem key="size">&lt;DIR&gt;</elem>
--         <elem key="time">2011-12-16 14:40:18</elem>
--         <elem key="filename">usr</elem>
--       </table>
--       <table>
--         <elem key="size">&lt;DIR&gt;</elem>
--         <elem key="time">2007-12-02 00:42:40</elem>
--         <elem key="filename">WINDOWS</elem>
--       </table>
--       <table>
--         <elem key="size">&lt;DIR&gt;</elem>
--         <elem key="time">2007-12-02 00:22:38</elem>
--         <elem key="filename">wmpub</elem>
--       </table>
--     </table>
--     <elem key="volume">\\192.168.1.2\Downloads</elem>
--   </table>
-- </table>

author = "Patrik Karlsson"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}
dependencies = {"smb-enum-shares"}

local arg_shares   = stdnse.get_script_args(SCRIPT_NAME .. '.shares')
local arg_share    = stdnse.get_script_args(SCRIPT_NAME .. '.share')
local arg_path     = stdnse.get_script_args(SCRIPT_NAME .. '.path') or '\\'
local arg_pattern  = stdnse.get_script_args(SCRIPT_NAME .. '.pattern') or '*'

hostrule = function(host)
  return ( smb.get_port(host) ~= nil and
    (arg_shares or arg_share
    or host.registry['smb_shares'] ~= nil) )
end

-- checks whether the file entry is a directory
local function is_dir(fe)
  return ( (fe.attrs & 16) == 16 )
end

local function list_files(host, share, smbstate, path, options, output, maxdepth, basedir)
  basedir = basedir or ""
  local continue

  for fe in smb.find_files(smbstate, path .. '\\' .. arg_pattern, options) do
    if basedir == "" or (fe.fname ~= "." and fe.fname ~= "..") then
      if ls.config('checksum') and not(is_dir(fe)) then
        local status, content = smb.file_read(host, share, path .. '\\' .. fe.fname, nil, {file_create_disposition=1})
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
      if is_dir(fe) and not (fe.fname == "." or fe.fname == "..") then
        continue = true
        if maxdepth > 0 then
          continue = list_files(host, share, smbstate,
            path .. '\\' .. fe.fname, options,
            output, maxdepth - 1,
            basedir .. fe.fname .. '\\')
        elseif maxdepth < 0 then
          continue = list_files(host, share, smbstate,
            path .. '\\' .. fe.fname, options,
            output, -1,
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
    arg_shares = stringaux.strsplit(":", arg_shares)
  elseif arg_share ~= nil then
    arg_shares = {arg_share}
  else
    arg_shares = host.registry['smb_shares']
  end

  local output = ls.new_listing()

  for _, share in ipairs(arg_shares) do
    stdnse.debug1("Share name:%s", share)
    local status, smbstate = smb.start_ex(host, true, true, share,
      nil, nil, nil)
    if ( not(status) ) then
      ls.report_error(
        output,
        ("Failed to authenticate to server (%s) for directory of \\\\%s\\%s%s"):format(smbstate, stdnse.get_hostname(host), share, arg_path))
    else

      -- remove leading slash
      arg_path = ( arg_path:sub(1,2) == '\\' and arg_path:sub(2) or arg_path )

      local options = {maxfiles = ls.config('maxfiles')}
      local depth, path, dirs = 0, arg_path, {}
      local file_count, dir_count, total_bytes = 0, 0, 0
      local continue = true

      ls.new_vol(
        output,
        share .. path,
        false)
      continue = list_files(host, share, smbstate, path, options,
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

  return ls.end_listing(output)
end
