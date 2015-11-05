local afp = require "afp"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local ls = require "ls"

description = [[
Attempts to get useful information about files from AFP volumes.
The output is intended to resemble the output of <code>ls</code>.
]]

---
--
-- @usage
-- nmap -sS -sV -p 548 --script=afp-ls target
--
-- @output
-- PORT    STATE SERVICE
-- 548/tcp open  afp     syn-ack
-- | afp-ls:
-- |   Information retrieved as patrik
-- |   Volume Macintosh HD
-- |   maxfiles limit reached (10)
-- |   PERMISSION  UID  GID  SIZE    TIME              FILENAME
-- |   -rw-r--r--  501  80   15364   2010-06-13 17:52  .DS_Store
-- |   ----------  0    80   0       2009-10-05 07:42  .file
-- |   drwx------  501  20   0       2009-11-04 17:28  .fseventsd
-- |   -rw-------  0    0    393216  2010-06-14 01:49  .hotfiles.btree
-- |   drwx------  0    80   0       2009-11-04 18:19  .Spotlight-V100
-- |   d-wx-wx-wx  0    80   0       2009-11-04 18:25  .Trashes
-- |   drwxr-xr-x  0    0    0       2009-05-18 21:29  .vol
-- |   drwxrwxr-x  0    80   0       2009-04-28 00:06  Applications
-- |   drwxr-xr-x  0    0    0       2009-05-18 21:43  bin
-- |   drwxr-xr-x  501  80   0       2010-08-10 22:55  bundles
-- |
-- |   Volume Patrik Karlsson's Public Folder
-- |   PERMISSION  UID  GID  SIZE  TIME              FILENAME
-- |   -rw-------  501  20   6148  2010-12-27 23:45  .DS_Store
-- |   -rw-r--r--  501  20   0     2007-07-24 21:17  .localized
-- |   drwx-wx-wx  501  20   0     2009-06-19 04:01  Drop Box
-- |
-- |   Volume patrik
-- |   maxfiles limit reached (10)
-- |   PERMISSION  UID  GID  SIZE   TIME              FILENAME
-- |   -rw-------  501  20   11281  2010-06-14 22:51  .bash_history
-- |   -rw-r--r--  501  20   33     2011-01-19 20:11  .bashrc
-- |   -rw-------  501  20   3      2007-07-24 21:17  .CFUserTextEncoding
-- |   drwx------  501  20   0      2010-09-12 14:52  .config
-- |   drwx------  501  20   0      2010-09-12 12:29  .cups
-- |   -rw-r--r--  501  20   15364  2010-06-13 18:34  .DS_Store
-- |   drwxr-xr-x  501  20   0      2010-09-12 14:13  .fontconfig
-- |   -rw-------  501  20   102    2010-06-14 01:46  .lesshst
-- |   -rw-r--r--  501  20   241    2010-06-14 01:45  .profile
-- |   -rw-------  501  20   218    2010-09-12 16:35  .recently-used.xbel
-- |_
--
-- @xmloutput
-- <table key="volumes">
--   <table>
--     <elem key="volume">Storage01</elem>
--     <table key="files">
--       <table>
--         <elem key="permission">drwx-&#45;&#45;&#45;&#45;&#45;</elem>
--         <elem key="uid">0</elem>
--         <elem key="gid">100</elem>
--         <elem key="size">0</elem>
--         <elem key="time">2015-06-26 17:17</elem>
--         <elem key="filename">Backups</elem>
--       </table>
--       <table>
--         <elem key="permission">drwxr-xr-x</elem>
--         <elem key="uid">0</elem>
--         <elem key="gid">37</elem>
--         <elem key="size">0</elem>
--         <elem key="time">2015-06-19 06:36</elem>
--         <elem key="filename">Network Trash Folder</elem>
--       </table>
--       <table>
--         <elem key="permission">drwxr-xr-x</elem>
--         <elem key="uid">0</elem>
--         <elem key="gid">37</elem>
--         <elem key="size">0</elem>
--         <elem key="time">2015-06-19 06:36</elem>
--         <elem key="filename">Temporary Items</elem>
--       </table>
--     </table>
--   </table>
-- </table>
-- <table key="info">
--   <elem>information retrieved as nil</elem>
-- </table>
-- <table key="total">
--   <elem key="files">3</elem>
--   <elem key="bytes">0</elem>
-- </table>

-- Version 0.1
-- Created 04/03/2011 - v0.1 - created by Patrik Karlsson


author = "Patrik Karlsson"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}
dependencies = {"afp-brute"}

portrule = shortport.port_or_service(548, {"afp"})

action = function(host, port)

  local afpHelper = afp.Helper:new()
  local args = nmap.registry.args
  local users = nmap.registry.afp or { ['nil'] = 'nil' }
  local maxfiles = ls.config("maxfiles")
  local output = ls.new_listing()

  if ( args['afp.username'] ) then
    users = {}
    users[args['afp.username']] = args['afp.password']
  end

  for username, password in pairs(users) do

    local status, response = afpHelper:OpenSession(host, port)
    if ( not status ) then
      stdnse.debug1("%s", response)
      return
    end

    -- if we have a username attempt to authenticate as the user
    -- Attempt to use No User Authentication?
    if ( username ~= 'nil' ) then
      status, response = afpHelper:Login(username, password)
    else
      status, response = afpHelper:Login()
    end

    if ( not status ) then
      stdnse.debug1("Login failed")
      stdnse.debug3("Login error: %s", response)
      return
    end

    local vols
    status, vols = afpHelper:ListShares()

    if status then
      for _, vol in ipairs( vols ) do
        local status, tbl = afpHelper:Dir( vol )
        if ( not(status) ) then
          ls.report_error(
            output,
            ("ERROR: Failed to list the contents of %s"):format(vol))
        else
          ls.new_vol(output, vol, true)
          local continue = true
          for _, item in ipairs(tbl[1]) do
            if ( item and item.name ) then
              local status, result = afpHelper:GetFileUnixPermissions(
                vol, item.name)
              if ( status ) then
                local status, fsize = afpHelper:GetFileSize( vol, item.name)
                if ( not(status) ) then
                  ls.report_error(
                    output,
                    ("ERROR: Failed to retrieve file size for %/%s"):format(vol, item.name))
                else
                  local status, date = afpHelper:GetFileDates( vol, item.name)
                  if ( not(status) ) then
                    ls.report_error(
                      output,
                      ("\n\nERROR: Failed to retrieve file dates for %/%s"):format(vol, item.name))
                  else
                    continue = ls.add_file(output, {
                        result.privs, result.uid, result.gid,
                        fsize, date.create, item.name
                      })
                  end
                end
              end
            end
            if not continue then
              ls.report_info(output, ("maxfiles limit reached (%d)"):format(maxfiles))
              break
            end
          end
          ls.end_vol(output)
        end
      end
    end

    status, response = afpHelper:Logout()
    status, response = afpHelper:CloseSession()

    -- stop after first successful attempt
    if #output["volumes"] > 0 then
      ls.report_info(output, ("information retrieved as %s"):format(username))
      return ls.end_listing(output)
    end
  end
  return
end
