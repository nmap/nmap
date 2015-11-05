local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local ls = require "ls"
local have_ssl, openssl = pcall(require,'openssl')

description = [[
Shows the content of an "index" Web page.

TODO:
  - add support for more page formats
]]

author = "Pierre Lalet"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"default", "discovery", "safe"}

---
-- @usage
-- nmap -n -p 80 --script http-ls test-debit.free.fr
--
-- @args http-ls.checksum compute a checksum for each listed file. Requires OpenSSL.
--       (default: false)
-- @args http-ls.url base URL path to use (default: /)
--
-- @output
-- PORT   STATE SERVICE
-- 80/tcp open  http
-- | http-ls:
-- | Volume /
-- | maxfiles limit reached (10)
-- | SIZE        TIME               FILENAME
-- | 524288      02-Oct-2013 18:26  512.rnd
-- | 1048576     02-Oct-2013 18:26  1024.rnd
-- | 2097152     02-Oct-2013 18:26  2048.rnd
-- | 4194304     02-Oct-2013 18:26  4096.rnd
-- | 8388608     02-Oct-2013 18:26  8192.rnd
-- | 16777216    02-Oct-2013 18:26  16384.rnd
-- | 33554432    02-Oct-2013 18:26  32768.rnd
-- | 67108864    02-Oct-2013 18:26  65536.rnd
-- | 1073741824  03-Oct-2013 16:46  1048576.rnd
-- | 188         03-Oct-2013 17:15  README.html
-- |_
--
-- @xmloutput
-- <table key="volumes">
--   <table>
--     <elem key="volume">/</elem>
--     <table key="files">
--       <table>
--         <elem key="size">524288</elem>
--         <elem key="time">02-Oct-2013 18:26</elem>
--         <elem key="filename">512.rnd</elem>
--       </table>
--       <table>
--         <elem key="size">1048576</elem>
--         <elem key="time">02-Oct-2013 18:26</elem>
--         <elem key="filename">1024.rnd</elem>
--       </table>
--       <table>
--         <elem key="size">2097152</elem>
--         <elem key="time">02-Oct-2013 18:26</elem>
--         <elem key="filename">2048.rnd</elem>
--       </table>
--       <table>
--         <elem key="size">4194304</elem>
--         <elem key="time">02-Oct-2013 18:26</elem>
--         <elem key="filename">4096.rnd</elem>
--       </table>
--       <table>
--         <elem key="size">8388608</elem>
--         <elem key="time">02-Oct-2013 18:26</elem>
--         <elem key="filename">8192.rnd</elem>
--       </table>
--       <table>
--         <elem key="size">16777216</elem>
--         <elem key="time">02-Oct-2013 18:26</elem>
--         <elem key="filename">16384.rnd</elem>
--       </table>
--       <table>
--         <elem key="size">33554432</elem>
--         <elem key="time">02-Oct-2013 18:26</elem>
--         <elem key="filename">32768.rnd</elem>
--       </table>
--       <table>
--         <elem key="size">67108864</elem>
--         <elem key="time">02-Oct-2013 18:26</elem>
--         <elem key="filename">65536.rnd</elem>
--       </table>
--       <table>
--         <elem key="size">1073741824</elem>
--         <elem key="time">03-Oct-2013 16:46</elem>
--         <elem key="filename">1048576.rnd</elem>
--       </table>
--       <table>
--         <elem key="size">188</elem>
--         <elem key="time">03-Oct-2013 17:15</elem>
--         <elem key="filename">README.html</elem>
--       </table>
--     </table>
--     <table key="info">
--       <elem>maxfiles limit reached (10)</elem>
--     </table>
--   </table>
-- </table>
-- <table key="total">
--   <elem key="files">10</elem>
--   <elem key="bytes">1207435452</elem>
-- </table>

portrule = shortport.http

local function isdir(fname, size)
  -- we consider a file is (probably) a directory if its name
  -- terminates with a '/' or if the string representing its size is
  -- either empty or a single dash ('-').
  if string.sub(fname, -1, -1) == '/' then
    return true
  end
  if size == '' or size == '-' then
    return true
  end
  return false
end

local function list_files(host, port, url, output, maxdepth, basedir)
  basedir = basedir or ""

  local resp = http.get(host, port, url)

  if resp.location or not resp.body then
    return true
  end

  if not string.match(resp.body, "<[Tt][Ii][Tt][Ll][Ee][^>]*> *[Ii][Nn][Dd][Ee][Xx] +[Oo][Ff]") then
    return true
  end

  local patterns = {
    '<[Aa] [Hh][Rr][Ee][Ff]="([^"]+)">[^<]+</[Aa]></[Tt][Dd]><[Tt][Dd][^>]*> *([0-9]+-[A-Za-z0-9]+-[0-9]+ [0-9]+:[0-9]+) *</[Tt][Dd]><[Tt][Dd][^>]*> *([^<]+)</[Tt][Dd]>',
    '<[Aa] [Hh][Rr][Ee][Ff]="([^"]+)">[^<]+</[Aa]> *([0-9]+-[A-Za-z0-9]+-[0-9]+ [0-9]+:[0-9]+) *([^ \r\n]+)',
  }
  for _, pattern in ipairs(patterns) do
    for fname, date, size in string.gmatch(resp.body, pattern) do
      local continue = true
      local directory = isdir(fname, size)
      if have_ssl and ls.config('checksum') and not directory then
        local checksum = ""
        local resp = http.get(host, port, url .. fname)
        if not resp.location and resp.body then
          checksum = stdnse.tohex(openssl.sha1(resp.body))
        end
        continue = ls.add_file(output, {size, date, basedir .. fname, checksum})
      else
        continue = ls.add_file(output, {size, date, basedir .. fname})
      end
      if not continue then
        return false
      end
      if directory then
        if string.sub(fname, -1, -1) ~= "/" then fname = fname .. '/' end
        continue = true
        if maxdepth > 0 then
          continue = list_files(host, port, url .. fname, output, maxdepth - 1,
            basedir .. fname)
        elseif maxdepth < 0 then
          continue = list_files(host, port, url .. fname, output, -1,
            basedir .. fname)
        end
        if not continue then
          return false
        end
      end
    end
  end
  return true
end

action = function(host, port)
  local url = stdnse.get_script_args(SCRIPT_NAME .. '.url') or "/"

  local output = ls.new_listing()
  ls.new_vol(output, url, false)
  local continue = list_files(host, port, url, output, ls.config('maxdepth'))
  if not continue then
    ls.report_info(
      output,
      string.format("maxfiles limit reached (%d)", ls.config('maxfiles')))
  end
  ls.end_vol(output)
  return ls.end_listing(output)
end
