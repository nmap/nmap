local datafiles = require "datafiles"
local http = require "http"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local url = require "url"

local openssl = stdnse.silent_require "openssl"

description = [[
Gets the favicon ("favorites icon") from a web page and matches it against a
database of the icons of known web applications. If there is a match, the name
of the application is printed; otherwise the MD5 hash of the icon data is
printed.

If the script argument <code>favicon.uri</code> is given, that relative URI is
always used to find the favicon. Otherwise, first the page at the root of the
web server is retrieved and parsed for a <code><link rel="icon"></code>
element. If that fails, the icon is looked for in <code>/favicon.ico</code>. If
a <code><link></code> favicon points to a different host or port, it is ignored.
]]

---
-- @args favicon.uri URI that will be requested for favicon.
-- @args favicon.root Web server path to search for favicon.
--
-- @usage
-- nmap --script=http-favicon.nse \
--    --script-args favicon.root=<root>,favicon.uri=<uri>
-- @output
-- |_ http-favicon: Socialtext

-- HTTP default favicon enumeration script
-- rev 1.2 (2009-03-11)
-- Original NASL script by Javier Fernandez-Sanguino Pena


author = "Vlatko Kosturjak"

license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

categories = {"default", "discovery", "safe"}


portrule = shortport.http

action = function(host, port)
  local md5sum,answer
  local match
  local status, favicondb
  local result
  local favicondbfile="nselib/data/favicon-db"
  local index, icon
  local root = ""

  status, favicondb = datafiles.parse_file( favicondbfile, {["^%s*([^%s#:]+)[%s:]+"] = "^%s*[^%s#:]+[%s:]+(.*)"})
  if not status then
    stdnse.debug1("Could not open file: %s", favicondbfile )
    return
  end

  if(stdnse.get_script_args('favicon.root')) then
    root = stdnse.get_script_args('favicon.root')
  end
  local favicon_uri = stdnse.get_script_args("favicon.uri")
  if(favicon_uri) then
    -- If we got a script arg URI, always use that.
    answer = http.get( host, port, root .. "/" .. favicon_uri)
    stdnse.debug4("Using URI %s", favicon_uri)
  else
    -- Otherwise, first try parsing the home page.
    index = http.get( host, port, root .. "/" )
    if index.status == 200 or index.status == 503 then
      -- find the favicon pattern
      icon = parseIcon( index.body )
      -- if we find a pattern
      if icon then
        local hostname = host.targetname or (host.name ~= "" and host.name) or host.ip
        stdnse.debug1("Got icon URL %s.", icon)
        local icon_host, icon_port, icon_path = parse_url_relative(icon, hostname, port.number, root)
        if (icon_host == host.ip or
          icon_host == host.targetname or
          icon_host == (host.name ~= '' and host.name)) and
          icon_port == port.number then
          -- request the favicon
          answer = http.get( icon_host, icon_port, icon_path )
        else
          answer = nil
        end
      else
        answer = nil
      end
    end

    -- If that didn't work, try /favicon.ico.
    if not answer or answer.status ~= 200 then
      answer = http.get( host, port, root .. "/favicon.ico" )
      stdnse.debug4("Using default URI.")
    end
  end

  --- check for 200 response code
  if answer and answer.status == 200 then
    md5sum=string.upper(stdnse.tohex(openssl.md5(answer.body)))
    match=favicondb[md5sum]
    if match then
      result = match
    else
      if nmap.verbosity() > 0 then
        result = "Unknown favicon MD5: " .. md5sum
      end
    end
  else
    stdnse.debug1("No favicon found.")
    return
  end --- status == 200
  return result
end

local function dirname(path)
  local dir
  dir = string.match(path, "^(.*)/")
  return dir or ""
end

-- Return a URL's host, port, and path, filling in the results with the given
-- host, port, and path if the URL is relative. Return nil if the scheme is not
-- "http" or "https".
function parse_url_relative(u, host, port, path)
  local defaultport, scheme, abspath
  u = url.parse(u)
  scheme = u.scheme or "http"
  if scheme == "http" then
    defaultport = 80
  elseif scheme == "https" then
    defaultport = 443
  else
    return nil
  end
  abspath = u.path or ""
  if not string.find(abspath, "^/") then
    abspath = dirname(path) .. "/" .. abspath
  end
  return u.host or host, u.port or defaultport, abspath
end

function parseIcon( body )
  local _, i, j
  local rel, href, word

  -- Loop through link elements.
  i = 0
  while i do
    _, i = string.find(body, "<%s*[Ll][Ii][Nn][Kk]%s", i + 1)
    if not i then
      return nil
    end
    -- Loop through attributes.
    j = i
    while true do
      local name, quote, value
      _, j, name, quote, value = string.find(body, "^%s*(%w+)%s*=%s*([\"'])(.-)%2", j + 1)
      if not j then
        break
      end
      if string.lower(name) == "rel" then
        rel = value
      elseif string.lower(name) == "href" then
        href = value
      end
    end
    for word in string.gmatch(rel or "", "%S+") do
      if string.lower(word) == "icon" then
        return href
      end
    end
  end
end
