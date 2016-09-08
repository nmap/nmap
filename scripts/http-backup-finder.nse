local coroutine = require "coroutine"
local http = require "http"
local httpspider = require "httpspider"
local shortport = require "shortport"
local stdnse = require "stdnse"
local table = require "table"
local url = require "url"

description = [[
Spiders a website and attempts to identify backup copies of discovered files.
It does so by requesting a number of different combinations of the filename (eg. index.bak, index.html~, copy of index.html).
]]

---
-- @usage
-- nmap --script=http-backup-finder <target>
--
-- @output
-- PORT   STATE SERVICE REASON
-- 80/tcp open  http    syn-ack
-- | http-backup-finder:
-- | Spidering limited to: maxdepth=3; maxpagecount=20; withindomain=example.com
-- |   http://example.com/index.bak
-- |   http://example.com/login.php~
-- |   http://example.com/index.php~
-- |_  http://example.com/help.bak
--
-- @args http-backup-finder.maxdepth the maximum amount of directories beneath
--       the initial url to spider. A negative value disables the limit.
--       (default: 3)
-- @args http-backup-finder.maxpagecount the maximum amount of pages to visit.
--       A negative value disables the limit (default: 20)
-- @args http-backup-finder.url the url to start spidering. This is a URL
--       relative to the scanned host eg. /default.html (default: /)
-- @args http-backup-finder.withinhost only spider URLs within the same host.
--       (default: true)
-- @args http-backup-finder.withindomain only spider URLs within the same
--       domain. This widens the scope from <code>withinhost</code> and can
--       not be used in combination. (default: false)
--

author = "Patrik Karlsson"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}


portrule = shortport.http

local function backupNames(filename)
  local function createBackupNames()
    local dir = filename:match("^(.*/)") or ""
    local basename, suffix = filename:match("([^/]*)%.(.*)$")

    local backup_names = {}
    if basename then
      table.insert(backup_names, "{basename}.bak") -- generic bak file
    end
    if basename and suffix then
      table.insert(backup_names, "{basename}.{suffix}~") -- emacs
      table.insert(backup_names, "{basename} copy.{suffix}") -- mac copy
      table.insert(backup_names, "Copy of {basename}.{suffix}") -- windows copy
      table.insert(backup_names, "Copy (2) of {basename}.{suffix}") -- windows second copy
      table.insert(backup_names, "{basename}.{suffix}.1") -- generic backup
      table.insert(backup_names, "{basename}.{suffix}.~1~") -- bzr --revert residue

    end

    local replace_patterns = {
      ["{filename}"] = filename,
      ["{basename}"] = basename,
      ["{suffix}"] = suffix,
    }

    for _, name in ipairs(backup_names) do
      local backup_name = name
      for p, v in pairs(replace_patterns) do
        backup_name = backup_name:gsub(p,v)
      end
      coroutine.yield(dir .. backup_name)
    end
  end
  return coroutine.wrap(createBackupNames)
end

action = function(host, port)

  local crawler = httpspider.Crawler:new(host, port, nil, { scriptname = SCRIPT_NAME } )
  crawler:set_timeout(10000)

  -- Identify servers that answer 200 to invalid HTTP requests and exit as these would invalidate the tests
  local status_404, result_404, known_404 = http.identify_404(host,port)
  if ( status_404 and result_404 == 200 ) then
    stdnse.debug1("Exiting due to ambiguous response from web server on %s:%s. All URIs return status 200.", host.ip, port.number)
    return nil
  end

  -- Check if we can use HEAD requests
  local use_head = http.can_use_head(host, port, result_404)

  local backups = {}
  while(true) do
    local status, r = crawler:crawl()
    -- if the crawler fails it can be due to a number of different reasons
    -- most of them are "legitimate" and should not be reason to abort
    if ( not(status) ) then
      if ( r.err ) then
        return stdnse.format_output(false, r.reason)
      else
        break
      end
    end

    -- parse the returned url
    local parsed = url.parse(tostring(r.url))

    -- handle case where only hostname was provided
    if ( parsed.path == nil ) then
      parsed.path = '/'
    end

    -- only pursue links that have something looking as a file
    if ( parsed.path:match(".*%.*.$") ) then
      -- iterate over possible backup files
      for link in backupNames(parsed.path) do
        local host, port = parsed.host, parsed.port

        -- if no port was found, try to deduce it from the scheme
        if ( not(port) ) then
          port = (parsed.scheme == 'https') and 443
          port = port or ((parsed.scheme == 'http') and 80)
        end

        -- the url.escape doesn't work here as it encodes / to %2F
        -- which results in 400 bad request, so we simple do a space
        -- replacement instead.
        local escaped_link = link:gsub(" ", "%%20")

        local response
        if(use_head) then
          response = http.head(host, port, escaped_link, {redirect_ok=false})
        else
          response = http.get(host, port, escaped_link, {redirect_ok=false})
        end

        if http.page_exists(response, result_404, known_404, escaped_link, false) then
          if ( not(parsed.port) ) then
            table.insert(backups,
              ("%s://%s%s"):format(parsed.scheme, host, link))
          else
            table.insert(backups,
              ("%s://%s:%d%s"):format(parsed.scheme, host, port, link))
          end
        end
      end
    end
  end

  if ( #backups > 0 ) then
    backups.name = crawler:getLimitations()
    return stdnse.format_output(true, backups)
  end
end
