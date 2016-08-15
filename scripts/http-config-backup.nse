local coroutine = require "coroutine"
local http = require "http"
local io = require "io"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"
local url = require "url"

description = [[
Checks for backups and swap files of common content management system
and web server configuration files.

When web server files are edited in place, the text editor can leave
backup or swap files in a place where the web server can serve them. The
script checks for these files:

* <code>wp-config.php</code>: WordPress
* <code>config.php</code>: phpBB, ExpressionEngine
* <code>configuration.php</code>: Joomla
* <code>LocalSettings.php</code>: MediaWiki
* <code>/mediawiki/LocalSettings.php</code>: MediaWiki
* <code>mt-config.cgi</code>: Movable Type
* <code>mt-static/mt-config.cgi</code>: Movable Type
* <code>settings.php</code>: Drupal
* <code>.htaccess</code>: Apache

And for each of these file applies the following transformations (using
<code>config.php</code> as an example):

* <code>config.bak</code>: Generic backup.
* <code>config.php.bak</code>: Generic backup.
* <code>config.php~</code>: Vim, Gedit.
* <code>#config.php#</code>: Emacs.
* <code>config copy.php</code>: Mac OS copy.
* <code>Copy of config.php</code>: Windows copy.
* <code>config.php.save</code>: GNU Nano.
* <code>.config.php.swp</code>: Vim swap.
* <code>config.php.swp</code>: Vim swap.
* <code>config.php.old</code>: Generic backup.

This script is inspired by the CMSploit program by Feross Aboukhadijeh:
http://www.feross.org/cmsploit/.
]];

---
-- @usage
-- nmap --script=http-config-backup <target>
--
-- @output
-- PORT   STATE SERVICE REASON
-- 80/tcp open  http    syn-ack
-- | http-config-backup:
-- |   /%23wp-config.php%23 HTTP/1.1 200 OK
-- |_  /config.php~ HTTP/1.1 200 OK
--
-- @args http-config-backup.path the path where the CMS is installed
-- @args http-config-backup.save directory to save all the valid config files found
--

author = "Riccardo Cecolin";
license = "Same as Nmap--See https://nmap.org/book/man-legal.html";
categories = { "auth", "intrusive" };


portrule = shortport.http;

local function make_grep(pattern)
  return function(s)
    return string.match(s, pattern)
  end
end

local grep_php = make_grep("<%?php");
local grep_cgipath = make_grep("CGIPath");

local function check_htaccess(s)
  return string.match("<Files") or string.match(s, "RewriteRule")
end

local CONFIGS = {
  { filename = "wp-config.php", check = grep_php }, -- WordPress
  { filename = "config.php", check = grep_php }, -- phpBB, ExpressionEngine
  { filename = "configuration.php", check = grep_php }, -- Joomla
  { filename = "LocalSettings.php", check = grep_php }, -- MediaWiki
  { filename = "/mediawiki/LocalSettings.php", check = grep_php }, -- MediaWiki
  { filename = "mt-config.cgi", check = grep_cgipath }, -- Movable Type
  { filename = "mt-static/mt-config.cgi", check = grep_cgipath }, -- Movable Type
  { filename = "settings.php", check = grep_php }, -- Drupal
  { filename = ".htaccess", check = check_htaccess }, -- Apache
};

-- Return directory, filename pair. directory may be empty.
local function splitdir(path)
  local dir, filename

  dir, filename = string.match(path, "^(.*/)(.*)$")
  if not dir then
    dir = ""
    filename = path
  end

  return dir, filename
end

-- Return basename, extension pair. extension may be empty.
local function splitext(filename)
  local base, ext;

  base, ext = string.match(filename, "^(.+)(%..+)")
  if not base then
    base = filename
    ext = ""
  end

  return base, ext
end

-- Functions mangling filenames.
local TRANSFORMS = {
  function(fn)
    local base, ext = splitext(fn);
    if ext ~= "" then
      return base .. ".bak" -- generic bak file
    end
  end,
  function(fn) return fn .. ".bak" end,
  function(fn) return fn .. "~" end, -- vim, gedit
  function(fn) return "#" .. fn .. "#" end, -- Emacs
  function(fn)
    local base, ext = splitext(fn);
    return base .. " copy" .. ext -- mac copy
  end,
  function(fn) return "Copy of " .. fn end, -- windows copy
  function(fn) return fn .. ".save" end, -- nano
  function(fn) if string.sub(fn, 1, 1) ~= "." then return "." .. fn .. ".swp" end end, -- vim swap
  function(fn) return fn .. ".swp" end, -- vim swap
  function(fn) return fn .. ".old" end, -- generic backup
};

---
--Creates combinations of backup names for a given filename
--Taken from: http-backup-finder.nse
local function backupNames (filename)
  local dir, basename;

  dir, basename = splitdir(filename);
  return coroutine.wrap(function()
    for _, transform in ipairs(TRANSFORMS) do
      local result = transform(basename);

      if result == nil then
      elseif type(result) == "string" then
        coroutine.yield(dir .. result);
        result = {result}
      elseif type(result) == "table" then
        for _, r in ipairs(result) do
          coroutine.yield(dir .. r);
        end
      end
    end
  end)
end

---
--Writes string to file
--Taken from: hostmap.nse
-- @param filename Filename to write
-- @param contents Content of file
-- @return True if file was written successfully
local function write_file (filename, contents)
  local f, err = io.open(filename, "w");
  if not f then
    return f, err;
  end
  f:write(contents);
  f:close();
  return true;
end

action = function (host, port)
  local path = stdnse.get_script_args("http-config-backup.path") or "/";
  local save = stdnse.get_script_args("http-config-backup.save");

  local backups = {};

  if not path:match("/$") then
    path = path .. "/";
  end

  if not path:match("^/") then
    path = "/" .. path;
  end

  if (save and not(save:match("/$") ) ) then
    save = save .. "/";
  end

  local status_404, result_404, known_404 = http.identify_404(host, port)
  if not status_404 then
    stdnse.debug1("Can't distinguish 404 response. Quitting.")
    return stdnse.format_output(false, "Can't determine file existence")
  end

  -- for each config file
  for _, cfg in ipairs(CONFIGS) do
    -- for each alteration of the filename
    for entry in backupNames(cfg.filename) do
      local url_path

      url_path = url.build({path = path .. entry});

      -- http request
      local response = http.get(host, port, url_path);

      -- if it's not 200, don't bother. If it is, check that it's not a false 404
      if response.status == 200 and http.page_exists(response, result_404, known_404, url_path) then
        -- check it if is valid before inserting
        if cfg.check(response.body) then
          local filename = stdnse.escape_filename((host.targetname or host.ip) .. url_path)

          -- save the content
          if save then
            local status, err = write_file(save .. filename, response.body);
            if status then
              stdnse.debug1("%s saved", filename);
            else
              stdnse.debug1("error saving %s", err);
            end
          end

          table.insert(backups, url_path .. " " .. response["status-line"]);
        else
          stdnse.debug1("%s: found but not matching: %s",
            host.targetname or host.ip, url_path);
        end
      end
    end
  end

  return stdnse.format_output(true, backups);
end;
