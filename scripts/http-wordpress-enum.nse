local coroutine = require "coroutine"
local http = require "http"
local io = require "io"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

description = [[
Enumerates themes and plugins of Wordpress installations. The script can also detect
 outdated plugins by comparing version numbers with information pulled from api.wordpress.org.

The script works with two separate databases for themes (wp-themes.lst) and plugins (wp-plugins.lst).
The databases are sorted by popularity and the script will search only the top 100 entries by default.
The theme database has around 32,000 entries while the plugin database has around 14,000 entries.

The script determines the version number of a plugin by looking at the readme.txt file inside the plugin
directory and it uses the file style.css inside a theme directory to determine the theme version.
If the script argument check-latest is set to true, the script will query api.wordpress.org to obtain
the latest version number available. This check is disabled by default since it queries an external service.

This script is a combination of http-wordpress-plugins.nse and http-wordpress-themes.nse originally
submited by Ange Gutek and Peter Hill.

TODO:
-Implement version checking for themes.
]]

---
-- @usage nmap -sV --script http-wordpress-enum <target>
-- @usage nmap --script http-wordpress-enum --script-args check-latest=true,search-limit=10 <target>
-- @usage nmap --script http-wordpress-enum --script-args type="themes" <target>
--
-- @args http-wordpress-enum.root Base path. By default the script will try to find a WP directory
--                                installation or fall back to '/'.
-- @args http-wordpress-enum.search-limit Number of entries or the string "all". Default:100.
-- @args http-wordpress-enum.type Search type. Available options:plugins, themes or all. Default:all.
-- @args http-wordpress-enum.check-latest Retrieves latest plugin version information from wordpress.org.
--                                        Default:false.
--
-- @output
-- PORT   STATE SERVICE
-- 80/tcp open  http
-- | http-wordpress-enum:
-- | Search limited to top 100 themes/plugins
-- |   plugins
-- |     akismet
-- |     contact-form-7 4.1 (latest version:4.1)
-- |     all-in-one-seo-pack  (latest version:2.2.5.1)
-- |     google-sitemap-generator 4.0.7.1 (latest version:4.0.8)
-- |     jetpack 3.3 (latest version:3.3)
-- |     wordfence 5.3.6 (latest version:5.3.6)
-- |     better-wp-security 4.6.4 (latest version:4.6.6)
-- |     google-analytics-for-wordpress 5.3 (latest version:5.3)
-- |   themes
-- |     twentytwelve
-- |_    twentyfourteen
--
-- @xmloutput
-- <table key="google-analytics-for-wordpress">
-- <elem key="installation_version">5.1</elem>
-- <elem key="latest_version">5.3</elem>
-- <elem key="name">google-analytics-for-wordpress</elem>
-- <elem key="path">/wp-content/plugins/google-analytics-for-wordpress/</elem>
-- <elem key="category">plugins</elem>
-- </table>
-- <table key="twentytwelve">
-- <elem key="category">themes</elem>
-- <elem key="path">/wp-content/themes/twentytwelve/</elem>
-- <elem key="name">twentytwelve</elem>
-- </table>
-- <elem key="title">Search limited to top 100 themes/plugins</elem>
---

author = {"Ange Gutek", "Peter Hill", "Gyanendra Mishra", "Paulino Calderon"}

license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

categories = {"discovery", "intrusive"}

local DEFAULT_SEARCH_LIMIT = 100
local DEFAULT_PLUGINS_PATH = '/wp-content/plugins/'
local WORDPRESS_API_URL = 'http://api.wordpress.org/plugins/info/1.0/'

portrule = shortport.http

--Reads database
local function read_data_file(file)
  return coroutine.wrap(function()
    for line in file:lines() do
      if not line:match("^%s*#") and not line:match("^%s*$") then
        coroutine.yield(line)
      end
    end
  end)
end

--Checks if the plugin/theme file exists
local function existence_check_assign(act_file)
  if not act_file then
    return false
  end
  local temp_file = io.open(act_file,"r")
  if not temp_file then
    return false
  end
  return temp_file
 end

--Obtains version from readme.txt or style.css
local function get_version(path, typeof, host, port)
  local pattern, version, versioncheck

  if typeof == 'plugins' then
    path = path .. "readme.txt"
    pattern = 'Stable tag: ([.0-9]*)'
  else
    path = path .. "style.css"
    pattern = 'Version: ([.0-9]*)'
  end

  stdnse.debug1("Extracting version of path:%s", path)
  versioncheck = http.get(host, port, path)
  if versioncheck.body then
    version = versioncheck.body:match(pattern)
  end
  stdnse.debug1("Version found: %s", version)
  return version
end

-- check if the plugin is the latest
local function get_latest_plugin_version(plugin)
  stdnse.debug1("Retrieving the latest version of %s", plugin)
  local apiurl = WORDPRESS_API_URL .. plugin .. ".json"
  local latestpluginapi = http.get('api.wordpress.org', '80', apiurl)
  local latestpluginpattern = '","version":"([.0-9]*)'
  local latestpluginversion = latestpluginapi.body:match(latestpluginpattern)
  stdnse.debug1("Latest version:%s", latestpluginversion)
  return latestpluginversion
end

action = function(host, port)

  local result = {}
  local file = {}
  local all = {}
  local bfqueries = {}
  local wp_autoroot
  local output_table = stdnse.output_table()

  --Read script arguments
  local operation_type_arg = stdnse.get_script_args(SCRIPT_NAME .. ".type") or "all"
  local apicheck = stdnse.get_script_args(SCRIPT_NAME .. ".check-latest")
  local wp_root = stdnse.get_script_args(SCRIPT_NAME .. ".root")
  local resource_search_arg = stdnse.get_script_args(SCRIPT_NAME .. ".search-limit") or DEFAULT_SEARCH_LIMIT

  local wp_themes_file = nmap.fetchfile("nselib/data/wp-themes.lst")
  local wp_plugins_file = nmap.fetchfile("nselib/data/wp-plugins.lst")

  if operation_type_arg == "themes" or operation_type_arg == "all" then
    local theme_db = existence_check_assign(wp_themes_file)
    if not theme_db then
      return false, "Couldn't find wp-themes.lst in /nselib/data/"
    else
      file['themes'] = theme_db
    end
  end
  if operation_type_arg == "plugins" or operation_type_arg == "all" then
    local plugin_db = existence_check_assign(wp_plugins_file)
    if not plugin_db then
      return  false, "Couldn't find wp-plugins.lst in /nselib/data/"
    else
      file['plugins'] = plugin_db
    end
  end

  local resource_search
  if resource_search_arg == "all" then
    resource_search = nil
  else
    resource_search = tonumber(resource_search_arg)
  end

  -- Identify servers that answer 200 to invalid HTTP requests and exit as these would invalidate the tests
  local status_404, result_404, known_404 = http.identify_404(host,port)
  if ( status_404 and result_404 == 200 ) then
    stdnse.debug1("Exiting due to ambiguous response from web server on %s:%s. All URIs return status 200.", host.ip, port.number)
    return nil
  end
  
  -- search the website root for evidences of a Wordpress path
  if not wp_root then
    local target_index = http.get(host,port, "/")

    if target_index.status and target_index.body then
      wp_autoroot = string.match(target_index.body, "http://[%w%-%.]-/([%w%-%./]-)wp%-content")
      if wp_autoroot then
        wp_autoroot = "/" .. wp_autoroot
        stdnse.debug(1,"WP root directory: %s", wp_autoroot)
      else
        stdnse.debug(1,"WP root directory: wp_autoroot was unable to find a WP content dir (root page returns %d).", target_index.status)
      end
    end
  end

  --build a table of both directories to brute force and the corresponding WP resources' name
  local resource_count=0
  for key,value in pairs(file) do
    local l_file = value
    resource_count = 0
    for line in read_data_file(l_file) do
      if resource_search and resource_count >= resource_search then
        break
      end

    local target
    if wp_root then
      -- Give user-supplied argument the priority
      target = wp_root .. string.gsub(DEFAULT_PLUGINS_PATH, "plugins", key) .. line .. "/"
    elseif wp_autoroot then
      -- Maybe the script has discovered another Wordpress content directory
      target = wp_autoroot .. string.gsub(DEFAULT_PLUGINS_PATH, "plugins", key) .. line .. "/"
    else
      -- Default WP directory is root
      target = string.gsub(DEFAULT_PLUGINS_PATH, "plugins", key) .. line .. "/"
    end


    target = string.gsub(target, "//", "/")
    table.insert(bfqueries, {target, line})
    all = http.pipeline_add(target, nil, all, "GET")
    resource_count = resource_count + 1

  end
  -- release hell...
  local pipeline_returns = http.pipeline_go(host, port, all)
  if not pipeline_returns then
    stdnse.verbose1("got no answers from pipelined queries")
    return nil
  end
  local response = {}
  response['name'] = key
  for i, data in pairs(pipeline_returns) do
    -- if it's not a four-'o-four, it probably means that the plugin is present
    if http.page_exists(data, result_404, known_404, bfqueries[i][1], true) then
      stdnse.debug(1,"Found a plugin/theme:%s", bfqueries[i][2])
      local version = get_version(bfqueries[i][1],key,host,port)
      local output  = nil

      --We format the table for XML output
      bfqueries[i].path = bfqueries[i][1]
      bfqueries[i].category = key
      bfqueries[i].name = bfqueries[i][2]
      bfqueries[i][1] = nil
      bfqueries[i][2] = nil

      if version then
         output = bfqueries[i].name .." ".. version
         bfqueries[i].installation_version = version
         --Right now we can only get the version number of plugins through api.wordpress.org
         if apicheck == "true" and key=="plugins" then
           local latestversion = get_latest_plugin_version(bfqueries[i].name)
           if latestversion then
             output = output .. " (latest version:" .. latestversion .. ")"
             bfqueries[i].latest_version = latestversion
           end
         end
      else
         output = bfqueries[i].name
     end
       output_table[bfqueries[i].name] = bfqueries[i]
       table.insert(response, output)
    end
  end
  table.insert(result, response)
  bfqueries={}
  all = {}

end
  local len = 0
  for i, v in ipairs(result) do len = len >= #v and len or #v end
  if len > 0 then
    output_table.title = string.format("Search limited to top %s themes/plugins", resource_count)
    result.name = output_table.title
    return output_table, stdnse.format_output(true, result)
  else
    if nmap.verbosity()>1 then
      return string.format("Nothing found amongst the top %s resources,"..
                         "use --script-args search-limit=<number|all> for deeper analysis)", resource_count)
    else
      return nil
    end
  end

end

