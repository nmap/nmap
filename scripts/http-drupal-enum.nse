local coroutine = require "coroutine"
local http = require "http"
local io = require "io"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"
local rand = require "rand"

description = [[
Enumerates the installed Drupal modules/themes by using a list of known modules and themes.

The script works by iterating over module/theme names and requesting
MODULE_PATH/MODULE_NAME/LICENSE.txt for modules and THEME_PATH/THEME_NAME/LICENSE.txt.
MODULE_PATH/THEME_PATH which is either provided by the user, grepped for in the html body
or defaulting to sites/all/modules/.

If the response status code is 200, it means that the module/theme is installed. By
default, the script checks for the top 100 modules/themes (by downloads), given the
huge number of existing modules (~18k) and themes(~1.4k).

If you want to update your themes or module list refer to the link below.

* https://svn.nmap.org/nmap-exp/gyani/misc/drupal-update.py
]]

---
-- @see http-vuln-cve2014-3704.nse
--
-- @args http-drupal-enum.root The base path. Defaults to <code>/</code>.
-- @args http-drupal-enum.number Number of modules to check.
-- Use this option with a number or "all" as an argument to test for all modules.
-- Defaults to <code>100</code>.
-- @args http-drupal-enum.modules_path Direct Path for Modules
-- @args http-drupal-enum.themes_path Direct Path for Themes
-- @args http-drupal-enum.type default all.choose between "themes" and "modules"
--
-- @usage nmap -p 80 --script http-drupal-enum <target>
--
-- @output
-- PORT   STATE SERVICE REASON
-- 80/tcp open  http    syn-ack
-- | http-drupal-enum:
-- |   Themes:
-- |     adaptivetheme
-- |   Modules:
-- |     views
-- |     token
-- |     ctools
-- |     pathauto
-- |     date
-- |     imce
-- |_    webform
--
-- Final times for host: srtt: 329644 rttvar: 185712  to: 1072492
--
-- @xmloutput
-- <table key="Themes">
--  <elem>adaptivetheme</elem>
-- </table>
-- <table key="Modules">
--  <elem>views</elem>
--  <elem>token</elem>
--  <elem>ctools</elem>
--  <elem>pathauto</elem>
--  <elem>date</elem>
--  <elem>imce</elem>
--  <elem>webform</elem>
-- </table>


author = {
  "Hani Benhabiles",
  "Gyanendra Mishra",
}

license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

categories = {
  "discovery",
  "intrusive",
}

local DEFAULT_SEARCH_LIMIT = 100
local DEFAULT_MODULES_PATH = 'sites/all/modules/'
local DEFAULT_THEMES_PATH = 'sites/all/themes/'
local IDENTIFICATION_STRING = "GNU GENERAL PUBLIC LICENSE"

portrule = shortport.http

--Reads database
local function read_data (file)
  return coroutine.wrap(function ()
      for line in file:lines() do
        if not line:match "^%s*#" and not line:match "^%s*$" then
          coroutine.yield(line)
        end
      end
    end)
end

--Checks if the module/theme file exists
local function assign_file (act_file)
  if not act_file then
    return false
  end
  local temp_file = io.open(act_file, "r")
  if not temp_file then
    return false
  end
  return temp_file
end

--- Attempts to find modules path
local get_path = function (host, port, root, type_of)
  local default_path
  if type_of == "themes" then
    default_path = DEFAULT_THEMES_PATH
  else
    default_path = DEFAULT_MODULES_PATH
  end
  local body = http.get(host, port, root).body or ""
  local pattern = "sites/[%w.-/]*/" .. type_of .. "/"
  local found_path = body:match(pattern)
  return found_path or default_path
end


function action (host, port)
  local result = stdnse.output_table()
  local file = {}
  local all = {}
  local requests = {}
  local method = "HEAD"

  --Read script arguments
  local resource_type = stdnse.get_script_args(SCRIPT_NAME .. ".type") or "all"
  local root = stdnse.get_script_args(SCRIPT_NAME .. ".root") or "/"
  local search_limit = stdnse.get_script_args(SCRIPT_NAME .. ".number") or DEFAULT_SEARCH_LIMIT
  local themes_path = stdnse.get_script_args(SCRIPT_NAME .. ".themes_path")
  local modules_path = stdnse.get_script_args(SCRIPT_NAME .. ".modules_path")

  local themes_file = nmap.fetchfile "nselib/data/drupal-themes.lst"
  local modules_file = nmap.fetchfile "nselib/data/drupal-modules.lst"

  if resource_type == "themes" or resource_type == "all" then
    local theme_db = assign_file(themes_file)
    if not theme_db then
      return false, "Couldn't find drupal-themes.lst in /nselib/data/"
    else
      file['Themes'] = theme_db
    end
  end

  if resource_type == "modules" or resource_type == "all" then
    local modules_db = assign_file(modules_file)
    if not modules_db then
      return false, "Couldn't find drupal-modules.lst in /nselib/data/"
    else
      file['Modules'] = modules_db
    end
  end

  if search_limit == "all" then
    search_limit = nil
  else
    search_limit = tonumber(search_limit)
  end

  if not themes_path then
    themes_path = (root .. get_path(host, port, root, "themes")):gsub("//", "/")
  end
  if not modules_path then
    modules_path = (root .. get_path(host, port, root, "modules")):gsub("//", "/")
  end

  -- We default to HEAD requests unless the server returns
  -- non 404 (200 or other) status code

  local response = http.head(host, port, modules_path .. rand.random_alpha(8) .. "/LICENSE.txt")
  if response.status ~= 404 then
    method = "GET"
  end

  for key, value in pairs(file) do
    local count = 0
    for resource_name in read_data(value) do
      count = count + 1
      if search_limit and count > search_limit then
        break
      end
      -- add request to pipeline
      if key == "Modules" then
        all = http.pipeline_add(modules_path .. resource_name .. "/LICENSE.txt", nil, all, method)
      else
        all = http.pipeline_add(themes_path .. resource_name .. "/LICENSE.txt", nil, all, method)
      end
      -- add to requests buffer
      table.insert(requests, resource_name)
    end

    -- send requests
    local pipeline_responses = http.pipeline_go(host, port, all)
    if not pipeline_responses then
      stdnse.print_debug(1, "No answers from pipelined requests")
      return nil
    end

    for i, response in ipairs(pipeline_responses) do
      -- Module exists if 200 on HEAD.
      -- A lot Drupal of instances return 200 for all GET requests,
      -- hence we check for the identifcation string.
      if response.status == 200 and (method == "HEAD" or (method == "GET" and response.body:match(IDENTIFICATION_STRING))) then
        result[key] = result[key] or {}
        table.insert(result[key], requests[i])
      end
    end
    requests = {}
    all = {}
  end

  if result['Themes'] or result['Modules'] then
    return result
  else
    if nmap.verbosity() > 1 then
      return string.format("Nothing found amongst the top %s resources," .. "use --script-args number=<number|all> for deeper analysis)", search_limit)
    else
      return nil
    end
  end

end
