description = [[
Identifies the used software for each found http port and builds CPEs for the identified versions.

* Makes an HTTP GET request to the found open http port (with a default empty path of "/").
* Uses a local copy of Vulners regular expressions (defaults to http-vulners-regex.json) to identify software mentioned on the page of the HTTP service and forms CPEs for the found entries
* Outputs all the found CPEs by page (so mind the duplicates)
]]

---
-- @usage
-- nmap -sV --script http-vulners-regex.nse [--script-args paths={"/"}] <target>
--
-- @args http-vulners-regex.paths Specify paths to make requests to. Should be a single string meaning filename to read or a list of strings.
--
-- @output
--
-- 80/tcp open  http    syn-ack Apache httpd 2.4.10
-- | http-vulners-regex:
-- |   /:
-- |     cpe:/a:nginx:nginx:1.13.4
-- |_    cpe:/a:php:php:5.6.38
--
-- @xmloutput
--
-- <table key="/">
--   <elem>cpe:/a:nginx:nginx:1.13.4</elem>
--   <elem>cpe:/a:php:php:5.6.38</elem>
-- </table>

author = 'gmedian AT vulners DOT com'
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "default"}


local shortport = require "shortport"
local http = require "http"
local json = require "json"
local string = require "string"
local table = require "table"
local nmap = require "nmap"
local stdnse = require "stdnse"

local patterns = {}
local registry_tab = {} 
local tab = {}
local paths = {}
local default_paths = { 
        "/",
        "/index.html",
        "/index.php",
        "/wp-admin/login.php",
        "/about.html",
        "/about.php",
        "/500.html",
        "/theonethatdoesnotexist" -- cause why not
      }

portrule = shortport.http


function get_cpes(field)
  local vers

  for name, pattern in pairs(patterns) do
    _, _, vers = field:find(pattern.regex)
    if vers ~= nil then
      cpe = pattern.alias .. ":" .. vers
      if not registry_tab[cpe] then
        table.insert(tab, cpe)
        registry_tab[cpe] = 1
      end
    end
  end
end

function get_paths_from_file(filename)
  local file, filename_full, status
  local paths = {}

  filename_full = nmap.fetchfile('nselib/data/' .. filename) 
  if not(filename_full) then
	stdnse.debug1("No file found at nselib/data/%s, using local copy", filename)
    filename_full = filename
  end

  file = io.open(filename_full, "r")
  if file == nil then
	stdnse.debug1("Failed to open a file with paths")
    return {}
  end
  file:close()
  for line in io.lines(filename_full) do
    paths[#paths+1] = line
  end
  return paths
end

function get_paths(paths_arg)
  local default_paths_file = 'http-vulners-paths.txt'

  if type(paths_arg) == 'table' then
    -- Just do nothing whether it has entries or is an empty one
    do end
  elseif type(paths_arg) == 'string' then
    stdnse.debug1("Trying to read paths from a specified file " .. paths_arg)
    paths_arg = get_paths_from_file(paths_arg)
  else
    stdnse.debug1("Paths arguments should be a filename or a list of paths to use. Ignoring the argument")
    paths_arg = {}
  end

  -- If provided file could not be found, try the default one
  if #paths_arg == 0 then
    stdnse.debug1("Trying to read paths from a default file " .. default_paths_file)
    paths_arg = get_paths_from_file(default_paths_file)
  end

  -- Fall back to the hardcoded values when the default file could not be found as well
  if #paths_arg == 0 then
    stdnse.debug1("Using the default hardcoded paths.")
    paths_arg = default_paths
  end

  for _, path in ipairs(paths_arg) do
    paths[path] = 1
  end
end

action = function(host, port)
  local output = stdnse.output_table()
  local changed = false
  local paths_arg = stdnse.get_script_args(SCRIPT_NAME .. ".paths") or {}
  local regex_filename = 'http-vulners-regex.json'
  local regex_filename_full, file
  local cpe
  local response, status

  get_paths(paths_arg)

  regex_filename_full = nmap.fetchfile('nselib/data/' .. regex_filename) 
  if not(regex_filename_full) then
	stdnse.debug1("No file found at nselib/data/%s, using local copy", regex_filename)
    regex_filename_full = regex_filename
  end

  file = io.open(regex_filename_full, "r")
  if file == nil then
	stdnse.debug1("Failed to open the json file")
    return
  end
  
  status, patterns = json.parse(file:read("*all"))
  if status == nil then
    stdnse.debug1("Unable to parse json from file read.")
    return
  end
  file:close()

  if port.version == nil or port.version.cpe == nil then
    stdnse.debug1("port.version (or .cpe) table is nil")
    return
  end


  for path, _ in pairs(paths) do
    if type(path) ~= 'string' then
      path = tostring(path)
    end
    stdnse.debug1("Analyze path " .. path)
    tab = {}
    response = http.get(host, port, path)
    if not response.status then
      stdnse.debug1("HTTP Error retrieving %s: %s", path, response["status-line"])
      return
    end
    
    local body = response.rawbody or tostring(response.body)
    body = stdnse.string_or_blank(body, nil)
    if body ~= nil then
      get_cpes(body)
    end

    local rawheaders = response.rawheader
    if #rawheaders == 0 then
      stdnse.debug1("Rawheaders are empty...")
    else
      for i, header in ipairs(rawheaders) do
        stdnse.debug1("Analyzing:\t"..header)
        get_cpes(header)
      end
    end

    if #tab > 0 then
      output[path] = tab
      changed = true
    end
  end

  if (not changed) then
    return
  end

  -- NOTE[gmedian]: store the results in a somewhat persistent storage for other scripts to access
  -- It so happens that sometimes port.version.cpe does not contain the CPEs found by the  predecessing script
  -- So have to additionally store the results separately
  host.registry.vulners_cpe = host.registry.vulners_cpe or {}
  for cpe, _ in pairs(registry_tab) do
    stdnse.debug1("Add CPE %s to host registry", cpe)
    table.insert(host.registry.vulners_cpe, cpe)
    table.insert(port.version.cpe, cpe)
  end

  nmap.set_port_version(host, port)

  return output
end
