local http = require "http"
local httpspider = require "httpspider"
local io = require "io"
local lfs = require "lfs"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

description = [[The script is used to fetch files from servers.

The script supports three different use cases :
* The paths argument isn't provided, the script spiders the host
  and downloads files in their respective folders relative to
  the one provided using "destination".
* The paths argument(a single item or list) is provided and the path starts
  with "/", the script tries to fetch the path relative to the url
  provided via the argument "url".
* The paths argument(a single item or list) is provided and the path doesn't
  start with "/". Then the script spiders the host and tries to find
  files which contain the path(now treated as a pattern).
]]

---
-- @usage nmap --script http-fetch --script-args destination=/tmp/mirror <target>
-- nmap --script http-fetch --script-args 'paths={/robots.txt,/favicon.ico}' <target>
-- nmap --script http-fetch --script-args 'paths=.html' <target>
-- nmap --script http-fetch --script-args 'url=/images,paths={.jpg,.png,.gif}' <target>
--
-- @args http-fetch.destination - The full path of the directory to save the file(s) to preferably with the trailing slash.
-- @args http-fetch.files - The name of the file(s) to be fetched.
-- @args http-fetch.url The base URL to start fetching. Default: "/"
-- @args http-fetch.paths A list of paths to fetch. If relative, then the site will be spidered to find matching filenames.
-- Otherwise, they will be fetched relative to the url script-arg.
-- @args http-fetch.maxdepth The maximum amount of directories beneath
--       the initial url to spider. A negative value disables the limit.
--       (default: 3)
-- @args http-fetch.maxpagecount The maximum amount of pages to fetch.
-- @args http-fetch.noblacklist By default files like jpg, rar, png are blocked. To
-- fetch such files set noblacklist to true.
-- @args http-fetch.withinhost The default behavior is to fetch files from the same host. Set to False
-- to do otherwise.
-- @args http-fetch.withindomain If set to true then the crawling would be restricted to the domain provided
-- by the user.
--
-- @output
-- | http-fetch:
-- |   Successfully Downloaded:
-- |     http://nmap.org:80/ as /tmp/mirror/index.html
-- |     http://nmap.org/shared/css/insecdb.css as /tmp/mirror/shared/css/insecdb.css
-- |     http://nmap.org/movies/ as /tmp/mirror/movies/index.html
-- |     http://nmap.org/book/man.html as /tmp/mirror/book/man.html
--
--
-- <table key="Successfully Downloaded">
--   <elem>http://nmap.org:80/ as /tmp/mirror/index.html</elem>
--   <elem>http://nmap.org/shared/css/insecdb.css as /tmp/mirror/shared/css/insecdb.css</elem>
--   <elem>http://nmap.org/movies/ as /tmp/mirror/movies/index.html</elem>
--   <elem>http://nmap.org/book/man.html as /tmp/mirror/book/man.html</elem>
-- </table>

author = "Gyanendra Mishra"

license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

categories = {"safe"}

portrule = shortport.http

local SEPARATOR =  lfs.get_path_separator()

local function build_path(file, url)
  local path = '/' .. url .. file
  return path:gsub('//', '/')
end

local function create_directory(path)
  local status, err = lfs.mkdir(path)
  if status then
    stdnse.debug2("Created path %s", path)
    return true
  elseif err == "No such file or directory" then
    stdnse.debug2("Parent directory doesn't exist %s", path)
    local index  = string.find(path:sub(1, path:len() -1), SEPARATOR .. "[^" .. SEPARATOR .. "]*$")
    local sub_path = path:sub(1, index)
    stdnse.debug2("Trying path...%s", sub_path)
    create_directory(sub_path)
    lfs.mkdir(path)
  end
end

local function  save_file(content, file_name, destination, url)

  local file_path

  if file_name then
    file_path = destination .. file_name
  else
    file_path = destination .. url:getDir()
    create_directory(file_path)
    if url:getDir() == url:getFile() then
      file_path = file_path .. "index.html"
    else
      file_path = file_path .. stdnse.filename_escape(url:getFile():gsub(url:getDir(),""))
    end
  end

  file_path = file_path:gsub("//", "/")
  file_path = file_path:gsub("\\/", "\\")

  local file,err = io.open(file_path,"r")
  if not err then
    stdnse.debug1("File Already Exists")
    return true, file_path
  end
  file, err = io.open(file_path,"w")
  if file  then
    stdnse.debug1("Saving to ...%s",file_path)
    file:write(content)
    file:close()
    return true, file_path
  else
    stdnse.debug1("Error encountered in  writing file.. %s",err)
    return false, err
  end
end

local function fetch_recursively(host, port, url, destination, patterns, output)
  local crawler = httpspider.Crawler:new(host, port, url, { scriptname = SCRIPT_NAME })
  crawler:set_timeout(10000)
  while(true) do
    local status, r = crawler:crawl()
    if ( not(status) ) then
      if ( r.err ) then
        return stdnse.format_output(false, r.reason)
      else
        break
      end
    end
    local body = r.response.body
    local url_string = tostring(r.url)
    local file = r.url:getFile():gsub(r.url:getDir(),"")
    if body and r.response.status == 200 and patterns then
      for _, pattern in pairs(patterns) do
        if file:find(pattern, nil, true) then
          local status, err_message = save_file(r.response.body, nil, destination, r.url)
          if status then
            output['Matches'] = output['Matches'] or {}
            output['Matches'][pattern] = output['Matches'][pattern] or {}
            table.insert(output['Matches'][pattern], string.format("%s as %s",r.url:getFile()),err_message)
          else
            output['ERROR'] = output['ERROR'] or {}
            output['ERROR'][url_string] = err_message
          end
          break
        end
      end
    elseif body and r.response.status == 200 then
      stdnse.debug1("Processing url.......%s",url_string)
      local stat, path_or_err = save_file(body, nil, destination, r.url)
      if stat then
        output['Successfully Downloaded'] = output['Successfully Downloaded'] or {}
        table.insert(output['Successfully Downloaded'], string.format("%s as %s", url_string, path_or_err))
      else
        output['ERROR'] = output['ERROR'] or {}
        output['ERROR'][url_string] = path_or_err
      end
    else
      if not r.response.body then
        stdnse.debug1("No Body For: %s",url_string)
      elseif r.response and r.response.status ~= 200 then
        stdnse.debug1("Status not 200 For: %s",url_string)
      else
        stdnse.debug1("False URL picked by spider!: %s",url_string)
      end
    end
  end
end


local function fetch(host, port, url, destination, path, output)
  local response = http.get(host, port, build_path(path, url), nil)
  if response and response.status and response.status == 200 then
    local file = path:sub(path:find("/[^/]*$") + 1)
    local save_as = (host.targetname or host.ip) .. ":" ..  tostring(port.number) .. "-" .. file
    local status, err_message = save_file(response.body, save_as, destination)
    if status then
      output['Successfully Downloaded'] = output['Successfully Downloaded'] or {}
      table.insert(output['Successfully Downloaded'], string.format("%s as %s", path, save_as))
    else
      output['ERROR'] = output['ERROR'] or {}
      output['ERROR'][path] = err_message
    end
  else
    stdnse.debug1("%s doesn't exist on server at %s.", path, url)
  end
end

action = function(host, port)

  local destination = stdnse.get_script_args(SCRIPT_NAME..".destination") or false
  local url = stdnse.get_script_args(SCRIPT_NAME..".url") or "/"
  local paths = stdnse.get_script_args(SCRIPT_NAME..'.paths') or nil

  local output = stdnse.output_table()
  local patterns = {}

  if not destination then
    output.ERROR = "Please enter the complete path of the directory to save data in."
    return output, output.ERROR
  end

  if destination:sub(-1) == '\\' or destination:sub(-1) == '/' then
    destination = destination
  else
    destination = destination .. SEPARATOR
  end

  if paths then
    if type(paths) ~= 'table' then
      paths = {paths}
    end
    for _, path in pairs(paths) do
      if path:sub(1, 1) == "/" then
        fetch(host, port, url, destination, path, output)
      else
        table.insert(patterns, path)
      end
    end
    if #patterns > 0 then
      fetch_recursively(host, port, url, destination, patterns, output)
    end
  else
    fetch_recursively(host, port, url, destination, nil, output)
  end

  if #output > 0 then
    if paths then
      return output
    else
      if nmap.verbosity() > 1 then
        return output
      else
        output.result = "Successfully Downloaded Everything At: " .. destination
        return output, output.result
      end
    end
  end
end

