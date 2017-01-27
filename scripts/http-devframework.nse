description = [[

Tries to find out the technology behind the target website.

The script checks for certain defaults that might not have been changed, like
common headers or URLs or HTML content.

While the script does some guessing, note that overall there's no way to
determine what technologies a given site is using.

You can help improve this script by adding new entries to
nselib/data/http-devframework-fingerprints.lua

Each entry must have:
* <code>rapidDetect</code> - Callback function that is called in the beginning
of detection process. It takes the host and port of target website as arguments.
* <code>consumingDetect</code> - Callback function that is called for each
spidered page. It takes the body of the response (HTML code) and the requested
path as arguments.

Note that the <code>consumingDetect</code> callback will not take place only if
<code>rapid</code> option is enabled.

]]

---
-- @usage nmap -p80 --script http-devframework.nse <target>
--
-- @args http-errors.rapid boolean value that determines if a rapid detection
--       should take place. The main difference of a rapid vs a lengthy detection
--       is that second one requires crawling through the website. Default: false
--       (lengthy detection is performed)
--
-- @output
-- PORT   STATE SERVICE REASON
-- 80/tcp open  http    syn-ack
-- |_http-devframework: Django detected. Found Django admin login page on /admin/
---

categories = {"discovery", "intrusive"}
author = "George Chatzisofroniou"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local httpspider = require "httpspider"
local _G = require "_G"

portrule = shortport.port_or_service( {80, 443}, {"http", "https"}, "tcp", "open")

local function loadFingerprints(filename)

  local file, fingerprints

  -- Find the file
  filename = nmap.fetchfile('nselib/data/' .. filename) or filename

  -- Load the file
  stdnse.debug1("Loading fingerprints: %s", filename)
  local env = setmetatable({fingerprints = {}}, {__index = _G});
  file = loadfile(filename, "t", env)

  if( not(file) ) then
    stdnse.debug1("Couldn't load the file: %s", filename)
    return
  end

  file()
  fingerprints = env.tools

  return fingerprints

end

action = function(host, port)

  local filename = stdnse.get_script_args("http-devframework.fingerprintfile") or "http-devframework-fingerprints.lua"
  local tools = loadFingerprints(filename)
  if not tools then
    stdnse.debug1("Failed to load fingerprints")
    return nil
  end
  local rapid = stdnse.get_script_args("http-devframework.rapid")

  local d

  -- Run rapidDetect() callbacks.
  for f, method in pairs(tools) do
    d = method["rapidDetect"](host, port)
    if d then
      return d
    end
  end

  local crawler = httpspider.Crawler:new(host, port, '/', { scriptname = SCRIPT_NAME,
      maxpagecount = 40,
      maxdepth = -1,
      withinhost = 1
    })

  if rapid then
    return "Couldn't determine the underlying framework or CMS. Try turning off 'rapid' mode."
  end

  crawler.options.doscraping = function(url)
    if crawler:iswithinhost(url)
      and not crawler:isresource(url, "js")
      and not crawler:isresource(url, "css") then
      return true
    end
  end

  crawler:set_timeout(10000)

  while (true) do

    local response, path

    local status, r = crawler:crawl()
    -- if the crawler fails it can be due to a number of different reasons
    -- most of them are "legitimate" and should not be reason to abort
    if (not(status)) then
      if (r.err) then
        return stdnse.format_output(false, r.reason)
      else
        break
      end
    end

    response = r.response
    path = tostring(r.url)

    if (response.body) then

      -- Run consumingDetect() callbacks.
      for f, method in pairs(tools) do
        d = method["consumingDetect"](response.body, path)
        if d then
          return d
        end
      end
    end

    return "Couldn't determine the underlying framework or CMS. Try increasing 'httpspider.maxpagecount' value to spider more pages."

  end

end
