description = [[
It looks for places where attacker-controlled information in the DOM may be used
to affect JavaScript execution in certain ways. The attack is explained here:
http://www.webappsec.org/projects/articles/071105.shtml
]]

---
-- @usage nmap -p80 --script http-dombased-xss.nse <target>
--
-- DOM-based XSS occur in client-side JavaScript and this script tries to detect
-- them by using some patterns. Please note, that the script may generate some
-- false positives. Don't take everything in the output as a vulnerability, if
-- you don't review it first.
--
-- Most of the patterns used to determine the vulnerable code have been taken
-- from this page: https://code.google.com/p/domxsswiki/wiki/LocationSources
--
-- @args http-dombased-xss.singlepages The pages to test. For example,
--       {/index.php,  /profile.php}. Default: nil (crawler mode on)
--
-- @output
-- PORT   STATE SERVICE REASON
-- 80/tcp open  http    syn-ack
-- | http-dombased-xss:
-- | Spidering limited to: maxdepth=3; maxpagecount=20; withinhost=some-very-random-page.com
-- |   Found the following indications of potential DOM based XSS:
-- |
-- |     Source: document.write("<OPTION value=1>"+document.location.href.substring(document.location.href.indexOf("default=")
-- |     Pages: http://some-very-random-page.com:80/, http://some-very-random-page.com/foo.html
-- |
-- |     Source: document.write(document.URL.substring(pos,document.URL.length)
-- |_    Pages: http://some-very-random-page.com/foo.html
--
---

categories = {"intrusive", "exploit", "vuln"}
author = "George Chatzisofroniou"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"
local table = require "table"
local string = require "string"
local httpspider = require "httpspider"

JS_FUNC_PATTERNS = {
    '(document%.write%s*%((.-)%))',
    '(document%.writeln%s*%((.-)%))',
    '(document%.execCommand%s*%((.-)%))',
    '(document%.open%s*%((.-)%))',
    '(window%.open%s*%((.-)%))',
    '(eval%s*%((.-)%))',
    '(window%.execScript%s*%((.-)%))',
}

JS_CALLS_PATTERNS = {
   'document%.URL',
   'document%.documentURI',
   'document%.URLUnencoded',
   'document%.baseURI',
   'document%.referrer',
   'location',
}

portrule = shortport.port_or_service( {80, 443}, {"http", "https"}, "tcp", "open")

action = function(host, port)

  local singlepages = stdnse.get_script_args("http-dombased-xss.singlepages")

  local domxss = {}

  local crawler = httpspider.Crawler:new( host, port, '/', { scriptname = SCRIPT_NAME, withinhost = 1 } )

  if (not(crawler)) then
    return
  end

  crawler:set_timeout(10000)

  local index, k, target, response, path
  while (true) do

    if singlepages then
      k, target = next(singlepages, index)
      if (k == nil) then
        break
      end
      response = http.get(host, port, target)
      path = target

    else
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
    end

    if response.body then

      for _, fp in ipairs(JS_FUNC_PATTERNS) do
        for i in string.gmatch(response.body, fp) do
          for _, cp in ipairs(JS_CALLS_PATTERNS) do
            if string.find(i, cp) then
              if not domxss[i] then
                domxss[i] = {path}
              else
                table.insert(domxss[i], ", " .. path)
              end
            end
          end
        end
      end

      if (index) then
        index = index + 1
      else
        index = 1
      end
    end

  end

  -- If the table is empty.
  if next(domxss) == nil then
    return "Couldn't find any DOM based XSS."
  end

  local results = {}
  for x, _ in pairs(domxss) do
    table.insert(results, { "\nSource: " .. x, "Pages: " .. table.concat(_) })
  end

  table.insert(results, 1, "Found the following indications of potential DOM based XSS: ")

  results.name = crawler:getLimitations()

  return stdnse.format_output(true, results)

end
