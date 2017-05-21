description = [[
Extracts and outputs HTML and JavaScript comments from HTTP responses.
]]

---
-- @usage nmap -p80 --script http-comments-displayer.nse <host>
--
-- This scripts uses patterns to extract HTML comments from HTTP
-- responses and writes these to the command line.
--
-- @args http-comments-displayer.singlepages Some single pages
--       to check for comments. For example, {"/",  "/wiki"}.
--       Default: nil (crawler mode on)
-- @args http-comments-displayer.context declares the number of chars
--       to extend our final strings. This is useful when we need to
--       to see the code that the comments are referring to.
--       Default: 0, Maximum Value: 50
--
--
-- @output
-- PORT   STATE SERVICE REASON
-- 80/tcp open  http    syn-ack
-- | http-comments-displayer:
-- |     Path: /
-- |     Line number: 214
-- |     Comment:
-- |         <!-- This needs fixing. -->
-- |
-- |     Path: /register.php
-- |     Line number: 15
-- |     Comment:
-- |_        /* We should avoid the hardcoding here */
--
---

categories = {"discovery", "safe"}
author = "George Chatzisofroniou"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"
local table = require "table"
local string = require "string"
local httpspider = require "httpspider"

PATTERNS = {
    "<!%-.-%-!?>", -- HTML comment
    "/%*.-%*/", -- Javascript multiline comment
    "[ ,\n]//.-\n" -- Javascript one-line comment. Could be better?
    }

portrule = shortport.port_or_service( {80, 443}, {"http", "https"}, "tcp", "open")

-- Returns comment's line number by counting the occurrences of the
-- new line character ("\n") from the start of the HTML file until
-- the related comment.
local getLineNumber = function(body, comment)

  local partofresponse = body:find(comment, 1, true)
  partofresponse = body:sub(0, partofresponse)
  local _, count = string.gsub(partofresponse, "\n", "\n")

  return count + 1

end

action = function(host, port)

  local context = stdnse.get_script_args("http-comments-displayer.context")
  local singlepages = stdnse.get_script_args("http-comments-displayer.singlepages")

  local comments = {}

  local crawler = httpspider.Crawler:new( host, port, '/', { scriptname = SCRIPT_NAME, withinhost = 1 } )

  if (not(crawler)) then
    return
  end

  crawler:set_timeout(10000)

  if context then
    if (tonumber(context) > 100) then
      context = 100
    end

    -- Lua's abbreviated patterns support doesn't have a fixed-number-of-repetitions syntax.
    for i, pattern in ipairs(PATTERNS) do
      PATTERNS[i] = string.rep(".", context) .. PATTERNS[i] .. string.rep(".", context)
    end
  end

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

      for i, pattern in ipairs(PATTERNS) do
        for c in string.gmatch(response.body, pattern) do

          local linenumber = getLineNumber(response.body, c)

          comments[c] = "\nPath: " .. path .. "\nLine number: " ..  linenumber .. "\nComment: \n"
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
  if next(comments) == nil then
    return "Couldn't find any comments."
  end

  -- Create a nice output.
  local results = {}
  for c, _ in pairs(comments) do
    table.insert(results, {_, {{c}}})
  end

  results.name = crawler:getLimitations()

  return stdnse.format_output(true, results)

end
