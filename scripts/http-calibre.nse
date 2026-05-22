local http = require "http"
local json = require "json"
local shortport = require "shortport"
local stdnse = require "stdnse"
local table = require "table"

description = [[
Checks for presence of Calibre e-book web server. It will check if Calibre requires authentication and will attempt to enumerate how many books are available.

References: https://calibre-ebook.com/

]]

---
-- @usage
-- nmap --script=http-calibre.nse <ip>
--
-- @output
-- 80/tcp open  http    syn-ack ttl 47
-- | http-calibre:
-- |   version:
-- |     calibre 3.21.0
-- |   authentication:
-- |     false
-- |   number_of_books:
-- |_    657

author = "Chris Bonk"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}


-- Used for catching errors and returning somewhat cleanly.
local function fail (err) return stdnse.format_output(false, err) end

-- Attempting to parse how many books are available via the /mobile URI.
local function get_books (host,port,url)
  response = http.get(host,port,'/mobile')
  
  if response.status == 200 then
    return string.match(response.body, ">Books%s%d%sto%s%d+%sof%s(%d+)")
  end
  return false
end
  
local function get_auth (host, port)

  -- newer versions
  response = http.head(host,port,'/interface-data/init')
  
  if response.status == 200 then
    return "false"
  end
  -- older versions
  response = http.head(host,port, '/browse/categories/allbooks')
  
  if response.status == 200 then
    return "false"
  end
  
  return "true"
  
end

-- RULE
portrule = shortport.http

-- ACTION
action = function(host, port)
  response = http.head(host,port,'/')
  
  -- if we get no response or headers to work with.
  if response == nil then
    return fail("Request failed")
  end
  if response.rawheader == nil then
    return fail("Response didn't include a proper header")
  end
  
  -- Checking the status code and header for a match to calibre.
  stdnse.debug1(response.status)
  if response.status == 200 then
    stdnse.debug1("Headers")
    if string.find(response.header['server'], "calibre") then
      output = stdnse.output_table()
      output.version = {}
      stdnse.debug1(response.header['server'])
      table.insert(output.version,string.format("%s", response.header['server']))
    else
      return fail("not calibre")
    end
  else
    return fail (string.format("Status code: %s", response.status))
  end
  
  -- On some versions, you can land on the main page, but not have authorization to access books. Hence we need to check further.
  authentication = get_auth(host,port)
  if authentication then
    output.authentication = {}
    table.insert(output.authentication, string.format("%s", authentication))
  end
  
  if authentication == "false" then
    output.number_of_books = {}
    number_of_books = get_books(host,port)
    if get_books then
      table.insert(output.number_of_books,string.format("%s", number_of_books))
    end
  end

  return output, stdnse.format_output(true, output)
end
