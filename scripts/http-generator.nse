description = [[
Displays the contents of the "generator" meta tag if there is one.
]]

author = "Michael Kohl"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

---
-- @usage
-- nmap -p 80,443 --script http-generator <host>
-- @output
-- PORT    STATE SERVICE
-- 80/tcp  open  http
-- |_http-generator: TYPO3 4.2 CMS
-- 443/tcp open  https
-- |_http-generator: TYPO3 4.2 CMS

--- TODO:
-- add arg for web path
-- add arg for maximum number of redirects

require('http')
require('shortport')

portrule = shortport.http

action = function(host, port)
   local response, loc, generator
   -- Worst case: <meta name=Generator content="Microsoft Word 11">
   local pattern = '<meta name="?generator"? content="([^\"]*)" ?/?>'

   -- make pattern case-insensitive
   pattern = pattern:gsub("%a", function (c)
               return string.format("[%s%s]", string.lower(c),
                                              string.upper(c))
             end)

   response = http.get(host, port, '/')

   -- deals with only one redirect
   if response['status-line']:lower():match("^http/1.1 30[12]") then
      loc = response.header['location']
      response = http.get_url(loc)
   end

   return response.body:match(pattern)

end
