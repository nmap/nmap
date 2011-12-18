description = [[
Retrieves the authentication scheme and realm of a web service that requires
authentication.
]]

---
-- @usage
-- nmap --script http-auth [--script-args='http-auth.path=/login/']
--
-- @output
-- PORT   STATE SERVICE REASON
-- 80/tcp open  http    syn-ack
-- | http-auth: 
-- |   Negotiate
-- |   NTLM
-- |   Digest
-- |     charset=utf-8
-- |     nonce=+Upgraded+v1e4e256b4afb7f89bf...0eb280e9c4b015cbe43bb7ab
-- |     qop=auth
-- |     algorithm=MD5-sess
-- |     realm=example.com
-- |   Basic
-- |_    realm=example.com
--
-- @args http-auth.path The url to query (default: /)

-- HTTP authentication information gathering script
-- rev 1.1 (2007-05-25)
-- 2008-11-06 Vlatko Kosturjak <kost@linux.hr>
-- * bug fixes against base64 encoded strings, more flexible auth/pass check,
--   corrected sample output
-- 2011-12-18 Patrik Karlsson <patrik@cqure.net>
-- * added path argument and changed so that the script processes all
--   www-authenticate arguments


author = "Thomas Buchanan"

license = "Same as Nmap--See http://nmap.org/book/man-legal.html"

categories = {"default", "auth", "safe"}

require "shortport"
require "http"

portrule = shortport.http

local PATH = stdnse.get_script_args("http-auth.path")

local function getChallenges(www_authenticate)
	local challenges = http.parse_www_authenticate(www_authenticate)
	local result = {}
	
	if not challenges then
    	table.insert( result, ("WWW-Authenticate: %s"):format(www_authenticate) )
		return result
	end

	for _, challenge in ipairs(challenges) do
		result.name = challenge.scheme
		for name, value in pairs(challenge.params) do
			table.insert(result, string.format("%s=%s", name, value))
		end
	end
	return ( #result == 0 and result.name or result )
end

action = function(host, port)
  local www_authenticate
  local challenges

  local request_opts = {
    bypass_cache = true
  }
  local answer = http.get(host, port, PATH or "/", request_opts)

  --- check for 401 response code
  if answer.status ~= 401 then
    return
  end

  local result = {}
  www_authenticate = answer.header["www-authenticate"]
  if not www_authenticate then
    table.insert(result, ("Server returned status %d but no WWW-Authenticate header."):format(answer.status))
    return stdnse.format_output(true, result)
  end

  for _, header in ipairs(answer.rawheader) do
    local n, v = header:match("^(.-): (.*)$")
	if ( n and n:lower() == "www-authenticate" ) then
      local r = getChallenges(v)
	  table.insert(result, r)
	end
  end

  return stdnse.format_output(true, result)
end
