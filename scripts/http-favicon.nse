description = [[
Gets the favicon.ico from the root of a web service and tries to enumerate it
]]

---
-- @args favicon.uri Uri that will be requested for favicon
-- @output
-- |_ http-favicon: Found favicon from Socialtext

-- HTTP default favicon enumeration script
-- rev 1.2 (2009-03-11)
-- Original NASL script by Javier Fernandez-Sanguino Pena

author = "Vlatko Kosturjak <kost@linux.hr>"

license = "Same as Nmap--See http://nmap.org/book/man-legal.html"

categories = {"default", "discovery"}

require "shortport"
require "http"
require "stdnse"
require "datafiles"
require "nsedebug"

portrule = shortport.port_or_service({80, 443, 8080, 8443},
	{"http", "https", "http-alt", "https-alt"})

action = function(host, port)
  local md5sum,answer
  local match
  local status, favicondb
  local result= ""
  local favicondbfile="favicon-db"
  local index, icon
  local root = ""

  status, favicondb = datafiles.parse_file( favicondbfile, {["^%s*([^%s#:]+)[%s:]+"] = "^%s*[^%s#:]+[%s:]+(.*)"})
  if not status then
  	stdnse.print_debug( 1, "Could not open file: %s", favicondbfile )
	return
  end

  if not pcall(require,'openssl') then
	stdnse.print_debug( 3, "Skipping %s script because OpenSSL is missing.", filename )
	return
  end

  if(nmap.registry.args['favicon.root']) then
	root = nmap.registry.args['favicon.root']
  end

  if(nmap.registry.args['favicon.uri']) then
  	answer = http.get( host, port, root .. "/" .. nmap.registry.args['favicon.uri'])
	stdnse.print_debug( 4, "Using URI %s", nmap.registry.args['favicon.uri'])
  else
  	answer = http.get( host, port, root .. "/favicon.ico" )
	stdnse.print_debug( 4, "Using default URI.")
  end

  -- if we didn't find a correct favicon, let's parse the first page and search for one!
  if answer.status ~= 200 then
	stdnse.print_debug( 1, "No favicon found on root of web server, parsing initial page for favicon.")
 	index = http.get( host, port, root .. "/" )
	-- if we get the first page
	if index.status == 200 or index.status == 503 then
		-- find the favicon pattern
		icon = parseIcon( index.body )
		-- if we find a pattern
		if icon then
			-- check if the path is in './' format, what means that we must replace it by the root directory
			if string.match(icon, "^%.") then
				icon = string.gsub(icon, "^%.", root, 1)
			end
			-- request the favicon
			answer = http.get( host, port, icon )
		else 
			answer = nil
		end
	end
  end
	

  --- check for 200 response code
  if answer and answer.status == 200 then
	md5sum=string.upper(stdnse.tohex(openssl.md5(answer.body)))
	match=favicondb[md5sum]
	if match then
		result = result .. "Found favicon from " .. match .. "."
	else
		result="Unknown favicon MD5: " .. md5sum 
	end
  else		
	stdnse.print_debug( 1, "No favicon found.")
	return
  end --- status == 200
  return result
end

function parseIcon( body )
  local icon, absolute_icon, parsed_icon
  local tag_start, tag_end, tag
  local tags = {}

  -- separate tags
  tag_start, tag_end = string.find(body,'(<.->)')
  while tag_start do
        tag = string.sub(body, tag_start, tag_end)
        body = string.sub(body, tag_end)
        tags[#tags+1] = tag
        tag_start, tag_end = string.find(body,'(<.->)')
  end
        
  -- check each tag for our favicon tag
  for k, v in ipairs(tags) do
        icon = string.match( v, '<(%s-link.-rel%s-=%s-".-icon".-/?)>')
        if icon then
                icon = string.match( icon, 'href%s*=%s*"(.-)"')
                -- if favicon is in absolute format, we need to parse it!
                absolute_icon = string.match(icon, '^http://')
                if absolute_icon then
                        parsed_icon = url.parse(icon)
                        icon = parsed_icon.path
                end
                break
        end
  end
  return icon
end
