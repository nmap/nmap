-- HTTP authentication information gathering script
-- rev 1.1 (2007-05-25)

id = "HTTP Auth"

description = "If a web server requires authentication, prints the authentication scheme and realm"

author = "Thomas Buchanan <tbuchanan@thecompassgrp.net>"

license = "See nmaps COPYING for licence"

-- uncomment the following line to enable safe category
-- categories = {"safe"}
categories = {"intrusive"}

require "shortport"

portrule = shortport.port_or_service({80, 8080}, "http")

action = function(host, port)
       local socket
       local catch = function()
               socket:close()
       end

       local try = nmap.new_try(catch)

       local get_http_headers = function(dst, dst_port, query_string)
               socket = nmap.new_socket()

               try(socket:connect(dst, dst_port))
               try(socket:send(query_string))

               local response = ""
               local lines
               local status

               while true do
                       status, lines = socket:receive_lines(1)

                       if not status then
                               break
                       end

                       response = response .. lines
               end

               try(socket:close())

               local tags = {"(.-)<![Dd][Oo][Cc][Tt][Yy][Pp][Ee]", "(.-)<[Hh][Tt][Mm][Ll]", "(.-)<[Hh][Ee][Aa][Dd]", "(.-)<[Bb][Oo][Dd][Yy]"}
               local hdrs

               for I = 1, #tags do
                       hdrs = string.match(response, tags[I])
                       if hdrs ~= nil and hdrs ~= response and hdrs ~= "" then
                               return hdrs
                       end
               end

               return response
       end

       local auth
       local value
       local realm
       local scheme
       local result
       local basic = false

       local query = "GET / HTTP/1.1\r\n"
       query = query .. "Accept: */*\r\n"
       query = query .. "Accept-Language: en\r\n"
       query = query .. "User-Agent: Nmap NSE\r\n"
       query = query .. "Connection: close\r\n"
       query = query .. "Host: " .. host.ip .. ":" .. port.number .. "\r\n\r\n"

       local headers = get_http_headers(host.ip, port.number, query)

       --- check for 401 response code
       auth = string.match(headers, "HTTP/1.- 401")
       if auth ~= nil then
               result = "HTTP Service requires authentication\n"
               -- loop through any WWW-Authenticate: headers to determine valid authentication schemes
               for value in string.gmatch(headers, "[Aa]uthenticate:(.-)\n") do
                       result = result .. "  Auth type: "
                       scheme, realm = string.match(value, "(%a+).-[Rr]ealm=\"(.-)\"")
                       if scheme == "Basic" then
                               basic = true
                       end
                       if realm ~= nil then
                               result = result .. scheme .. ", realm = " .. realm .. "\n"
                       else
                               result = result .. string.match(value, "(%a+)") .. "\n"
                       end
               end
       end

       if basic then
               query = "GET / HTTP/1.1\r\n"
               query = query .. "Authorization: Basic YWRtaW46C\r\n"
               query = query .. "Accept: */*\r\n"
               query = query .. "Accept-Language: en\r\n"
               query = query .. "User-Agent: Nmap NSE\r\n"
               query = query .. "Connection: close\r\n"
               query = query .. "Host: " .. host.ip .. ":" .. port.number .. "\r\n\r\n"

               auth = ""
               headers = get_http_headers(host.ip, port.number, query)

               auth = string.match(headers, "HTTP/1.- 40[013]")
               if auth == nil then
                       result = result .. "  HTTP server may accept user=\"admin\" with blank password for Basic authentication\n"
               end

               query = "GET / HTTP/1.1\r\n"
               query = query .. "Authorization: Basic YWRtaW46YWRtaW4\r\n"
               query = query .. "Accept: */*\r\n"
               query = query .. "Accept-Language: en\r\n"
               query = query .. "User-Agent: Nmap NSE\r\n"
               query = query .. "Connection: close\r\n"
               query = query .. "Host: " .. host.ip .. ":" .. port.number .. "\r\n\r\n"

               auth = ""
               headers = get_http_headers(host.ip, port.number, query)

               auth = string.match(headers, "HTTP/1.- 40[013]")
               if auth == nil then
                       result = result .. "  HTTP server may accept user=\"admin\" with password=\"admin\" for Basic authentication\n"
               end
       end

       return result
end

