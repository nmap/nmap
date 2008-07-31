--- POP3 functions
--@copyright See nmaps COPYING for licence

module(...,package.seeall)

require 'base64'
require 'bit'


err = {
   none = 0,
   userError = 1,
   pwError = 2,
   informationMissing = 3
}


function stat(line)
   return string.match(line, "+OK")
end




function login_user(socket, user, pw)
   socket:send("USER " .. user .. "\r\n")
   status, line = socket:receive_lines(1)
   if not stat(line) then return false, err.user_error end
   print("my way")
   socket:send("PASS " .. pw .. "\r\n")
      
   status, line = socket:receive_lines(1)
      
   if stat(line) then return true, err.none 
   else return false, err.pwError
   end
end


function login_sasl_plain(socket, user, pw)
   
   local auth64 = base64.enc(user .. "\0" .. user .. "\0" .. pw)
   socket:send("AUTH PLAIN " .. auth64 .. "\r\n")
   
   status, line = socket:receive_lines(1)
   
   if stat(line) then 
      return true, err.none
   else 
      return false, err.pwError
   end
end

function login_sasl_login(socket, user, pw)

   local user64 = base64.enc(user)
   
   local pw64 = base64.enc(pw)

   socket:send("AUTH LOGIN\r\n")
      
   status, line = socket:receive_lines(1)
   if not base64.dec(string.sub(line, 3)) == "User Name:" then 
      return false, err.userError 
   end

   socket:send(user64)
      
   status, line = socket:receive_lines(1)

   if not base64.dec(string.sub(line, 3)) == "Password:" then 
      return false, err.userError
   end

   socket:send(pw64)
      
   status, line = socket:receive_lines(1)
    
   if stat(line) then
      return true, err.none
   else
      return false, err.pwError
   end
end


function login_apop(socket, user, pw, challenge)
   if type(challenge) ~= "string" then return false, err.informationMissing end

   local apStr = hash.md5(challenge .. pw)
   socket:send("APOP " .. user .. " " .. apStr .. "\r\n")
      
   status, line = socket:receive_lines(1)
   
   if (stat(line)) then 
      return true, err.none
   else
      return false, err.pwError
   end
end

function capabilities(host, port)
   local socket = nmap.new_socket()
   local capas = {}
   if not socket:connect(host.ip, port.number) then return "no conn" end
   
   status, line = socket:receive_lines(1)
   if not stat(line) then return "no popconn" end
   
   if string.find(line, "<[%p%w]+>") then capas.APOP = true end
   
   socket:send("CAPA\r\n")
   status, line = socket:receive_buf("\r\n", false)
   -- print("resp " .. line)
   if not stat(line) then 
      capas.capa = false
   else 
      status, line = socket:receive_buf("\r\n", false)
      while line do
	 if line ~= "." then
	    local capability = string.sub(line, string.find(line, "[%w-]+"))
	    line = string.sub(line, #capability + 1)
	    capas[capability] = true
	    local args = {}
	    local w
	    for w in string.gmatch(line, "[%w-]+") do
	       table.insert(args, w)
	    end
	    if #args == 1 then capas[capability] = args[1]
	    else if #args > 1 then capas[capability] = args 
	    end end
	 else
	    break 
	 end
	 status, line = socket:receive_buf("\r\n", false)
      end
   end
   socket:close()
   return capas
end


function hmacMD5(key, msg)
   local ipad = {}
   local opad = {}

   if (string.len(key) > 64) then
      key = hash.md5binary(key)
   end

   -- create both pads, XORing with key
   for i = 1, string.len(key) do
      ipad[i] = string.char(bit.bxor(0x36, string.byte(string.sub(key, i))))
      opad[i] = string.char(bit.bxor(0x5c, string.byte(string.sub(key, i))))
   end
   for i = #ipad + 1, 64 do
      ipad[i] = string.char(0x36)
      opad[i] = string.char(0x5c)
   end

   -- calc HMAC-md5
   return hash.md5(table.concat(opad) .. hash.md5bin(table.concat(ipad) .. msg))
end


function login_sasl_crammd5(socket, user, pw)

   socket:send("AUTH CRAM-MD5\r\n")
   
   status, line = socket:receive_lines(1)
   
   local challenge = base64.dec(string.sub(line, 3))

   local digest = hmacMD5(pw, challenge)
   local authStr = base64.enc(user .. " " .. digest)
   socket:send(authStr .. "\r\n")
      
   status, line = socket:receive_lines(1)
   
   if stat(line) then 
      return true, err.none
   else 
      return false, err.pwError
   end
end
