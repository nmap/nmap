description = [[
Tries to log into a POP3 account by guessing usernames and passwords.
]]

---
-- @args pop3loginmethod The login method to use: <code>"USER"</code>
-- (default), <code>"SASL-PLAIN"</code>, <code>"SASL-LOGIN"</code>,
-- <code>"SASL-CRAM-MD5"</code>, or <code>"APOP"</code>.
--
-- @output
-- PORT    STATE SERVICE
-- 110/tcp open  pop3
-- | pop3-brute: root : password

author = "Philip Pickering"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"

categories = {"intrusive", "auth"}

require 'pop3'
require 'shortport'
require 'unpwdb'

portrule = shortport.port_or_service({110, 995}, {"pop3","pop3s"})

action = function(host, port)
   local pMeth = nmap.registry.args.pop3loginmethod
   if (not pMeth) then pMeth = nmap.registry.pop3loginmethod end
   if (not pMeth) then pMeth = "USER" end

   local login
   local additional

   local stat = pop3.stat

   if (pMeth == "USER") then 
      login = pop3.login_user
   elseif (pMeth == "SASL-PLAIN") then 
      login = pop3.login_sasl_plain
   elseif (pMeth == "SASL-LOGIN") then 
      login = login_sasl_login
   elseif (pMeth == "SASL-CRAM-MD5") then
      login = login_sasl_crammd5
   elseif (pMeth == "APOP") then 
      login = login_apop     
   end


   local status
   local line
   local socket = nmap.new_socket()
   local opts = {timeout=10000, recv_before=true}
   
   local socket, nothing, bopt, line = comm.tryssl(host, port, "" , opts)

   if not socket then return end -- no connection 
   if not stat(line) then return end -- no pop-connection

   local apopChallenge = string.match(line, "<[%p%w]+>") 
  
   if pMeth == "APOP" then 
      additional = apopChallenge 
   end
   
   local getUser
   local _

   status, getUser = unpwdb.usernames()
   if (not status) then return end


   local currUser = getUser()
   while currUser do
      local getPW
      status, getPW = unpwdb.passwords()
      if (not status) then return end

      local currPw = getPW()

      while currPw do
	 local pstatus
	 local perror

	 pstatus, perror = login(socket, currUser, currPw, additional)
	 
	 if (pstatus) then 
	    return currUser .. " : " .. currPw
	 elseif (perror == pop3.err.pwError) then
	    currPw = getPW()
	 elseif (perror == pop3.err.userError) then
	    currPw = nil
	 else
            local socstatus = socket:connect(host, port, bopt)
	    if not socstatus 
	       then return
               else _, line = socket:receive()
                    if not stat(line) then return end -- no connection
            end
         end
      end
      currUser = getUser()
      getPW("reset")
   end
   return -- "wrong pw" 

end
