local stdnse = require "stdnse"
local dns = require "dns"
local shortport = require "shortport"
local target = require "target"

description = [[
Checks if ANY dns type is allowed.

Usually if server allows ANY queries, it will send more than one answers.
During prerule phase, if <code>newtargets</code> script argument is passed
it will find new targets to nmap scanning queue
]]

---
-- @usage
-- nmap --script=dns-any-query -p53 <host>
--
-- Script uses dns library to connect to dns server
--
-- @output
-- PORT   STATE SERVICE REASON
-- 53/udp open  domain  udp-response ttl 55
-- | dns-any-query:
-- |   Result: Server is likely responding to ANY query
-- |   Authoritative: TRUE
-- |   Found:
-- |     		MX
-- |     		SOA
-- |     		TXT
-- |     		TXT
-- |_    		TXT

author = "Erhad Husovic"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"default","safe"}

local options = {}

-- During prerule phase, we except two variables: dns-any-query.server to query against and
-- dns-any-query.query-domain domain to query
-- Also, passing additional script arg <code>newtargets</code> will add domain name and server
-- to new targets
prerule = function()
  options.domain_name, options.server, options.full_output,options.newtargets = stdnse.get_script_args(
	"dns-any-query.query-domain","dns-any-query.server","dns-any-query.full-output","newtargets"
  )

  if not options.domain_name then
    return false
  end

  if not options.server then
    return false
  end

  options.port = 53
  if options.newtargets then
    local status, err = target.add(options.domain_name,options.server)
  end
  return true
end

-- During hostrule phase, we check if there is dns-any-query.server passed as argument
-- If argument isn't passed, we will set server as host.targetname or host.name
-- false is returned if neither of them is accessible
hostrule = function(host)
  options.server = stdnse.get_script_args("dns-any-query.server")
  options.port = 53

  if not host.name then
    if not host.targetname then
      return false
    else
     options.domain_name = host.target
    end
  else
    options.domain_name = host.name
  end

  if not options.server then
    return false
  end

  return true
end

-- portrule checks if we received 53/udp port and tries to obtain query-domain from
-- script arguments.
-- if query-domain isn't passed, we try to extract domain name from parts of host 
portrule = function(host,port)
  stdnse.debug1('trigerred portrule')
  if shortport.portnumber(53,{'udp','tcp'})(host,port) then
    options.domain_name = stdnse.get_script_args("dns-any-query.query-domain")
    if not options.domain_name then
      if host.targetname then
        options.domain_name = host.targetname
      elseif host.name ~= "" then
        options.domain_name = host.name
      else
        -- we couldnt obtain domain_name query through script arg, print error and exit
        stdnse.debug3("Skipping '%s' '%s', 'dns-any-query.query-domain' argument is missing",SCRIPT_NAME,SCRIPT_TYPE)
        return false
      end
    end
    options.port = port
    options.server = host.ip


    return true
  end

  return false
end

function print_data(result)
  local full_output = stdnse.get_script_args("dns-any-query.full-output")
  local output = stdnse.output_table()


  if result.answers then
    if #result.answers > 1 then
      output.Result = "Server is likely responding to ANY query"
      if result.flags.AA == true then
        output.Authoritative = "TRUE"
      else
        output.Authoritative = "FALSE"
      end
      output.Found = {}
      -- loop through every dns type
        -- loop through answers returned by dns server
      for i=1,#result.answers do 
        for j,k in pairs(result.answers[i]) do
          if j == 'dtype' then
            for l,m in pairs(dns.types) do
              if k == m then
		output.Found[#output.Found+1] = "\t\t" .. l
	      end
	    end
	  end
	end
      end
    else
      output.Result = "Server probably doesn't respond to ANY query"
    end

    if full_output then
      output.Results = result.answers
    end
  else
    output = ""
  end

  return output
end

action = function()
  local status,result = dns.query(options.domain_name,{host = options.server,port=options.port,dtype='ANY',retAll=true,retPkt=true,norecurse=false,noauth=true})
  local output = print_data(result)
  return output
end
