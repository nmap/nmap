description = [[
Attempts to guess the name of the CVS repositories hosted on the remote server.
With knowledge of the correct repository name, usernames and passwords can be guessed.
]]

---
-- @usage 
-- nmap -p 2401 --script cvs-brute-repository <host>
--
-- @output
-- PORT     STATE SERVICE    REASON
-- 2401/tcp open  cvspserver syn-ack
-- | cvs-brute-repository: 
-- |   Repositories
-- |     /myrepos
-- |     /demo
-- |   Statistics
-- |_    Performed 14 guesses in 1 seconds, average tps: 14
--
-- @args cvs-brute-repository.nodefault when set the script does not attempt to
--       guess the list of hardcoded repositories
-- @args cvs-brute-repository.repofile a file containing a list of repositories
--       to guess

-- Version 0.1
-- Created 07/13/2010 - v0.1 - created by Patrik Karlsson <patrik@cqure.net>

author = "Patrik Karlsson"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"intrusive", "brute"}

require 'cvs'
require 'brute'
require 'creds'
require 'shortport'

portrule = shortport.port_or_service(2401, "cvspserver")

Driver = 
{

	new = function(self, host, port )
		local o = { host = host, helper = cvs.Helper:new(host, port) }
       	setmetatable(o, self)
        self.__index = self
		return o
	end,
	
	connect = function( self )
		self.helper:connect()
		return true
	end,

	login = function( self, username, password )
		username = ""
		if ( password:sub(1,1) ~= "/" ) then password = "/" .. password end
		local status, err = self.helper:login( password, "repository", "repository" )
		if ( not(status) and err:match("I HATE YOU") ) then
			-- let's store the repositories in the registry so the brute
			-- script can use them later.
			nmap.registry.cvs = nmap.registry.cvs or {}
			nmap.registry.cvs[self.host.ip] = nmap.registry.cvs[self.host.ip] or {}
			nmap.registry.cvs[self.host.ip].repos = nmap.registry.cvs[self.host.ip].repos or {}
			table.insert(nmap.registry.cvs[self.host.ip].repos, password)
			return true, brute.Account:new(username, password, 0)
		end
		return false, brute.Error:new( "Incorrect password" )
	end,
	
	disconnect = function( self )
		self.helper:close()
	end,
		
}


action = function(host, port)
	
	local status, result 
	local engine = brute.Engine:new(Driver, host, port)
	
	-- a list of "common" repository names:
	-- the first two are Debian/Ubuntu default names
	-- the rest were found during tests or in google searches
	local repos = {"myrepos", "demo", "cvs", "cvsroot", "prod", "src", "test",
	 				"source", "devel", "cvsroot", "/var/lib/cvsroot", 
					"cvs-repository", "/home/cvsroot", "/var/cvs",
					"/usr/local/cvs"}
	
	local repofile = stdnse.get_script_args("cvs-brute-repository.repofile")
	local f
	
	if ( repofile ) then
		f = io.open( repofile, "r" )
		if ( not(f) ) then
			return ("\n  ERROR: Failed to open repository file: %s"):format(repofile)
		end
	end

	repository_iterator = function()
		local function next_repo()
			for line in f:lines() do
				if ( not(line:match("#!comment")) ) then
					coroutine.yield("", line)
				end
			end
			while(true) do coroutine.yield(nil, nil) end
		end
		return coroutine.wrap(next_repo)
	end
	
	engine.options:setTitle("Repositories")
	engine.options.script_name = SCRIPT_NAME
	engine.options.passonly = true
	engine.options.firstonly = false
	engine.options.nostore = true
	engine:addIterator(brute.Iterators.account_iterator({""}, repos, "user"))
	if ( repofile ) then engine:addIterator(repository_iterator()) end
	status, result = engine:start()

	return result
end

