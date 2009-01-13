--- Username/password database library.
--
-- The <code>usernames</code> and <code>passwords</code> functions return
-- multiple values for use with exception handling via
-- <code>nmap.new_try</code>. The first value is the Boolean success
-- indicator, the second value is the closure.
--
-- The closures can take an argument of <code>"reset"</code> to rewind the list
-- to the beginning.
--
-- You can select your own username and/or password database to read from with
-- the script arguments <code>userdb</code> and <code>passdb</code>,
-- respectively.  Comments are allowed in these files, prefixed with
-- <code>"#!comment:"</code>.  Comments cannot be on the same line as a
-- username or password because this leaves too much ambiguity, e.g. does the
-- password in <code>"mypass  #!comment: blah"</code> contain a space, two
-- spaces, or do they just separate the password from the comment?
--
-- @args userdb The filename of an alternate username database.
-- @args passdb The filename of an alternate password database.
-- @author Kris Katterjohn 06/2008
-- @copyright Same as Nmap--See http://nmap.org/book/man-legal.html

module(... or "unpwdb", package.seeall)

local usertable = {}
local passtable = {}

local customdata = false

-- So I don't have to type as much :)
local args = nmap.registry.args

local userfile = function()
	if args.userdb then
		customdata = true
		return args.userdb
	end

	return nmap.fetchfile("nselib/data/usernames.lst")
end

local passfile = function()
	if args.passdb then
		customdata = true
		return args.passdb
	end

	return nmap.fetchfile("nselib/data/passwords.lst")
end

local filltable = function(filename, table)
	if #table ~= 0 then
		return true
	end

	local file = io.open(filename, "r")

	if not file then
		return false
	end

	while true do
		local l = file:read()

		if not l then
			break
		end

		-- Comments takes up a whole line
		if not l:match("#!comment:") then
			table[#table + 1] = l
		end
	end

	file:close()

	return true
end

local closure = function(table)
	local i = 1

	return function(cmd)
		if cmd == "reset" then
			i = 1
			return
		end
		local elem = table[i]
		if elem then i = i + 1 end
		return elem
	end
end

--- Returns the suggested number of seconds to attempt a brute force attack,
-- based on Nmap's timing values (<code>-T4</code> etc.) and whether or not a
-- user-defined list is used.
--
-- You can use the script argument <code>notimelimit</code> to make this
-- function return <code>nil</code>, which means the brute-force should run
-- until the list is empty. If <code>notimelimit</code> is not used, be sure to
-- still check for <code>nil</code> return values on the above two functions in
-- case you finish before the time limit is up.
timelimit = function()
   -- If we're reading from a user-defined username or password list,
   -- we'll give them a timeout 1.5x the default.  If the "notimelimit"
   -- script argument is used, we return nil.
	local t = nmap.timing_level()

	-- Easy enough
	if args.notimelimit then
		return nil
	end

	if t <= 3 then
		return (customdata and 900) or 600
	elseif t == 4 then
		return (customdata and 450) or 300
	elseif t == 5 then
		return (customdata and 270) or 180
	end
end

--- Returns a function closure which returns a new username with every call
-- until the username list is exhausted (in which case it returns
-- <code>nil</code>).
-- @return boolean Status.
-- @return function The usernames iterator.
usernames = function()
	local path = userfile()

	if not path then
		return false, "Cannot find username list"
	end

	if not filltable(path, usertable) then
		return false, "Error parsing username list"
	end

	return true, closure(usertable)
end

--- Returns a function closure which returns a new password with every call
-- until the password list is exhausted (in which case it returns
-- <code>nil</code>).
-- @return boolean Status.
-- @return function The passwords iterator.
passwords = function()
	local path = passfile()

	if not path then
		return false, "Cannot find password list"
	end

	if not filltable(path, passtable) then
		return false, "Error parsing password list"
	end

	return true, closure(passtable)
end

