--- Buffered network I/O helper functions.
-- \n\n
-- The functions in this module can be used for delimiting data received
-- by the receive_buf function in the Network I/O API.
--@copyright See nmaps COPYING for licence

module(... or "match",  package.seeall)
require "pcre"

--various functions for use with nse's nsock:receive_buf - function

-- e.g. 
-- sock:receivebuf(regex("myregexpattern")) - does a match using pcre- regular-
--                                          - expressions
-- sock:receivebuf(numbytes(80)) - is the buffered version of 
--                                 sock:receive_bytes(80) - i.e. it returns
--                                 exactly 80 bytes and no more 

--- Return a function that allows delimiting with a regular expression.
-- \n\n
-- This function is a wrapper around the exec function of the pcre
-- library. It purpose is to give script developers the ability to use
-- regular expressions for delimiting instead of Lua's string patterns.
-- @param The regex.
-- @usage sock:receivebuf(regex("myregexpattern"))
regex = function(pattern)
	local r = pcre.new(pattern, 0,"C")

	return function(buf)
		s,e = r:exec(buf, 0,0);
		return s,e
	end
end

--- Return a function that allows delimiting at a certain number of bytes.
-- \n\n
-- This function can be used to get a buffered version of
-- sockobj:receive_bytes(n) in case a script requires more than one
-- fixed-size chunk, as the unbuffered version may return more bytes
-- than requested and thus would require you to do the parsing on your
-- own. 
-- @param num Number of bytes.
-- @usage sock:receivebuf(numbytes(80))
numbytes = function(num)
	local n = num
	return function(buf)
		if(string.len(buf) >=n) then
			return n, n
		end
		return nil
	end
end

