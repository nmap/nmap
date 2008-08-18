--- Provides functions which can be used for delimiting data received
-- by receive_buf() function in the Network I/O API.
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

--- This is actually a wrapper around NSE's PCRE library exec function,
-- thus giving script developers the possibility to use regular expressions
-- for delimiting instead of Lua's string patterns. If you want to get the
-- data in chunks separated by pattern (which has to be a valid regular
-- expression), you would write:
-- status, val = sockobj:receive_buf(match.regex("pattern")). 
-- @param The regex.
regex = function(pattern)
	local r = pcre.new(pattern, 0,"C")

	return function(buf)
		s,e = r:exec(buf, 0,0);
		return s,e
	end
end

--- Takes a number as its argument and returns that many bytes. It can be
-- used to get a buffered version of sockobj:receive_bytes(n) in case a
-- script requires more than one fixed-size chunk, as the unbuffered
-- version may return more bytes than requested and thus would require
-- you to do the parsing on your own. 
-- @param num Number of bytes.
numbytes = function(num)
	local n = num
	return function(buf)
		if(string.len(buf) >=n) then
			return n, n
		end
		return nil
	end
end

