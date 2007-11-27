-- See nmaps COPYING for licence
module(...,  package.seeall)
require "pcre"

--various functions for use with nse's nsock:receive_buf - function

-- e.g. 
-- sock:receivebuf(regex("myregexpattern")) - does a match using pcre- regular-
--                                          - expressions
-- sock:receivebuf(numbytes(80)) - is the buffered version of 
--                                 sock:receive_bytes(80) - i.e. it returns
--                                 exactly 80 bytes and no more 
regex = function(pattern)
	local r = pcre.new(pattern, 0,"C")

	return function(buf)
		s,e = r:exec(buf, 0,0);
		return s,e
	end
end

numbytes = function(num)
	local n = num
	return function(buf)
		if(string.len(buf) >=n) then
			return n, n
		end
		return nil
	end
end

