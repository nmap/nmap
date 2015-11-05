---
-- Buffered network I/O helper functions.
--
-- The functions in this module can be used for delimiting data received by the
-- <code>nmap.receive_buf</code> function in the Network I/O API (which see).
-- @copyright Same as Nmap--See https://nmap.org/book/man-legal.html

local stdnse = require "stdnse"
_ENV = stdnse.module("match", stdnse.seeall)

--various functions for use with NSE's nsock:receive_buf - function

-- e.g.
-- sock:receive_buf(numbytes(80), true) - is the buffered version of
--                                        sock:receive_bytes(80) - i.e. it
--                                        returns exactly 80 bytes and no more

--- Return a function that allows delimiting at a certain number of bytes.
--
-- This function can be used to get a buffered version of
-- <code>sock:receive_bytes(n)</code> in case a script requires more than one
-- fixed-size chunk, as the unbuffered version may return more bytes than
-- requested and thus would require you to do the parsing on your own.
--
-- The <code>keeppattern</code> parameter to receive_buf should be set to
-- <code>true</code>, otherwise the string returned will be 1 less than
-- <code>num</code>
-- @param num Number of bytes.
-- @usage sock:receive_buf(match.numbytes(80), true)
-- @see nmap.receive_buf
numbytes = function(num)
  local n = num
  return function(buf)
    if(#buf >=n) then
      return n, n
    end
    return nil
  end
end


return _ENV;
