-- See nmaps COPYING for licence
module(... or "stdnse", package.seeall)

print_debug = function(...)
	local verbosity = 1;
	if ((#arg > 1) and (tonumber(arg[1]))) then
		verbosity = table.remove(arg, 1);
	end
	
	nmap.print_debug_unformatted(verbosity, string.format(unpack(arg, start)));
end

-- Concat the contents of the parameter list,
-- separated by the string delimiter (just like in perl)
-- example: strjoin(", ", {"Anna", "Bob", "Charlie", "Dolores"})
function strjoin(delimiter, list)
	return table.concat(list, delimiter);
end

-- Split text into a list consisting of the strings in text,
-- separated by strings matching delimiter (which may be a pattern). 
-- example: strsplit(",%s*", "Anna, Bob, Charlie,Dolores")
function strsplit(delimiter, text)
	local list = {}
	local pos = 1

	if string.find("", delimiter, 1) then -- this would result in endless loops
		error("delimiter matches empty string!")
	end

	while 1 do
		local first, last = string.find(text, delimiter, pos)
		if first then -- found?
			table.insert(list, string.sub(text, pos, first-1))
			pos = last+1
		else
			table.insert(list, string.sub(text, pos))
			break
		end
	end

	return list
end


-- Generic buffer implementation using lexical closures
--
-- Pass make_buffer a socket and a separator lua pattern [1].
--
-- Returns a function bound to your provided socket with behaviour identical
-- to receive_lines() except it will return AT LEAST ONE [2] and AT MOST ONE
-- "line" at a time.
--
-- [1] Use the pattern "\r?\n" for regular newlines
-- [2] Except where there is trailing "left over" data not terminated by a
--     pattern (in which case you get the data anyways)
-- [3] The data is returned WITHOUT the pattern/newline on the end.
-- [4] Empty "lines" are returned as "". With the pattern in [1] you will
--     receive a "" for each newline in the stream.
-- [5] Errors/EOFs are delayed until all "lines" have been processed.
--
-- -Doug, June, 2007

make_buffer = function(sd, sep)
  local self, result
  local buf = ""

  self = function()
    local i, j, status, value

    i, j = string.find(buf, sep)

    if i then
      if i == 1 then  -- empty line
        buf = string.sub(buf, j+1, -1)
        --return self() -- skip empty, tail
        return true, "" -- return empty
      else
        value = string.sub(buf, 1, i-1)
        buf = string.sub(buf, j+1, -1)
        return true, value
      end
    end

    if result then
      if string.len(buf) > 0 then  -- left over data with no terminating pattern
        value = buf
        buf = ""
        return true, value
      end
      return nil, result
    end

    status, value = sd:receive()

    if status then
      buf = buf .. value
    else
      result = value
    end

    return self() -- tail
  end

  return self
end

do
  local t = {
    ["0"] = "0000",
    ["1"] = "0001",
    ["2"] = "0010",
    ["3"] = "0011",
    ["4"] = "0100",
    ["5"] = "0101",
    ["6"] = "0110",
    ["7"] = "0111",
    ["8"] = "1000",
    ["9"] = "1001",
    a = "1010",
    b = "1011",
    c = "1100",
    d = "1101",
    e = "1110",
    f = "1111"
  };

  function tobinary(n)
    assert(tonumber(n), "number expected");
    return (("%x"):format(n):gsub("%w", t):gsub("^0*", ""));
  end
end

function tooctal(n)
  assert(tonumber(n), "number expected");
  return ("%o"):format(n)
end

function tohex(n)
  assert(tonumber(n), "number expected");
  return ("%x"):format(n);
end
