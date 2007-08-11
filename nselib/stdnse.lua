module(..., package.seeall)

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
	local len = getn(list)
	if len == 0 then 
		return "" 
	end

	local string = list[1]
	for i = 2, len do 
		string = string .. delimiter .. list[i] 
	end

	return string
end

-- Split text into a list consisting of the strings in text,
-- separated by strings matching delimiter (which may be a pattern). 
-- example: strsplit(",%s*", "Anna, Bob, Charlie,Dolores")
function strsplit(delimiter, text)
	local list = {}
	local pos = 1

	if strfind("", delimiter, 1) then -- this would result in endless loops
		error("delimiter matches empty string!")
	end

	while 1 do
		local first, last = strfind(text, delimiter, pos)
		if first then -- found?
			tinsert(list, strsub(text, pos, first-1))
			pos = last+1
		else
			tinsert(list, strsub(text, pos))
			break
		end
	end

	return list
end

-- String buffer functions. Concatenation is not efficient in 
-- lua as strings are immutable. If a large amount of '..' 
-- operations are needed a string buffer should be used instead

--[[
	local buf = strbuf.new()
	strbuf.add(buf, 'string') ; strbuf.add(buf, 'data')

	print(buf)                   -- default seperator is a new line
	print(strbuf.dump(buf))      -- no seperator
	print(strbuf.dump(buf, ' ')) -- seperated by spaces
	strbuf.clear(buf)
--]]

strbuf_dump = table.concat 

function strbuf_new()
	local sbuf = {}
	sbuf.mt = {}
	setmetatable(sbuf, sbuf.mt)
	sbuf.mt.__tostring = function(s) return strbuf_dump(s, '\n') end
	return sbuf
end

function strbuf_add(sbuf, s)
	if not (type(s) == 'string') or
	   not (type(sbuf) == 'table') then
		return nil 
	end
	table.insert(sbuf, s)
	return table.getn(sbuf)
end

function strbuf_clear(sbuf)
	for i, v in pairs(sbuf) do
		sbuf[i] = nil
    	end
end

-- pseudo namespace for string buffers
strbuf = { new=strbuf_new, add=strbuf_add, dump=strbuf_dump, clear=strbuf_clear }

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
