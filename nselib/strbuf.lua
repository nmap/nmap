-- license = "See nmaps COPYING for license"
module("strbuf" ,package.seeall)

-- String buffer functions. Concatenation is not efficient in 
-- lua as strings are immutable. If a large amount of '..' 
-- operations are needed a string buffer should be used instead

--[[
	local buf = strbuf.new()
	-- from here buf may be used like a string for concatenation operations
	-- (the lefthand-operand has to be a strbuf, the righthand-operand may be 
	-- a string or a strbuf)
	-- alternativly you can assign a value (which will become the first string
	-- inside the buffer) with new
	local buf2 = strbuf.new('hello')
	buf = buf .. 'string'
	buf = buf .. 'data'
	print(buf)                   -- default seperator is a new line
	print(strbuf.dump(buf))      -- no seperator
	print(strbuf.dump(buf, ' ')) -- seperated by spaces
	strbuf.clear(buf)
--]]



dump = table.concat 

concatbuf =function(sbuf, s)
	if sbuf == s then
		error("refusing to concat the same buffer (recursion)!")
	end
	if getmetatable(sbuf) ~= mt then
		error("left-hand operand of the concat operation has to be a strbuf!")
	end
	if type(s)=="string" then
		table.insert(sbuf, s)
	elseif getmetatable(s) == mt then
		for _,v in ipairs(s) do
			table.insert(sbuf, v)
		end
	else 
		error("right-hand operand of concat has to be either string or strbuf!")
	end
	return sbuf
end

local eqbuf = function(sbuf1, sbuf2)
	if getmetatable(sbuf1) ~= mt then
		error("equal function expects a value of type strbuf as left-hand operand")
	end
	if getmetatable(sbuf1) ~= getmetatable(sbuf2) then
		return false
	end

	if #sbuf1 ~= #sbuf2 then
		return false
	end
	
	for i=1, #sbuf1 do
		if sbuf1[i] ~= sbuf2[i] then
			return false
		end
	end
	return true
end
clear = function(sbuf)
	for i, v in pairs(sbuf) do
		sbuf[i] = nil
    	end
end

mt = { __concat = concatbuf, __tostring = function(s) return dump(s, '\n') end ,  __eq=eqbuf}

new = function(val)
	local tmp ={}
	setmetatable(tmp, mt)
	if val ~=nil then
		table.insert(tmp, val)
	end
	return tmp
end



