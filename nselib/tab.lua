--- Provide NSE scripts with a way to output structured tables similar to
-- NmapOutputTable.cc.
--@copyright See nmaps COPYING for license

module(... or "tab",package.seeall)

require('strbuf')

--- Create and return a new table with a number of columns equal to col and
-- the row counter set to 1.
function new(cols)
	assert(cols > 0)
	local table ={}

	table['cols'] = cols
	table['rows'] = 1
	setmetatable(table, {__tostring=dump})
	return table
end

--- Add a new string item (v) in a previously initialised table (t)
-- at column position 'c'. The data will be added to the current
-- row, if nextrow() hasn't been called yet that will be row 1.
function add(t, c, v)
	assert(t)
	assert(v)
	assert(t['rows'])
	assert(t['cols'])
	assert(type(v) == "string")

	if c < 1 or c > t['cols'] then
		return false
	end

	-- add a new row if one doesn't exist
	if t[t['rows']] == nil then
		t[t['rows']] = {}
	end

	t[t['rows']][c] = v
	return true
end

--- Move on to the next row in the table. If this is not called
-- then previous column values will be over-written by subsequent
-- values.
function nextrow(t)
	assert(t)
	assert(t['rows'])
	t['rows'] = t['rows'] + 1
end

--- Once items have been added to a table, call this to return a
-- string which contains an equally spaced table. Number of spaces 
-- is based on the largest element of a column with an additional
-- two spaces for padding.
function dump(t)
	assert(t)
	assert(t['rows'])
	assert(t['cols'])

	local col_len = {}	
	local table = strbuf.new()
	local len

	-- find largest string in column
	for i=1, t['cols'] do
		local max = 0
		for x=1, t['rows'] do
			if t[x] == nil then t[x] = {} end
			if t[x][i] ~= nil and string.len(t[x][i]) > max then
				max = string.len(t[x][i])
			end
		end
		col_len[i] = max+2
	end

	-- build table with padding so all column elements line up
	for i=1,t['rows'] do
		for x=1, t['cols'] do
			if t[i][x] ~= nil then
				length = string.len(t[i][x])
				table = table .. t[i][x]
				table = table .. string.rep(' ', col_len[x]-length)
			end
		end
		table = table .. "\n"
	end

	return strbuf.dump(table)
end

--[[ Example Usage

local t = tab.new(2)
tab.add(t, 1, 'A1')
tab.add(t, 2, 'A2')
tab.nextrow(t)
tab.add(t, 1, 'BBBBBBBBB1')
tab.add(t, 2, 'BBB2')
tab.dump(t)

--]]
