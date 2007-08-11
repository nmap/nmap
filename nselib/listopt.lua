module('listopt', package.seeall)

--[[
--
Functional programming style 'list' operations

	bool	is_empty(list)
	bool	is_list(value)

	value	apply(function, list)
	list	map(function, list)
	list	filter(function, list)
	list	flatten(list)
	list	append(list1, list2)
	list	cons(value1, value2)
	list	reverse(list)

	value	car(list)
	value	ncar(list, x)
	list	cdr(list)
	list	ncdr(list, x)
	
	where 'list' is an indexed table 
	where 'value' is an lua datatype
--]]

-- true if l is empty
function is_empty(l)
	return table.getn(l) == 0 and true or false
end

-- true if l is a list
function is_list(l)
	return type(l) == 'table' and true or false
end

-- Pass each elements of l to a function f which takes a single
-- argument. All the results are returned in an list
function map(f, l) 
	local results = {}
	for i, v in ipairs(l) do
		table.insert(results, f(v))
	end
	return results
end

-- Pass all elements of l to function f which takes a variable 
-- number of arguments or a number of arguments equal to the
-- size of l. The result of f is returned
function apply(f, l)
	return f(unpack(l))
end

-- Pass all elements of l to a predicate function f which takes a single
-- argument. All elements where f(l[x]) is true are returned in an 
-- indexed list
function filter(f, l) 
	local results = {}
	for i, v in ipairs(l) do
		if(f(v)) then
			table.insert(results, v)
		end
	end
	return results
end

-- return first element of a list
function car(l)
	return l[1]
end

-- return everything but the first element of a list
function cdr(l)
	return ncdr(l)
end

-- same as car but start at element x
function ncar(l, x)
	x = x or 1
	return l[x]
end

-- same as cdr but start at element x
function ncdr(l, x) 
	local results = {}
	x = x or 2
	for i = x, table.getn(l) do
		results[i-1] = l[i]
	end
	return results
end

-- prepend a value or list to another value or list
function cons(v1, v2)
	return{ is_list(v1) and {unpack(v1)} or v1, is_list(v2) and {unpack(v2)} or v2}
end

-- concatenate two lists and return the result
function append(l1, l2)
	local results = {}
	for i, v in ipairs(l1) do 
		table.insert(results, v)
	end

	for i, v in ipairs(l2) do
		table.insert(results, v)
	end
	return results
end

-- returned l in reverse order
function reverse(l)
	local results = {}
	for i=table.getn(l), 1, -1 do
		table.insert(results, l[i])
	end
	return results
end

-- return a flat version of nested list l
function flatten(l)
	local function flat(r, t)
		for i, v in ipairs(t) do
			if(type(v) == 'table') then
				flat(r, v)
			else
				table.insert(r, v)
			end
		end
		return r
	end
	return flat({}, l)
end
