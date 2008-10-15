--- Functional-style list operations.
-- \n\n
-- People used to programming in functional languages, such as Lisp
-- or Haskell, appreciate their handling of lists very much. The listop
-- module tries to bring much of the functionality from functional languages
-- to Lua using Lua's central data structure, the table, as a base for its
-- list operations. Highlights include a map function applying a given
-- function to each element of a list. 
--@copyright See nmaps COPYING for licence

module(... or "listop", package.seeall)

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

--- Returns true if the given list is empty.
-- @param l A list.
-- @return boolean
function is_empty(l)
  return #l == 0 and true or false;
end

--- Returns true if the given value is a list (or rather a table).
-- @param l Any value.
-- @return boolean
function is_list(l)
  return type(l) == 'table' and true or false;
end

--- Calls f for each element in the list. The returned list contains
-- the results of each function call.
-- \n\n
-- For example, listop.map(tostring,{1,2,true})  returns
-- {"1","2","true"}. 
-- @param f The function to call.
-- @param l A list.
-- @return List
function map(f, l) 
    local results = {}
    for _, v in ipairs(l) do
    	results[#results+1] = f(v);
    end
    return results;
end

--- Calls the function with all the elements in the list as the parameters.
-- \n\n
-- For example, listop.apply(math.max,{1,5,6,7,50000}) yields 50000. 
-- @param f The function to call.
-- @param l A list.
-- @return Results from f.
function apply(f, l)
  return f(unpack(l))
end

--- Returns a list containing only those elements for which a predicate
-- function returns true.
-- \n\n
-- The predicate has to be a function taking one argument and returning
-- a Boolean. If it returns true (or rather anything besides false and
-- nil) the argument is appended to the return value of filter. For
-- example, listop.filter(isnumber,{1,2,3,"foo",4,"bar"}) returns
-- {1,2,3,4}. 
-- @param f The function.
-- @param l The list.
-- @return List
function filter(f, l) 
  local results = {}
  for i, v in ipairs(l) do
  	if(f(v)) then
   	  results[#results+1] = v;
   	end
  end
  return results
end

--- Fetch the first element of a list.
-- @param l The List.
-- @return The first element.
function car(l)
  return l[1]
end

--- Fetch all elements following the first in a new List.
-- @param l The List.
-- @return List
function cdr(l)
  return {unpack(l, 2)}
end

--- Fetch element at index x from l.
-- @param l The List.
-- @param x Element index.
-- @return Element x or 1.
function ncar(l, x)
  return l[x or 1];
end

--- Fetch all elements following the element at index x or the first.
-- @param l The List.
-- @param x Element index.
-- @return List
function ncdr(l, x) 
  return {unpack(l, x or 2)};
end

--- Prepend a value or list to another value or list.
-- @param v1 value or list
-- @param v2 value or list
-- @return List
function cons(v1, v2)
    return{ is_list(v1) and {unpack(v1)} or v1, is_list(v2) and {unpack(v2)} or v2}
end

--- Concatenate two lists and return the result.
-- @param l1 List
-- @param l2 List
-- @return List
function append(l1, l2)
    local results = {unpack(l1)}

    for _, v in ipairs(l2) do
   	  results[#results+1] = v;
    end
    return results
end

--- Return l in reverse order.
-- @param l List.
-- @return List
function reverse(l)
    local results = {}
    for i=#l, 1, -1 do
    	results[#results+1] = l[i];
    end
    return results
end

--- Return a flattened version of a list. The flattened list contains
-- only non-list values.
-- \n\n
-- For example, listop.flatten({1,2,3,"foo",{4,5,{"bar"}}}) returns
-- {1,2,3,"foo",4,5,"bar"}.
-- @param l The list to flatten.
-- @return List
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
