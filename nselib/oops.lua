--- Useful error stack objects
--
-- Many NSE library functions return a boolean status and an optional error
-- message. The Oops library consists of several simple functions to accumulate
-- these errors and pass them up the stack, resulting in a useful and verbose
-- error message when debugging.
--
-- @author Daniel Miller
-- @copyright Same as Nmap--See https://nmap.org/book/man-legal.html
-- @class module
-- @name oops

local require = require
local setmetatable = setmetatable
local _ENV = require "strict" {}

local nmap = require "nmap"
local debugging = nmap.debugging
local verbosity = nmap.verbosity

local table = require "table"
local concat = table.concat
local insert = table.insert

local Oops = {
  new = function (self, message)
    local o = {message}
    setmetatable(o, self)
    self.__index = self
    return o
  end,

  push = function (self, message)
    insert(self, 1, message)
  end,

  __tostring = function (self)
    local banner = "The script encountered an error"
    local sep = ":\n- "
    if debugging() > 0 then
      -- Print full error trace
      return banner .. sep .. concat(self, sep)
    end
    if verbosity() > 0 then
      -- Show just the top error
      return banner .. ": " .. self[1]
    end
    -- By default, no string output shown.
    return ""
  end,
}

--- Add an error message to a stack of errors
--
-- @param message The error message to add to the stack.
-- @param previous (Optional) Any error reported by other functions that failed.
-- @return An Oops object representing the error stack.
err = function (message, previous)
  local result
  if previous then
    if previous.push then
      result = previous
    else
      result = Oops:new(previous)
    end
    result:push(message)
  elseif message.push then
    result = message
  else
    result = Oops:new(message)
  end
  return result
end
local err = err

--- Report an error or return a good value
--
-- If the status is true, just return the message. If it's false, return the
-- message as an Oops object. This can be easily used as the final return value
-- of a script.
-- @param status The return status of the script.
-- @param message The output of the script, or an error message if status is false.
-- @return The message if status is true, or an error message if it is false.
output = function (status, message)
  if status then
    return message
  else
    return err(message)
  end
end
local output = output

--- Report a status and error or return values
--
-- This is intended to wrap a function that returns a status and either an
-- error or some value. If the status is false, the message is added to the
-- stack of errors. Instead of this code:
--
-- <code>
-- local status, value_or_error, value = somefunction(args)
-- if not status then
--   return status, "somefunction failed for some reason"
-- end
-- </code>
--
-- with this instead:
--
-- <code>
-- local status, value_or_error, value = oops.raise("somefunction failed", somefunction(args))
-- if not status then
--   return status, value_or_error
-- end
-- </code>
--
-- but instead of just the one error, you get a stack of errors from
-- <code>somefunction</code> with your own message at the top.
--
-- @param message The error message to report if status is false.
-- @param status The first return value of the function. Treated as boolean, but returned unmodified.
-- @param previous The second return value of the function, or error.
-- @return The same status that was input.
-- @return The rest of the return values, but on error, the message will be added to the stack.
raise = function (message, status, previous, ...)
  local r = previous
  if not status then
    r = err(message, previous)
  end
  return status, r, ...
end

return _ENV
