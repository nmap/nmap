---
-- This module was written to marshall parameters for Microsoft RPC (MSRPC) calls. The values passed in and out are based
-- on structs defined by the protocol, and documented by Samba developers. For detailed breakdowns of the types, take a
-- look at Samba 4.0's <code>.idl</code> files.
--
-- There is nothing simple about how this all comes together, so I'll take some time to explain how it's done. This
-- is fairly technical and, when it comes right down to it, unnecessary for how to use these functions (although if you
-- want to write one of these, you best understand it).
--
-- There are base types, like int32 and int16. These are marshalled the way you'd expect (converted to a 4- or
-- 2-byte little endian string). The only trick with these is that they have to end up aligned on 4-byte boundaries.
-- So, a 2-byte integer requires 2 bytes of padding, and a 1-byte integer requires 3 bytes of padding. The functions
-- <code>marshall_int32</code>, <code>marshall_int16</code>, etc. will marshall the base types, and <code>unmarshall_int32</code>,
-- <code>unmarshall_int16</code>, etc. will unmarshall them.
--
-- Strings are a little bit trickier. A string is preceded by three 32-bit values: the max length, the offset, and
-- the length. Additionally, strings may or may not be null terminated, depending on where they're being used. For
-- more information on strings, see the comments on <code>marshall_unicode</code>. The functions <code>marshall_unicode</code>
-- and <code>unmarshall_unicode</code> can be used to marshall/unmarshall strings.
--
-- Pointers also have interesting properties. A pointer is preceded by a 4-byte value called (at least by Wireshark)
-- the "referent id". For a valid pointer, this can be anything except 0 (I use 'NMAP' for it). If it's '0', then
-- it's a null pointer and the data doesn't actually follow. To help clarify, a pointer to the integer '4' could be
-- marshalled as the hex string <code>78 56 34 12 04 00 00 00</code> (the referent_id is 0x12345678 and the integer
-- itself is 0x00000004). If the integer is nil, then it's marshalled as <code>00 00 00 00</code>, which is simply
-- a referent_id of 0.
--
-- From the perspective of the program, pointers can be marshalled by using the "<code>_ptr</code>" versions of normal functions
-- (for example, <code>marshall_int32_ptr</code> and <code>unmarshall_unicode_ptr</code>. From the perspective
-- of functions within this module, especially functions for marshalling structs and arrays, the <code>marshall_ptr</code>
-- and <code>unmarshall_ptr</code> functions should be used. These can marshall any data type; the marshalling function
-- is passed as a parameter.
--
-- So far, this is fairly straight forward. Arrays are where everything falls apart.
--
-- An array of basic types is simply the types themselves, preceded by the "max length" of the array (which can be
-- longer than the actual length). When pointers are used in an array, however, things get hairy. The 'referent_id's
-- of the pointers are all put at the start of the array, along with the base types. Then, the data is put at the
-- end of the array, for all the referent_ids that aren't null. Let's say you have four strings, "abc", "def", null, and
-- "jkl", in an array. The array would look like this:
-- <code>
--  0x00200000 (referent_id for "abc")
--  0x00400000 (referent_id for "def")
--  0x00000000 (null referent_id)
--  0x00800000 (referent_id for "jkl")
--  "abc" (note that this also has the standard string stuff, the max_length, offset, and actual_length)
--  "def"
--  "ghi"
-- </code>
--
-- If you mix in a base type, it goes at the front along with the referent_ids. So, let's say you have a structure
-- that contains two integers and a string. You have an array of these. It would encode like this:
-- <code>
--  0x00200000 (referent_id for the string in the first struct)
--  0x00000001 (first integer in the first struct)
--  0x00000002 (second integer in the first struct)
--  0x00400000 (referent_id for the string in the second struct)
--  0x00000003 (first integer in the second struct)
--  0x00000004 (second integer in the second struct)
--  "string1" (contains max_length, offset, and actual_length)
--  "string2"
-- </code>
--
-- From the perspective of the program, arrays shouldn't need to be marshalled/unmarshalled, this is tricky and should be
-- left up to functions within this module. Functions within this module should use <code>marshall_array</code> and
-- <code>unmarshall_array</code> to interact with arrays. These take callback functions for the datatype being stored
-- in the array; these callback functions have to be in a particular format, so care should be taken when writing them.
-- In particular, the first parameter has to be <code>location</code>, which is used to separate the header (the part with the
-- referent_ids) and the body (the part with the pointer data). These are explained more thoroughly in the function headers.
--
-- Structs are handled the same as arrays. The referent_ids and base types go at the top, and the values being pointed to
-- go at the bottom. An array of struct, as has already been shown, will have all the base types and referent_ids for all the
-- members at the top, and all the values for all the pointers at the bottom.
--
-- Structs tend to be custom functions. Sometimes, these functions are passed as the callback to <code>marshall_ptr</code> or
-- <code>marshall_array</code> (and the equivalent <code>unmarshall_</code> functions). This means that the custom struct
-- functions have to be able to split themselves into the base types and the pointer data automatically. For an example, see
-- the functions that have already been written.
--
-- In the case where you need to unmarshall the same struct from both an array and a pointer, there's an issue; they require
-- different prototypes. There's really no way to directly fix this, at least, none that I could come up with, so I write
-- a function called <code>unmarshall_struct</code>. <code>unmarshall_struct</code> basically calls a struct unmarshalling
-- function the same way <code>unmarshall_array</code> would. This is a bit of a kludge, but it's the best I could come up
-- with.
--
-- There are different sections in here, which correspond to "families" of types. I modeled these after Samba's <code>.idl</code> files.
-- MISC corresponds to <code>misc.idl</code>, LSA to <code>lsa.idl</code>, etc. Each of these sections has possible dependencies; for example, SAMR
-- functions use LSA strings, and everything uses SECURITY and MISC. So the order is important -- dependencies have to go
-- above the module.
--
-- The datatypes used here are modeled after the datatypes used by Microsoft's functions. Each function that represents
-- a struct will have the struct definition in its comment; and that struct (or the closest representation to it) will be
-- returned. Often, this requires scripts to access something like <code>result['names']['names'][0]['name']</code>, which is
-- rather unwieldy, but I decided that following Microsoft's definitions was the most usable way for many reasons. I find
-- the best way to figure out how to work a function is to call a print_table()-style function on the result and look at
-- how the response is laid out.
--
-- Many datatypes are automatically encoded when sent and decoded when received to make life easier for developers. Some
-- examples are:
-- * All absolute time values will be seconds from 1970
-- * All relative time values will be in seconds (this includes the <code>hyper</code> datatype); when possible, the milliseconds/microseconds (as far down as we have access to) will be preserved as a decimal
-- * All enumerations will be a string representing the constant (which can be converted to a user-readable string using one of the <code>_tostr</code> functions); what that means is, enumeration values are never used, only the names
-- * SIDs will be converted to user-readable strings in the standard format (S-x-y-...)
-- * GUIDs are stored as tables of values; however, I might change this to a string representation at some point

local bin = require "bin"
local bit = require "bit"
local os = require "os"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"
local unicode = require "unicode"
_ENV = stdnse.module("msrpctypes", stdnse.seeall)

local REFERENT_ID = 0x50414d4e
local HEAD = 'HEAD'
local BODY = 'BODY'
local ALL  = 'ALL'

--- Convert a string to Unicode (UTF-16 LE), optionally add a null terminator,
-- and align it to 4-byte boundaries.
--
-- This is frequently used in MSRPC calls, so I put it here, but it might be a
-- good idea to move this function (and the converse one below) into a separate
-- library.
--
--@param string The string to convert.
--@param do_null [optional] Add a null-terminator to the unicode string.
--               Default false.
--@return The unicode version of the string.
function string_to_unicode(string, do_null)
  local i

  stdnse.debug4("MSRPC: Entering string_to_unicode(string = %s)", string)

  if(do_null == nil) then
    do_null = false
  end

  -- Try converting the value to a string
  if(type(string) ~= 'string') then
    string = tostring(string)
  end

  if(string == nil) then
    stdnse.debug1("MSRPC: WARNING: couldn't convert value to string in string_to_unicode()")
  end


  local result = unicode.utf8to16(string)

  -- Add a null, if the caller requested it
  if(do_null == true) then
    result = result .. "\0\0"
  end

  -- Align it to a multiple of 4, if necessary
  if(#result % 4 ~= 0) then
    result = result .. "\0\0"
  end

  stdnse.debug4("MSRPC: Leaving string_to_unicode()")

  return result
end

--- Read a unicode string from a buffer, similar to how <code>bin.unpack</code> would, optionally eat the null terminator,
--  and optionally align it to 4-byte boundaries.
--
--@param buffer   The buffer to read from, typically the full 'arguments' value for MSRPC
--@param pos      The position in the buffer to start (just like <code>bin.unpack</code>)
--@param length   The number of ascii characters that will be read (including the null, if do_null is set).
--@param do_null  [optional] Remove a null terminator from the string as the last character. Default false.
--@return (pos, string) The new position and the string read, again imitating <code>bin.unpack</code>. If there was an
--        attempt to read off the end of the string, then 'nil' is returned for both parameters.
function unicode_to_string(buffer, pos, length, do_null)
  stdnse.debug4("MSRPC: Entering unicode_to_string(pos = %d, length = %d)", pos, length)

  local endpos = pos + length * 2 - 1

  if endpos > #buffer then
    stdnse.debug1("MSRPC: ERROR: Ran off the end of a string in unicode_to_string(), this likely means we are reading a packet incorrectly. Please report! (pos = %d, #buffer = %d, endpos = %d)", pos, #buffer, endpos)

    return nil, nil
  end

  local str = unicode.utf16to8(string.sub(buffer, pos, endpos))

  if do_null then
    str = string.sub(str, 1, -2) -- Eat the null terminator
  end

  -- Align to 4-byte boundary
  endpos = endpos + (endpos + 1 - pos) % 4

  stdnse.debug4("MSRPC: Leaving unicode_to_string()")

  return endpos + 1, str
end

-------------------------------------
--          SPECIAL
-- (dependencies: n/a)
-------------------------------------

---Marshalls a pointer to another datatype.
--
-- This function will optionally separate the REFERENT_ID of the pointer (which
-- goes at location = HEAD) from the data part of the pointer (which goes at
-- location = BODY). If the entire pointer is needed, then location should be
-- set to ALL.
--
-- When marshalling the body, the function <code>func</code> is called, which
-- is passed as a parameter, with the arguments <code>args</code>. This
-- function has to return a marshalled parameter, but other than that it can be
-- any marshalling function. The 'value' parameter simply determined whether or
-- not it's a null pointer, and will probably be a repeat of one of the
-- arguments.
--
-- Note that the function <code>func</code> doesn't have to conform to any
-- special prototype, as long as the <code>args</code> array matches what the
-- function wants.
--
-- This can be used to marshall an int16 value of 0x1234 with padding like this:
-- <code>
--  marshall_ptr(ALL, marshall_int16, {0x1234, true}, 0x1234)
-- </code>
--
-- And here's how a 'nil' string might be marshalled:
-- <code>
--  local str = nil
--  marshall_ptr(ALL, marshall_unicode, {str, true}, str)
-- </code>
--
--@param location The part of the pointer wanted, either HEAD (for the
--                referent_id), BODY (for the pointer data), or ALL (for both
--                together). Generally, unless the referent_id is split from
--                the data (for example, in an array), you will want ALL.
--@param func The function to call when encoding the body. Should convert the
--            arguments passed in the <code>args</code> parameter to a string.
--@param args An array of arguments that will be directly passed to the
--            function <code>func</code>
--@param value The value that's actually being encoded. This is simply used to
--             determine whether or not the pointer is null.
--@return A string representing the marshalled data.
local function marshall_ptr(location, func, args, value)
  local result = ""

  stdnse.debug4("MSRPC: Entering marshall_ptr(location = %s)", location)

  -- If we're marshalling the HEAD section, add a REFERENT_ID.
  if(location == HEAD or location == ALL) then
    if(func == nil or args == nil or value == nil) then
      result = result .. bin.pack("<I", 0)
    else
      result = result .. bin.pack("<I", REFERENT_ID)
    end
  end

  -- If we're marshalling the BODY section, and the value isn't null, call the function to marshall
  -- the data.
  if(location == BODY or location == ALL) then
    if(func == nil or args == nil or value == nil) then
    else
      result = result .. func(table.unpack(args))
    end
  end

  stdnse.debug4("MSRPC: Leaving marshall_ptr()")

  return result
end

---Unmarshalls a pointer by removing the referent_id in the HEAD section and
--the data in the BODY section (or both in the ALL section).
--
-- Because the unmarshall function for the body is called if and only if the
-- referent_id is non-zero, if the head and the body are split apart, the
-- second call to this function has to know the context. This is the purpose
-- for the <code>result</code> parameter, it is the result from the first time
-- this is called.
--
-- The function <code>func</code> has to conform to this format:
--<code>
-- func(data, pos, <args>)
--</code>
--
--@param location The part of the pointer being processed, either HEAD (for the
--                referent_id), BODY (for the pointer data), or ALL (for both
--                together). Generally, unless the referent_id is split from
--                the data (for example, in an array), you will want ALL.
--@param data The data being processed.
--@param pos The position within <code>data</code>
--@param func The function that's used to process the body data (only
--            called if it isn't a null pointer). This function has to conform
--            to a specific prototype, see above.
--@param args The arguments that'll be passed to the function
--            <code>func</code>, after the data array and the position.
--@param result This is required when unmarshalling the BODY section, which
--              always comes after unmarshalling the HEAD. It is the result
--              returned for this parameter during the HEAD unmarshall. If the
--              referent_id was '0', then this function doesn't unmarshall
--              anything.
--@return The new position
--@reutrn The result. For HEAD the result is either <code>true</code> for valid
--        pointers or <code>false</code> for null pointers. For BODY or ALL,
--        the result is <code>nil</code> for null pointers, or the data for
--        valid pointers.
local function unmarshall_ptr(location, data, pos, func, args, result)
  stdnse.debug4("MSRPC: Entering unmarshall_ptr()")
  if(args == nil) then
    args = {}
  end
  -- If we're unmarshalling the header, then pull off a referent_id.
  if(location == HEAD or location == ALL) then
    local referent_id
    pos, referent_id = bin.unpack("<I", data, pos)
    if(referent_id == nil) then
      stdnse.debug1("MSRPC: ERROR: Ran off the end of a packet in unmarshall_ptr(). Please report!")
    end

    if(location == HEAD) then
      if(referent_id == 0) then
        result = false
      else
        result = true
      end
    else
      if(referent_id == 0) then
        result = nil
      else
        result = true
      end
    end
  end

  if(location == BODY or location == ALL) then
    if(result == true) then
      pos, result = func(data, pos, table.unpack(args))
    else
      result = nil
    end
  end

  return pos, result
end

---Similar to <code>marshall_ptr</code>, except that this marshalls a type that isn't a pointer.
--
-- It also understands pointers, in the sense that it'll only return data in
-- the HEAD section, since basetypes are printed in the HEAD and not the BODY.
--
-- Using this isn't strictly necessary, but it cleans up functions for
-- generating structs containing both pointers and basetypes (see
-- <code>marshall_srvsvc_NetShareInfo2</code>).
--
-- Like <code>marshall_ptr</code>, the function doesn't have to match any
-- prototype, as long as the proper arguments are passed to it.
--
--@param location The part of the pointer wanted, either HEAD (for the data
--                itself), BODY (for nothing, since this isn't a pointer), or
--                ALL (for the data). Generally, unless the referent_id is
--                split from the data (for example, in an array), you will want
--                ALL.
--@param func The function to call when encoding the body. Should convert the
--            arguments passed in the <code>args</code> parameter to a string.
--@param args An array of arguments that will be directly passed to the
--            function <code>func</code>
--@return A string representing the marshalled data.
local function marshall_basetype(location, func, args)
  local result
  stdnse.debug4("MSRPC: Entering marshall_basetype()")

  if(location == HEAD or location == ALL) then
    result = bin.pack("<A", func(table.unpack(args)))
  else
    result = ""
  end

  stdnse.debug4("MSRPC: Leaving marshall_basetype()")

  return result
end

---Marshalls an array.
--
-- Recall (from the module comment) that the data in an array is split into the
-- referent_ids and base types at the top and the data at the bottom. This
-- function will call any number of location-aware functions twice (once for
-- the top and once for the bottom).
--
-- Each element in the array can technically have a different function. I don't
-- know why I allowed that, and may refactor it out in the future. For now, I
-- strongly recommend setting the function to the same for every element.
--
-- The function that's called has to have the prototype:
--<code>
-- func(location, <args>)
--</code>
-- where "location" is the standard HEAD/BODY/ALL location used throughout the
-- functions.
--
--@param array An array of tables. Each table contains 'func', a pointer to the
--             marshalling function and 'args', the arguments to pass to the
--             marshalling function after the 'location' variable.
--@return A string representing the marshalled data.
function marshall_array(array)
  local i
  local result = ""

  stdnse.debug4("MSRPC: Entering marshall_array()")

  -- The max count is always at the front of the array (at least, in my tests). It is possible that
  -- this won't always hold true, so if you're having an issue that you've traced back to this function,
  -- you might want to double-check my assumption.
  result = result .. bin.pack("<I", #array)

  -- Encode the HEAD sections of all the elements in the array
  for i = 1, #array, 1 do
    local func = array[i]['func']
    local args = array[i]['args']

    result = result .. func(HEAD, table.unpack(args))
  end

  -- Encode the BODY sections of all the elements in the array
  for i = 1, #array, 1 do
    local func = array[i]['func']
    local args = array[i]['args']

    result = result .. func(BODY, table.unpack(args))
  end

  stdnse.debug4("MSRPC: Leaving marshall_array()")
  return result
end

---Unmarshalls an array.
--
-- This function starts to get a little hairy, due to the number of parameters
-- that need to be propagated, but it isn't too bad. Basically, this
-- unmarshalls an array by calling the given function for each element.
--
-- The function <code>func</code> has to conform to a very specific prototype:
--<code>
-- func(location, data, pos, result, <args>)
--</code>
-- Where <code>location<code> is the standard HEAD/BODY location,
-- <code>data<code> and <code>pos<code> are the packet and position within it,
-- <code>result<code> is the result from the HEAD section (if it's nil, it
-- isn't used), and <code>args<code> are arbitrary arguments passed to it.
--
-- I made the call to pass the same arguments to each function when it's
-- called. This is, for example, whether or not to null-terminate a string, or
-- whether or not to pad an int16. If different types are required, you're
-- probably out of luck.
--
--@param data     The data being processed.
--@param pos      The position within <code>data</code>.
--@param count    The number of elements in the array.
--@param func The function to call to unmarshall each parameter. Has to match a
--            specific prototype; see the function comment.
--@param args     Arbitrary arguments to pass to the function.
--@return The new position
--@return The result of unmarshalling this value.
local function unmarshall_array(data, pos, count, func, args)
  local i
  local size
  local result = {}

  stdnse.debug4("MSRPC: Entering unmarshall_array()")

  if(args == nil) then
    args = {}
  end

  local pos, max_count = bin.unpack("<I", data, pos)
  if(max_count == nil) then
    stdnse.debug1("MSRPC: ERROR: Ran off the end of a packet in unmarshall_array(). Please report!")
  end

  -- Unmarshall the header, which will be referent_ids and base types.
  for i = 1, count, 1 do
    pos, result[i] = func(HEAD, data, pos, nil, table.unpack(args))
  end

  -- Unmarshall the body. Note that the original result (result[i]) is passed back
  -- into this function. This is required for pointers because, to unmarshall a pointer,
  -- we have to remember whether or not it's null.
  for i = 1, count, 1 do
    pos, result[i] = func(BODY, data, pos, result[i], table.unpack(args))
  end

  stdnse.debug4("MSRPC: Leaving unmarshall_array()")

  return pos, result
end

---Call a function that matches the prototype for <code>unmarshall_array</code>.
--
-- This allows the same struct to be used in <code>unmarshall_array</code> and
-- in <code>unmarshall_ptr</code>. It is kind of a kludge, but it makes sense,
-- and was the cleanest solution I could come up with to this problem (although
-- I'm sure that there's a better one staring me in the face).
--
-- The <code>func</code> parameter, obviously, has to match the same prototype
-- as strings being passed to <code>unmarshall_array</code>, which is:
--<code>
-- func(location, data, pos, result, <args>)
--</code>
--
--@param data     The data being processed.
--@param pos      The position within <code>data</code>.
--@param func The function to call to unmarshall each parameter. Has to match a
--            specific prototype; see the function comment.
--@param args     Arbitrary arguments to pass to the function.
--@return The new position
--@return The result of unmarshalling this value.
local function unmarshall_struct(data, pos, func, args)
  local result

  stdnse.debug4("MSRPC: Entering unmarshall_struct()")

  if(args == nil) then
    args = {}
  end

  pos, result = func(ALL, data, pos, nil, args)

  stdnse.debug4("MSRPC: Leaving unmarshall_struct()")

  return pos, result
end

-------------------------------------
--          BASE TYPES
-- (dependencies: n/a)
-------------------------------------

--- Marshall a string that is in the format:
-- <code>[string,charset(UTF16)] uint16 *str</code>
--
-- This has the max size of the buffer, the offset (I'm not sure what the offset does, I've
-- never seen it used), the actual size, and the string itself. This will always align to
-- the 4-byte boundary.
--
--@param str The string to insert. Cannot be nil.
--@param do_null [optional] Appends a null to the end of the string. Default false.
--@param max_length [optional] Sets a max length that's different than the string's length. Length
--                  is in characters, not bytes.
--@return A string representing the marshalled data.
function marshall_unicode(str, do_null, max_length)
  local buffer_length
  local result

  stdnse.debug4("MSRPC: Entering marshall_unicode()")

  if(do_null == nil) then
    do_null = false
  end

  if(do_null) then
    buffer_length = #str + 1
  else
    buffer_length = #str
  end

  if(max_length == nil) then
    max_length = buffer_length
  end

  result = bin.pack("<IIIA",
    max_length,       -- Max count
    0,                -- Offset
    buffer_length,    -- Actual count
    string_to_unicode(str, do_null, true)
    )

  stdnse.debug4("MSRPC: Leaving marshall_unicode()")

  return result
end

--- Marshall a null-terminated ascii string, with the length/maxlength prepended. Very similar
-- to <code>marshall_unicode</code>, except it's ascii and the null terminator is always used.
--
--@param str        The string to marshall.
--@param max_length [optional] The maximum length; default: actual length.
function marshall_ascii(str, max_length)
  local buffer_length
  local result

  buffer_length = #str + 1

  if(max_length == nil) then
    max_length = buffer_length
  end

  local padding = string.rep('\0', (4 - (buffer_length % 4)) % 4)

  result = bin.pack("<IIIzA",
    max_length,
    0,
    buffer_length,
    str,
    padding
    )

  return result
end

--- Marshall a pointer to a unicode string.
--
--@param str The string to insert. Can be nil.
--@param do_null [optional] Appends a null to the end of the string. Default false.
--@param max_length [optional] Sets a max length that's different than the string's length. Length
--                  is in characters, not bytes.
--@return A string representing the marshalled data.
function marshall_unicode_ptr(str, do_null, max_length)
  local result

  stdnse.debug4("MSRPC: Entering marshall_unicode()")

  result = marshall_ptr(ALL, marshall_unicode, {str, do_null, max_length}, str)

  stdnse.debug4("MSRPC: Leaving marshall_unicode()")

  return result
end

--- Marshall a pointer to an ascii string.
--
--@param str The string to insert. Can be nil.
--@param max_length [optional] Sets a max length that's different than the string's length.
--@return A string representing the marshalled data.
function marshall_ascii_ptr(str, max_length)
  local result

  result = marshall_ptr(ALL, marshall_ascii, {str, max_length}, str)

  return result
end

--- Unmarshall a string that is in the format:
-- <code>[string,charset(UTF16)] uint16 *str</code>
--
-- See <code>marshall_unicode</code> for more information.
--
--@param data   The data buffer.
--@param pos    The position in the data buffer.
--@param do_null [optional] Discards the final character, the string terminator. Default false.
--
--@return (pos, str) The new position, and the string. The string may be nil.
function unmarshall_unicode(data, pos, do_null)
  local ptr, str
  local max, offset, actual

  stdnse.debug4("MSRPC: Entering unmarshall_unicode()")

  if(do_null == nil) then
    do_null = false
  end

  pos, max, offset, actual = bin.unpack("<III", data, pos)
  if(actual == nil) then
    stdnse.debug1("MSRPC: ERROR: Ran off the end of a packet in unmarshall_unicode(). Please report!")
  end

  pos, str = unicode_to_string(data, pos, actual, do_null, true)

  stdnse.debug4("MSRPC: Leaving unmarshall_unicode()")

  return pos, str
end

---Unmarshall a pointer to a unicode string.
--
--@param data     The data being processed.
--@param pos      The position within <code>data</code>.
--@param do_null [optional] Assumes a null is at the end of the string. Default false.
--@return (pos, result) The new position and the string.
function unmarshall_unicode_ptr(data, pos, do_null)
  local result

  stdnse.debug4("MSRPC: Entering unmarshall_unicode_ptr()")
  pos, result = unmarshall_ptr(ALL, data, pos, unmarshall_unicode, {do_null})
  stdnse.debug4("MSRPC: Leaving unmarshall_unicode_ptr()")

  return pos, result
end

---Marshall an array of unicode strings. This is a perfect demonstration of how to use
-- <code>marshall_array</code>.
--
--@param strings The array of strings to marshall
--@param do_null [optional] Appends a null to the end of the string. Default false.
--@return A string representing the marshalled data.
function marshall_unicode_array(strings, do_null)
  local array = {}
  local result

  for i = 1, #strings, 1 do
    array[i] = {}
    array[i]['func'] = marshall_ptr
    array[i]['args'] = {marshall_unicode, {strings[i], do_null}, strings[i]}
  end

  result = marshall_array(array)

  return result
end

---Marshall a pointer to an array of unicode strings. See <code>marshall_unicode_array</code>
-- for more information.
--
--@param strings The array of strings to marshall
--@param do_null [optional] Appends a null to the end of the string. Default false.
--@return A string representing the marshalled data.
function marshall_unicode_array_ptr(strings, do_null)
  local result

  result = marshall_ptr(ALL, marshall_unicode_array, {strings, do_null}, strings)

  return result
end

--- Marshall an int64. This is simply an 8-byte integer inserted into the buffer, nothing fancy.
--@param int64 The integer to insert
--@return A string representing the marshalled data.
function marshall_int64(int64)
  local result

  stdnse.debug4("MSRPC: Entering marshall_int64()")
  result = bin.pack("<L", int64)
  stdnse.debug4("MSRPC: Leaving marshall_int64()")

  return result
end

--- Marshall an int32
--
-- <code>     [in]            uint32           var</code>
--
-- This is simply an integer inserted into the buffer, nothing fancy.
--@param int32 The integer to insert
--@return A string representing the marshalled data.
function marshall_int32(int32)
  local result

  stdnse.debug4("MSRPC: Entering marshall_int32()")
  result = bin.pack("<I", int32)
  stdnse.debug4("MSRPC: Leaving marshall_int32()")

  return result
end

---Marshall an array of int32 values.
--
--@param data The array
--@return A string representing the marshalled data
function marshall_int32_array(data)
  local result = ""

  result = result .. marshall_int32(0x0400) -- Max count
  result = result .. marshall_int32(0)     -- Offset
  result = result .. marshall_int32(#data) -- Actual count

  for _, v in ipairs(data) do
    result = result .. marshall_int32(v)
  end

  return result
end

--- Marshall an int16
--
-- <code>     [in]            uint16           var</code>
--
-- This is simply an integer inserted into the buffer, nothing fancy.
--@param int16 The integer to insert
--@param pad   [optional] If set, will align the insert on 4-byte boundaries. Default: true.
--@return A string representing the marshalled data.
function marshall_int16(int16, pad)
  local result

  stdnse.debug4("MSRPC: Entering marshall_int16()")

  if(pad == false) then
    return bin.pack("<S", int16)
  end

  result = bin.pack("<SS", int16, 0)

  stdnse.debug4("MSRPC: Leaving marshall_int16()")

  return result
end

--- Marshall an int8
--
-- <code>     [in]            uint8           var</code>
--
-- This is simply an integer inserted into the buffer, nothing fancy.
--
--@param int8  The integer to insert
--@param pad   [optional] If set, will align the insert on 4-byte boundaries. Default: true.
--@return A string representing the marshalled data.
function marshall_int8(int8, pad)
  local result

  stdnse.debug4("MSRPC: Entering marshall_int8()")

  if(pad == false) then
    return bin.pack("<C", int8)
  end

  result = bin.pack("<CCS", int8, 0, 0)
  stdnse.debug4("MSRPC: Leaving marshall_int8()")

  return result
end

--- Unmarshall an int64. See <code>marshall_int64</code> for more information.
--
--@param data     The data being processed.
--@param pos      The position within <code>data</code>.
--@return (pos, int64) The new position, and the value.
function unmarshall_int64(data, pos)
  local value

  stdnse.debug4("MSRPC: Entering unmarshall_int64()")
  pos, value = bin.unpack("<l", data, pos)
  if(value == nil) then
    stdnse.debug1("MSRPC: ERROR: Ran off the end of a packet in unmarshall_int64(). Please report!")
  end
  stdnse.debug4("MSRPC: Leaving unmarshall_int64()")

  return pos, value
end

--- Unmarshall an int32. See <code>marshall_int32</code> for more information.
--
--@param data     The data being processed.
--@param pos      The position within <code>data</code>.
--@return (pos, int32) The new position, and the value.
function unmarshall_int32(data, pos)
  local value

  pos, value = bin.unpack("<I", data, pos)
  if(value == nil) then
    stdnse.debug1("MSRPC: ERROR: Ran off the end of a packet in unmarshall_int32(). Please report!")
  end

  return pos, value
end

--- Unmarshall an int16. See <code>marshall_int16</code> for more information.
--
--@param data The data packet.
--@param pos  The position within the data.
--@param pad  [optional] If set, will remove extra bytes to align the packet, Default: true
--@return (pos, int16) The new position, and the value.
function unmarshall_int16(data, pos, pad)
  local value

  stdnse.debug4("MSRPC: Entering unmarshall_int16()")

  pos, value = bin.unpack("<S", data, pos)
  if(value == nil) then
    stdnse.debug1("MSRPC: ERROR: Ran off the end of a packet in unmarshall_int16(). Please report!")
  end

  if(pad == nil or pad == true) then
    pos = pos + 2
  end

  stdnse.debug4("MSRPC: Leaving unmarshall_int16()")

  return pos, value
end

--- Unmarshall an int8. See <code>marshall_int8</code> for more information.
--
--@param data The data packet.
--@param pos  The position within the data.
--@param pad  [optional] If set, will remove extra bytes to align the packet, Default: true
--@return (pos, int8) The new position, and the value.
function unmarshall_int8(data, pos, pad)
  local value

  stdnse.debug4("MSRPC: Entering unmarshall_int8()")

  pos, value = bin.unpack("<C", data, pos)
  if(value == nil) then
    stdnse.debug1("MSRPC: ERROR: Ran off the end of a packet in unmarshall_int8(). Please report!")
  end

  if(pad == nil or pad == true) then
    pos = pos + 3
  end

  stdnse.debug4("MSRPC: Leaving unmarshall_int8()")

  return pos, value
end

--- Marshall a pointer to an int64.
--
-- If the pointer is null, it simply marshalls the
-- integer '0'. Otherwise, it uses a referent id followed by the integer.
--
--@param int64 The value of the integer pointer
--@return A string representing the marshalled data.
function marshall_int64_ptr(int64)
  local result

  stdnse.debug4("MSRPC: Entering marshall_int64_ptr()")
  result = marshall_ptr(ALL, marshall_int64, {int64}, int64)
  stdnse.debug4("MSRPC: Leaving marshall_int64_ptr()")

  return result
end

--- Marshall a pointer to an int32
--
-- <code>     [in,out]   uint32 *ptr</code>
--
-- If the pointer is null, it simply marshalls the integer '0'. Otherwise,
-- it uses a referent id followed by the integer.
--
--@param int32 The value of the integer pointer
--@return A string representing the marshalled data.
function marshall_int32_ptr(int32)
  local result

  stdnse.debug4("MSRPC: Entering marshall_int32_ptr()")
  result = marshall_ptr(ALL, marshall_int32, {int32}, int32)
  stdnse.debug4("MSRPC: Leaving marshall_int32_ptr()")

  return result
end

--- Marshall a pointer to an int16
--
-- <code>     [in,out]   uint16 *ptr</code>
--
-- If the pointer is null, it simply marshalls the integer '0'. Otherwise,
-- it uses a referent id followed by the integer.
--
--@param int16 The value of the integer pointer
--@param pad   [optional] If set, will align the insert on 4-byte boundaries. Default: true.
--@return A string representing the marshalled data.
function marshall_int16_ptr(int16, pad)
  local result

  stdnse.debug4("MSRPC: Entering marshall_int16_ptr()")
  result = marshall_ptr(ALL, marshall_int16, {int16, pad}, int16)
  stdnse.debug4("MSRPC: Leaving marshall_int16_ptr()")

  return result
end

--- Marshall a pointer to an int8
--
-- <code>     [in,out]   uint8 *ptr</code>
--
-- If the pointer is null, it simply marshalls the integer '0'. Otherwise,
-- it uses a referent id followed by the integer.
--
--@param int8 The value of the integer pointer
--@param pad   [optional] If set, will align the insert on 4-byte boundaries. Default: true.
--@return A string representing the marshalled data.
function marshall_int8_ptr(int8, pad)
  local result

  stdnse.debug4("MSRPC: Entering marshall_int8_ptr()")
  result = marshall_ptr(ALL, marshall_int8, {int8, pad}, int8)
  stdnse.debug4("MSRPC: Leaving marshall_int8_ptr()")

  return result
end

--- Unmarshall a pointer to an int32. See <code>marshall_int32_ptr</code> for more information.
--
--@param data The data packet.
--@param pos  The position within the data.
--@return (pos, int32) The new position, and the value.
function unmarshall_int32_ptr(data, pos)
  local result

  stdnse.debug4("MSRPC: Entering unmarshall_int32_ptr()")
  pos, result = unmarshall_ptr(ALL, data, pos, unmarshall_int32, {})
  stdnse.debug4("MSRPC: Leaving unmarshall_int32_ptr()")

  return pos, result
end

--- Unmarshall a pointer to an int16. See <code>marshall_int16_ptr</code> for more information.
--
--@param data The data packet.
--@param pos  The position within the data.
--@param pad  [optional] If set, will remove extra bytes to align the packet, Default: true
--@return (pos, int16) The new position, and the value.
function unmarshall_int16_ptr(data, pos, pad)
  local result

  stdnse.debug4("MSRPC: Entering unmarshall_int16_ptr()")
  pos, result = unmarshall_ptr(ALL, data, pos, unmarshall_int16, {pad})
  stdnse.debug4("MSRPC: Leaving unmarshall_int16_ptr()")

  return pos, result
end

--- Unmarshall a pointer to an int8. See <code>marshall_int8_ptr</code> for more information.
--
--@param data The data packet.
--@param pos  The position within the data.
--@param pad  [optional] If set, will remove extra bytes to align the packet, Default: true
--@return (pos, int8) The new position, and the value.
function unmarshall_int8_ptr(data, pos, pad)
  local result

  stdnse.debug4("MSRPC: Entering unmarshall_int8_ptr()")
  pos, result = unmarshall_ptr(ALL, data, pos, unmarshall_int8, {pad})
  stdnse.debug4("MSRPC: Leaving unmarshall_int8_ptr()")

  return pos, result
end

--- Marshall an array of int8s, with an optional max_length set.
--
--@param data The array to marshall, as a string. Cannot be nil.
--@param max_length [optional] The maximum length of the buffer. Default: the length of
--       <code>data</code>.
--@return A string representing the marshalled data.
function marshall_int8_array(data, max_length)
  stdnse.debug4("MSRPC: Entering marshall_int8_array()")

  if(max_length == nil) then
    max_length = #data
  end

  local result = bin.pack("<IIa", max_length, 0, data)

  stdnse.debug4("MSRPC: Leaving marshall_int8_array()")

  return result
end

--- Unmarshall an array of int8s.
--
--@param data The data packet.
--@param pos  The position within the data.
--@param pad  [optional] If set to true, will align data on 4-byte boundaries. Default:
--            true.
--@return (pos, str) The position, and the resulting string, which cannot be nil.
function unmarshall_int8_array(data, pos, pad)
  local max, offset, actual
  local str

  stdnse.debug4("MSRPC: Entering unmarshall_int8_array()")

  pos, max, offset, actual = bin.unpack("<III", data, pos)
  if(actual == nil) then
    stdnse.debug1("MSRPC: ERROR: Ran off the end of a packet in unmarshall_int8_array(). Please report!")
  end

  pos, str = bin.unpack("<A"..actual, data, pos)
  if(str == nil) then
    stdnse.debug1("MSRPC: ERROR: Ran off the end of a packet in unmarshall_int8_array() [2]. Please report!")
  end

  -- Do the alignment (note the "- 1", it's there because of 1-based arrays)
  if(pad == nil or pad == true) then
    while(((pos - 1) % 4) ~= 0) do
      pos = pos + 1
    end
  end

  stdnse.debug4("MSRPC: Leaving unmarshall_int8_array()")

  return pos, str
end

--- Marshall a pointer to an array of int8s.
--
--@param data The array to marshall, as a string. Can be nil.
--@param max_length [optional] The maximum length of the buffer. Default: the length of
--       <code>data</code>.
--@return A string representing the marshalled data.
function marshall_int8_array_ptr(data, max_length)
  local result
  stdnse.debug4("MSRPC: Entering marshall_int8_array_ptr()")

  result = marshall_ptr(ALL, marshall_int8_array, {data, max_length}, data)

  stdnse.debug4("MSRPC: Leaving marshall_int8_array_ptr()")
  return result
end

--- Unmarshall a pointer to an array of int8s. By default, aligns the result to 4-byte
--  boundaries.
--
--@param data The data packet.
--@param pos  The position within the data.
--@param pad  [optional] If set to true, will align data on 4-byte boundaries. Default:
--            true.
--@return (pos, str) The position, and the resulting string, which cannot be nil.
function unmarshall_int8_array_ptr(data, pos, pad)
  local str
  stdnse.debug4("MSRPC: Entering unmarshall_int8_array_ptr()")

  pos, str = unmarshall_ptr(ALL, data, pos, unmarshall_int8_array, {pad})

  stdnse.debug4("MSRPC: Leaving unmarshall_int8_array_ptr()")
  return pos, str
end

--- Unmarshall an array of int32s.
--
--@param data The data packet.
--@param pos  The position within the data.
--@return (pos, str) The position, and the resulting string, which cannot be nil.
function unmarshall_int32_array(data, pos, count)
  local maxcount
  local result = {}

  pos, maxcount = unmarshall_int32(data, pos)

  for i = 1, count, 1 do
    pos, result[i] = unmarshall_int32(data, pos)
  end

  return pos, result
end

--- Unmarshall a pointer to an array of int32s.
--
--@param data The data packet.
--@param pos  The position within the data.
--@return (pos, str) The position, and the resulting string, which cannot be nil.
function unmarshall_int32_array_ptr(data, pos)
  local count, array

  pos, count = unmarshall_int32(data, pos)
  pos, array = unmarshall_ptr(ALL, data, pos, unmarshall_int32_array, {count})

  return pos, array
end

---Marshalls an NTTIME.
--
-- This is sent as the number of 1/10 microseconds since 1601; however the
-- internal representation is the number of seconds since 1970. Because doing
-- conversions in code is annoying, the user will never have to understand
-- anything besides seconds since 1970.
--
--@param time The time, in seconds since 1970.
--@return A string representing the marshalled data.
function marshall_NTTIME(time)
  local result
  stdnse.debug4("MSRPC: Entering marshall_NTTIME()")

  if(time == 0) then
    result = bin.pack("<L", 0)
  else
    result = bin.pack("<L", (time + 11644473600) * 10000000)
  end

  stdnse.debug4("MSRPC: Leaving marshall_NTTIME()")
  return result
end

---Unmarshalls an NTTIME. See <code>marshall_NTTIME</code> for more information.
--
--@param data The data packet.
--@param pos  The position within the data.
--@return (pos, time) The new position, and the time in seconds since 1970.
function unmarshall_NTTIME(data, pos)
  local time
  stdnse.debug4("MSRPC: Entering unmarshall_NTTIME()")

  pos, time = bin.unpack("<L", data, pos)
  if(time == nil) then
    stdnse.debug1("MSRPC: ERROR: Ran off the end of a packet in unmarshall_NTTIME(). Please report!")
  end

  if(time ~= 0) then
    time = (time / 10000000) - 11644473600
  end

  stdnse.debug4("MSRPC: Leaving unmarshall_NTTIME()")
  return pos, time
end

---Marshalls an NTTIME*.
--
--@param time The time, in seconds since 1970.
--@return A string representing the marshalled data.
function marshall_NTTIME_ptr(time)
  local result
  stdnse.debug4("MSRPC: Entering marshall_NTTIME_ptr()")

  result = marshall_ptr(ALL, marshall_NTTIME, {time}, time)

  stdnse.debug4("MSRPC: Leaving marshall_NTTIME_ptr()")
  return result
end

---Unmarshalls an <code>NTTIME*</code>.
--
--@param data The data packet.
--@param pos  The position within the data.
--@return (pos, time) The new position, and the time in seconds since 1970.
function unmarshall_NTTIME_ptr(data, pos)
  local time
  stdnse.debug4("MSRPC: Entering unmarshall_NTTIME_ptr()")

  pos, time = unmarshall_ptr(ALL, data, pos, unmarshall_NTTIME, {})

  stdnse.debug4("MSRPC: Leaving unmarshall_NTTIME_ptr()")
  return pos, time
end

---Unmarshall a SYSTEMTIME structure, converting it to a standard representation.
--
--The structure is as follows:
--
-- <code>
--   typedef struct _SYSTEMTIME {
--     WORD wYear;
--     WORD wMonth;
--     WORD wDayOfWeek;
--     WORD wDay;
--     WORD wHour;
--     WORD wMinute;
--     WORD wSecond;
--     WORD wMilliseconds;
--   } SYSTEMTIME
-- </code>
--
--@param data The data packet.
--@param pos  The position within the data.
--@return (pos, time) The new position, and the time in seconds since 1970.
function unmarshall_SYSTEMTIME(data, pos)
  local date = {}
  local _

  pos, date['year'], date['month'], _, date['day'], date['hour'], date['min'], date['sec'], _ = bin.unpack("<SSSSSSSS", data, pos)
  if(date['sec'] == nil) then
    stdnse.debug1("MSRPC: ERROR: Ran off the end of a packet in unmarshall_SYSTEMTIME(). Please report!")
  end

  return pos, os.time(date)
end

---Unmarshalls a <code>hyper</code>.
--
-- I have no idea what a <code>hyper</code> is, just that it seems to be a
-- 64-bit data type used for measuring time, and that the units happen to be
-- negative microseconds. This function converts the value to seconds and
-- returns it.
--
--@param data The data packet.
--@param pos  The position within the data.
--@return (pos, val) The new position, and the result in seconds.
function unmarshall_hyper(data, pos)
  local result
  stdnse.debug4("MSRPC: Entering unmarshall_hyper()")

  pos, result = unmarshall_int64(data, pos)
  result = result / -10000000

  stdnse.debug4("MSRPC: Leaving unmarshall_hyper()")
  return pos, result
end

---Marshall an entry in a table.
--
-- Basically, converts the string to a number based on the entries in
-- <code>table</code> before sending. Multiple values can be ORed together
-- (like flags) by separating them with pipes ("|").
--
--@param val The value to look up. Can be multiple values with pipes between,
--           e.g. "A|B|C".
--@param table The table to use for lookups. The keys should be the names, and
--             the values should be the numbers.
--@return A string representing the marshalled data.
local function marshall_Enum32(val, table)
  local result = 0
  stdnse.debug4("MSRPC: Entering marshall_Enum32()")

  local vals = stdnse.strsplit("|", val)
  local i

  for i = 1, #vals, 1 do
    result = bit.bor(result, table[vals[i]])
  end

  result = marshall_int32(result)

  stdnse.debug4("MSRPC: Leaving marshall_Enum32()")
  return result
end

---Unmarshall an entry in a table. Basically, converts the next int32 in the buffer to a string
-- based on the entries in <code>table</code> before returning.
--
--@param data    The data packet.
--@param pos     The position within the data.
--@param table   The table to use for lookups. The keys should be the names, and the values should be
--               the numbers.
--@param default The default value to return if the lookup was unsuccessful.
--@return (pos, policy_handle) The new position, and a table representing the policy_handle.
local function unmarshall_Enum32(data, pos, table, default)
  stdnse.debug4("MSRPC: Entering unmarshall_Enum32()")

  if(default == nil) then
    default = "<unknown>"
  end

  local pos, val = unmarshall_int32(data, pos)

  for i, v in pairs(table) do
    if(v == val) then
      return pos, i
    end
  end

  stdnse.debug4("MSRPC: Leaving unmarshall_Enum32()")
  return pos, default
end

---Unmarshall an entry in a table. Basically, converts the next int16 in the buffer to a string
-- based on the entries in <code>table</code> before returning.
--
--@param data    The data packet.
--@param pos     The position within the data.
--@param table   The table to use for lookups. The keys should be the names, and the values should be
--               the numbers.
--@param default The default value to return if the lookup was unsuccessful.
--@param pad     [optional] If set, will ensure that we end up on an even multiple of 4. Default: true.
--@return (pos, policy_handle) The new position, and a table representing the policy_handle.
local function unmarshall_Enum16(data, pos, table, default, pad)
  stdnse.debug4("MSRPC: Entering unmarshall_Enum16()")

  if(default == nil) then
    default = "<unknown>"
  end

  local pos, val = unmarshall_int16(data, pos, pad)

  for i, v in pairs(table) do
    if(v == val) then
      return pos, i
    end
  end

  stdnse.debug4("MSRPC: Leaving unmarshall_Enum16()")
  return pos, default
end

---Marshall an entry in a table.
--
-- Basically, converts the string to a number based on the entries in
-- <code>table</code> before sending. Multiple values can be ORed together
-- (like flags) by separating them with pipes ("|").
--
--@param val The value to look up. Can be multiple values with pipes between,
--           e.g. "A|B|C".
--@param table The table to use for lookups. The keys should be the names, and
--             the values should be the numbers.
--@param pad [optional] If set, will ensure that we end up on an even multiple of 4. Default: true.
--@return A string representing the marshalled data.
local function marshall_Enum8(val, table, pad)
  local result = 0
  stdnse.debug4("MSRPC: Entering marshall_Enum8()")

  local vals = stdnse.strsplit("|", val)
  local i

  for i = 1, #vals, 1 do
    result = bit.bor(result, table[vals[i]])
  end

  result = marshall_int8(result, pad)

  stdnse.debug4("MSRPC: Leaving marshall_Enum8()")
  return result
end



---Similar to <code>unmarshall_Enum32</code>, except it'll return every value that could be ANDed together to
-- create the resulting value (except a 0 value). This is effective for parsing flag data types.
--@param data    The data packet.
--@param pos     The position within the data.
--@param table   The table to use for lookups. The keys should be the names, and the values should be
--               the numbers.
--@return (pos, array) The new position, and a table representing the enumeration values.
local function unmarshall_Enum32_array(data, pos, table)
  local array = {}
  local i, v
  local val
  stdnse.debug4("MSRPC: Entering unmarshall_Enum32_array()")

  pos, val = unmarshall_int32(data, pos)

  for i, v in pairs(table) do
    if(bit.band(v, val) ~= 0) then
      array[#array + 1] = i
    end
  end

  stdnse.debug4("MSRPC: Leaving unmarshall_Enum32_array()")
  return pos, array
end

---Unmarshall raw data.
--@param data    The data packet.
--@param pos     The position within the data.
--@param length  The number of bytes to unmarshall.
--@return (pos, data) The new position in the packet, and a string representing the raw data.
function unmarshall_raw(data, pos, length)
  local val
  stdnse.debug4("MSRPC: Entering unmarshall_raw()")

  pos, val = bin.unpack(string.format("A%d", length), data, pos)
  if(val == nil) then
    stdnse.debug1("MSRPC: ERROR: Ran off the end of a packet in unmarshall_raw(). Please report!")
  end

  stdnse.debug4("MSRPC: Leaving unmarshall_raw()")
  return pos, val
end


-------------------------------------
--          MISC
-- (dependencies: n/a)
-------------------------------------

---Marshalls a GUID, which looks like this:
--
--<code>
--  typedef [public,noprint,gensize,noejs] struct {
--    uint32 time_low;
--    uint16 time_mid;
--    uint16 time_hi_and_version;
--    uint8  clock_seq[2];
--    uint8  node[6];
--  } GUID;
--</code>
--
--@param guid A table representing the GUID.
--@return A string representing the marshalled data.
local function marshall_guid(guid)
  local result
  stdnse.debug4("MSRPC: Entering marshall_guid()")

  result = bin.pack("<ISSAA", guid['time_low'], guid['time_high'], guid['time_hi_and_version'], guid['clock_seq'], guid['node'])

  stdnse.debug4("MSRPC: Leaving marshall_guid()")
  return result
end

---Unmarshalls a GUID. See <code>marshall_guid</code> for the structure.
--
--@param data The data packet.
--@param pos  The position within the data.
--@return (pos, result) The new position in <code>data</code>, and a table representing the datatype.
local function unmarshall_guid(data, pos)
  local guid = {}
  stdnse.debug4("MSRPC: Entering unmarshall_guid()")

  pos, guid['time_low'], guid['time_high'], guid['time_hi_and_version'], guid['clock_seq'], guid['node'] = bin.unpack("<ISSA2A6", data, pos)
  if(guid['node'] == nil) then
    stdnse.debug1("MSRPC: ERROR: Ran off the end of a packet in unmarshall_guid(). Please report!")
  end

  stdnse.debug4("MSRPC: Leaving unmarshall_guid()")
  return pos, guid
end

---Marshalls a policy_handle, which looks like this:
--
--<code>
--  typedef struct {
--    uint32 handle_type;
--    GUID   uuid;
--  } policy_handle;
--</code>
--
--@param policy_handle The policy_handle to marshall.
--@return A string representing the marshalled data.
function marshall_policy_handle(policy_handle)
  local result
  stdnse.debug4("MSRPC: Entering marshall_policy_handle()")

  result = bin.pack("<IA", policy_handle['handle_type'], marshall_guid(policy_handle['uuid']))

  stdnse.debug4("MSRPC: Leaving marshall_policy_handle()")
  return result
end

---Unmarshalls a policy_handle. See <code>marshall_policy_handle</code> for the structure.
--
--@param data The data packet.
--@param pos  The position within the data.
--@return (pos, result) The new position in <code>data</code>, and a table representing the datatype.
function unmarshall_policy_handle(data, pos)
  local policy_handle = {}
  stdnse.debug4("MSRPC: Entering unmarshall_policy_handle()")

  pos, policy_handle['handle_type'] = unmarshall_int32(data, pos)
  pos, policy_handle['uuid']        = unmarshall_guid(data, pos)

  stdnse.debug4("MSRPC: Leaving unmarshall_policy_handle()")
  return pos, policy_handle
end

----------------------------------
--       SECURITY
-- (dependencies: MISC)
----------------------------------

---Unmarshall a dom_sid struct
--
--<code>
--    typedef [public,gensize,noprint,noejs,nosize] struct {
--        uint8  sid_rev_num;             /**< SID revision number */
--        [range(0,15)] int8  num_auths;  /**< Number of sub-authorities */
--        uint8  id_auth[6];              /**< Identifier Authority */
--        uint32 sub_auths[num_auths];
--    } dom_sid;
--</code>
--
--@param data     The data being processed.
--@param pos      The position within <code>data</code>.
--@return (pos, result) The new position in <code>data</code>, and a table representing the datatype.
function unmarshall_dom_sid2(data, pos)
  local i

  -- Read the SID from the packet
  local sid = {}
  pos, sid['count']          = unmarshall_int32(data, pos)
  pos, sid['sid_rev_num']    = unmarshall_int8(data, pos, false)
  pos, sid['num_auths']      = unmarshall_int8(data, pos, false)

  -- Note that authority is big endian (I guess it's an array, not really an integer like we're handling it)
  pos, sid['authority_high'], sid['authority_low'] = bin.unpack(">SI", data, pos)
  if(sid['authority_low'] == nil) then
    stdnse.debug1("MSRPC: ERROR: Ran off the end of a packet in unmarshall_dom_sid2(). Please report!")
  end
  sid['authority'] = bit.bor(bit.lshift(sid['authority_high'], 32), sid['authority_low'])

  sid['sub_auths']   = {}
  for i = 1, sid['num_auths'], 1 do
    pos, sid['sub_auths'][i] = unmarshall_int32(data, pos)
  end

  -- Convert the SID to a string
  local result = string.format("S-%u-%u", sid['sid_rev_num'], sid['authority'])
  for i = 1, sid['num_auths'], 1 do
    result = result .. string.format("-%u", sid['sub_auths'][i])
  end

  return pos, result
end

---Unmarshall a pointer to a <code>dom_sid2</code> struct. See the <code>unmarshall_dom_sid2</code> function
-- for more information.
--
--@param data     The data being processed.
--@param pos      The position within <code>data</code>.
--@return (pos, result) The new position in <code>data</code>, and a table representing the datatype.
function unmarshall_dom_sid2_ptr(data, pos)
  return unmarshall_ptr(ALL, data, pos, unmarshall_dom_sid2, {})
end

---Marshall a dom_sid struct
--
--<code>
--    typedef [public,gensize,noprint,noejs,nosize] struct {
--        uint8  sid_rev_num;             /**< SID revision number */
--        [range(0,15)] int8  num_auths;  /**< Number of sub-authorities */
--        uint8  id_auth[6];              /**< Identifier Authority */
--        uint32 sub_auths[num_auths];
--    } dom_sid;
--</code>
--
--@return A string representing the marshalled data.
function marshall_dom_sid2(sid)
  local i
  local pos_next
  local sid_array = {}
  local result = ""
  stdnse.debug4("MSRPC: Entering marshall_dom_sid2()")


  if(string.find(sid, "^S%-") == nil) then
    stdnse.debug1("MSRPC: ERROR: Invalid SID encountered: %s\n", sid)
    return nil
  end
  if(string.find(sid, "%-%d+$") == nil) then
    stdnse.debug1("MSRPC: ERROR: Invalid SID encountered: %s\n", sid)
    return nil
  end

  local pos = 3

  pos_next = string.find(sid, "-", pos)
  sid_array['sid_rev_num'] = string.sub(sid, pos, pos_next - 1)

  pos = pos_next + 1
  pos_next = string.find(sid, "-", pos)
  sid_array['authority_high'] = bit.rshift(string.sub(sid, pos, pos_next - 1), 32)
  sid_array['authority_low']  = bit.band(string.sub(sid, pos, pos_next - 1), 0xFFFFFFFF)

  sid_array['sub_auths'] = {}
  i = 1
  repeat
    pos = pos_next + 1
    pos_next = string.find(sid, "-", pos)
    if(pos_next == nil) then
      sid_array['sub_auths'][i] = string.sub(sid, pos)
    else
      sid_array['sub_auths'][i] = string.sub(sid, pos, pos_next - 1)
    end
    i = i + 1
  until pos_next == nil
  sid_array['num_auths'] = i - 1

  result = bin.pack("<I", sid_array['num_auths'])
  result = result .. bin.pack("<CC>SI", sid_array['sid_rev_num'], sid_array['num_auths'], sid_array['authority_high'], sid_array['authority_low'])
  for i = 1, sid_array['num_auths'], 1 do
    result = result .. bin.pack("<I", sid_array['sub_auths'][i])
  end

  stdnse.debug4("MSRPC: Leaving marshall_dom_sid2()")
  return result
end




----------------------------------
--       LSA
-- (dependencies: SECURITY)
----------------------------------


---A <code>lsa_String</code> is a buffer that holds a non-null-terminated string. It can have a max size that's different
-- from its actual size. I tagged this one as "internal" because I don't want the user to have to provide
-- a "location".
--
-- This is the format:
--
--<code>
--    typedef [public,noejs] struct {
--        [value(2*strlen_m(string))] uint16 length;
--        [value(2*strlen_m(string))] uint16 size;
--        [charset(UTF16),size_is(size/2),length_is(length/2)] uint16 *string;
--    } lsa_String;
--</code>
--
--@param location   The part of the pointer wanted, either HEAD (for the referent_id), BODY
--                  (for the pointer data), or ALL (for both together). Generally, unless the
--                  referent_id is split from the data (for example, in an array), you will want
--                  ALL.
--@param str        The string to marshall
--@param max_length [optional] The maximum size of the buffer, in characters, including the null terminator.
--                  Defaults to the length of the string, including the null.
--@param do_null    [optional] Appends a null to the end of the string. Default false.
--@return A string representing the marshalled data.
local function marshall_lsa_String_internal(location, str, max_length, do_null)
  local length
  local result = ""
  stdnse.debug4("MSRPC: Entering marshall_lsa_String_internal()")

  -- Handle default max lengths
  if(max_length == nil) then
    if(str == nil) then
      max_length = 0
    else
      max_length = #str
    end
  end

  if(str == nil) then
    length = 0
  else
    length = #str
  end

  if(do_null == nil) then
    do_null = false
  end

  if(location == HEAD or location == ALL) then
    result = result .. bin.pack("<SSA", length * 2, max_length * 2, marshall_ptr(HEAD, marshall_unicode, {str, do_null, max_length}, str))
  end

  if(location == BODY or location == ALL) then
    result = result .. bin.pack("<A", marshall_ptr(BODY, marshall_unicode, {str, do_null, max_length}, str))
  end

  stdnse.debug4("MSRPC: Leaving marshall_lsa_String_internal()")
  return result
end

---Unmarshall a <code>lsa_String</code> value. See <code>marshall_lsa_String_internal</code> for more information.
--
--@param location The part of the pointer wanted, either HEAD (for the data itself), BODY
--                (for nothing, since this isn't a pointer), or ALL (for the data). Generally, unless the
--                referent_id is split from the data (for example, in an array), you will want
--                ALL.
--@param data     The data packet.
--@param pos      The position within the data.
--@param result   This is required when unmarshalling the BODY section, which always comes after
--                unmarshalling the HEAD. It is the result returned for this parameter during the
--                HEAD unmarshall. If the referent_id was '0', then this function doesn't unmarshall
--                anything.
--@return (pos, str) The new position, and the unmarshalled string.
local function unmarshall_lsa_String_internal(location, data, pos, result)
  local length, size
  local str
  stdnse.debug4("MSRPC: Entering unmarshall_lsa_String_internal()")

  if(location == HEAD or location == ALL) then
    pos, length = unmarshall_int16(data, pos, false)
    pos, size   = unmarshall_int16(data, pos, false)

    pos, str = unmarshall_ptr(HEAD, data, pos, unmarshall_unicode, {false})
  end

  if(location == BODY or location == ALL) then
    pos, str = unmarshall_ptr(BODY, data, pos, unmarshall_unicode, {false}, result)
  end

  stdnse.debug4("MSRPC: Leaving unmarshall_lsa_String_internal()")
  return pos, str
end

---Public version of <code>marshall_lsa_String_internal</code> -- see that function on that for more information.
-- This version doesn't require a <code>location</code>, so it's suitable to be a public function.
--
--@param str        The string to marshall
--@param max_length [optional] The maximum size of the buffer, in characters, including the null terminator.
--                  Defaults to the length of the string, including the null.
--@return A string representing the marshalled data.
function marshall_lsa_String(str, max_length)
  local result
  stdnse.debug4("MSRPC: Entering marshall_lsa_String()")

  result = marshall_lsa_String_internal(ALL, str, max_length)

  stdnse.debug4("MSRPC: Leaving marshall_lsa_String()")
  return result
end

---Marshall an array of lsa_String objects. This is a perfect demonstration of how to use
-- <code>marshall_array</code>.
--
--@param strings The array of strings to marshall
--@return A string representing the marshalled data.
function marshall_lsa_String_array(strings)
  local array = {}
  local result
  stdnse.debug4("MSRPC: Entering marshall_lsa_String_array()")

  for i = 1, #strings, 1 do
    array[i] = {}
    array[i]['func'] = marshall_lsa_String_internal
    array[i]['args'] = {strings[i]}
  end

  result = marshall_array(array)

  stdnse.debug4("MSRPC: Leaving marshall_lsa_String_array()")
  return result
end

---Basically the same as <code>marshall_lsa_String_array</code>, except it has a different structure
--
--@param strings The array of strings to marshall
function marshall_lsa_String_array2(strings)
  local array = {}
  local result

  for i = 1, #strings, 1 do
    array[i] = {}
    array[i]['func'] = marshall_lsa_String_internal
    array[i]['args'] = {strings[i], nil, nil, false}
  end

  result = marshall_int32(1000) -- Max length
  .. marshall_int32(0) -- Offset
  .. marshall_array(array)

  --require 'nsedebug'
  --nsedebug.print_hex(result)
  --os.exit()
  return result
end

---Table of SID types.
local lsa_SidType =
{
  SID_NAME_USE_NONE = 0, -- NOTUSED
  SID_NAME_USER     = 1, -- user
  SID_NAME_DOM_GRP  = 2, -- domain group
  SID_NAME_DOMAIN   = 3, -- domain: don't know what this is
  SID_NAME_ALIAS    = 4, -- local group
  SID_NAME_WKN_GRP  = 5, -- well-known group
  SID_NAME_DELETED  = 6, -- deleted account: needed for c2 rating
  SID_NAME_INVALID  = 7, -- invalid account
  SID_NAME_UNKNOWN  = 8, -- oops.
  SID_NAME_COMPUTER = 9  -- machine
}
---String versions of SID types
local lsa_SidType_str =
{
  SID_NAME_USE_NONE = "n/a",
  SID_NAME_USER     = "User",
  SID_NAME_DOM_GRP  = "Domain group",
  SID_NAME_DOMAIN   = "Domain",
  SID_NAME_ALIAS    = "Local group",
  SID_NAME_WKN_GRP  = "Well known group",
  SID_NAME_DELETED  = "Deleted account",
  SID_NAME_INVALID  = "Invalid account",
  SID_NAME_UNKNOWN  = "Unknown account",
  SID_NAME_COMPUTER = "Machine"
}
---Marshall a <code>lsa_SidType</code>. This datatype is tied to the table above with that
-- name.
--
--@param sid_type The value to marshall, as a string
--@return The marshalled integer representing the given value, or <code>nil</code> if it wasn't
--        found.
function marshall_lsa_SidType(sid_type)
  local result
  stdnse.debug4("MSRPC: Entering marshall_lsa_SidType()")

  result = marshall_Enum32(sid_type, lsa_SidType)

  stdnse.debug4("MSRPC: Leaving marshall_lsa_SidType()")
  return result
end

---Unmarshall a <code>lsa_SidType</code>. This datatype is tied to the table with that name.
--
--@param data The data packet.
--@param pos  The position within the data.
--@return (pos, str) The new position, and the string representing the datatype.
function unmarshall_lsa_SidType(data, pos)
  local str
  stdnse.debug4("MSRPC: Entering unmarshall_lsa_SidType()")

  pos, str = unmarshall_Enum16(data, pos, lsa_SidType)

  stdnse.debug4("MSRPC: Leaving unmarshall_lsa_SidType()")
  return pos, str
end

---Convert a <code>lsa_SidType</code> value to a string that can be shown to the user. This is
-- based on the <code>_str</code> table.
--
--@param val The string value (returned by the <code>unmarshall_</code> function) to convert.
--@return A string suitable for displaying to the user, or <code>nil</code> if it wasn't found.
function lsa_SidType_tostr(val)
  local result
  stdnse.debug4("MSRPC: Entering lsa_SidType_tostr()")

  result = lsa_SidType_str[val]

  stdnse.debug4("MSRPC: Leaving lsa_SidType_tostr()")
  return result
end

---LSA name levels.
local lsa_LookupNamesLevel =
{
  LOOKUP_NAMES_ALL                  = 1,
  LOOKUP_NAMES_DOMAINS_ONLY         = 2,
  LOOKUP_NAMES_PRIMARY_DOMAIN_ONLY  = 3,
  LOOKUP_NAMES_UPLEVEL_TRUSTS_ONLY  = 4,
  LOOKUP_NAMES_FOREST_TRUSTS_ONLY   = 5,
  LOOKUP_NAMES_UPLEVEL_TRUSTS_ONLY2 = 6
}
---LSA name level strings.
local lsa_LookupNamesLevel_str =
{
  LOOKUP_NAMES_ALL                  = "All",
  LOOKUP_NAMES_DOMAINS_ONLY         = "Domains only",
  LOOKUP_NAMES_PRIMARY_DOMAIN_ONLY  = "Primary domains only",
  LOOKUP_NAMES_UPLEVEL_TRUSTS_ONLY  = "Uplevel trusted domains only",
  LOOKUP_NAMES_FOREST_TRUSTS_ONLY   = "Forest trusted domains only",
  LOOKUP_NAMES_UPLEVEL_TRUSTS_ONLY2 = "Uplevel trusted domains only (2)"
}
---Marshall a <code>lsa_LookupNamesLevel</code>. This datatype is tied to the table above with that
-- name.
--
--@param names_level The value to marshall, as a string
--@return The marshalled integer representing the given value, or <code>nil</code> if it wasn't
--        found.
function marshall_lsa_LookupNamesLevel(names_level)
  local result
  stdnse.debug4("MSRPC: Entering marshall_lsa_LookupNamesLevel()")

  result = marshall_Enum32(names_level, lsa_LookupNamesLevel)

  stdnse.debug4("MSRPC: Leaving marshall_lsa_LookupNamesLevel()")
  return result
end

---Unmarshall a <code>lsa_LookupNamesLevel</code>. This datatype is tied to the table with that name.
--
--@param data The data packet.
--@param pos  The position within the data.
--@return (pos, str) The new position, and the string representing the datatype.
function unmarshall_lsa_LookupNamesLevel(data, pos)
  local str
  stdnse.debug4("MSRPC: Entering unmarshall_lsa_LookupNamesLevel()")

  pos, str = unmarshall_Enum32(data, pos, lsa_LookupNamesLevel)

  stdnse.debug4("MSRPC: Leaving unmarshall_lsa_LookupNamesLevel()")
  return pos, str
end

---Convert a <code>lsa_LookupNamesLevel</code> value to a string that can be shown to the user. This is
-- based on the <code>_str</code> table.
--
--@param val The string value (returned by the <code>unmarshall_</code> function) to convert.
--@return A string suitable for displaying to the user, or <code>nil</code> if it wasn't found.
function lsa_LookupNamesLevel_tostr(val)
  local result
  stdnse.debug4("MSRPC: Entering lsa_LookupNamesLevel_tostr()")

  result = lsa_LookupNamesLevel_str[val]

  stdnse.debug4("MSRPC: Leaving lsa_LookupNamesLevel_tostr()")
  return result
end

---Marshall a lsa_TranslatedSid2 struct
--
--<code>
--    typedef struct {
--        lsa_SidType sid_type;
--        uint32 rid;
--        uint32 sid_index;
--        uint32 unknown;
--    } lsa_TranslatedSid2;
--</code>
--
--@param location The part of the pointer wanted, either HEAD (for the data itself), BODY
--                (for nothing, since this isn't a pointer), or ALL (for the data). Generally, unless the
--                referent_id is split from the data (for example, in an array), you will want
--                ALL.
--@param sid_type  The <code>sid_type</code> value (I don't know what this means)
--@param rid       The <code>rid</code> (a number representing the user)
--@param sid_index The <code>sid_index</code> value (I don't know what this means, either)
--@param unknown   An unknown value (is normally 0).
--@return A string representing the marshalled data.
local function marshall_lsa_TranslatedSid2(location, sid_type, rid, sid_index, unknown)
  local result = ""
  stdnse.debug4("MSRPC: Entering marshall_lsa_TranslatedSid2()")

  -- Set some default values
  if(sid_type == nil)  then sid_type  = "SID_NAME_USE_NONE" end
  if(rid == nil)       then rid       = 0 end
  if(sid_index == nil) then sid_index = 0 end
  if(unknown == nil)   then unknown   = 0 end

  if(location == HEAD or location == ALL) then
    result = marshall_lsa_SidType(sid_type)
    .. marshall_int32(rid)
    .. marshall_int32(sid_index)
    .. marshall_int32(unknown)
  end

  if(location == BODY or location == ALL) then
  end

  stdnse.debug4("MSRPC: Leaving marshall_lsa_TranslatedSid2()")
  return result
end

---Unmarshall a lsa_TranslatedSid2 struct
--
--<code>
--    typedef struct {
--        lsa_SidType sid_type;
--        uint32 rid;
--        uint32 sid_index;
--        uint32 unknown;
--    } lsa_TranslatedSid2;
--</code>
--
--@param location The part of the pointer wanted, either HEAD (for the data itself), BODY
--                (for nothing, since this isn't a pointer), or ALL (for the data). Generally, unless the
--                referent_id is split from the data (for example, in an array), you will want
--                ALL.
--@param data     The data being processed.
--@param pos      The position within <code>data</code>.
--@param result   This is required when unmarshalling the BODY section, which always comes after
--                unmarshalling the HEAD. It is the result returned for this parameter during the
--                HEAD unmarshall. If the referent_id was '0', then this function doesn't unmarshall
--                anything.
--@return (pos, result) The new position in <code>data</code>, and a table representing the datatype.
local function unmarshall_lsa_TranslatedSid2(location, data, pos, result)
  if(result == nil) then
    result = {}
  end

  if(location == HEAD or location == ALL) then
    pos, result['sid_type']  = unmarshall_lsa_SidType(data, pos)
    pos, result['rid']       = unmarshall_int32(data, pos)
    pos, result['sid_index'] = unmarshall_int32(data, pos)
    pos, result['unknown']   = unmarshall_int32(data, pos)
  end


  if(location == BODY or location == ALL) then
  end

  return pos, result
end

---Marshall a lsa_TranslatedName2 struct
--
--<code>
--    typedef struct {
--        lsa_SidType sid_type;
--        lsa_String name;
--        uint32 sid_index;
--        uint32 unknown;
--    } lsa_TranslatedName2;
--</code>
--
--@param location  The part of the pointer wanted, either HEAD (for the data itself), BODY
--                 (for nothing, since this isn't a pointer), or ALL (for the data). Generally, unless the
--                 referent_id is split from the data (for example, in an array), you will want
--                 ALL.
--@param sid_type  The <code>sid_type</code> value, as a string
--@param name      The name of the user
--@param sid_index The sid_index (I don't know what this is)
--@param unknown   An unknown value, normally 0
--@return A string representing the marshalled data.
local function marshall_lsa_TranslatedName2(location, sid_type, name, sid_index, unknown)
  local result = ""
  stdnse.debug4("MSRPC: Entering marshall_lsa_TranslatedName2()")

  -- Set some default values
  if(sid_type == nil)  then sid_type  = "SID_NAME_USE_NONE" end
  if(name == nil)      then name      = "" end
  if(sid_index == nil) then sid_index = 0 end
  if(unknown == nil)   then unknown   = 0 end

  if(location == HEAD or location == ALL) then
    result = marshall_lsa_SidType(sid_type)
    .. marshall_lsa_String_internal(HEAD, name)
    .. marshall_int32(sid_index)
    .. marshall_int32(unknown)
  end

  if(location == BODY or location == ALL) then
    result = result .. marshall_lsa_String_internal(BODY, name)
  end

  stdnse.debug4("MSRPC: Leaving marshall_lsa_TranslatedName2()")
  return result
end

--@param location The part of the pointer wanted, either HEAD (for the data itself), BODY
--                (for nothing, since this isn't a pointer), or ALL (for the data). Generally, unless the
--                referent_id is split from the data (for example, in an array), you will want
--                ALL.
--@param data     The data being processed.
--@param pos      The position within <code>data</code>.
--@param result   This is required when unmarshalling the BODY section, which always comes after
--                unmarshalling the HEAD. It is the result returned for this parameter during the
--                HEAD unmarshall. If the referent_id was '0', then this function doesn't unmarshall
--                anything.
--@return (pos, result) The new position in <code>data</code>, and a table representing the datatype.
local function unmarshall_lsa_TranslatedName2(location, data, pos, result)
  stdnse.debug4("MSRPC: Entering unmarshall_lsa_TranslatedName2()")
  if(result == nil) then
    result = {}
  end

  if(location == HEAD or location == ALL) then
    pos, result['sid_type']  = unmarshall_lsa_SidType(data, pos)
    pos, result['name']      = unmarshall_lsa_String_internal(HEAD, data, pos)
    pos, result['sid_index'] = unmarshall_int32(data, pos)
    pos, result['unknown']   = unmarshall_int32(data, pos)
  end


  if(location == BODY or location == ALL) then
    pos, result['name']      = unmarshall_lsa_String_internal(BODY, data, pos, result['name'])
  end

  stdnse.debug4("MSRPC: Leaving unmarshall_lsa_TranslatedName2()")
  return pos, result
end


---Marshall a lsa_TransSidArray2 struct
--
--<code>
--    typedef struct {
--        [range(0,1000)] uint32 count;
--        [size_is(count)] lsa_TranslatedSid2 *sids;
--    } lsa_TransSidArray2;
--</code>
--
--@param sids An array of SIDs to translate (as strings)
--@return A string representing the marshalled data.
function marshall_lsa_TransSidArray2(sids)
  local array = {}
  stdnse.debug4("MSRPC: Entering marshall_lsa_TransSidArray2()")


  for i = 1, #sids, 1 do
    array[i] = {}
    array[i]['func'] = marshall_lsa_TranslatedSid2
    array[i]['args'] = {sids[i]['sid_type'], sids[i]['rid'], sids[i]['sid_index'], sids[i]['unknown']}
  end

  local result = marshall_int32(#sids)
  .. marshall_ptr(ALL, marshall_array, {array}, array)

  stdnse.debug4("MSRPC: Leaving marshall_lsa_TransSidArray2()")
  return result
end

---Marshall a lsa_StringLarge struct
--
--<code>
--    typedef [public] struct {
--        [value(2*strlen_m(string))] uint16 length;
--        [value(2*(strlen_m(string)+1))] uint16 size;
--        [charset(UTF16),size_is(size/2),length_is(length/2)] uint16 *string;
--    } lsa_StringLarge;
--</code>
--
--@param location The part of the pointer wanted, either HEAD (for the data itself), BODY
--                (for nothing, since this isn't a pointer), or ALL (for the data). Generally, unless the
--                referent_id is split from the data (for example, in an array), you will want
--                ALL.
--@param data     The data being processed.
--@param pos      The position within <code>data</code>.
--@param result   This is required when unmarshalling the BODY section, which always comes after
--                unmarshalling the HEAD. It is the result returned for this parameter during the
--                HEAD unmarshall. If the referent_id was '0', then this function doesn't unmarshall
--                anything.
--@return (pos, result) The new position in <code>data</code>, and the string value.
local function unmarshall_lsa_StringLarge(location, data, pos, result)
  local length, size
  local str
  stdnse.debug4("MSRPC: Entering unmarshall_lsa_StringLarge()")

  if(location == HEAD or location == ALL) then
    pos, length = unmarshall_int16(data, pos, false)
    pos, size   = unmarshall_int16(data, pos, false)

    pos, str = unmarshall_ptr(HEAD, data, pos, unmarshall_unicode, {false})
  end

  if(location == BODY or location == ALL) then
    pos, str = unmarshall_ptr(BODY, data, pos, unmarshall_unicode, {false}, result)
  end

  stdnse.debug4("MSRPC: Leaving unmarshall_lsa_StringLarge()")
  return pos, str
end

---Unmarshall a lsa_DomainInfo struct
--
--<code>
--    typedef struct {
--        lsa_StringLarge name;
--        dom_sid2 *sid;
--    } lsa_DomainInfo;
--</code>
--
--@param location The part of the pointer wanted, either HEAD (for the data itself), BODY
--                (for nothing, since this isn't a pointer), or ALL (for the data). Generally, unless the
--                referent_id is split from the data (for example, in an array), you will want
--                ALL.
--@param data     The data being processed.
--@param pos      The position within <code>data</code>.
--@param result   This is required when unmarshalling the BODY section, which always comes after
--                unmarshalling the HEAD. It is the result returned for this parameter during the
--                HEAD unmarshall. If the referent_id was '0', then this function doesn't unmarshall
--                anything.
--@return (pos, result) The new position in <code>data</code>, and a table representing the datatype.
local function unmarshall_lsa_DomainInfo(location, data, pos, result)
  stdnse.debug4("MSRPC: Entering unmarshall_lsa_DomainInfo()")
  if(result == nil) then
    result = {}
  end

  if(location == HEAD or location == ALL) then
    pos, result['name'] = unmarshall_lsa_StringLarge(HEAD, data, pos)
    pos, result['sid']  = unmarshall_ptr(HEAD, data, pos, unmarshall_dom_sid2)
  end

  if(location == BODY or location == ALL) then
    pos, result['name'] = unmarshall_lsa_StringLarge(BODY, data, pos, result['name'])
    pos, result['sid']  = unmarshall_ptr(BODY, data, pos, unmarshall_dom_sid2, {}, result['sid'])
  end

  stdnse.debug4("MSRPC: Leaving unmarshall_lsa_DomainInfo()")
  return pos, result
end

---Unmarshall a lsa_RefDomainList struct
--
--<code>
--    typedef struct {
--        [range(0,1000)] uint32 count;
--        [size_is(count)] lsa_DomainInfo *domains;
--        uint32 max_size;
--    } lsa_RefDomainList;
--</code>
--
--@param data     The data being processed.
--@param pos      The position within <code>data</code>.
--@return (pos, result) The new position in <code>data</code>, and a table representing the datatype.
function unmarshall_lsa_RefDomainList(data, pos)
  local result = {}
  stdnse.debug4("MSRPC: Entering unmarshall_lsa_RefDomainList()")

  -- Head
  pos, result['count'] = unmarshall_int32(data, pos)
  pos, result['domains'] = unmarshall_ptr(HEAD, data, pos, unmarshall_array, {result['count'], unmarshall_lsa_DomainInfo, {}})
  pos, result['max_size'] = unmarshall_int32(data, pos)

  -- Body
  pos, result['domains'] = unmarshall_ptr(BODY, data, pos, unmarshall_array, {result['count'], unmarshall_lsa_DomainInfo, {}}, result['domains'])

  stdnse.debug4("MSRPC: Leaving unmarshall_lsa_RefDomainList()")
  return pos, result
end

---Unmarshall a pointer to a <code>lsa_RefDomainList</code>. See the <code>unmarshall_lsa_RefDomainList</code> function
-- for more information.
--
--@param data     The data being processed.
--@param pos      The position within <code>data</code>.
--@return (pos, result) The new position in <code>data</code>, and a table representing the datatype.
function unmarshall_lsa_RefDomainList_ptr(data, pos)
  local result
  stdnse.debug4("MSRPC: Entering unmarshall_lsa_RefDomainList_ptr()")

  pos, result = unmarshall_ptr(ALL, data, pos, unmarshall_lsa_RefDomainList, nil)

  stdnse.debug4("MSRPC: Leaving unmarshall_lsa_RefDomainList_ptr()")
  return pos, result
end

---Unmarshall a lsa_TransSidArray2 struct
--
--<code>
--    typedef struct {
--        [range(0,1000)] uint32 count;
--        [size_is(count)] lsa_TranslatedSid2 *sids;
--    } lsa_TransSidArray2;
--</code>
--
--@param data     The data being processed.
--@param pos      The position within <code>data</code>.
--@return (pos, result) The new position in <code>data</code>, and a table representing the datatype.
function unmarshall_lsa_TransSidArray2(data, pos)
  local result = {}
  stdnse.debug4("MSRPC: Entering unmarshall_lsa_TransSidArray2()")

  pos, result['count'] = unmarshall_int32(data, pos)
  pos, result['sid']   = unmarshall_ptr(ALL, data, pos, unmarshall_array, {result['count'], unmarshall_lsa_TranslatedSid2, {}})

  stdnse.debug4("MSRPC: Leaving unmarshall_lsa_TransSidArray2()")
  return pos, result
end

---Marshall a lsa_QosInfo struct
--
--<code>
--    typedef struct {
--        uint32  len; /* ignored */
--        uint16  impersonation_level;
--        uint8   context_mode;
--        uint8   effective_only;
--    } lsa_QosInfo;
--</code>
--
-- I didn't bother letting the user specify values, since I don't know what any of them do. The
-- defaults seem to work really well.
--
--@return A string representing the marshalled data.
function marshall_lsa_QosInfo()
  stdnse.debug4("MSRPC: Entering marshall_lsa_QosInfo()")

  local result = marshall_int32(12)
  .. marshall_int16(2, false)
  .. marshall_int8(1, false)
  .. marshall_int8(0, false)

  stdnse.debug4("MSRPC: Leaving marshall_lsa_QosInfo()")
  return result
end

---Marshall a lsa_ObjectAttribute struct
--
--<code>
--    typedef struct {
--        uint32 len; /* ignored */
--        uint8 *root_dir;
--        [string,charset(UTF16)] uint16 *object_name;
--        uint32 attributes;
--        security_descriptor *sec_desc;
--        lsa_QosInfo *sec_qos;
--    } lsa_ObjectAttribute;
--</code>
--
-- I didn't bother letting the user specify values, since I don't know what any of them do. The
-- defaults seem to work really well.
--
--@return A string representing the marshalled data.
function marshall_lsa_ObjectAttribute()
  stdnse.debug4("MSRPC: Entering marshall_lsa_ObjectAttribute()")

  local result = marshall_int32(24)
  .. marshall_int32(0)  -- Null'ing out these pointers for now. Maybe we'll need them in the future...
  .. marshall_int32(0)
  .. marshall_int32(0)
  .. marshall_int32(0)
  .. marshall_ptr(ALL, marshall_lsa_QosInfo, {})

  stdnse.debug4("MSRPC: Leaving marshall_lsa_ObjectAttribute()")
  return result
end

---Marshall a lsa_SidPtr struct
--
--<code>
--    typedef struct {
--        dom_sid2 *sid;
--    } lsa_SidPtr;
--</code>
--
--@param location The part of the pointer wanted, either HEAD (for the data itself), BODY
--                (for nothing, since this isn't a pointer), or ALL (for the data). Generally, unless the
--                referent_id is split from the data (for example, in an array), you will want
--                ALL.
--@param sid      The SID to marshall (as a string).
--@return A string representing the marshalled data.
local function marshall_lsa_SidPtr(location, sid)
  local result
  stdnse.debug4("MSRPC: Entering marshall_lsa_SidPtr()")

  result = marshall_ptr(location, marshall_dom_sid2, {sid}, sid)

  stdnse.debug4("MSRPC: Leaving marshall_lsa_SidPtr()")
  return result
end

---Marshall a lsa_SidArray struct
--
--<code>
--    typedef [public] struct {
--        [range(0,1000)] uint32 num_sids;
--        [size_is(num_sids)] lsa_SidPtr *sids;
--    } lsa_SidArray;
--</code>
--
--@param sids The array of SIDs to marshall (as strings).
--@return A string representing the marshalled data.
function marshall_lsa_SidArray(sids)
  local array = {}

  for i = 1, #sids, 1 do
    array[i] = {}
    array[i]['func'] = marshall_lsa_SidPtr
    array[i]['args'] = {sids[i]}
  end

  local result = marshall_int32(#sids)
  .. marshall_ptr(ALL, marshall_array, {array}, array)

  return result
end

---Unmarshall a lsa_SidPtr struct
--
--<code>
--    typedef struct {
--        dom_sid2 *sid;
--    } lsa_SidPtr;
--</code>
--
--@param location The part of the pointer wanted, either HEAD (for the data itself), BODY
--                (for nothing, since this isn't a pointer), or ALL (for the data). Generally, unless the
--                referent_id is split from the data (for example, in an array), you will want
--                ALL.
--@param data     The data being processed.
--@param pos      The position within <code>data</code>.
--@param result   This is required when unmarshalling the BODY section, which always comes after
--                unmarshalling the HEAD. It is the result returned for this parameter during the
--                HEAD unmarshall. If the referent_id was '0', then this function doesn't unmarshall
--                anything.
--@return (pos, result) The new position in <code>data</code>, and a table representing the datatype.
function unmarshall_lsa_SidPtr(location, data, pos, result)
  return unmarshall_ptr(location, data, pos, unmarshall_dom_sid2, {}, result)
end

---Unmarshall a lsa_SidArray struct
--
--    typedef [public] struct {
--        [range(0,1000)] uint32 num_sids;
--        [size_is(num_sids)] lsa_SidPtr *sids;
--    } lsa_SidArray;
--
--@param data     The data being processed.
--@param pos      The position within <code>data</code>.
--@return (pos, result) The new position in <code>data</code>, and a table representing the datatype.
function unmarshall_lsa_SidArray(data, pos)
  local sidarray = {}

  pos, sidarray['count'] = unmarshall_int32(data, pos)
  pos, sidarray['sids']  = unmarshall_ptr(ALL, data, pos, unmarshall_array, {sidarray['count'], unmarshall_lsa_SidPtr, {}})

  return pos, sidarray
end

---Marshall a lsa_TransNameArray2 struct
--
--<code>
--    typedef struct {
--        [range(0,1000)] uint32 count;
--        [size_is(count)] lsa_TranslatedName2 *names;
--    } lsa_TransNameArray2;
--</code>
--
--@param names An array of names to translate.
--@return A string representing the marshalled data.
function marshall_lsa_TransNameArray2(names)
  local result = ""
  local array = {}
  stdnse.debug4("MSRPC: Entering marshall_lsa_TransNameArray2()")

  if(names == nil) then
    result = result .. marshall_int32(0)
    array = nil
  else
    result = result .. marshall_int32(#names)

    for i = 1, #names, 1 do
      array[i] = {}
      array[i]['func'] = marshall_lsa_TranslatedName2
      array[i]['args'] = {names[i]['sid_type'], names[i]['name'], names[i]['sid_index'], names[i]['unknown']}
    end
  end

  result = result .. marshall_ptr(ALL, marshall_array, {array}, array)

  stdnse.debug4("MSRPC: Leaving marshall_lsa_TransNameArray2()")
  return result
end

---Unmarshall a <code>lsa_TransNameArray2</code> structure. See the <code>marshall_lsa_TransNameArray2</code> for more
-- information.
--
--@param data     The data being processed.
--@param pos      The position within <code>data</code>.
--@return (pos, result) The new position in <code>data</code>, and a table representing the datatype.
function unmarshall_lsa_TransNameArray2(data, pos)
  local result = {}
  stdnse.debug4("MSRPC: Entering unmarshall_lsa_TransNameArray2()")

  pos, result['count'] = unmarshall_int32(data, pos)
  pos, result['names'] = unmarshall_ptr(ALL, data, pos, unmarshall_array, {result['count'], unmarshall_lsa_TranslatedName2, {}})

  stdnse.debug4("MSRPC: Leaving unmarshall_lsa_TransNameArray2()")
  return pos, result
end



-------------------------------------
--          WINREG
-- (dependencies: LSA, INITSHUTDOWN, SECURITY)
-------------------------------------
--- Access masks for Windows registry calls
local winreg_AccessMask =
{
  DELETE_ACCESS          = 0x00010000,
  READ_CONTROL_ACCESS    = 0x00020000,
  WRITE_DAC_ACCESS       = 0x00040000,
  WRITE_OWNER_ACCESS     = 0x00080000,
  SYNCHRONIZE_ACCESS     = 0x00100000,
  ACCESS_SACL_ACCESS     = 0x00800000,
  SYSTEM_SECURITY_ACCESS = 0x01000000,
  MAXIMUM_ALLOWED_ACCESS = 0x02000000,
  GENERIC_ALL_ACCESS     = 0x10000000,
  GENERIC_EXECUTE_ACCESS = 0x20000000,
  GENERIC_WRITE_ACCESS   = 0x40000000,
  GENERIC_READ_ACCESS    = 0x80000000
}
--- String versions of access masks for Windows registry calls
local winreg_AccessMask_str =
{
  DELETE_ACCESS          = "Delete",
  READ_CONTROL_ACCESS    = "Read",
  WRITE_DAC_ACCESS       = "Write",
  WRITE_OWNER_ACCESS     = "Write (owner)",
  SYNCHRONIZE_ACCESS     = "Synchronize",
  ACCESS_SACL_ACCESS     = "Access SACL",
  SYSTEM_SECURITY_ACCESS = "System security",
  MAXIMUM_ALLOWED_ACCESS = "Maximum allowed access",
  GENERIC_ALL_ACCESS     = "All access",
  GENERIC_EXECUTE_ACCESS = "Execute access",
  GENERIC_WRITE_ACCESS   = "Write access",
  GENERIC_READ_ACCESS    = "Read access"
}

---Marshall a <code>winreg_AccessMask</code>.
--
--@param accessmask The access mask as a string (see the <code>winreg_AccessMask</code>
--                  table)
--@return A string representing the marshalled data.
function marshall_winreg_AccessMask(accessmask)
  local result
  stdnse.debug4("MSRPC: Entering marshall_winreg_AccessMask()")

  result = marshall_Enum32(accessmask, winreg_AccessMask)

  stdnse.debug4("MSRPC: Leaving marshall_winreg_AccessMask()")
  return result
end

---Unmarshall a <code>winreg_AccessMask</code>. This datatype is tied to the table with that name.
--
--@param data The data packet.
--@param pos  The position within the data.
--@return (pos, str) The new position, and the string representing the datatype.
function unmarshall_winreg_AccessMask(data, pos)
  local str
  stdnse.debug4("MSRPC: Entering unmarshall_winreg_AccessMask()")

  pos, str = unmarshall_Enum32(data, pos, winreg_AccessMask)

  stdnse.debug4("MSRPC: Leaving unmarshall_winreg_AccessMask()")
  return pos, str
end

---Convert a <code>winreg_AccessMask</code> value to a string that can be shown to the user. This is
-- based on the <code>_str</code> table.
--
--@param val The string value (returned by the <code>unmarshall_</code> function) to convert.
--@return A string suitable for displaying to the user, or <code>nil</code> if it wasn't found.
function winreg_AccessMask_tostr(val)
  local result
  stdnse.debug4("MSRPC: Entering winreg_AccessMask_tostr()")

  result = winreg_AccessMask_str[val]

  stdnse.debug4("MSRPC: Leaving winreg_AccessMask_tostr()")
  return result
end

---Registry types
winreg_Type =
{
  REG_NONE                       = 0,
  REG_SZ                         = 1,
  REG_EXPAND_SZ                  = 2,
  REG_BINARY                     = 3,
  REG_DWORD                      = 4,
  REG_DWORD_BIG_ENDIAN           = 5,
  REG_LINK                       = 6,
  REG_MULTI_SZ                   = 7,
  REG_RESOURCE_LIST              = 8,
  REG_FULL_RESOURCE_DESCRIPTOR   = 9,
  REG_RESOURCE_REQUIREMENTS_LIST = 10,
  REG_QWORD                      = 11
}

---Registry type strings
winreg_Type_str =
{
  REG_NONE                       = "None",
  REG_SZ                         = "String",
  REG_EXPAND_SZ                  = "String (expanded)",
  REG_BINARY                     = "Binary",
  REG_DWORD                      = "Dword",
  REG_DWORD_BIG_ENDIAN           = "Dword (big endian)",
  REG_LINK                       = "Link",
  REG_MULTI_SZ                   = "String (multi)",
  REG_RESOURCE_LIST              = "Resource list",
  REG_FULL_RESOURCE_DESCRIPTOR   = "Full resource descriptor",
  REG_RESOURCE_REQUIREMENTS_LIST = "Resource requirements list",
  REG_QWORD                      = "Qword"
}

---Marshall a <code>winreg_Type</code>. This datatype is tied to the table above with that
-- name.
--
--@param winregtype The value to marshall, as a string
--@return The marshalled integer representing the given value, or <code>nil</code> if it wasn't
--        found.
function marshall_winreg_Type(winregtype)
  local result
  stdnse.debug4("MSRPC: Entering marshall_winreg_Type()")

  result = marshall_Enum32(winregtype, winreg_Type)

  stdnse.debug4("MSRPC: Leaving marshall_winreg_Type()")
  return result
end

---Unmarshall a <code>winreg_Type</code>. This datatype is tied to the table with that name.
--
--@param data The data packet.
--@param pos  The position within the data.
--@return (pos, str) The new position, and the string representing the datatype.
function unmarshall_winreg_Type(data, pos)
  local str
  stdnse.debug4("MSRPC: Entering unmarshall_winreg_Type()")

  pos, str = unmarshall_Enum32(data, pos, winreg_Type)

  stdnse.debug4("MSRPC: Leaving unmarshall_winreg_Type()")
  return pos, str
end

---Marshall a pointer to a <code>winreg_Type</code>. This datatype is tied to the table above with that
-- name.
--
--@param winreg_type The value to marshall, as a string
--@return The marshalled integer representing the given value, or <code>nil</code> if it wasn't
--        found.
function marshall_winreg_Type_ptr(winreg_type)
  local result
  stdnse.debug4("MSRPC: Entering marshall_winreg_Type_ptr()")

  result = marshall_ptr(ALL, marshall_winreg_Type, {winreg_type}, winreg_type)

  stdnse.debug4("MSRPC: Leaving marshall_winreg_Type_ptr()")
  return result
end

---Unmarshall a pointer to a <code>winreg_Type</code>. This datatype is tied to the table with that name.
--
--@param data The data packet.
--@param pos  The position within the data.
--@return (pos, str) The new position, and the string representing the datatype.
function unmarshall_winreg_Type_ptr(data, pos)
  local str
  stdnse.debug4("MSRPC: Entering unmarshall_winreg_Type_ptr()")

  pos, str = unmarshall_ptr(ALL, data, pos, unmarshall_winreg_Type, {})

  stdnse.debug4("MSRPC: Leaving unmarshall_winreg_Type_ptr()")
  return pos, str
end

---Convert a <code>winreg_Type</code> value to a string that can be shown to the user. This is
-- based on the <code>_str</code> table.
--
--@param val The string value (returned by the <code>unmarshall_</code> function) to convert.
--@return A string suitable for displaying to the user, or <code>nil</code> if it wasn't found.
function winreg_Type_tostr(val)
  local result
  stdnse.debug4("MSRPC: Entering winreg_Type_tostr()")

  result = winreg_Type_str[val]

  stdnse.debug4("MSRPC: Leaving winreg_Type_tostr()")
  return result
end

--- A winreg_stringbuf is a buffer that holds a null-terminated string. It can have a max size that's different
--  from its actual size.
--
-- This is the format:
--
--<code>
--  typedef struct {
--    [value(strlen_m_term(name)*2)] uint16 length;
--    uint16 size;
--    [size_is(size/2),length_is(length/2),charset(UTF16)] uint16 *name;
--  } winreg_StringBuf;
--</code>
--
--@param table The table to marshall. Will probably contain just the 'name' entry.
--@param max_length [optional] The maximum size of the buffer, in characters, including the null terminator.
--                  Defaults to the length of the string, including the null.
--@return A string representing the marshalled data.
function marshall_winreg_StringBuf(table, max_length)
  local result
  stdnse.debug4("MSRPC: Entering marshall_winreg_StringBuf()")

  local name = table['name']
  local length

  -- Handle default max lengths
  if(max_length == nil) then
    if(name == nil) then
      max_length = 0
    else
      max_length = #name + 1
    end
  end

  -- For some reason, 0-length strings are handled differently (no null terminator)...
  if(name == "") then
    length = 0
    result = bin.pack("<SSA", length * 2, max_length * 2, marshall_ptr(ALL, marshall_unicode, {name, false, max_length}, name))
  else
    if(name == nil) then
      length = 0
    else
      length = #name + 1
    end

    result = bin.pack("<SSA", length * 2, max_length * 2, marshall_ptr(ALL, marshall_unicode, {name, true, max_length}, name))
  end

  stdnse.debug4("MSRPC: Leaving marshall_winreg_StringBuf()")
  return result
end

---Unmarshall a winreg_StringBuf buffer.
--
--@param data   The data buffer.
--@param pos    The position in the data buffer.
--@return (pos, str) The new position and the string.
function unmarshall_winreg_StringBuf(data, pos)
  local length, size
  local str
  stdnse.debug4("MSRPC: Entering unmarshall_winreg_StringBuf()")

  pos, length = unmarshall_int16(data, pos, false)
  pos, size   = unmarshall_int16(data, pos, false)

  pos, str = unmarshall_ptr(ALL, data, pos, unmarshall_unicode, {true})

  stdnse.debug4("MSRPC: Leaving unmarshall_winreg_StringBuf()")
  return pos, str
end

---Marshall a winreg_StringBuffer pointer. Same as <code>marshall_winreg_StringBuf</code>, except
-- the string can be <code>nil</code>.
--
--@param table The table representing the String.
--@param max_length [optional] The maximum size of the buffer, in characters. Defaults to the length of the string, including the null.
--@return A string representing the marshalled data.
function marshall_winreg_StringBuf_ptr(table, max_length)
  local result
  stdnse.debug4("MSRPC: Entering marshall_winreg_StringBuf_ptr()")

  result = marshall_ptr(ALL, marshall_winreg_StringBuf, {table, max_length}, table)

  stdnse.debug4("MSRPC: Leaving marshall_winreg_StringBuf_ptr()")
  return result
end

---Unmarshall a winreg_StringBuffer pointer
--
--@param data   The data buffer.
--@param pos    The position in the data buffer.
--@return (pos, str) The new position and the string.
function unmarshall_winreg_StringBuf_ptr(data, pos)
  local str
  stdnse.debug4("MSRPC: Entering unmarshall_winreg_StringBuf_ptr()")

  pos, str = unmarshall_ptr(ALL, data, pos, unmarshall_winreg_StringBuf, {})

  stdnse.debug4("MSRPC: Leaving unmarshall_winreg_StringBuf_ptr()")
  return pos, str
end


--- A winreg_String has the same makeup as a winreg_StringBuf, as far as I can tell, so delegate to that function.
--
--@param table The table representing the String.
--@param max_length [optional] The maximum size of the buffer, in characters. Defaults to the length of the string, including the null.
--@return A string representing the marshalled data.
function marshall_winreg_String(table, max_length)
  local result
  stdnse.debug4("MSRPC: Entering marshall_winreg_String()")

  result = marshall_winreg_StringBuf(table, max_length)

  stdnse.debug4("MSRPC: Leaving marshall_winreg_String()")
  return result
end

---Unmarshall a winreg_String. Since it has the same makeup as winreg_StringBuf, delegate to that.
--
--@param data   The data buffer.
--@param pos    The position in the data buffer.
--@return (pos, str) The new position and the string.
function unmarshall_winreg_String(data, pos)
  local str
  stdnse.debug4("MSRPC: Entering unmarshall_winreg_String()")

  pos, str = unmarshall_winreg_StringBuf(data, pos)

  stdnse.debug4("MSRPC: Leaving unmarshall_winreg_String()")
  return pos, str
end


-------------------------------------
--          SRVSVC
-- (dependencies: SECURITY, SVCCTL)
-------------------------------------
---Share types
local srvsvc_ShareType =
{
  STYPE_DISKTREE           = 0x00000000,
  STYPE_DISKTREE_TEMPORARY = 0x40000000,
  STYPE_DISKTREE_HIDDEN    = 0x80000000,
  STYPE_PRINTQ             = 0x00000001,
  STYPE_PRINTQ_TEMPORARY   = 0x40000001,
  STYPE_PRINTQ_HIDDEN      = 0x80000001,
  STYPE_DEVICE             = 0x00000002, -- Serial device
  STYPE_DEVICE_TEMPORARY   = 0x40000002,
  STYPE_DEVICE_HIDDEN      = 0x80000002,
  STYPE_IPC                = 0x00000003, -- Interprocess communication (IPC)
  STYPE_IPC_TEMPORARY      = 0x40000003,
  STYPE_IPC_HIDDEN         = 0x80000003
}
---Share type strings
local srvsvc_ShareType_str =
{
  STYPE_DISKTREE           = "Disk",
  STYPE_DISKTREE_TEMPORARY = "Disk (temporary)",
  STYPE_DISKTREE_HIDDEN    = "Disk (hidden)",
  STYPE_PRINTQ             = "Print queue",
  STYPE_PRINTQ_TEMPORARY   = "Print queue (temporary)",
  STYPE_PRINTQ_HIDDEN      = "Print queue (hidden)",
  STYPE_DEVICE             = "Serial device",
  STYPE_DEVICE_TEMPORARY   = "Serial device (temporary)",
  STYPE_DEVICE_HIDDEN      = "Serial device (hidden)",
  STYPE_IPC                = "Interprocess Communication",
  STYPE_IPC_TEMPORARY      = "Interprocess Communication (temporary)",
  STYPE_IPC_HIDDEN         = "Interprocess Communication (hidden)"
}

---Marshall a <code>srvsvc_ShareType</code>. This datatype is tied to the table above with that
-- name.
--
--@param sharetype The value to marshall, as a string
--@return The marshalled integer representing the given value, or <code>nil</code> if it wasn't
--        found.
function marshall_srvsvc_ShareType(sharetype)
  local result
  stdnse.debug4("MSRPC: Entering marshall_srvsvc_ShareType()")

  result = marshall_Enum32(sharetype, srvsvc_ShareType)

  stdnse.debug4("MSRPC: Leaving marshall_srvsvc_ShareType()")
  return result
end

---Unmarshall a <code>srvsvc_ShareType</code>. This datatype is tied to the table with that name.
--
--@param data The data packet.
--@param pos  The position within the data.
--@return (pos, str) The new position, and the string representing the datatype.
function unmarshall_srvsvc_ShareType(data, pos)
  local str
  stdnse.debug4("MSRPC: Entering unmarshall_srvsvc_ShareType()")

  pos, str = unmarshall_Enum32(data, pos, srvsvc_ShareType)

  stdnse.debug4("MSRPC: Leaving unmarshall_srvsvc_ShareType()")
  return pos, str
end

---Convert a <code>srvsvc_ShareType</code> value to a string that can be shown to the user. This is
-- based on the <code>_str</code> table.
--
--@param val The string value (returned by the <code>unmarshall_</code> function) to convert.
--@return A string suitable for displaying to the user, or <code>nil</code> if it wasn't found.
function srvsvc_ShareType_tostr(val)
  local result
  stdnse.debug4("MSRPC: Entering srvsvc_ShareType_tostr()")

  result = srvsvc_ShareType_str[val]

  stdnse.debug4("MSRPC: Leaving srvsvc_ShareType_tostr()")
  return result
end

---Marshall a NetShareInfo type 0, which is just a name.
--
--<code>
--    typedef struct {
--        [string,charset(UTF16)] uint16 *name;
--    } srvsvc_NetShareInfo0;
--</code>
--
--@param location The part of the pointer wanted, either HEAD (for the data itself), BODY
--                (for nothing, since this isn't a pointer), or ALL (for the data). Generally, unless the
--                referent_id is split from the data (for example, in an array), you will want
--                ALL.
--@param name     The name to marshall.
--@return A string representing the marshalled data.
local function marshall_srvsvc_NetShareInfo0(location, name)
  local result
  stdnse.debug4("MSRPC: Entering marshall_srvsvc_NetShareInfo0()")

  result = marshall_ptr(location, marshall_unicode, {name, true}, name)

  stdnse.debug4("MSRPC: Leaving marshall_srvsvc_NetShareInfo0()")
  return result
end

---Unmarshall a NetShareInfo type 0, which is just a name. See the marshall function for more information.
--
--@param location The part of the pointer wanted, either HEAD (for the data itself), BODY
--                (for nothing, since this isn't a pointer), or ALL (for the data). Generally, unless the
--                referent_id is split from the data (for example, in an array), you will want
--                ALL.
--@param data   The data packet.
--@param pos    The position within the data.
--@param result   This is required when unmarshalling the BODY section, which always comes after
--                unmarshalling the HEAD. It is the result returned for this parameter during the
--                HEAD unmarshall. If the referent_id was '0', then this function doesn't unmarshall
--                anything.
--@return (pos, result) The new position in <code>data</code>, and a table representing the datatype.
local function unmarshall_srvsvc_NetShareInfo0(location, data, pos, result)
  stdnse.debug4("MSRPC: Entering unmarshall_srvsvc_NetShareInfo0()")
  if(result == nil) then
    result = {}
  end

  if(location == HEAD or location == ALL) then
    pos, result['name'] = unmarshall_ptr(HEAD, data, pos, unmarshall_unicode, {true})
  end

  if(location == BODY or location == ALL) then
    pos, result['name'] = unmarshall_ptr(BODY, data, pos, unmarshall_unicode, {true}, result['name'])
  end

  stdnse.debug4("MSRPC: Leaving unmarshall_srvsvc_NetShareInfo0()")
  return pos, result
end

---Marshall a NetShareInfo type 1, which is the name and a few other things.
--
--<code>
--    typedef struct {
--        [string,charset(UTF16)] uint16 *name;
--        srvsvc_ShareType type;
--        [string,charset(UTF16)] uint16 *comment;
--    } srvsvc_NetShareInfo1;
--</code>
--
--@param location  The part of the pointer wanted, either HEAD (for the data itself), BODY
--                 (for nothing, since this isn't a pointer), or ALL (for the data). Generally, unless the
--                 referent_id is split from the data (for example, in an array), you will want
--                 ALL.
--@param name      The name to marshall.
--@param sharetype The sharetype to marshall (as a string).
--@param comment   The comment to marshall.
--@return A string representing the marshalled data.
local function marshall_srvsvc_NetShareInfo1(location, name, sharetype, comment)
  local result
  stdnse.debug4("MSRPC: Entering marshall_srvsvc_NetShareInfo1()")
  local name      = marshall_ptr(location, marshall_unicode, {name, true}, name)
  local sharetype = marshall_basetype(location, marshall_srvsvc_ShareType, {sharetype})
  local comment   = marshall_ptr(location, marshall_unicode, {comment, true}, comment)

  result = bin.pack("<AAA", name, sharetype, comment)

  stdnse.debug4("MSRPC: Leaving marshall_srvsvc_NetShareInfo1()")
  return result
end

---Unmarshall a NetShareInfo type 1, which is a name and a couple other things. See the marshall
-- function for more information.
--
--@param location The part of the pointer wanted, either HEAD (for the data itself), BODY
--                (for nothing, since this isn't a pointer), or ALL (for the data). Generally, unless the
--                referent_id is split from the data (for example, in an array), you will want
--                ALL.
--@param data     The data packet.
--@param pos      The position within the data.
--@param result   This is required when unmarshalling the BODY section, which always comes after
--                unmarshalling the HEAD. It is the result returned for this parameter during the
--                HEAD unmarshall. If the referent_id was '0', then this function doesn't unmarshall
--                anything.
--@return (pos, result) The new position in <code>data</code>, and a table representing the datatype.
local function unmarshall_srvsvc_NetShareInfo1(location, data, pos, result)
  stdnse.debug4("MSRPC: Entering unmarshall_srvsvc_NetShareInfo1()")
  if(result == nil) then
    result = {}
  end

  if(location == HEAD or location == ALL) then
    pos, result['name']      = unmarshall_ptr(HEAD, data, pos, unmarshall_unicode, {true})
    pos, result['sharetype'] = unmarshall_srvsvc_ShareType(data, pos)
    pos, result['comment']   = unmarshall_ptr(HEAD, data, pos, unmarshall_unicode, {true})
  end

  if(location == BODY or location == ALL) then
    pos, result['name']    = unmarshall_ptr(BODY, data, pos, unmarshall_unicode, {true}, result['name'])
    pos, result['comment'] = unmarshall_ptr(BODY, data, pos, unmarshall_unicode, {true}, result['comment'])
  end

  stdnse.debug4("MSRPC: Leaving unmarshall_srvsvc_NetShareInfo1()")
  return pos, result
end


---Marshall a NetShareInfo type 2, which is the name and a few other things.
--
--<code>
--    typedef struct {
--        [string,charset(UTF16)] uint16 *name;
--        srvsvc_ShareType type;
--        [string,charset(UTF16)] uint16 *comment;
--        uint32 permissions;
--        uint32 max_users;
--        uint32 current_users;
--        [string,charset(UTF16)] uint16 *path;
--        [string,charset(UTF16)] uint16 *password;
--    } srvsvc_NetShareInfo2;
--</code>
--
--@param location      The part of the pointer wanted, either HEAD (for the data itself), BODY
--                     (for nothing, since this isn't a pointer), or ALL (for the data). Generally, unless the
--                     referent_id is split from the data (for example, in an array), you will want
--                     ALL.
--@param name          The name to marshall.
--@param sharetype     The sharetype to marshall (as a string).
--@param comment       The comment to marshall.
--@param permissions   The permissions, an integer.
--@param max_users     The max users, an integer.
--@param current_users The current users, an integer.
--@param path          The path, a string.
--@param password      The share-level password, a string (never used on Windows).
--@return A string representing the marshalled data.
local function marshall_srvsvc_NetShareInfo2(location, name, sharetype, comment, permissions, max_users, current_users, path, password)
  local result
  stdnse.debug4("MSRPC: Entering marshall_srvsvc_NetShareInfo2()")
  local name          = marshall_ptr(location, marshall_unicode, {name,    true},   name)
  local sharetype     = marshall_basetype(location, marshall_srvsvc_ShareType, {sharetype})
  local comment       = marshall_ptr(location, marshall_unicode, {comment, true},   comment)
  local permissions   = marshall_basetype(location, marshall_int32, {permissions})
  local max_users     = marshall_basetype(location, marshall_int32, {max_users})
  local current_users = marshall_basetype(location, marshall_int32, {current_users})
  local path          = marshall_ptr(location, marshall_unicode, {path, true},      path)
  local password      = marshall_ptr(location, marshall_unicode, {password, true}, password)

  result =  name .. sharetype .. comment .. permissions .. max_users .. current_users .. path .. password

  stdnse.debug4("MSRPC: Leaving marshall_srvsvc_NetShareInfo2()")
  return result
end

---Unmarshall a NetShareInfo type 2, which is a name and a few other things. See the marshall
-- function for more information.
--
--@param location The part of the pointer wanted, either HEAD (for the data itself), BODY
--                (for nothing, since this isn't a pointer), or ALL (for the data). Generally, unless the
--                referent_id is split from the data (for example, in an array), you will want
--                ALL.
--@param data     The data packet.
--@param pos      The position within the data.
--@param result   This is required when unmarshalling the BODY section, which always comes after
--                unmarshalling the HEAD. It is the result returned for this parameter during the
--                HEAD unmarshall. If the referent_id was '0', then this function doesn't unmarshall
--                anything.
--@return (pos, result) The new position in <code>data</code>, and a table representing the datatype.
local function unmarshall_srvsvc_NetShareInfo2(location, data, pos, result)
  stdnse.debug4("MSRPC: Entering unmarshall_srvsvc_NetShareInfo2()")
  if(result == nil) then
    result = {}
  end

  if(location == HEAD or location == ALL) then
    pos, result['name']          = unmarshall_ptr(HEAD, data, pos, unmarshall_unicode, {true})
    pos, result['sharetype']     = unmarshall_srvsvc_ShareType(data, pos)
    pos, result['comment']       = unmarshall_ptr(HEAD, data, pos, unmarshall_unicode, {true})
    pos, result['permissions']   = unmarshall_int32(data, pos)
    pos, result['max_users']     = unmarshall_int32(data, pos)
    pos, result['current_users'] = unmarshall_int32(data, pos)
    pos, result['path']          = unmarshall_ptr(HEAD, data, pos, unmarshall_unicode, {true})
    pos, result['password']      = unmarshall_ptr(HEAD, data, pos, unmarshall_unicode, {true})
  end

  if(location == BODY or location == ALL) then
    pos, result['name']     = unmarshall_ptr(BODY, data, pos, unmarshall_unicode, {true}, result['name'])
    pos, result['comment']  = unmarshall_ptr(BODY, data, pos, unmarshall_unicode, {true}, result['comment'])
    pos, result['path']     = unmarshall_ptr(BODY, data, pos, unmarshall_unicode, {true}, result['path'])
    pos, result['password'] = unmarshall_ptr(BODY, data, pos, unmarshall_unicode, {true}, result['password'])
  end

  stdnse.debug4("MSRPC: Leaving unmarshall_srvsvc_NetShareInfo2()")
  return pos, result
end

---Marshall a NetShareCtr (container) type 0.
--
--It is a simple array with the following definition:
--
--<code>
--     typedef struct {
--        uint32 count;
--        [size_is(count)] srvsvc_NetShareInfo0 *array;
--    } srvsvc_NetShareCtr0;
--</code>
--
--@param NetShareCtr0 A table representing the structure.
--@return A string representing the marshalled data.
function marshall_srvsvc_NetShareCtr0(NetShareCtr0)
  local i
  local result = ""
  stdnse.debug4("MSRPC: Entering marshall_srvsvc_NetShareCtr0()")

  if(NetShareCtr0 == nil) then
    result = result .. bin.pack("<I", 0)
  else
    local array = NetShareCtr0['array']
    local marshall = nil

    if(array == nil) then
      result = result .. bin.pack("<I", 0)
    else
      result = result .. bin.pack("<I", #array) -- count

      -- Build the array that we can marshall
      marshall = {}
      for i = 1, #array, 1 do
        marshall[i] = {}
        marshall[i]['func'] = marshall_srvsvc_NetShareInfo0
        marshall[i]['args'] = {array[i]['name']}
      end
    end

    result = result .. marshall_ptr(ALL, marshall_array, {marshall}, marshall) -- array
  end

  stdnse.debug4("MSRPC: Leaving marshall_srvsvc_NetShareCtr0()")
  return result
end

---Unmarshall a NetShareCtr (container) type 0. See the marshall function for the definition.
--
--@param data The data packet.
--@param pos  The position within the data.
--@return (pos, result) The new position in <code>data</code>, and a table representing the datatype.
function unmarshall_srvsvc_NetShareCtr0(data, pos)
  local count
  local result = {}
  stdnse.debug4("MSRPC: Entering unmarshall_srvsvc_NetShareCtr0()")

  pos, count = unmarshall_int32(data, pos)

  pos, result['array'] = unmarshall_ptr(ALL, data, pos, unmarshall_array, {count, unmarshall_srvsvc_NetShareInfo0, {}})

  stdnse.debug4("MSRPC: Leaving unmarshall_srvsvc_NetShareCtr0()")
  return pos, result
end

---Marshall a NetShareCtr (container) type 1.
--
--It is a simple array with the following definition:
--
--<code>
--    typedef struct {
--        uint32 count;
--        [size_is(count)] srvsvc_NetShareInfo1 *array;
--    } srvsvc_NetShareCtr1;
--</code>
--
--@param NetShareCtr1 A table representing the structure.
--@return A string representing the marshalled data.
function marshall_srvsvc_NetShareCtr1(NetShareCtr1)
  local i
  local result = ""
  stdnse.debug4("MSRPC: Entering marshall_srvsvc_NetShareCtr1()")

  if(NetShareCtr1 == nil) then
    result = result .. bin.pack("<I", 0)
  else
    local array = NetShareCtr1['array']
    local marshall = nil

    if(array == nil) then
      result = result .. bin.pack("<I", 0)
    else
      result = result .. bin.pack("<I", #array) -- count

      -- Build the array that we can marshall
      marshall = {}
      for i = 1, #array, 1 do
        marshall[i] = {}
        marshall[i]['func'] = marshall_srvsvc_NetShareInfo1
        marshall[i]['args'] = {array[i]['name'], array[i]['sharetype'], array[i]['comment']}
      end
    end

    result = result .. marshall_ptr(ALL, marshall_array, {marshall}, marshall) -- array
  end

  stdnse.debug4("MSRPC: Leaving marshall_srvsvc_NetShareCtr1()")
  return result
end


---Marshall a NetShareCtr (container) type 2.
--
--It is a simple array with the following definition:
--
--<code>
--    typedef struct {
--        uint32 count;
--        [size_is(count)] srvsvc_NetShareInfo2 *array;
--    } srvsvc_NetShareCtr2;
--</code>
--
--@param NetShareCtr2 A pointer to the structure.
--@return A string representing the marshalled data.
function marshall_srvsvc_NetShareCtr2(NetShareCtr2)
  local i
  local result = ""
  stdnse.debug4("MSRPC: Entering marshall_srvsvc_NetShareCtr2()")

  if(NetShareCtr2 == nil) then
    result = result .. bin.pack("<I", 0)
  else
    local array = NetShareCtr2['array']
    local marshall = nil

    if(array == nil) then
      result = result .. bin.pack("<I", 0)
    else
      result = result .. bin.pack("<I", #array) -- count

      -- Build the array that we can marshall
      marshall = {}
      for i = 1, #array, 1 do
        marshall[i] = {}
        marshall[i]['func'] = marshall_srvsvc_NetShareInfo2
        marshall[i]['args'] = {array[i]['name'], array[i]['sharetype'], array[i]['comment'], array[i]['permissions'], array[i]['max_users'], array[i]['current_users'], array[i]['path'], array[i]['password']}
        marshall[i]['args'] = {array[i]['name']}
      end
    end

    result = result .. marshall_ptr(ALL, marshall_array, {marshall}, marshall) -- array
  end

  stdnse.debug4("MSRPC: Leaving marshall_srvsvc_NetShareCtr2()")
  return result
end

---Marshall the top-level NetShareCtr. This is a union of a bunch of different containers:
--
--<code>
--    typedef union {
--        [case(0)] srvsvc_NetShareCtr0 *ctr0;
--        [case(1)] srvsvc_NetShareCtr1 *ctr1;
--        [case(2)] srvsvc_NetShareCtr2 *ctr2;
--        [case(501)] srvsvc_NetShareCtr501 *ctr501;
--        [case(502)] srvsvc_NetShareCtr502 *ctr502;
--        [case(1004)] srvsvc_NetShareCtr1004 *ctr1004;
--        [case(1005)] srvsvc_NetShareCtr1005 *ctr1005;
--        [case(1006)] srvsvc_NetShareCtr1006 *ctr1006;
--        [case(1007)] srvsvc_NetShareCtr1007 *ctr1007;
--        [case(1501)] srvsvc_NetShareCtr1501 *ctr1501;
--        [default] ;
--    } srvsvc_NetShareCtr;
--</code>
--
-- Not all of them are implemented, however; look at the code to see which are implemented (at the
-- time of this writing, it's 0, 1, and 2).
--
--@param level The level to request. Different levels will return different results, but also require
--             different access levels to call.
--@param data  The data to populate the array with. Depending on the level, this data will be different.
--             For level 0, you'll probably want a table containing array=nil.
--@return A string representing the marshalled data, or 'nil' if it couldn't be marshalled.
function marshall_srvsvc_NetShareCtr(level, data)
  local result
  stdnse.debug4("MSRPC: Entering marshall_srvsvc_NetShareCtr()")

  if(level == 0) then
    result = bin.pack("<IA", level, marshall_ptr(ALL, marshall_srvsvc_NetShareCtr0, {data}, data))
  elseif(level == 1) then
    result = bin.pack("<IA", level, marshall_ptr(ALL, marshall_srvsvc_NetShareCtr1, {data}, data))
  elseif(level == 2) then
    result = bin.pack("<IA", level, marshall_ptr(ALL, marshall_srvsvc_NetShareCtr2, {data}, data))
  else
    stdnse.debug1("MSRPC: ERROR: Script requested an unknown level for srvsvc_NetShareCtr: %d", level)
    result = nil
  end

  stdnse.debug4("MSRPC: Leaving marshall_srvsvc_NetShareCtr()")
  return result
end

---Unmarshall the top-level NetShareCtr. This is a union of a bunch of containers, see the equivalent
-- marshall function for more information; at the time of this writing I've only implemented level = 0.
--
--@param data The data packet.
--@param pos  The position within the data.
--@return (pos, result) The new position in <code>data</code>, and a table representing the datatype.
--        The result may be <code>nil</code> if there's an error.
function unmarshall_srvsvc_NetShareCtr(data, pos)
  local level
  local result
  stdnse.debug4("MSRPC: Entering unmarshall_srv_NetShareCtr()")

  pos, level = unmarshall_int32(data, pos)

  if(level == 0) then
    pos, result = unmarshall_ptr(ALL, data, pos, unmarshall_srvsvc_NetShareCtr0, {})
  else
    stdnse.debug1("MSRPC: ERROR: Server returned an unknown level for srvsvc_NetShareCtr: %d", level)
    pos, result = nil, nil
  end

  stdnse.debug4("MSRPC: Leaving unmarshall_srv_NetShareCtr()")
  return pos, result
end

---Unmarshall the top-level NetShareInfo. This is a union of a bunch of different structs:
--
--<code>
--    typedef union {
--        [case(0)] srvsvc_NetShareInfo0 *info0;
--        [case(1)] srvsvc_NetShareInfo1 *info1;
--        [case(2)] srvsvc_NetShareInfo2 *info2;
--        [case(501)] srvsvc_NetShareInfo501 *info501;
--        [case(502)] srvsvc_NetShareInfo502 *info502;
--        [case(1004)] srvsvc_NetShareInfo1004 *info1004;
--        [case(1005)] srvsvc_NetShareInfo1005 *info1005;
--        [case(1006)] srvsvc_NetShareInfo1006 *info1006;
--        [case(1007)] srvsvc_NetShareInfo1007 *info1007;
--        [case(1501)] sec_desc_buf *info1501;
--        [default] ;
--    } srvsvc_NetShareInfo;
--</code>
--
-- Not all of them are implemented, however; look at the code to see which are implemented (at the
-- time of this writing, it's 0, 1, and 2).
--
--@param data     The data being processed.
--@param pos      The position within <code>data</code>.
--@return (pos, result) The new position in <code>data</code>, and a table representing the datatype. This may be
--                <code>nil</code> if there was an error.
function unmarshall_srvsvc_NetShareInfo(data, pos)
  local level
  local result
  stdnse.debug4("MSRPC: Entering unmarshall_srvsvc_NetShareInfo()")
  pos, level = unmarshall_int32(data, pos)

  if(level == 0) then
    pos, result = unmarshall_ptr(ALL, data, pos, unmarshall_struct, {unmarshall_srvsvc_NetShareInfo0, {}})
  elseif(level == 1) then
    pos, result = unmarshall_ptr(ALL, data, pos, unmarshall_struct, {unmarshall_srvsvc_NetShareInfo1, {}})
  elseif(level == 2) then
    pos, result = unmarshall_ptr(ALL, data, pos, unmarshall_struct, {unmarshall_srvsvc_NetShareInfo2, {}})
  else
    stdnse.debug1("MSRPC: ERROR: Invalid level returned by NetShareInfo: %d\n", level)
    pos, result = nil, nil
  end

  stdnse.debug4("MSRPC: Leaving unmarshall_srvsvc_NetShareInfo()")
  return pos, result
end

---Marshall a NetSessInfo type 10.
--
--<code>
--    typedef struct {
--        [string,charset(UTF16)] uint16 *client;
--        [string,charset(UTF16)] uint16 *user;
--        uint32 time;
--        uint32 idle_time;
--    } srvsvc_NetSessInfo10;
--</code>
--
--@param location  The part of the pointer wanted, either HEAD (for the data itself), BODY
--                 (for nothing, since this isn't a pointer), or ALL (for the data). Generally, unless the
--                 referent_id is split from the data (for example, in an array), you will want
--                 ALL.
--@param client    The client string.
--@param user      The user string.
--@param time      The number of seconds that the user has been logged on.
--@param idle_time The number of seconds that the user's been idle.
--@return A string representing the marshalled data.
local function marshall_srvsvc_NetSessInfo10(location, client, user, time, idle_time)
  local result
  stdnse.debug4("MSRPC: Entering marshall_srvsvc_NetShareInfo10()")
  local client    = marshall_ptr(location, marshall_unicode, {client, true}, client)
  local user      = marshall_ptr(location, marshall_unicode, {user, true}, user)
  local time      = marshall_basetype(location, marshall_int32, {time})
  local idle_time = marshall_basetype(location, marshall_int32, {idle_time})

  result = bin.pack("<AAAA", client, user, time, idle_time)

  stdnse.debug4("MSRPC: Leaving marshall_srvsvc_NetShareInfo10()")
  return result
end

---Unmarshall a NetSessInfo type 10. For more information, see the marshall function.
--
--@param location  The part of the pointer wanted, either HEAD (for the data itself), BODY
--                 (for nothing, since this isn't a pointer), or ALL (for the data). Generally, unless the
--                 referent_id is split from the data (for example, in an array), you will want
--                 ALL.
--@param data   The data packet.
--@param pos    The position within the data.
--@param result   This is required when unmarshalling the BODY section, which always comes after
--                unmarshalling the HEAD. It is the result returned for this parameter during the
--                HEAD unmarshall. If the referent_id was '0', then this function doesn't unmarshall
--                anything.
--@return (pos, result) The new position in <code>data</code>, and a table representing the datatype.
local function unmarshall_srvsvc_NetSessInfo10(location, data, pos, result)
  stdnse.debug4("MSRPC: Entering unmarshall_srvsvc_NetSessInfo10()")
  if(result == nil) then
    result = {}
  end

  if(location == HEAD or location == ALL) then
    pos, result['client']    = unmarshall_ptr(HEAD, data, pos, unmarshall_unicode, {true})
    pos, result['user']      = unmarshall_ptr(HEAD, data, pos, unmarshall_unicode, {true})
    pos, result['time']      = unmarshall_int32(data, pos)
    pos, result['idle_time'] = unmarshall_int32(data, pos)
  end

  if(location == BODY or location == ALL) then
    pos, result['client'] = unmarshall_ptr(BODY, data, pos, unmarshall_unicode, {true}, result['client'])
    pos, result['user']   = unmarshall_ptr(BODY, data, pos, unmarshall_unicode, {true}, result['user'])
  end

  stdnse.debug4("MSRPC: Leaving unmarshall_srvsvc_NetSessInfo10()")
  return pos, result
end

---Marshall a NetSessCtr (session container) type 10.
--
--It is a simple array with the following definition:
--
--<code>
--    typedef struct {
--        uint32 count;
--        [size_is(count)] srvsvc_NetSessInfo10 *array;
--    } srvsvc_NetSessCtr10;
--</code>
--
--@param NetSessCtr10 A table representing the structure.
--@return A string representing the marshalled data.
function marshall_srvsvc_NetSessCtr10(NetSessCtr10)
  local i
  local result = ""
  stdnse.debug4("MSRPC: Entering marshall_srvsvc_NetSessCtr10()")

  if(NetSessCtr10 == nil) then
    result = result .. bin.pack("<I", 0)
  else
    local array = NetSessCtr10['array']
    local marshall = nil

    if(array == nil) then
      result = result .. bin.pack("<I", 0)
    else
      result = result .. bin.pack("<I", #array) -- count

      -- Build the array that we can marshall
      marshall = {}
      for i = 1, #array, 1 do
        marshall[i] = {}
        marshall[i]['func'] = marshall_srvsvc_NetSessInfo10
        marshall[i]['args'] = {array[i]['client'], array[i]['user'], array[i]['time'], array[i]['idle_time']}
      end
    end

    result = result .. marshall_ptr(ALL, marshall_array, {marshall}, marshall) -- array
  end

  stdnse.debug4("MSRPC: Leaving marshall_srvsvc_NetSessCtr10()")
  return result
end

---Unmarshall a NetSessCtr (session container) type 10. See the marshall function for the definition.
--
--@param data The data packet.
--@param pos  The position within the data.
--@return (pos, result) The new position in <code>data</code>, and a table representing the datatype.
function unmarshall_srvsvc_NetSessCtr10(data, pos)
  local count
  local result = {}
  stdnse.debug4("MSRPC: Entering unmarshall_srvsvc_NetSessCtr10()")

  pos, count = unmarshall_int32(data, pos)

  pos, result['array'] = unmarshall_ptr(ALL, data, pos, unmarshall_array, {count, unmarshall_srvsvc_NetSessInfo10, {}})

  stdnse.debug4("MSRPC: Leaving unmarshall_srvsvc_NetSessCtr10()")
  return pos, result
end

---Marshall the top-level NetShareCtr. This is a union of a bunch of different containers:
--
--<code>
--    typedef union {
--        [case(0)] srvsvc_NetSessCtr0 *ctr0;
--        [case(1)] srvsvc_NetSessCtr1 *ctr1;
--        [case(2)] srvsvc_NetSessCtr2 *ctr2;
--        [case(10)] srvsvc_NetSessCtr10 *ctr10;
--        [case(502)] srvsvc_NetSessCtr502 *ctr502;
--        [default] ;
--    } srvsvc_NetSessCtr;
--</code>
--
-- Not all of them are implemented, however; look at the code to see which are implemented (at the
-- time of this writing, it's just 10).
--
--@param level The level to request. Different levels will return different results, but also require
--             different access levels to call.
--@param data  The data to populate the array with. Depending on the level, this data will be different.
--@return A string representing the marshalled data.
function marshall_srvsvc_NetSessCtr(level, data)
  local result
  stdnse.debug4("MSRPC: Entering marshall_srvsvc_NetShareCtr()")

  if(level == 10) then
    result = bin.pack("<IA", level, marshall_ptr(ALL, marshall_srvsvc_NetSessCtr10, {data}, data))
  else
    stdnse.debug1("MSRPC: ERROR: Script requested an unknown level for srvsvc_NetSessCtr")
    result = nil
  end

  stdnse.debug4("MSRPC: Leaving marshall_srvsvc_NetShareCtr()")
  return result
end

---Unmarshall the top-level NetShareCtr. This is a union; see the marshall function for more information.
--
--@param data     The data being processed.
--@param pos      The position within <code>data</code>
--@return (pos, result) The new position in <code>data</code>, and a table representing the datatype. Can be
--                <code>nil</code> if there's an error.
function unmarshall_srvsvc_NetSessCtr(data, pos)
  local level
  local result
  stdnse.debug4("MSRPC: Entering unmarshall_srvsvc_NetSessCtr()")

  pos, level = bin.unpack("<I", data, pos)

  if(level == 10) then
    pos, result = unmarshall_ptr(ALL, data, pos, unmarshall_srvsvc_NetSessCtr10, {})
  else
    stdnse.debug1("MSRPC: ERROR: Invalid level returned by NetSessCtr: %d\n", level)
    pos, result = nil, nil
  end

  stdnse.debug4("MSRPC: Leaving unmarshall_srvsvc_NetSessCtr()")
  return pos, result
end


---Unmarshall a <code>srvsvc_Statistics</code> packet. This is basically a great big struct:
--
--<code>
--    typedef struct {
--        uint32 start;
--        uint32 fopens;
--        uint32 devopens;
--        uint32 jobsqueued;
--        uint32 sopens;
--        uint32 stimeouts;
--        uint32 serrorout;
--        uint32 pwerrors;
--        uint32 permerrors;
--        uint32 syserrors;
--        uint32 bytessent_low;
--        uint32 bytessent_high;
--        uint32 bytesrcvd_low;
--        uint32 bytesrcvd_high;
--        uint32 avresponse;
--        uint32 reqbufneed;
--        uint32 bigbufneed;
--    } srvsvc_Statistics;
--</code>
--
-- Note that Wireshark (at least, the version I'm using, 1.0.3) gets this wrong, so be careful.
--
--@param data     The data being processed.
--@param pos      The position within <code>data</code>
--@return (pos, result) The new position in <code>data</code>, and a table representing the datatype.
function unmarshall_srvsvc_Statistics(data, pos)
  local response = {}
  stdnse.debug4("MSRPC: Entering unmarshall_srvsvc_Statistics()")

  pos, response['start']          = unmarshall_int32(data, pos)
  pos, response['fopens']         = unmarshall_int32(data, pos)
  pos, response['devopens']       = unmarshall_int32(data, pos)
  pos, response['jobsqueued']     = unmarshall_int32(data, pos)
  pos, response['sopens']         = unmarshall_int32(data, pos)
  pos, response['stimeouts']      = unmarshall_int32(data, pos)
  pos, response['serrorout']      = unmarshall_int32(data, pos)
  pos, response['pwerrors']       = unmarshall_int32(data, pos)
  pos, response['permerrors']     = unmarshall_int32(data, pos)
  pos, response['syserrors']      = unmarshall_int32(data, pos)
  pos, response['bytessent_low']  = unmarshall_int32(data, pos)
  pos, response['bytessent_high'] = unmarshall_int32(data, pos)
  pos, response['bytesrcvd_low']  = unmarshall_int32(data, pos)
  pos, response['bytesrcvd_high'] = unmarshall_int32(data, pos)
  pos, response['avresponse']     = unmarshall_int32(data, pos)
  pos, response['reqbufneed']     = unmarshall_int32(data, pos)
  pos, response['bigbufneed']     = unmarshall_int32(data, pos)

  stdnse.debug4("MSRPC: Leaving unmarshall_srvsvc_Statistics()")
  return pos, response
end

---Unmarshalls a <code>srvsvc_Statistics</code> as a pointer. Wireshark fails to do this, and ends
-- up parsing the packet wrong, so take care when packetlogging.
--
-- See <code>unmarshall_srvsvc_Statistics</code> for more information.
--
--@param data     The data being processed.
--@param pos      The position within <code>data</code>
--@return (pos, result) The new position in <code>data</code>, and a table representing the datatype.
function unmarshall_srvsvc_Statistics_ptr(data, pos)
  local result
  stdnse.debug4("MSRPC: Entering unmarshall_srvsvc_Statistics_ptr()")

  pos, result = unmarshall_ptr(ALL, data, pos, unmarshall_srvsvc_Statistics, {})

  stdnse.debug4("MSRPC: Leaving unmarshall_srvsvc_Statistics_ptr()")
  return pos, result
end



----------------------------------
--       SAMR
-- (dependencies: MISC, LSA, SECURITY)
----------------------------------

local samr_ConnectAccessMask =
{
  SAMR_ACCESS_CONNECT_TO_SERVER   = 0x00000001,
  SAMR_ACCESS_SHUTDOWN_SERVER     = 0x00000002,
  SAMR_ACCESS_INITIALIZE_SERVER   = 0x00000004,
  SAMR_ACCESS_CREATE_DOMAIN       = 0x00000008,
  SAMR_ACCESS_ENUM_DOMAINS        = 0x00000010,
  SAMR_ACCESS_OPEN_DOMAIN         = 0x00000020
}
local samr_ConnectAccessMask_str =
{
  SAMR_ACCESS_CONNECT_TO_SERVER   = "Connect to server",
  SAMR_ACCESS_SHUTDOWN_SERVER     = "Shutdown server",
  SAMR_ACCESS_INITIALIZE_SERVER   = "Initialize server",
  SAMR_ACCESS_CREATE_DOMAIN       = "Create domain",
  SAMR_ACCESS_ENUM_DOMAINS        = "Enum domains",
  SAMR_ACCESS_OPEN_DOMAIN         = "Open domain"
}

---Marshall a <code>samr_ConnectAccessMask</code>. This datatype is tied to the table above with that
-- name.
--
--@param accessmask The value to marshall, as a string
--@return The marshalled integer representing the given value, or <code>nil</code> if it wasn't
--        found.
function marshall_samr_ConnectAccessMask(accessmask)
  local result
  stdnse.debug4("MSRPC: Entering marshall_samr_ConnectAccessMask()")

  result = marshall_Enum32(accessmask, samr_ConnectAccessMask)

  stdnse.debug4("MSRPC: Leaving marshall_samr_ConnectAccessMask()")
  return result
end

---Unmarshall a <code>samr_ConnectAccessMask</code>. This datatype is tied to the table with that name.
--
--@param data The data packet.
--@param pos  The position within the data.
--@return (pos, result) The new position in <code>data</code>, and a table representing the datatype.
function unmarshall_samr_ConnectAccessMask(data, pos)
  local result
  stdnse.debug4("MSRPC: Entering unmarshall_samr_ConnectAccessMask()")

  pos, result = unmarshall_Enum32(data, pos, samr_ConnectAccessMask)

  stdnse.debug4("MSRPC: Leaving unmarshall_samr_ConnectAccessMask()")
  return pos, result
end

---Convert a <code>samr_ConnectAccessMask</code> value to a string that can be shown to the user. This is
-- based on the <code>_str</code> table.
--
--@param val The string value (returned by the <code>unmarshall_</code> function) to convert.
--@return A string suitable for displaying to the user, or <code>nil</code> if it wasn't found.
function samr_ConnectAccessMask_tostr(val)
  local result
  stdnse.debug4("MSRPC: Entering samr_ConnectAccessMask_tostr()")

  result = samr_ConnectAccessMask_str[val]

  stdnse.debug4("MSRPC: Leaving samr_ConnectAccessMask_tostr()")
  return result
end

local samr_DomainAccessMask =
{
  DOMAIN_ACCESS_LOOKUP_INFO_1  = 0x00000001,
  DOMAIN_ACCESS_SET_INFO_1     = 0x00000002,
  DOMAIN_ACCESS_LOOKUP_INFO_2  = 0x00000004,
  DOMAIN_ACCESS_SET_INFO_2     = 0x00000008,
  DOMAIN_ACCESS_CREATE_USER    = 0x00000010,
  DOMAIN_ACCESS_CREATE_GROUP   = 0x00000020,
  DOMAIN_ACCESS_CREATE_ALIAS   = 0x00000040,
  DOMAIN_ACCESS_LOOKUP_ALIAS   = 0x00000080,
  DOMAIN_ACCESS_ENUM_ACCOUNTS  = 0x00000100,
  DOMAIN_ACCESS_OPEN_ACCOUNT   = 0x00000200,
  DOMAIN_ACCESS_SET_INFO_3     = 0x00000400
}
local samr_DomainAccessMask_str =
{
  DOMAIN_ACCESS_LOOKUP_INFO_1  = "Lookup info (1)",
  DOMAIN_ACCESS_SET_INFO_1     = "Set info (1)",
  DOMAIN_ACCESS_LOOKUP_INFO_2  = "Lookup info (2)",
  DOMAIN_ACCESS_SET_INFO_2     = "Set info (2)",
  DOMAIN_ACCESS_CREATE_USER    = "Create user",
  DOMAIN_ACCESS_CREATE_GROUP   = "Create group",
  DOMAIN_ACCESS_CREATE_ALIAS   = "Create alias",
  DOMAIN_ACCESS_LOOKUP_ALIAS   = "Lookup alias",
  DOMAIN_ACCESS_ENUM_ACCOUNTS  = "Enum accounts",
  DOMAIN_ACCESS_OPEN_ACCOUNT   = "Open account",
  DOMAIN_ACCESS_SET_INFO_3     = "Set info (3)"
}

---Marshall a <code>samr_DomainAccessMask</code>. This datatype is tied to the table above with that
-- name.
--
--@param accessmask The value to marshall, as a string
--@return The marshalled integer representing the given value, or <code>nil</code> if it wasn't
--        found.
function marshall_samr_DomainAccessMask(accessmask)
  local result
  stdnse.debug4("MSRPC: Entering marshall_samr_DomainAccessMask()")

  result = marshall_Enum32(accessmask, samr_DomainAccessMask)

  stdnse.debug4("MSRPC: Leaving marshall_samr_DomainAccessMask()")
  return result
end

---Unmarshall a <code>samr_DomainAccessMask</code>. This datatype is tied to the table with that name.
--
--@param data The data packet.
--@param pos  The position within the data.
--@return (pos, result) The new position in <code>data</code>, and a table representing the datatype.
function unmarshall_samr_DomainAccessMask(data, pos)
  local result
  stdnse.debug4("MSRPC: Entering unmarshall_samr_DomainAccessMask()")

  pos, result = unmarshall_Enum32(data, pos, samr_DomainAccessMask)

  stdnse.debug4("MSRPC: Leaving unmarshall_samr_DomainAccessMask()")
  return pos, result
end

---Convert a <code>samr_DomainAccessMask</code> value to a string that can be shown to the user. This is
-- based on the <code>_str</code> table.
--
--@param val The string value (returned by the <code>unmarshall_</code> function) to convert.
--@return A string suitable for displaying to the user, or <code>nil</code> if it wasn't found.
function samr_DomainAccessMask_tostr(val)
  local result
  stdnse.debug4("MSRPC: Entering samr_DomainAccessMask_tostr()")

  result = samr_DomainAccessMask_str[val]

  stdnse.debug4("MSRPC: Leaving samr_DomainAccessMask_tostr()")
  return result
end

local samr_AcctFlags =
{
  ACB_NONE                    = 0x0000000,
  ACB_DISABLED                = 0x00000001,  -- User account disabled
  ACB_HOMDIRREQ               = 0x00000002,  -- Home directory required
  ACB_PWNOTREQ                = 0x00000004,  -- User password not required
  ACB_TEMPDUP                 = 0x00000008,  -- Temporary duplicate account
  ACB_NORMAL                  = 0x00000010,  -- Normal user account
  ACB_MNS                     = 0x00000020,  -- MNS logon user account
  ACB_DOMTRUST                = 0x00000040,  -- Interdomain trust account
  ACB_WSTRUST                 = 0x00000080,  -- Workstation trust account
  ACB_SVRTRUST                = 0x00000100,  -- Server trust account
  ACB_PWNOEXP                 = 0x00000200,  -- User password does not expire
  ACB_AUTOLOCK                = 0x00000400,  -- Account auto locked
  ACB_ENC_TXT_PWD_ALLOWED     = 0x00000800,  -- Encryped text password is allowed
  ACB_SMARTCARD_REQUIRED      = 0x00001000,  -- Smart Card required
  ACB_TRUSTED_FOR_DELEGATION  = 0x00002000,  -- Trusted for Delegation
  ACB_NOT_DELEGATED           = 0x00004000,  -- Not delegated
  ACB_USE_DES_KEY_ONLY        = 0x00008000,  -- Use DES key only
  ACB_DONT_REQUIRE_PREAUTH    = 0x00010000,  -- Preauth not required
  ACB_PW_EXPIRED              = 0x00020000,  -- Password Expired
  ACB_NO_AUTH_DATA_REQD       = 0x00080000   -- No authorization data required
}
local samr_AcctFlags_str =
{
  ACB_NONE                    = "n/a",
  ACB_DISABLED                = "Account disabled",
  ACB_HOMDIRREQ               = "Home directory required",
  ACB_PWNOTREQ                = "Password not required",
  ACB_TEMPDUP                 = "Temporary duplicate account",
  ACB_NORMAL                  = "Normal user account",
  ACB_MNS                     = "MNS logon user account",
  ACB_DOMTRUST                = "Interdomain trust account",
  ACB_WSTRUST                 = "Workstation trust account",
  ACB_SVRTRUST                = "Server trust account",
  ACB_PWNOEXP                 = "Password does not expire",
  ACB_AUTOLOCK                = "Auto locked",
  ACB_ENC_TXT_PWD_ALLOWED     = "Encryped text password is allowed",
  ACB_SMARTCARD_REQUIRED      = "Smart Card required",
  ACB_TRUSTED_FOR_DELEGATION  = "Trusted for Delegation",
  ACB_NOT_DELEGATED           = "Not delegated",
  ACB_USE_DES_KEY_ONLY        = "Use DES key only",
  ACB_DONT_REQUIRE_PREAUTH    = "Preauth not required",
  ACB_PW_EXPIRED              = "Password Expired",
  ACB_NO_AUTH_DATA_REQD       = "No authorization data required"
}

---Marshall a <code>samr_AcctFlags</code>. This datatype is tied to the table above with that
-- name.
--
--@param flags The value to marshall, as a string
--@return The marshalled integer representing the given value, or <code>nil</code> if it wasn't
--        found.
function marshall_samr_AcctFlags(flags)
  local result
  stdnse.debug4("MSRPC: Entering marshall_samr_AcctFlags()")

  result = marshall_Enum32(flags, samr_AcctFlags)

  stdnse.debug4("MSRPC: Leaving marshall_samr_AcctFlags()")
  return result
end

---Unmarshall a <code>samr_AcctFlags</code>. This datatype is tied to the table with that name.
--
--@param data The data packet.
--@param pos  The position within the data.
--@return (pos, str) The new position, and the string representing the datatype.
function unmarshall_samr_AcctFlags(data, pos)
  local str
  stdnse.debug4("MSRPC: Entering unmarshall_samr_AcctFlags()")

  pos, str = unmarshall_Enum32_array(data, pos, samr_AcctFlags)

  stdnse.debug4("MSRPC: Leaving unmarshall_samr_AcctFlags()")
  return pos, str
end

---Convert a <code>samr_AcctFlags</code> value to a string that can be shown to the user. This is
-- based on the <code>_str</code> table.
--
--@param val The string value (returned by the <code>unmarshall_</code> function) to convert.
--@return A string suitable for displaying to the user, or <code>nil</code> if it wasn't found.
function samr_AcctFlags_tostr(val)
  local result
  stdnse.debug4("MSRPC: Entering samr_AcctFlags_tostr()")

  result = samr_AcctFlags_str[val]

  stdnse.debug4("MSRPC: Leaving samr_AcctFlags_tostr()")
  return result
end

local samr_PasswordProperties =
{
  DOMAIN_PASSWORD_COMPLEX         = 0x00000001,
  DOMAIN_PASSWORD_NO_ANON_CHANGE  = 0x00000002,
  DOMAIN_PASSWORD_NO_CLEAR_CHANGE = 0x00000004,
  DOMAIN_PASSWORD_LOCKOUT_ADMINS  = 0x00000008,
  DOMAIN_PASSWORD_STORE_CLEARTEXT = 0x00000010,
  DOMAIN_REFUSE_PASSWORD_CHANGE   = 0x00000020
}
local samr_PasswordProperties_str =
{
  DOMAIN_PASSWORD_COMPLEX         = "Complexity requirements exist",
  DOMAIN_PASSWORD_NO_ANON_CHANGE  = "Must be logged in to change password",
  DOMAIN_PASSWORD_NO_CLEAR_CHANGE = "Cannot change passwords in cleartext",
  DOMAIN_PASSWORD_LOCKOUT_ADMINS  = "Admin account can be locked out",
  DOMAIN_PASSWORD_STORE_CLEARTEXT = "Cleartext passwords can be stored",
  DOMAIN_REFUSE_PASSWORD_CHANGE   = "Passwords cannot be changed"
}

---Marshall a <code>samr_PasswordProperties</code>. This datatype is tied to the table above with that
-- name.
--
--@param properties The value to marshall, as a string
--@return The marshalled integer representing the given value, or <code>nil</code> if it wasn't
--        found.
function marshall_samr_PasswordProperties(properties)
  local result
  stdnse.debug4("MSRPC: Entering marshall_samr_PasswordProperties()")

  result = marshall_Enum32(properties, samr_PasswordProperties)

  stdnse.debug4("MSRPC: Leaving marshall_samr_PasswordProperties()")
  return result
end

---Unmarshall a <code>samr_PasswordProperties</code>. This datatype is tied to the table with that name.
--
--@param data The data packet.
--@param pos  The position within the data.
--@return (pos, str) The new position, and the string representing the datatype.
function unmarshall_samr_PasswordProperties(data, pos)
  local str
  stdnse.debug4("MSRPC: Entering unmarshall_samr_PasswordProperties()")

  pos, str = unmarshall_Enum32_array(data, pos, samr_PasswordProperties)

  stdnse.debug4("MSRPC: Leaving unmarshall_samr_PasswordProperties()")
  return pos, str
end

---Convert a <code>samr_PasswordProperties</code> value to a string that can be shown to the user. This is
-- based on the <code>_str</code> table.
--
--@param val The string value (returned by the <code>unmarshall_</code> function) to convert.
--@return A string suitable for displaying to the user, or <code>nil</code> if it wasn't found.
function samr_PasswordProperties_tostr(val)
  local result
  stdnse.debug4("MSRPC: Entering samr_PasswordProperties_tostr()")

  result = samr_PasswordProperties_str[val]

  stdnse.debug4("MSRPC: Leaving samr_PasswordProperties_tostr()")
  return result
end


---Unmarshall a samr_SamEntry struct
--
--<code>
--    typedef struct {
--        uint32 idx;
--        lsa_String name;
--    } samr_SamEntry;
--</code>
--
--@param location The part of the pointer wanted, either HEAD (for the data itself), BODY
--                (for nothing, since this isn't a pointer), or ALL (for the data). Generally, unless the
--                referent_id is split from the data (for example, in an array), you will want
--                ALL.
--@param data     The data being processed.
--@param pos      The position within <code>data</code>.
--@param result   This is required when unmarshalling the BODY section, which always comes after
--                unmarshalling the HEAD. It is the result returned for this parameter during the
--                HEAD unmarshall. If the referent_id was '0', then this function doesn't unmarshall
--                anything.
--@return (pos, result) The new position in <code>data</code>, and a table representing the datatype.
local function unmarshall_samr_SamEntry(location, data, pos, result)
  stdnse.debug4("MSRPC: Entering unmarshall_samr_SamEntry()")
  if(result == nil) then
    result = {}
  end

  if(location == HEAD or location == ALL) then
    pos, result['idx']       = unmarshall_int32(data, pos)
    pos, result['name']      = unmarshall_lsa_String_internal(HEAD, data, pos)
  end


  if(location == BODY or location == ALL) then
    pos, result['name']      = unmarshall_lsa_String_internal(BODY, data, pos, result['name'])
  end

  stdnse.debug4("MSRPC: Leaving unmarshall_samr_SamEntry()")
  return pos, result
end

---Unmarshall a samr_SamArray struct
--
--<code>
--    typedef struct {
--        uint32 count;
--        [size_is(count)] samr_SamEntry *entries;
--    } samr_SamArray;
--</code>
--
--@param data     The data being processed.
--@param pos      The position within <code>data</code>.
--@return (pos, result) The new position in <code>data</code>, and a table representing the datatype.
function unmarshall_samr_SamArray(data, pos)
  local result = {}
  stdnse.debug4("MSRPC: Entering unmarshall_samr_SamArray()")

  pos, result['count']   = unmarshall_int32(data, pos)
  pos, result['entries'] = unmarshall_ptr(ALL, data, pos, unmarshall_array, {result['count'], unmarshall_samr_SamEntry, {}})

  stdnse.debug4("MSRPC: Leaving unmarshall_samr_SamArray()")
  return pos, result
end

---Unmarshall a pointer to a <code>samr_SamArray</code> type. See <code>unmarshall_samr_SamArray</code> for
-- more information.
--
--@param data     The data being processed.
--@param pos      The position within <code>data</code>.
--@return (pos, result) The new position in <code>data</code>, and a table representing the datatype.
function unmarshall_samr_SamArray_ptr(data, pos)
  local result
  stdnse.debug4("MSRPC: Entering unmarshall_samr_SamArray_ptr()")

  pos, result = unmarshall_ptr(ALL, data, pos, unmarshall_samr_SamArray, {})

  stdnse.debug4("MSRPC: Leaving unmarshall_samr_SamArray_ptr()")
  return pos, result
end

---Unmarshall a samr_DispEntryGeneral struct
--
--<code>
--    typedef struct {
--        uint32    idx;
--        uint32    rid;
--        samr_AcctFlags acct_flags;
--        lsa_String account_name;
--        lsa_String description;
--        lsa_String full_name;
--    } samr_DispEntryGeneral;
--</code>
--
--@param location The part of the pointer wanted, either HEAD (for the data itself), BODY
--                (for nothing, since this isn't a pointer), or ALL (for the data). Generally, unless the
--                referent_id is split from the data (for example, in an array), you will want
--                ALL.
--@param data     The data being processed.
--@param pos      The position within <code>data</code>.
--@param result   This is required when unmarshalling the BODY section, which always comes after
--                unmarshalling the HEAD. It is the result returned for this parameter during the
--                HEAD unmarshall. If the referent_id was '0', then this function doesn't unmarshall
--                anything.
--@return (pos, result) The new position in <code>data</code>, and a table representing the datatype.
local function unmarshall_samr_DispEntryGeneral(location, data, pos, result)
  stdnse.debug4("MSRPC: Entering unmarshall_samr_DispEntryGeneral()")
  if(result == nil) then
    result = {}
  end

  if(location == HEAD or location == ALL) then
    pos, result['idx']          = unmarshall_int32(data, pos)
    pos, result['rid']          = unmarshall_int32(data, pos)
    pos, result['acct_flags']   = unmarshall_samr_AcctFlags(data, pos)
    pos, result['account_name'] = unmarshall_lsa_String_internal(HEAD, data, pos)
    pos, result['description']  = unmarshall_lsa_String_internal(HEAD, data, pos)
    pos, result['full_name']    = unmarshall_lsa_String_internal(HEAD, data, pos)
  end


  if(location == BODY or location == ALL) then
    pos, result['account_name'] = unmarshall_lsa_String_internal(BODY, data, pos, result['account_name'])
    pos, result['description']  = unmarshall_lsa_String_internal(BODY, data, pos, result['description'])
    pos, result['full_name']    = unmarshall_lsa_String_internal(BODY, data, pos, result['full_name'])
  end

  stdnse.debug4("MSRPC: Leaving unmarshall_samr_DispEntryGeneral()")
  return pos, result
end

---Unmarshall a samr_DispInfoGeneral struct
--
--<code>
--    typedef struct {
--        uint32 count;
--        [size_is(count)] samr_DispEntryGeneral *entries;
--    } samr_DispInfoGeneral;
--</code>
--
--@param data     The data being processed.
--@param pos      The position within <code>data</code>.
--@return (pos, result) The new position in <code>data</code>, and a table representing the datatype.
function unmarshall_samr_DispInfoGeneral(data, pos)
  local result = {}
  stdnse.debug4("MSRPC: Entering unmarshall_samr_DispInfoGeneral()")

  pos, result['count']   = unmarshall_int32(data, pos)
  pos, result['entries'] = unmarshall_ptr(ALL, data, pos, unmarshall_array, {result['count'], unmarshall_samr_DispEntryGeneral, {}})

  stdnse.debug4("MSRPC: Leaving unmarshall_samr_DispInfoGeneral()")
  return pos, result
end


---Unmarshall a samr_DispInfo struct
--
--<code>
--    typedef [switch_type(uint16)] union {
--        [case(1)] samr_DispInfoGeneral info1;/* users */
--        [case(2)] samr_DispInfoFull info2; /* trust accounts? */
--        [case(3)] samr_DispInfoFullGroups info3; /* groups */
--        [case(4)] samr_DispInfoAscii info4; /* users */
--        [case(5)] samr_DispInfoAscii info5; /* groups */
--    } samr_DispInfo;
--</code>
--
--@param data     The data being processed.
--@param pos      The position within <code>data</code>.
--@return (pos, result) The new position in <code>data</code>, and a table representing the datatype. It may also return
--                <code>nil</code>, if there was an error.
function unmarshall_samr_DispInfo(data, pos)
  local level
  local result
  stdnse.debug4("MSRPC: Entering unmarshall_samr_DispInfo()")

  pos, level = unmarshall_int16(data, pos)

  if(level == 1) then
    pos, result = unmarshall_samr_DispInfoGeneral(data, pos)
  else
    stdnse.debug1("MSRPC: ERROR: Server returned an unknown level for samr_DispInfo: %d", level)
    pos, result = nil, nil
  end

  stdnse.debug4("MSRPC: Leaving unmarshall_samr_DispInfo()")
  return pos, result
end

---Unmarshall a samr_DomInfo1 struct
--
--<code>
--  typedef struct {
--    uint16 min_password_length;
--    uint16 password_history_length;
--    samr_PasswordProperties password_properties;
--    /* yes, these are signed. They are in negative 100ns */
--    dlong  max_password_age;
--    dlong  min_password_age;
--  } samr_DomInfo1;
--</code>
--
--@param data     The data being processed.
--@param pos      The position within <code>data</code>.
--@return (pos, result) The new position in <code>data</code>, and a table representing the datatype.
function unmarshall_samr_DomInfo1(data, pos)
  local result = {}
  stdnse.debug4("MSRPC: Entering unmarshall_samr_DomInfo1()")

  pos, result['min_password_length']     = unmarshall_int16(data, pos, false)
  pos, result['password_history_length'] = unmarshall_int16(data, pos, false)
  pos, result['password_properties']     = unmarshall_samr_PasswordProperties(data, pos)
  pos, result['max_password_age']        = unmarshall_hyper(data, pos)
  pos, result['min_password_age']        = unmarshall_hyper(data, pos)

  stdnse.debug4("MSRPC: Leaving unmarshall_samr_DomInfo1()")
  return pos, result
end

---Unmarshall a samr_DomInfo8 struct
--
--<code>
--  typedef struct {
--    hyper sequence_num;
--    NTTIME domain_create_time;
--  } samr_DomInfo8;
--</code>
--
--@param data     The data being processed.
--@param pos      The position within <code>data</code>.
--@return (pos, result) The new position in <code>data</code>, and a table representing the datatype.
function unmarshall_samr_DomInfo8(data, pos)
  local result = {}
  stdnse.debug4("MSRPC: Entering unmarshall_samr_DomInfo8()")

  pos, result['sequence_num']       = unmarshall_hyper(data, pos)
  pos, result['domain_create_time'] = unmarshall_NTTIME(data, pos)

  stdnse.debug4("MSRPC: Leaving unmarshall_samr_DomInfo8()")
  return pos, result
end

---Unmarshall a samr_DomInfo12 struct
--
--<code>
--  typedef struct {
--    hyper lockout_duration;
--    hyper lockout_window;
--    uint16 lockout_threshold;
--  } samr_DomInfo12;
--</code>
--
--@param data     The data being processed.
--@param pos      The position within <code>data</code>.
--@return (pos, result) The new position in <code>data</code>, and a table representing the datatype.
function unmarshall_samr_DomInfo12(data, pos)
  local result = {}
  stdnse.debug4("MSRPC: Entering unmarshall_samr_DomInfo12()")

  pos, result['lockout_duration']  = unmarshall_hyper(data, pos)
  pos, result['lockout_window']    = unmarshall_hyper(data, pos)
  pos, result['lockout_threshold'] = unmarshall_int16(data, pos)

  stdnse.debug4("MSRPC: Leaving unmarshall_samr_DomInfo12()")
  return pos, result
end

---Unmarshall a samr_DomainInfo union
--
--<code>
--  typedef [switch_type(uint16)] union {
--    [case(1)] samr_DomInfo1 info1;
--    [case(2)] samr_DomInfo2 info2;
--    [case(3)] samr_DomInfo3 info3;
--    [case(4)] samr_DomInfo4 info4;
--    [case(5)] samr_DomInfo5 info5;
--    [case(6)] samr_DomInfo6 info6;
--    [case(7)] samr_DomInfo7 info7;
--    [case(8)] samr_DomInfo8 info8;
--    [case(9)] samr_DomInfo9 info9;
--    [case(11)] samr_DomInfo11 info11;
--    [case(12)] samr_DomInfo12 info12;
--    [case(13)] samr_DomInfo13 info13;
--  } samr_DomainInfo;
--</code>
--
--@param data     The data being processed.
--@param pos      The position within <code>data</code>.
--@return (pos, result) The new position in <code>data</code>, and a table representing the datatype. May return
--                <code>nil</code> if there was an error.
function unmarshall_samr_DomainInfo(data, pos)
  local level
  local result
  stdnse.debug4("MSRPC: Entering unmarshall_samr_DomainInfo()")

  pos, level = unmarshall_int16(data, pos)

  if(level == 1) then
    pos, result = unmarshall_samr_DomInfo1(data, pos)
  elseif(level == 8) then
    pos, result = unmarshall_samr_DomInfo8(data, pos)
  elseif(level == 12) then
    pos, result = unmarshall_samr_DomInfo12(data, pos)
  else
    stdnse.debug1("MSRPC: ERROR: Server returned an unknown level for samr_DomainInfo: %d", level)
    pos, result = nil, nil
  end

  stdnse.debug4("MSRPC: Leaving unmarshall_samr_DomainInfo()")
  return pos, result
end

---Unmarshall a pointer to a <code>samr_DomainInfo</code>. See <code>unmarshall_samr_DomainInfo</code> for
-- more information.
--
--@param data     The data being processed.
--@param pos      The position within <code>data</code>.
--@return (pos, result) The new position in <code>data</code>, and a table representing the datatype. May return
--                <code>nil</code> if there was an error.
function unmarshall_samr_DomainInfo_ptr(data, pos)
  local result
  stdnse.debug4("MSRPC: Entering unmarshall_samr_DomainInfo_ptr()")

  pos, result = unmarshall_ptr(ALL, data, pos, unmarshall_samr_DomainInfo, {})

  stdnse.debug4("MSRPC: Leaving unmarshall_samr_DomainInfo_ptr()")
  return pos, result
end

---Unmarshall a samr_Ids struct
--
--<code>
--    typedef struct {
--        [range(0,1024)]  uint32 count;
--        [size_is(count)] uint32 *ids;
--    } samr_Ids;
--</code>
--
--@param data     The data being processed.
--@param pos      The position within <code>data</code>.
--@return (pos, result) The new position in <code>data</code>, and a table representing the datatype. May return
--                <code>nil</code> if there was an error.
function unmarshall_samr_Ids(data, pos)
  local array

  pos, array = unmarshall_int32_array_ptr(data, pos)

  return pos, array
end

----------------------------------
--       SVCCTL
-- (dependencies: MISC)
----------------------------------

local svcctl_ControlCode =
{
  SERVICE_CONTROL_CONTINUE       = 0x00000003,
  SERVICE_CONTROL_INTERROGATE    = 0x00000004,
  SERVICE_CONTROL_NETBINDADD     = 0x00000007,
  SERVICE_CONTROL_NETBINDDISABLE = 0x0000000A,
  SERVICE_CONTROL_NETBINDENABLE  = 0x00000009,
  SERVICE_CONTROL_NETBINDREMOVE  = 0x00000008,
  SERVICE_CONTROL_PARAMCHANGE    = 0x00000006,
  SERVICE_CONTROL_PAUSE          = 0x00000002,
  SERVICE_CONTROL_STOP           = 0x00000001,
}
local svcctl_ControlCode_str =
{
  SERVICE_CONTROL_CONTINUE       = "Notifies a paused service that it should resume.",
  SERVICE_CONTROL_INTERROGATE    = "Notifies a service that it should report its current status information to the service control manager.",
  SERVICE_CONTROL_NETBINDADD     = "Notifies a network service that there is a new component for binding. Deprecated.",
  SERVICE_CONTROL_NETBINDDISABLE = "Notifies a network service that one of its bindings has been disabled. Deprecated.",
  SERVICE_CONTROL_NETBINDENABLE  = "Notifies a network service that a disabled binding has been enabled. Deprecated",
  SERVICE_CONTROL_NETBINDREMOVE  = "Notifies a network service that a component for binding has been removed. Deprecated",
  SERVICE_CONTROL_PARAMCHANGE    = "Notifies a service that its startup parameters have changed.",
  SERVICE_CONTROL_PAUSE          = "Notifies a service that it should pause.",
  SERVICE_CONTROL_STOP           = "Notifies a service that it should stop."
}


---Marshall a <code>svcctl_ControlCode</code>. This datatype is tied to the table above with that
-- name.
--
--@param flags The value to marshall, as a string
--@return The marshalled integer representing the given value, or <code>nil</code> if it wasn't
--        found.
function marshall_svcctl_ControlCode(flags)
  local result
  stdnse.debug4("MSRPC: Entering marshall_svcctl_ControlCode()")

  result = marshall_Enum32(flags, svcctl_ControlCode)

  stdnse.debug4("MSRPC: Leaving marshall_svcctl_ControlCode()")
  return result
end

---Unmarshall a <code>svcctl_ControlCode</code>. This datatype is tied to the table with that name.
--
--@param data The data packet.
--@param pos  The position within the data.
--@return (pos, str) The new position, and the string representing the datatype.
function unmarshall_svcctl_ControlCode(data, pos)
  local str
  stdnse.debug4("MSRPC: Entering unmarshall_svcctl_ControlCode()")

  pos, str = unmarshall_Enum32_array(data, pos, svcctl_ControlCode)

  stdnse.debug4("MSRPC: Leaving unmarshall_svcctl_ControlCode()")
  return pos, str
end

---Convert a <code>svcctl_ControlCode</code> value to a string that can be shown to the user. This is
-- based on the <code>_str</code> table.
--
--@param val The string value (returned by the <code>unmarshall_</code> function) to convert.
--@return A string suitable for displaying to the user, or <code>nil</code> if it wasn't found.
function svcctl_ControlCode_tostr(val)
  local result
  stdnse.debug4("MSRPC: Entering svcctl_ControlCode_tostr()")

  result = svcctl_ControlCode_str[val]

  stdnse.debug4("MSRPC: Leaving svcctl_ControlCode_tostr()")
  return result
end

local svcctl_Type =
{
  SERVICE_TYPE_KERNEL_DRIVER       = 0x01,
  SERVICE_TYPE_FS_DRIVER           = 0x02,
  SERVICE_TYPE_ADAPTER             = 0x04,
  SERVICE_TYPE_RECOGNIZER_DRIVER   = 0x08,
  SERVICE_TYPE_DRIVER              = 0x0B,
  SERVICE_TYPE_WIN32_OWN_PROCESS   = 0x10,
  SERVICE_TYPE_WIN32_SHARE_PROCESS = 0x20,
  SERVICE_TYPE_WIN32               = 0x30
}

---Marshall a <code>svcctl_Type</code>. This datatype is tied to the table above with that
-- name.
--
--@param flags The value to marshall, as a string
--@return The marshalled integer representing the given value, or <code>nil</code> if it wasn't
--        found.
function marshall_svcctl_Type(flags)
  local result
  stdnse.debug4("MSRPC: Entering marshall_svcctl_Type()")

  result = marshall_Enum32(flags, svcctl_Type)

  stdnse.debug4("MSRPC: Leaving marshall_svcctl_Type()")
  return result
end

---Unmarshall a <code>svcctl_Type</code>. This datatype is tied to the table with that name.
--
--@param data The data packet.
--@param pos  The position within the data.
--@return (pos, str) The new position, and the string representing the datatype.
function unmarshall_svcctl_Type(data, pos)
  local str
  stdnse.debug4("MSRPC: Entering unmarshall_svcctl_Type()")

  pos, str = unmarshall_Enum32_array(data, pos, svcctl_Type)

  stdnse.debug4("MSRPC: Leaving unmarshall_svcctl_Type()")
  return pos, str
end

--[[Convert a <code>svcctl_Type</code> value to a string that can be shown to the user. This is
-- based on the <code>_str</code> table.
--
--@param val The string value (returned by the <code>unmarshall_</code> function) to convert.
--@return A string suitable for displaying to the user, or <code>nil</code> if it wasn't found.
function svcctl_Type_tostr(val)
  local result
  stdnse.debug4("MSRPC: Entering svcctl_Type_tostr()")

  result = svcctl_Type_str[val]

  stdnse.debug4("MSRPC: Leaving svcctl_Type_tostr()")
  return result
end]]--



local svcctl_State =
{
  SERVICE_STATE_ACTIVE   = 0x01,
  SERVICE_STATE_INACTIVE = 0x02,
  SERVICE_STATE_ALL      = 0x03
}
---Marshall a <code>svcctl_State</code>. This datatype is tied to the table above with that
-- name.
--
--@param flags The value to marshall, as a string
--@return The marshalled integer representing the given value, or <code>nil</code> if it wasn't
--        found.
function marshall_svcctl_State(flags)
  local result
  stdnse.debug4("MSRPC: Entering marshall_svcctl_State()")

  result = marshall_Enum32(flags, svcctl_State)

  stdnse.debug4("MSRPC: Leaving marshall_svcctl_State()")
  return result
end

---Unmarshall a <code>svcctl_State</code>. This datatype is tied to the table with that name.
--
--@param data The data packet.
--@param pos  The position within the data.
--@return (pos, str) The new position, and the string representing the datatype.
function unmarshall_svcctl_State(data, pos)
  local str
  stdnse.debug4("MSRPC: Entering unmarshall_svcctl_State()")

  pos, str = unmarshall_Enum32_array(data, pos, svcctl_State)

  stdnse.debug4("MSRPC: Leaving unmarshall_svcctl_State()")
  return pos, str
end

--[[Convert a <code>svcctl_State</code> value to a string that can be shown to the user. This is
-- based on the <code>_str</code> table.
--
--@param val The string value (returned by the <code>unmarshall_</code> function) to convert.
--@return A string suitable for displaying to the user, or <code>nil</code> if it wasn't found.
function svcctl_State_tostr(val)
  local result
  stdnse.debug4("MSRPC: Entering svcctl_State_tostr()")

  result = svcctl_State_str[val]

  stdnse.debug4("MSRPC: Leaving svcctl_State_tostr()")
  return result
end]]--


---Unmarshall a SERVICE_STATUS struct, converting it to a table.
--
-- The structure is as follows:
--
-- <code>
--    typedef struct {
--        uint32 type;
--        uint32 state;
--        uint32 controls_accepted;
--        WERROR win32_exit_code;
--        uint32 service_exit_code;
--        uint32 check_point;
--        uint32 wait_hint;
--    } SERVICE_STATUS;
-- </code>
--
--@param data The data packet.
--@param pos  The position within the data.
--@return (pos, table) The new position, and the table of values.
function unmarshall_SERVICE_STATUS(data, pos)
  local result = {}

  pos, result['type']              = unmarshall_svcctl_Type(data, pos)
  pos, result['state']             = unmarshall_svcctl_State(data, pos)
  pos, result['controls_accepted'] = unmarshall_svcctl_ControlCode(data, pos)
  pos, result['win32_exit_code']   = unmarshall_int32(data, pos)
  pos, result['service_exit_code'] = unmarshall_int32(data, pos)
  pos, result['check_point']       = unmarshall_int32(data, pos)
  pos, result['wait_hint']         = unmarshall_int32(data, pos)

  return pos, result
end



local atsvc_DaysOfMonth =
{
  First           =       0x00000001,
  Second          =       0x00000002,
  Third           =       0x00000004,
  Fourth          =       0x00000008,
  Fifth           =       0x00000010,
  Sixth           =       0x00000020,
  Seventh         =       0x00000040,
  Eighth          =       0x00000080,
  Ninth           =       0x00000100,
  Tenth           =       0x00000200,
  Eleventh        =       0x00000400,
  Twelfth         =       0x00000800,
  Thirteenth      =       0x00001000,
  Fourteenth      =       0x00002000,
  Fifteenth       =       0x00004000,
  Sixteenth       =       0x00008000,
  Seventeenth     =       0x00010000,
  Eighteenth      =       0x00020000,
  Ninteenth       =       0x00040000,
  Twentieth       =       0x00080000,
  Twentyfirst     =       0x00100000,
  Twentysecond    =       0x00200000,
  Twentythird     =       0x00400000,
  Twentyfourth    =       0x00800000,
  Twentyfifth     =       0x01000000,
  Twentysixth     =       0x02000000,
  Twentyseventh   =       0x04000000,
  Twentyeighth    =       0x08000000,
  Twentyninth     =       0x10000000,
  Thirtieth       =       0x20000000,
  Thirtyfirst     =       0x40000000
}

---Marshall a <code>atsvc_DaysOfMonth</code>. This datatype is tied to the table above with that
-- name.
--
--@param flags The value to marshall, as a string
--@return The marshalled integer representing the given value, or <code>nil</code> if it wasn't
--        found.
function marshall_atsvc_DaysOfMonth(flags)
  local result
  stdnse.debug4("MSRPC: Entering marshall_atsvc_DaysOfMonth()")

  result = marshall_Enum32(flags, atsvc_DaysOfMonth)

  stdnse.debug4("MSRPC: Leaving marshall_atsvc_DaysOfMonth()")
  return result
end


local atsvc_Flags =
{
  JOB_RUN_PERIODICALLY    = 0x01,
  JOB_EXEC_ERROR          = 0x02,
  JOB_RUNS_TODAY          = 0x04,
  JOB_ADD_CURRENT_DATE    = 0x08,
  JOB_NONINTERACTIVE      = 0x10
}
---Marshall a <code>atsvc_Flags</code>. This datatype is tied to the table above with that
-- name.
--
--@param flags The value to marshall, as a string
--@return The marshalled integer representing the given value, or <code>nil</code> if it wasn't
--        found.
function marshall_atsvc_Flags(flags)
  local result
  stdnse.debug4("MSRPC: Entering marshall_atsvc_Flags()")

  result = marshall_Enum8(flags, atsvc_Flags, false)

  stdnse.debug4("MSRPC: Leaving marshall_atsvc_Flags()")
  return result
end


local atsvc_DaysOfWeek =
{
  DAYSOFWEEK_MONDAY    = 0x01,
  DAYSOFWEEK_TUESDAY   = 0x02,
  DAYSOFWEEK_WEDNESDAY = 0x04,
  DAYSOFWEEK_THURSDAY  = 0x08,
  DAYSOFWEEK_FRIDAY    = 0x10,
  DAYSOFWEEK_SATURDAY  = 0x20,
  DAYSOFWEEK_SUNDAY    = 0x40
}
---Marshall a <code>atsvc_DaysOfWeek</code>. This datatype is tied to the table above with that
-- name.
--
--@param flags The value to marshall, as a string
--@return The marshalled integer representing the given value, or <code>nil</code> if it wasn't
--        found.
function marshall_atsvc_DaysOfWeek(flags)
  local result
  stdnse.debug4("MSRPC: Entering marshall_atsvc_DaysOfWeek()")

  result = marshall_Enum8(flags, atsvc_DaysOfWeek, false)

  stdnse.debug4("MSRPC: Leaving marshall_atsvc_DaysOfWeek()")
  return result
end

---Marshall a JobInfo struct.
--
--The structure is as follows:
--
--<code>
--    typedef struct {
--        uint32 job_time;
--        atsvc_DaysOfMonth days_of_month;
--        atsvc_DaysOfWeek days_of_week;
--        atsvc_Flags flags;
--        [string,charset(UTF16)] uint16 *command;
--    } atsvc_JobInfo;
--</code>
--
--@param command The command to run. This has to be just the command, no parameters; if a
--               program requires parameters, then the best way to run it is through a batch
--               file.
--@param time The time at which to run the job, in milliseconds from midnight.
function marshall_atsvc_JobInfo(command, time)
  local result = marshall_int32(time)                       -- Job time
  .. marshall_int32(0)                          -- Day of month
  .. marshall_int8(0, false)                    -- Day of week
  .. marshall_atsvc_Flags("JOB_NONINTERACTIVE") -- Flags
  .. marshall_int16(0, false)                   -- Padding
  .. marshall_unicode_ptr(command, true)        -- Command

  return result
end




return _ENV;
