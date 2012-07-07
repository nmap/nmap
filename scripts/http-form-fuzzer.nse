description = [[
Performs a simple form fuzzing against forms found on websites.
Tries strings and numbers of increasing length and attempts to
determine if the fuzzing was successful.
]]

---
-- @usage
-- nmap --script http-form-fuzzer -p 80 <host>
--
-- This script attempts to fuzz fields in forms it detects (it fuzzes one field at a time).
-- In each iteration it first tries to fuzz a field with a string, then with a number.
-- In the output, actions and paths for which errors were observed are listed, along with
-- names of fields that were being fuzzed during error occurrence. Length and type
-- (string/integer) of the input that caused the error are also provided.
-- We consider an error to be either: a response with status 500 or with an empty body,
-- a response that contains "server error" or "sql error" strings. ATM anything other than
-- that is considered not to be an 'error'.
-- TODO: develop more sophisticated techniques that will let us determine if the fuzzing was
-- successful (i.e. we got an 'error'). Ideally, an algorithm that will tell us a percentage
-- difference between responses should be implemented.
--
-- @output
-- PORT   STATE SERVICE REASON
-- 80/tcp open  http    syn-ack
-- | http-form-fuzzer: 
-- |   Path: /register.html Action: /validate.php
-- |     age
-- |       integer lengths that caused errors:
-- |         10000, 10001
-- |     name
-- |       string lengths that caused errors:
-- |         40000
-- |   Path: /form.html Action: /check_form.php
-- |     fieldfoo
-- |       integer lengths that caused errors:
-- |_        1, 2
--
-- @args http-form-fuzzer.targets a table with the targets of fuzzing, for example
-- {{path = /index.html, minlength = 40002}, {path = /foo.html, maxlength = 10000}}.
-- The path parameter is required, if minlength or maxlength is not specified,
-- then the values of http-form-fuzzer.minlength or http-form-fuzzer.maxlength will be used.
-- Defaults to {{path="/"}}
-- @args http-form-fuzzer.minlength the minimum length of a string that will be used for fuzzing,
-- defaults to 300000
-- @args http-form-fuzzer.maxlength the maximum length of a string that will be used for fuzzing,
-- defaults to 310000
--

author = "Piotr Olma"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"fuzzer", "intrusive"}

local shortport = require 'shortport'
local http = require 'http'
local stdnse = require 'stdnse'
local string = require 'string'
local table = require 'table'
local tab = require 'tab'
local url = require 'url'

-- generate a charset that will be used for fuzzing
local function generate_charset(left_bound, right_bound, ...)
  local t = ... or {}
  if left_bound > right_bound then
    return t
  end
  for i=left_bound,right_bound do
    table.insert(t, string.char(i))
  end
  return t
end

-- check if the response we got indicates that fuzzing was successful
local function check_response(response)
  if not(response.body) or response.status==500 then
    return true
  end
  if response.body:find("[Ss][Ee][Rr][Vv][Ee][Rr]%s*[Ee][Rr][Rr][Oo][Rr]") or response.body:find("[Ss][Qq][Ll]%s*[Ee][Rr][Rr][Oo][Rr]") then
    return true
  end
  return false
end

-- checks if a field is of type we want to fuzz
local function fuzzable(field_type)
  return field_type=="text" or field_type=="radio" or field_type=="checkbox" or field_type=="textarea"
end

-- generates postdata with value of "sampleString" for every field (that is fuzzable()) of a form
local function generate_safe_postdata(form)
  local postdata = {}
  for _,field in ipairs(form["fields"]) do
    if fuzzable(field["type"]) then
      postdata[field["name"]] = "sampleString"
    end
  end
  return postdata
end

local function generate_get_string(data)
  local get_str = {"?"}
  for name,value in pairs(data) do
    get_str[#get_str+1]=url.escape(name).."="..url.escape(value).."&"
  end
  return table.concat(get_str)
end

-- generate a charset of characters with ascii codes from 33 to 126
-- you can use http://www.asciitable.com/ to see which characters those actually are
local charset = generate_charset(33,126)
local charset_number = generate_charset(49,57) -- ascii 49 -> 1; 57 -> 9

local function fuzz_field(field, minlen, maxlen, postdata, sending_function)
  local affected_string = {}
  local affected_int = {}
  
  for i=minlen,maxlen do -- maybe a better idea would be to increment the string's length by more then 1 in each step
    local response_string
    local response_number
    
    --first try to fuzz with a string
    postdata[field["name"]] = stdnse.generate_random_string(i, charset)
    response_string = sending_function(postdata)
    --then with a number
    postdata[field["name"]] = stdnse.generate_random_string(i, charset_number)
    response_number = sending_function(postdata)

    if (check_response(response_string)) then
      affected_string[#affected_string+1]=i
    end
    if (check_response(response_number)) then
      affected_int[#affected_int+1]=i
    end
  end
  postdata[field["name"]] = "sampleString"
  return affected_string, affected_int
end

local function fuzz_form(form, minlen, maxlen, host, port, path)
  local affected_fields = {}
  local postdata = generate_safe_postdata(form)
  local action_absolute = string.find(form["action"], "https*://")
  
  -- determine the path where the form needs to be submitted
  local form_submission_path
  if action_absolute then
    form_submission_path = form["action"]
  else
    local path_cropped = string.match(path, "(.*/).*")
    path_cropped = path_cropped and path_cropped or ""
    form_submission_path = path_cropped..form["action"]
  end
  
  -- determine should the form be sent by post or get
  local sending_function
  if form["method"]=="post" then
    sending_function = function(data) return http.post(host, port, form_submission_path, nil, nil, data) end
  else
    sending_function = function(data) return http.get(host, port, form_submission_path..generate_get_string(data), {no_cache=true, bypass_cache=true}) end
  end
  
  for _,field in ipairs(form["fields"]) do
    if fuzzable(field["type"]) then
      local affected_string, affected_int = fuzz_field(field, minlen, maxlen, postdata, sending_function)
      if #affected_string > 0 or #affected_int > 0 then
        local affected_next_index = #affected_fields+1
        affected_fields[affected_next_index] = {name = field["name"]}
        if #affected_string>0 then
          table.insert(affected_fields[affected_next_index], {name="string lengths that caused errors:", table.concat(affected_string, ", ")})
        end
        if #affected_int>0 then
          table.insert(affected_fields[affected_next_index], {name="integer lengths that caused errors:", table.concat(affected_int, ", ")})
        end
      end
    end
  end
  return affected_fields
end

portrule = shortport.port_or_service( {80, 443}, {"http", "https"}, "tcp", "open")

function action(host, port)
  local minlen_global = stdnse.get_script_args("http-form-fuzzer.minlength") or 300000
  local maxlen_global = stdnse.get_script_args("http-form-fuzzer.maxlength") or 310000
  local targets = stdnse.get_script_args('http-form-fuzzer.targets') or {{path="/"}}
  local return_table = {}
  
  for _,target in ipairs(targets) do
    stdnse.print_debug(2, "http-form-fuzzer: testing path: "..target["path"])
    local path = target["path"]
    if path then
      local response = http.get( host, port, path )
      local all_forms = http.grab_forms(response.body)
      local minlen = target["minlength"] or minlen_global
      local maxlen = target["maxlength"] or maxlen_global
      for _,form_plain in ipairs(all_forms) do
        local form = http.parse_form(form_plain)
        if form then
          local affected_fields = fuzz_form(form, minlen, maxlen, host, port, path)
          if #affected_fields > 0 then
            affected_fields["name"] = "Path: "..path.." Action: "..form["action"]
            table.insert(return_table, affected_fields)
          end
        end
      end
    end
  end
  return stdnse.format_output(true, return_table)
end

