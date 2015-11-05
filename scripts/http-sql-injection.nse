local http = require "http"
local httpspider = require "httpspider"
local io = require "io"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"
local url = require "url"

description = [[
Spiders an HTTP server looking for URLs containing queries vulnerable to an SQL
injection attack. It also extracts forms from found websites and tries to identify
fields that are vulnerable.

The script spiders an HTTP server looking for URLs containing queries. It then
proceeds to combine crafted SQL commands with susceptible URLs in order to
obtain errors. The errors are analysed to see if the URL is vulnerable to
attack. This uses the most basic form of SQL injection but anything more
complicated is better suited to a standalone tool.

We may not have access to the target web server's true hostname, which can prevent access to
virtually hosted sites.
]]


author = "Eddie Bell, Piotr Olma"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"intrusive", "vuln"}

---
-- @args http-sql-injection.maxpagecount the maximum amount of pages to visit.
--       A negative value disables the limit (default: 20)
-- @args http-sql-injection.url the url to start spidering. This is a URL
--       relative to the scanned host eg. /default.html (default: /)
-- @args http-sql-injection.withinhost only spider URLs within the same host.
--       (default: true)
-- @args http-sql-injection.withindomain only spider URLs within the same
--       domain. This widens the scope from <code>withinhost</code> and can
--       not be used in combination. (default: false)
-- @args http-sql-injection.errorstrings a path to a file containing the error
--       strings to search for (one per line, lines started with # are treated as
--       comments). The default file is nselib/data/http-sql-errors.lst
--       which was taken from fuzzdb project, for more info, see http://code.google.com/p/fuzzdb/.
--       If someone detects some strings in that file causing a lot of false positives,
--       then please report them to dev@nmap.org.
--
-- @output
-- PORT   STATE SERVICE
-- 80/tcp open  http    syn-ack
-- | http-sql-injection:
-- |   Possible sqli for queries:
-- |     http://foo.pl/forms/page.php?param=13'%20OR%20sqlspider
-- |   Possible sqli for forms:
-- |     Form at path: /forms/f1.html, form's action: a1/check1.php. Fields that might be vulnerable:
-- |       f1text
-- |     Form at path: /forms/a1/../f2.html, form's action: a1/check2.php. Fields that might be vulnerable:
-- |_      f2text
--


portrule = shortport.port_or_service({80, 443}, {"http","https"})

--[[
Pattern match response from a submitted injection query to see
if it is vulnerable
--]]

local errorstrings = {}
local function check_injection_response(response)

  local body = string.lower(response.body)

  if not (response.status == 200 or response.status ~= 500) then
    return false
  end

  if errorstrings then
    for _,e in ipairs(errorstrings) do
      if string.find(body, e) then
        stdnse.debug2("error string matched: %s", e)
        return true
      end
    end
  end
  return false
end

--[[
Replaces usual queries with malicious query and return a table with them.
]]--

local function build_injection_vector(urls)
  local utab, k, v, urlstr, response
  local qtab, old_qtab, results
  local all = {}

  for _, injectable in ipairs(urls) do
    if type(injectable) == "string"  then
      utab = url.parse(injectable)
      qtab = url.parse_query(utab.query)

      for k, v in pairs(qtab) do
        old_qtab = qtab[k];
        qtab[k] = qtab[k] ..  "' OR sqlspider"

        utab.query = url.build_query(qtab)
        urlstr = url.build(utab)
        table.insert(all, urlstr)

        qtab[k] = old_qtab
        utab.query = url.build_query(qtab)
      end
    end
  end
  return all
end

--[[
Creates a pipeline table and returns the result
]]--
local function inject(host, port, injectable)
  local all = {}
  for k, v in pairs(injectable) do
    all = http.pipeline_add(v, nil, all, 'GET')
  end
  return http.pipeline_go(host, port, all)
end

--[[
Checks if received responses matches with usual sql error messages,
what potentially means that the host is vulnerable to sql injection.
]]--
local function check_responses(queries, responses)
  local results = {}
  for k, v in pairs(responses) do
    if (check_injection_response(v)) then
      table.insert(results, queries[k])
    end
  end
  return results
end

-- checks if a field is of type we want to check for sqli
local function sqli_field(field_type)
  return field_type=="text" or field_type=="radio" or field_type=="checkbox" or field_type=="textarea"
end

-- generates postdata with value of "sampleString" for every field (that satisfies sqli_field()) of a form
local function generate_safe_postdata(form)
  local postdata = {}
  for _,field in ipairs(form["fields"]) do
    if sqli_field(field["type"]) then
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

-- checks each field of a form to see if it's vulnerable to sqli
local function check_form(form, host, port, path)
  local vulnerable_fields = {}
  local postdata = generate_safe_postdata(form)
  local sending_function, response

  local action_absolute = string.find(form["action"], "^https?://")
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
    sending_function = function(data) return http.get(host, port, form_submission_path..generate_get_string(data), nil) end
  end

  for _,field in ipairs(form["fields"]) do
    if sqli_field(field["type"]) then
      stdnse.debug2("checking field %s", field["name"])
      postdata[field["name"]] = "' OR sqlspider"
      response = sending_function(postdata)
      if response and response.body and response.status==200 then
        if check_injection_response(response) then
          vulnerable_fields[#vulnerable_fields+1] = field["name"]
        end
      end
      postdata[field["name"]] = "sampleString"
    end
  end
  return vulnerable_fields
end

-- load error strings to the errorstrings table
local function get_error_strings(path)
  local f = nmap.fetchfile(path) or path
  if f then
    for e in io.lines(f) do
      if not string.match(e, "^#") then
        table.insert(errorstrings, e:lower())
      end
    end
  end
  -- check if we loaded something
  if #errorstrings == 0 then
    -- if not, then load some default values
    errorstrings = {"invalid query", "sql syntax", "odbc drivers error"}
  end
end

action = function(host, port)
  local error_strings_path = stdnse.get_script_args('http-sql-injection.errorstrings') or 'nselib/data/http-sql-errors.lst'
  get_error_strings(error_strings_path)
  -- crawl to find injectable urls
  local crawler = httpspider.Crawler:new(host, port, nil, {scriptname = SCRIPT_NAME})
  local injectable = {}
  local results_forms = {name="Possible sqli for forms:"}

  while(true) do
    local status, r = crawler:crawl()
    if (not(status)) then
      if (r.err) then
        return stdnse.format_output(false, r.reason)
      else
        break
      end
    end

    -- first we try sqli on forms
    if r.response and r.response.body and r.response.status==200 then
      local all_forms = http.grab_forms(r.response.body)
      for _,form_plain in ipairs(all_forms) do
        local form = http.parse_form(form_plain)
        local path = r.url.path
        if form and form.action then
          local vulnerable_fields = check_form(form, host, port, path)
          if #vulnerable_fields > 0 then
            vulnerable_fields["name"] = "Form at path: "..path..", form's action: "..form["action"]..". Fields that might be vulnerable:"
            table.insert(results_forms, vulnerable_fields)
          end
        end
      end --for
    end --if
    local links = {}
    if r.response.status and r.response.body then
      links = httpspider.LinkExtractor:new(r.url, r.response.body, crawler.options):getLinks()
    end
    for _,u in ipairs(links) do
      if url.parse(u).query then
        table.insert(injectable, u)
      end
    end
  end

  -- try to inject
  local results_queries = {}
  if #injectable > 0 then
    stdnse.debug1("Testing %d suspicious URLs", #injectable)
    local injectableQs = build_injection_vector(injectable)
    local responses = inject(host, port, injectableQs)
    results_queries = check_responses(injectableQs, responses)
  end

  results_queries["name"] = "Possible sqli for queries:"
  local res = {results_queries, results_forms}
  return stdnse.format_output(true, res)
end

