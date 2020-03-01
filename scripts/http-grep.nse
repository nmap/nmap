local string = require "string"
local httpspider = require "httpspider"
local shortport = require "shortport"
local stdnse = require "stdnse"
local table = require "table"
local tableaux = require "tableaux"


description = [[
Spiders a website and attempts to match all pages and urls against a given
string. Matches are counted and grouped per url under which they were
discovered.

Features built in patterns like email, ip, ssn, discover, amex and more.
The script searches for email and ip by default.

]]

---
-- @usage
-- nmap -p 80 www.example.com --script http-grep --script-args='match="[A-Za-z0-9%.%%%+%-]+@[A-Za-z0-9%.%%%+%-]+%.%w%w%w?%w?",breakonmatch'
-- nmap -p 80 www.example.com --script http-grep --script-args 'http-grep.builtins ={"mastercard", "discover"}, http-grep.url="example.html"'
-- @output
-- | http-grep:
-- |   (1) https://nmap.org/book/man-bugs.html:
-- |     (1) email:
-- |       + dev@nmap.org
-- |   (1) https://nmap.org/book/install.html:
-- |     (1) email:
-- |       + fyodor@nmap.org
-- |   (16) https://nmap.org/changelog.html:
-- |     (7) ip:
-- |       + 255.255.255.255
-- |       + 10.99.24.140
-- |       + 74.125.53.103
-- |       + 64.147.188.3
-- |       + 203.65.42.255
-- |       + 192.31.33.7
-- |       + 168.0.40.135
-- |     (9) email:
-- |       + d1n@inbox.com
-- |       + fyodor@insecure.org
-- |       + uce@ftc.gov
-- |       + rhundt@fcc.gov
-- |       + jquello@fcc.gov
-- |       + sness@fcc.gov
-- |       + president@whitehouse.gov
-- |       + haesslich@loyalty.org
-- |       + rchong@fcc.gov
-- |   (6) https://nmap.org/5/#5changes:
-- |     (6) ip:
-- |       + 207.68.200.30
-- |       + 64.13.134.52
-- |       + 4.68.105.6
-- |       + 209.245.176.2
-- |       + 69.63.179.23
-- |_      + 69.63.180.12
--
--
-- @args http-grep.match the string to match in urls and page contents or list of patterns separated by delimiter
-- @args http-grep.maxdepth the maximum amount of directories beneath
--       the initial url to spider. A negative value disables the limit.
--       (default: 3)
-- @args http-grep.maxpagecount the maximum amount of pages to visit.
--       A negative value disables the limit (default: 20)
-- @args http-grep.url the url to start spidering. This is a URL
--       relative to the scanned host eg. /default.html (default: /)
-- @args http-grep.withinhost only spider URLs within the same host.
--       (default: true)
-- @args http-grep.withindomain only spider URLs within the same
--       domain. This widens the scope from <code>withinhost</code> and can
--       not be used in combination. (default: false)
-- @args http-grep.breakonmatch Returns output if there is a match for a single pattern type.
-- @args http-grep.builtins supply a single or a list of built in types. supports email, phone, mastercard, discover,
-- visa, amex, ssn and ip addresses. If you just put in script-args http-grep.builtins then all will be enabled.
--
-- @xmloutput
-- <table key="(1) https://nmap.org/book/man-bugs.html">
--   <table key="(1) email">
--     <elem>+ dev@nmap.org</elem>
--   </table>
-- </table>
-- <table key="(1) https://nmap.org/book/install.html">
--   <table key="(1) email">
--     <elem>+ fyodor@nmap.org</elem>
--   </table>
-- </table>
-- <table key="(16) https://nmap.org/changelog.html">
--   <table key="(7) ip">
--     <elem>+ 255.255.255.255</elem>
--     <elem>+ 10.99.24.140</elem>
--     <elem>+ 74.125.53.103</elem>
--     <elem>+ 64.147.188.3</elem>
--     <elem>+ 203.65.42.255</elem>
--     <elem>+ 192.31.33.7</elem>
--     <elem>+ 168.0.40.135</elem>
--   </table>
--   <table key="(9) email">
--     <elem>+ d1n@inbox.com</elem>
--     <elem>+ fyodor@insecure.org</elem>
--     <elem>+ uce@ftc.gov</elem>
--     <elem>+ rhundt@fcc.gov</elem>
--     <elem>+ jquello@fcc.gov</elem>
--     <elem>+ sness@fcc.gov</elem>
--     <elem>+ president@whitehouse.gov</elem>
--     <elem>+ haesslich@loyalty.org</elem>
--     <elem>+ rchong@fcc.gov</elem>
--   </table>
-- </table>
-- <table key="(6) https://nmap.org/5/#5changes">
--   <table key="(6) ip">
--     <elem>+ 207.68.200.30</elem>
--     <elem>+ 64.13.134.52</elem>
--     <elem>+ 4.68.105.6</elem>
--     <elem>+ 209.245.176.2</elem>
--     <elem>+ 69.63.179.23</elem>
--     <elem>+ 69.63.180.12</elem>
--   </table>
-- </table>

author = {"Patrik Karlsson", "Gyanendra Mishra"}
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}


portrule = shortport.http

-- Shortens a matching string if it exceeds 60 characters
-- All characters after 60 will be replaced with ...
local function shortenMatch(match)
  if ( #match > 60 ) then
    return match:sub(1, 60) .. " ..."
  else
    return match
  end
end

-- A function to validate IP addresses.
local function ip(matched_ip)
  local oct_1, oct_2, oct_3, oct_4 = matched_ip:match('(%d%d?%d?)%.(%d%d?%d?)%.(%d%d?%d)%.(%d%d?%d?)')
  oct_1, oct_2, oct_3, oct_4 = tonumber(oct_1), tonumber(oct_2), tonumber(oct_3), tonumber(oct_4)
  if oct_1 > 255 or oct_2 > 255 or oct_3 > 255 or oct_4 > 255 then
    return false
  end
  return true
end

-- A function to validate credit card numbers.
local function luhn(matched_ccno)
  local ccno = matched_ccno:gsub("%D", ""):reverse()
  local sum = 0
  for i = 1, #ccno do
    local d = tonumber(ccno:sub(i,i))
    if i % 2 == 0 then
      local dd = 2 * d
      d = dd // 10 + dd % 10
    end
    sum = sum + d
  end
  return sum % 10 == 0
end

-- A function to validate ssn numbers.
local bad_ssn = {
  -- https://www.ssa.gov/history/ssn/misused.html
  ["078-05-1120"] = true,
  ["219-09-9999"] = true,
  -- Obvious fakes
  ["123-12-1234"] = true,
  ["123-45-6789"] = true,
  ["321-21-4321"] = true,
  ["111-11-1111"] = true,
  ["222-22-2222"] = true,
  ["333-33-3333"] = true,
  ["444-44-4444"] = true,
  ["555-55-5555"] = true,
  ["666-66-6666"] = true,
  ["777-77-7777"] = true,
  ["888-88-8888"] = true,
  ["999-99-9999"] = true,
}
local bad_group_1 = {
  ["000"] = true,
  ["333"] = true,
  ["666"] = true,
}
local function ssn(matched_ssn)
  if bad_ssn[matched_ssn] then return false end
  local group_1, group_2, group_3 = matched_ssn:match('(%d%d%d)%-(%d%d)%-(%d%d%d%d)')
  if bad_group_1[group_1] then return false end
  if group_2 == "00" or group_3 == "0000" then return false end
  group_1 = tonumber(group_1)
  -- This line rules out ITINs, which may also be of interest.
  if 900 <= group_1 and group_1 <= 999 then return false end
  return true
end

-- The default function if there is no validator.
local function default()
  return true
end

action = function(host, port)
  -- a list of popular patterns with their validators.
  local BUILT_IN_PATTERNS = {
  ['email'] = {'[A-Za-z0-9%.%%%+%-]+@[A-Za-z0-9%.%%%+%-]+%.%w%w%w?%w?'},
  ['phone'] = {'%f[%d]%d%d%d%-%d%d%d%d%f[^%d]','%f[%d%(]%(%d%d%d%)%s%d%d%d%-%d%d%d%f[^%d]','%f[%d%+]%+%-%d%d%d%-%d%d%d%-%d%d%d%d%f[^%d]','%d%d%d%-%d%d%d%-%d%d%d%d%f[^%d]'},
  ['mastercard']= {'%f[%d]5%d%d%d%s?%-?%d%d%d%d%s?%-?%d%d%d%d%s?%-?%d%d%d%d%f[^%d]', ['validate'] = luhn},
  ['visa'] = {'%f[%d]4%d%d%d%s?%-?%d%d%d%d%s?%-?%d%d%d%d%s?%-?%d%d%d%d%f[^%d]', ['validate'] = luhn},
  ['discover']={'%f[%d]6011%s?%-?%d%d%d%d%s?%-?%d%d%d%d%s?%-?%d%d%d%d%f[^%d]', ['validate'] = luhn},
  ['amex'] ={'%f[%d]3%d%d%d%s?%-?%d%d%d%d%d%d%s?%-?%d%d%d%d%d%f[^%d]', ['validate'] = luhn},
  ['ssn'] = {'%f[%d]%d%d%d%-%d%d%-%d%d%d%d%f[^%d]', ['validate'] = ssn},
  ['ip']={'%f[%d]%d%d?%d?%.%d%d?%d?%.%d%d?%d%.%d%d?%d?%f[^%d]', ['validate'] = ip},
  }

  -- read script specific arguments
  local match = stdnse.get_script_args(SCRIPT_NAME .. ".match")
  local break_on_match = stdnse.get_script_args(SCRIPT_NAME .. ".breakonmatch")
  local builtins = stdnse.get_script_args(SCRIPT_NAME .. ".builtins")
  local to_be_searched = {}

  local crawler = httpspider.Crawler:new(host, port, nil, { scriptname = SCRIPT_NAME } )
  local results = stdnse.output_table()
  local all_match = {} -- a table that stores all matches. used to eliminate duplicates.

  -- check if builtin argument is a table or a single value
  if builtins and builtins == 1 then
    for name, patterns in pairs(BUILT_IN_PATTERNS) do
      to_be_searched[name] = {}
      for _, pattern in ipairs(patterns) do
        table.insert(to_be_searched[name], pattern)
      end
    end
  elseif builtins and type(builtins) ~= 'table' then
    if BUILT_IN_PATTERNS[builtins] ~= nil then
      to_be_searched[builtins] = {}
      for _, pattern in ipairs(BUILT_IN_PATTERNS[builtins]) do
        table.insert(to_be_searched[builtins], pattern)
      end
    end
  elseif builtins and type(builtins) == 'table' then
    for _, builtin in  ipairs(builtins) do
        if BUILT_IN_PATTERNS[builtin] ~= nil then
          to_be_searched[builtin] = {}
          for _, pattern in ipairs(BUILT_IN_PATTERNS[builtin]) do
            table.insert(to_be_searched[builtin], pattern)
          end
        end
    end
  end

  -- check if match argument is a table or a single value
  if match and type(match) ~= 'table' then
    to_be_searched['User Pattern 1'] = {}
    table.insert(to_be_searched['User Pattern 1'], match)
  elseif type(match) == 'table' then
    for i, pattern in pairs(match) do
      local k = 'User Pattern ' .. tostring(i)
      to_be_searched[k] = {}
      table.insert(to_be_searched[k], pattern)
    end
  end

  -- if nothing is specified then email and ip are checked.
  if not next(to_be_searched) then
    to_be_searched['email'] = {}
    to_be_searched['ip'] = {}
    table.insert(to_be_searched['email'], BUILT_IN_PATTERNS["email"][1])
    table.insert(to_be_searched['ip'], BUILT_IN_PATTERNS["ip"][1])
  end

  -- set timeout to 10 seconds
  crawler:set_timeout(10000)

  while(true) do
    local status, r = crawler:crawl()
    -- if the crawler fails it can be due to a number of different reasons
    -- most of them are "legitimate" and should not be reason to abort
    if ( not(status) ) then
      if ( r.err ) then
        return stdnse.format_output(false, r.reason)
      else
        break
      end
    end
    local count = 0 -- pattern matches per url
    local pattern_count = 0 -- number of matches for particual pattern type say 'email'
    local matches = {} -- a table that stores matches for all pattern types
    local pattern_type = {} -- a table that resets for every pattern type
    for pattern_name, pattern_table in pairs(to_be_searched) do
      pattern_type = {}
      pattern_count = 0
      for _, pattern in ipairs(pattern_table) do
        local body = r.response.body
        -- try to match the url and body
        if body and ( body:match( pattern ) or tostring(r.url):match(pattern) ) then
          pattern_count = select(2, body:gsub(pattern, ""))
          count = count + pattern_count
          for match in body:gmatch(pattern) do
            local validate = BUILT_IN_PATTERNS[pattern_name]and BUILT_IN_PATTERNS[pattern_name]['validate'] or default
            if validate(match) and not tableaux.contains(all_match, match) then
              table.insert(pattern_type, "+ " .. shortenMatch(match))
              table.insert(all_match, match)
            else
              count = count - 1
              pattern_count = pattern_count - 1
            end
          end
        end
      end
      if pattern_count > 0 then
        matches[("(%d) %s"):format(pattern_count, pattern_name)] = pattern_type
      end
    end
    if count > 0 then
      results[("(%d) %s"):format(count,tostring(r.url))] =  matches
    end
    -- should we continue to search for matches?
    if break_on_match and pattern_count > 0 then
      crawler:stop()
      break
    end
  end
  if #results > 0 then return results end
end

