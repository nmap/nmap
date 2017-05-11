---
-- Password profiling library.
--
-- Contains all the logic for profiling passwords in NSE.
--
-- The password profiling feature is triggered by unpwdb.lua that is called
-- by brute.lua.
--
-- An NSE developer that writes a discovery script and believes that some
-- of the gathered information might be useful for password profiling, can
-- simply use pwdprofile.save_for_pwdprofiling(host, keyword) method to
-- pass them to the pwdprofile.
--
-- An NSE developer that writes a brute script and wants his engine to take
-- advantage of the password profiling when the user sets the
-- --brute.passprofile argument, only has to add these special discovery
-- scripts as dependencies. If he is lazy to look for them, he may use
-- pwdprofile.PWDPROFILE_SCRIPTS table that holds a list with them. Be aware
-- that this may raise circular dependencies though.
--
-- @author "George Chatzisofroniou <sophron () latthi com>"
-- @copyright Same as Nmap--See https://nmap.org/book/man-legal.html
--

local io = require "io"
local nmap = require "nmap"
local os = require "os"
local stdnse = require "stdnse"

_ENV = stdnse.module("pwdprofile", stdnse.seeall)

-- Discovery scripts that retrieve useful keywords for password profiling
-- should be listed below. Brute scripts may use this table as their
-- dependencies. Review carefully to avoid any circular dependencies.
PWDPROFILE_SCRIPTS = {
    "http-title",
    "smb-enum-domains"
}

-- Length limits of a possible keyword.
-- Remove possible articles, determiners, and quantifiers with MIN_LENGTH.
-- Avoid system exhaustion with MAX_LENGTH. The longer the keyword, the more
-- passwords will be generated.
local MIN_LENGTH = 4
local MAX_LENGTH = 10

-- Skip a mangling algorithm by adjusting the below constants.
local RAND_CAPITAL = true
local RAND_LEET = true
local SUFFIX_APPEND = true

-- Used to filter out common articles, determiners, and quantifiers.
local t_filters = {
    "many",
    "some",
    "their",
    "yours",
    "each",
    "every",
    "this",
    "that"
}

-- Common leet replacements.
-- TODO: We should implement a better logic here.
-- For example, "a" can be written as "@" or "4".
local leet_replacements = {
    a="4",
    i="1",
    e="3",
    t="7",
    o="0",
    s="5",
    g="9",
    z="2",
    s="$"
}

-- Common suffixes.
-- TODO: I imported some suffixes I've seen here and there.
-- It's better if we do some research and include the most
-- used suffixes (e.g. as found in leaked password databases).
local suffixes = {
    "0",
    "1",
    "12",
    "123",
    "1234",
    "password",
    "pass",
    "!",
    "@",
    "$"
}

-- Include the last 5 years to the above list.
local cur_year = tonumber(os.date("%Y"))
for i=0,5 do
    table.insert(suffixes, cur_year - 4)
end

local filters = {}
for i, v in ipairs(t_filters) do
    filters[v] = true
end

-- Check if the word is suitable as a keyword.
local check_word = function( word )
    if ( filters[string.lower(word)] ~= nil ) then
        return false
    end

    if ( string.len(word) < MIN_LENGTH ) then
        return false
    end

    if ( string.len(word) > MAX_LENGTH ) then
        return false
    end

    return true
end

-- Public method that NSE discovery scripts should use to
-- cache interesting keywords.
save_for_pwdprofiling = function( host, key )

  nmap.registry.pwdprofiling = nmap.registry.pwdprofiling or {}
  nmap.registry.pwdprofiling.host = nmap.registry.pwdprofiling.host or {}
  for i in string.gmatch(key, "%S+") do
    if ( check_word(i) ) then
        table.insert( nmap.registry.pwdprofiling.host, i )
    end
  end

end

-- Simple copy table method.
local shallow_copy = function( original )

  local copy = {}
  for k, v in pairs(original) do
    copy[k] = v
  end
  return copy

end

-- Our mangling mathod that contains all the logic
-- and algorithms for generating mutations
local mangle_words = function( pwds )
  local mutants = {}

  for _, m in pairs(pwds) do
    table.insert(mutants, string.lower(m))

    -- The next snippet will generate mutations by trasforming to leet *only*
    -- consecutively letters. For example, it will generate b4n4na or ban4n4
    -- or b4n4n4 but not b4nan4.
    if ( RAND_LEET == true or tonumber(RAND_LEET) == 1 ) then

      local total_leet_count = 0
      for i=1, #m do
        local c = m:sub(i,i)
        if leet_replacements[c] ~= nil then
          total_leet_count = total_leet_count + 1
        end
      end

      local temp_leet_count = 0
      for count=1, total_leet_count do
        for i=1, #m do
          local c = m:sub(i,i)
          if leet_replacements[c] ~= nil then
            if temp_leet_count < total_leet_count then
              temp_leet_count = temp_leet_count + 1
              new_mutant = m:sub(1, i-1) .. leet_replacements[c] .. m:sub(i+1, #m)
              submutant = new_mutant:sub(1, i)
              table.insert(mutants, new_mutant)
            end
          end
        end
      end
    end
  end


  -- The next snippet will generate mutations by capitalizing *only*
  -- consecutively letters. For example, it will generate bANAna or
  -- bananA or BANana but not BanaNa.
  if ( RAND_CAPITAL == true or tonumber(RAND_CAPITAL) == 1 ) then
    imutants = shallow_copy(mutants)
    for _, p  in ipairs(imutants) do
      for i=1, #p do
        for j=1, #p do
          if i-j > -1 then
              _p = p
              mutant = string.lower(_p:sub(1,i-j)) .. string.upper(_p:sub(i-j+1,i)) .. string.lower(_p:sub(i+1, #_p))
              table.insert(mutants, mutant)
          end
        end
      end
    end
  end

  -- This last snippet will append the suffixes listed in 'suffixes'
  -- table.
  if ( SUFFIX_APPEND == true or tonumber(SUFFIX_APPEND) == 1 ) then
    imutants = shallow_copy(mutants)
    for _, p in ipairs(imutants) do
      for __, s in ipairs(suffixes) do
        table.insert(mutants, p .. s)
      end
    end
  end

  return mutants
end

-- This is currently called by unpwd.lua. It will
-- retrieve all cached keywords, mangle them and
-- return the generated list.
get_profiled_pwds = function( host )
  if ( nmap.registry["pwdprofiling"] ) then
    mangledpwds = mangle_words(nmap.registry.pwdprofiling.host)
    return mangledpwds
  end
end
