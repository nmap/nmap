local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local tab = require "tab"
local table = require "table"

description=[[
Retrieves a list of Git projects, owners and descriptions from a gitweb (web interface to the Git revision control system).
]]

---
-- @usage
-- nmap -p80 www.example.com --script http-gitweb-projects-enum
--
-- @output
-- 80/tcp open  http
-- | http-gitweb-projects-enum:
-- | Projects from gitweb.samba.org:
-- |   PROJECT                         AUTHOR            DESCRIPTION
-- |   sando.git                       authornum1        no description
-- |   camui/san.git                   devteam           no description
-- |   albert/tdx.git/.git             blueteam          no description
-- |
-- |   Number of projects: 172
-- |_  Number of owners: 42
--
-- @args http-gitweb.projects-enum.path specifies the location of gitweb
--       (default: /)

author = "riemann"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}


portrule = shortport.http

---
-- @param author bloc (if author name are too long we have a span bloc)
-- @return author name filtred from html entities
---
get_owner = function(res)
  local result=res
  local _
  if ( res:match('<span') ) then
    _,_,result=string.find(res,'title="(.-)"')
  end
  return result
end

action = function(host, port)

  local path = stdnse.get_script_args(SCRIPT_NAME .. '.path') or '/'
  local response = http.get(host,port,path)
  local result, result_stats = {}, {}

  if not response or not response.status or response.status ~= 200 or
    not response.body then
    stdnse.debug1("Failed to retrieve file: %s", path)
    return
  end

  local html = response.body
  local repo=tab.new()
  tab.addrow(repo,'PROJECT','AUTHOR','DESCRIPTION')

  -- verif generator
  if (html:match('meta name="generator" content="gitweb(.-)"')) then
    result['name'] = string.format("Projects from %s:", host.targetname or host.ip)

    local owners, projects_counter, owners_counter = {}, 0, 0

    for tr_code in html:gmatch('(%<tr[^<>]*%>(.-)%</tr%>)') do
      local regx='<a[^<>]*href="(.-)">(.-)</a>(.-)title="(.-)"(.-)<i>(.-)</i>'
      for _, project, _, desc, _, owner in tr_code:gmatch(regx) do

        --if desc result return default text of gitweb replace it by no description
        if(string.find(desc,'Unnamed repository')) then
          desc='no description'
        end

        tab.addrow(repo, project, get_owner(owner), desc)

        -- Protect from parsing errors or long owners
        -- just an arbitrary value
        if owner:len() < 128 and not owners[owner] then
          owners[owner] = true
          owners_counter = owners_counter + 1
        end

        projects_counter = projects_counter + 1
      end
    end

    table.insert(result,tab.dump(repo))
    table.insert(result, "")
    table.insert(result,
    string.format("Number of projects: %d", projects_counter))
    if (owners_counter > 0 ) then
      table.insert(result,
      string.format("Number of owners: %d", owners_counter))
    end

  end
  return stdnse.format_output(true,result)
end
