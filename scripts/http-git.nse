-- Checks for a Git repository found in a website's document root (GET /.git/<something> HTTP/1.1)
-- Gets as much information about the repository as possible, including language/framework, Github
-- username, last commit message, and repository description.
--
-- @output
-- PORT   STATE SERVICE
-- 80/tcp open  http
-- | http-git:
-- |   Git repository found in web root
-- |   Last commit message: This is my last commit...
-- |   Repository description: Unnamed repository; edit this file 'description' to name the...
-- |   GitHub remote: AlexWebr/nse (accessed over SSH)
-- |   BitBucket remote: AlexWebr/nse (accessed over HTTP, pull-only)
-- |_  Based on the file '.gitignore', this is a Ruby on Rails application
--
-- Version 1.1
-- Created 27 June 2012 - written by Alex Weber <alexwebr@gmail.com>


local http = require("http")
local shortport = require("shortport")
local stdnse = require("stdnse")
local strbuf = require("strbuf")
local string = require("string")
local table = require("table")
description = [[ Checks for a Git repository found in a website's document root (/.git/<something>) then retrieves as much repo information as possible, including language/framework, Github username, last commit message, and repository description.
]]

categories = { "safe", "vuln", "default" }
author = "Alex Weber"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
portrule = shortport.http

local STATUS_OK = 200 -- We consider 200 to mean "okay, file exists and we received its contents"

function action(host, port)
  -- All methods that we call on this table will be from the table library
  local out = {}
  setmetatable(out, {__index = table})
  local repos_found = 0

  -- We can accept a single root, or a table of roots to try
  local root_arg = stdnse.get_script_args("http-git.root")
  local roots
  if type(root_arg) == "table" then
    roots = root_arg
  elseif type(root_arg) == "string" or type(root_arg) == "number" then
    roots = { tostring(root_arg) }
  elseif root_arg == nil then -- if we didn't get an argument
    roots = { "/" }
  end

  -- Try each root in succession
  for i, root in ipairs(roots) do
    root = tostring(root)
    root = root or '/'

    -- Put a forward slash on the beginning and end of the root, if none was
    -- provided. We will print this, so the user will know that we've mangled it
    if not string.find(root, "/$") then -- if there is no slash at the end
      root = root .. "/"
    end
    if not string.find(root, "^/") then -- if there is no slash at the beginning
      root = "/" .. root
    end

    -- If we can't get /.git/HEAD, don't even bother continuing
    -- We could try for /.git/, but we will not get a 200 if directory
    -- listings are disallowed.
    if http.get(host, port, root .. ".git/HEAD").status == STATUS_OK then
      if repos_found > 0 then
        out:insert("")
      end
      repos_found = repos_found + 1
      local replies = {}
      -- This function returns true if we got a 200 OK when
      -- fetching 'filename' from the server
      local function ok(filename)
        return (replies[filename].status == STATUS_OK)
      end
      -- These are files that are small, very common, and don't
      -- require zlib to read
      -- These files are created by creating and using the repository,
      -- or by popular development frameworks.
      local repo = {
        ".git/config",
        ".git/description",
        ".git/info/exclude",
        ".git/COMMIT_EDITMSG",
        ".gitignore",
      }

      local count = { ok = 0, tried = 0 }
      local prequests = {} -- prequests = pipelined requests (temp)
      -- Go through all of the filenames and do an HTTP GET
      for _, name in ipairs(repo) do -- for every filename
        http.pipeline_add(root .. name, nil, prequests)
      end
      -- do the requests
      replies = http.pipeline_go(host, port, prequests)
      if replies == nil then
        stdnse.print_debug("%s: pipeline_go() error. Aborting.", SCRIPT_NAME)
        return nil
      end

      for i, reply in ipairs(replies) do
        count.tried = count.tried + 1
        -- We want this to be indexed by filename, not an integer, so we convert it
        -- We added to the pipeline in the same order as the filenames, so this is safe
        replies[repo[i]] = reply -- create index by filename
        replies[i] = nil -- delete integer-indexed entry
        if reply.status == STATUS_OK then count.ok = count.ok + 1 end
      end

      -- Tell the user that we found a repository, and indicate if
      -- we didn't find all the files we were looking for.
      local location = host.ip .. ":" .. port.number .. root .. ".git/"
      if count.ok == count.tried then
        out:insert("Git repository found at " .. location)
      else -- if we didn't find all the files we were hoping to, we might not actually have a repo
        out:insert("Potential Git repository found at " .. location .. " (found " ..
          tostring(count.ok + 1) .. " of " .. tostring(count.tried + 1) .. " expected files)")
        -- we already got /.git/HEAD, so add one to 'found' and 'expected'
      end

      -- This function matches a table of words/regexes against a single string
      -- This function is used immediately after it is declared
      local function match_many(str, table_of_words)
        local matched_string, lstr, t_to_return = false, string.lower(str), {}
        for i, word in ipairs(table_of_words) do
          matched_string = string.match(lstr, word)
          if matched_string then table.insert(t_to_return , matched_string) end
        end
        return t_to_return
      end

      -- Look through all the repo files we grabbed and see if we can find anything interesting
      local interesting = { "bug", "passw", "pw", "user", "uid", "key", "secret" }
      for name, reply in pairs(replies)  do
        if ok(name) then -- for all replies that were successful
          local found_anything = false -- have we found anything yet?
          local buf = strbuf.new()
          for _, matched in ipairs(match_many(reply.body:lower(), interesting)) do -- match all files against 'interesting'
            if not found_anything then -- if this is our first find, print filename and stuff
              buf = (((((buf .. "Contents of '") .. name) .. "' matched patterns '") .. matched) .. "'") -- the '..' is right-associative :(
              found_anything = true
            else
              buf = ((buf .. ", '" .. matched) .. "'")
            end -- if we found something already, tack this pattern onto the end
          end -- If we matched anything, finish the line up
          if found_anything then
            buf = buf .. " (case-insensitive match)"
            out:insert(strbuf.dump(buf))
          end
        end
      end

      -- Given a longer plain-text string (a large text file, for example), append
      -- a summary of it (the first 60 characters or the first line, whichever is shorter)
      local function append_short_version(description, original_string)
        local short = string.sub(original_string, 1, 60) -- trim the string first, in case it is huge
        -- We try to cut off the newline if we can
        local no_newline = string.match(short, "(.-)\r?\n") -- we don't want such an open-ended regex on a potentially huge string
        local s = no_newline or short
        if #original_string > #s then
          -- If we cut off something, we want to put an ellipsis on the end
          s = description .. ": " .. s .. "..."
        else
          s = description .. ": " .. s
        end
        out:insert(s)
      end

      -- Get the first line and trim to 60 characters, if we got a COMMIT_EDITMESSAGE
      if ok(".git/COMMIT_EDITMSG") then
        -- If there's no newline in the file (there usually is), this won't work.
        -- Normally, it's a commit message followed by a bunch of commented-out lines (#).
        append_short_version("Last commit message", replies[".git/COMMIT_EDITMSG"].body)
      end

      -- Do the same thing as for description - get first line, truncate to 60 characters.
      if ok(".git/description") then
        append_short_version("Repository description", replies[".git/description"].body)
      end

      -- If we got /.git/config, we might find out things like the user's GitHub name,
      -- if they have a Heroku remote, whether this is a bare repository or not (if it
      -- is bare, that means it's likely a remote for other people), and in future
      -- versions of Git when there are more than one repo format version, we will
      -- display that too.
      if ok(".git/config") then
        local config = replies[".git/config"].body
        local remotes = {}

        -- Try to extract URLs of all remotes.
        for url in string.gmatch(config, "\n%s*url%s*=%s*(%S*/%S*)") do
          table.insert(remotes, url)
        end

        -- These are some popular / well-known Git hosting services and/or hosting services
        -- that allow deployment via 'git push'
        local popular_remotes = {
          ["github.com"] =    "Source might be at https://github.com/<reponame>",
          ["gitorious.com"] = "Source might be at https://gitorious.com/<reponame>",
          ["bitbucket.org"] = "Source might be at https://bitbucket.org/<reponame>",
          ["heroku.com"] =    "App might be deployed to http://<reponame>.herokuapp.com",
        }
        for _, url in ipairs(remotes) do
          out:insert("Remote: " .. url)
          local domain, reponame = string.match(url, "[@/]([%w._-]+)[:/]([%w._-]+/?[%w._-]+)")
          local extrainfo = popular_remotes[domain]
          -- Try and cut off the '.git' extension
          reponame = string.match(reponame, "(.+)%.git") or reponame
          if extrainfo then
            out:insert(" -> " .. string.gsub(extrainfo, "<reponame>", reponame))
          end
        end
      end

      -- These are files that are used by Git to determine
      -- what files to ignore. We use this list to make the
      -- loop below (used to determine what kind of application
      -- is in the repository) more generic
      local ignorefiles = {
        ".gitignore",
        ".git/info/exclude",
      }
      local fingerprints = {
        -- Many of these taken from https://github.com/gitignore
        { "%.scala_dependencies", "Scala application" },
        { "npm%-debug%.log", "node.js application" },
        { "joomla%.xml", "Joomla! site" },
        { "jboss/server", "JBoss Java web application" },
        { "wp%-%*%.php", "WordPress site" },
        { "app/config/database%.php", "CakePHP web application" },
        { "sites/default/settings%.php", "Drupal site" },
        { "local_settings%.py", "Django web application" },
        { "/%.bundle", "Ruby on Rails web application" }, -- More specific matches (MyFaces > JSF > Java) on top
        { "%.py[dco]", "Python application" },
        { "%.jsp", "JSP web application" },
        { "%.bundle", "Ruby application" },
        { "%.class", "Java application" },
        { "%.php", "PHP application" },
      }
      local excludefile_that_matched = nil
      local app = nil
      -- We check every file against every fingerprint
      for _, file in ipairs(ignorefiles) do
        if ok(file) then -- we only test all fingerprints if we got the file
          for i, fingerprint in ipairs(fingerprints) do
            if string.match(replies[file].body, fingerprint[1]) then
              out:insert("Based on the file '" .. file .. "', this is a " .. fingerprint[2])
              --  Based on the file '.gitignore', this is a Ruby on Rails application"
              break -- we only want to print our first guess (the most specific one that matched)
            end
          end
        end
      end
    end
  end

  -- Replace non-printing characters with asterisks
  if #out > 0 then return stdnse.format_output(true, out)
  else return nil end
end
