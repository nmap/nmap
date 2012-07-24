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
-- Version 1.0
-- Created 27 June 2012 - written by Alex Weber <alexwebr@gmail.com>


local http = require("http")
local shortport = require("shortport")
local stdnse = require("stdnse")
local string = require("string")
local table  = require("table")

description = [[
Checks for a Git repository found in a website's document root (GET /.git/<something> HTTP/1.1)
Gets as much information about the repository as possible, including language/framework, Github
username, last commit message, and repository description.
]]

categories = { "safe", "vuln", "default" }
author = "Alex Weber"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
portrule = shortport.http

local STATUS_OK = 200 -- We consider 200 to mean "okay, file exists and we received its contents"
local out -- The string to return to Nmap
local replies = {}

-- Instead of concatenating everywhere
-- ap is short for 'append'
-- If second argument is nil or false, a new line is made
-- for every call. With 'true', we append to
-- to the most-recently ap()'ed line
local function ap(to_append, append_to_last_entry)
  if not out then out = {} end
  if append_to_last_entry then
    local len = #out
    out[len] = out[len] .. to_append
  else
    table.insert(out, to_append)
  end
end

-- This function returns true if we got a 200 OK when
-- fetching '/filename' from the server
local function ok(filename)
  return (replies[filename].status == STATUS_OK)
end

function action(host, port)
  -- If we can't get /.git/HEAD, don't even bother continuing
  -- We could try for /.git/, but we will not get a 200 if directory
  -- listings are disallowed.
  if http.get(host, port, "/.git/HEAD").status == STATUS_OK then
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
    local prequests = {}
    -- Go through all of the filenames and do an HTTP GET
    for _, name in ipairs(repo) do -- for every filename
      http.pipeline_add('/' .. name, nil, prequests)
    end
    -- do the requests
    replies = http.pipeline(host, port, prequests)
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
    if count.ok == count.tried then
      ap("Git repository found in web root")
    else -- if we didn't find all the files we were hoping to, we might not actually have a repo
      ap("Potential Git repository found in web root")
      ap(" (found " .. tostring(count.ok + 1) .. " of " .. tostring(count.tried + 1) .. " expected files)", true)
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
        for _, matched in ipairs(match_many(reply.body:lower(), interesting)) do -- match all files against 'interesting'
          if not found_anything then -- if this is our first find, print filename and stuff
            ap("Contents of '" .. name .. "' matched patterns '" .. matched .. "'")
            found_anything = true
          else ap(", '" .. matched .. "'", true) end -- if we found something already, tack this pattern onto the end
        end -- If we matched anything, finish the line up
        if found_anything then ap(" (case-insensitive)", true) end
      end
    end

    -- Given a longer plain-text string (a large text file, for example), append
    -- a summary of it (the first 60 characters or the first line, whichever is shorter)
    local function append_short_version(description, original_string)
      local short = string.sub(original_string, 1, 60) -- trim the string first, in case it is huge
      local no_newline = string.match(short, "(.-)\r?\n") -- we don't want such an open-ended regex on a potentially huge string
      -- We try to cut off the newline if we can
      local s = no_newline or short
      ap(description .. ": " .. s)
      -- If we cut off something, we want to put an ellipsis on the end
      if #original_string > #s then
        ap("...", true)
      end
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

    -- This function will take a Git hosting service URL or a service
    -- the allows deployment via Git and find out if there is an entry
    -- for it in the configuration file
    local function lookforremote(config, url, service, success_string)
      -- Different combinations of separating characters in the remote can
      -- indicate the access method - I know about SSH, HTTP, and Smart HTTP
      local access1, access2, reponame = string.match(
        config, "([@/])"..url.."([:/])([%w._-]+/?[%w._-]+)[%s$]")
      if reponame then
        -- Try and cut off the '.git' extension
        reponame = string.match(reponame, "(.+)%.git") or reponame
        ap(service .. " remote: " .. reponame)
        -- git@github:Username... = SSH,  https://github.com/Username... = HTTP{S}
        --    ^      ^    We match on these      ^          ^
        if access1 == "@" and access2 == "/" then
          -- Smart HTTP uses regular HTTP urls, but includes 'username@github.com...'
          ap(" (accessed over Smart HTTP)", true)
        elseif access1 == "@" and access2 == ":" then
          -- SSH syntax is like 'git@github.com:User/repo.git'
          ap(" (accessed over SSH)", true)
        elseif access1 == "/" and access2 == "/" then
          -- 'Dumb' HTTP is read-only, looks like "https://github.com/User/repo.git"
          ap(" (accessed over HTTP, pull-only)", true)
        else
          -- Not sure what / and : could be... perhaps regular, unencrypted Git protocol?
          ap(" (can't determine access method)")
        end
        -- If we did find an entry for this service in the configuration, that might
        -- mean something special (example - Heroku remotes might be deployed somewhere)
        -- We replace '<repo>' with the reponame, <url> with the URL, etc
        if success_string then
          local replace = { reponame = reponame, url = url, service = service }
          ap(string.gsub(success_string, "<(.-)>", replace))
        end
      end
    end

    -- If we got /.git/config, we might find out things like the user's GitHub name,
    -- if they have a Heroku remote, whether this is a bare repository or not (if it
    -- is bare, that means it's likely a remote for other people), and in future
    -- versions of Git when there are more than one repo format version, we will
    -- display that too.
    if ok(".git/config") then
      -- These are some popular / well-known Git hosting services and/or hosting services
      -- that allow deployment via 'git push'
      local popular_remotes = {
        { "github%.com", "GitHub" },
        { "gitorious%.com", "Gitorious" },
        { "bitbucket%.org", "BitBucket" },
        { "heroku%.com", "Heroku", "App might be deployed to http://<reponame>.herokuapp.com" },
      }
      -- Go through all of the popular remotes and look for it in the config file
      for _, remote in ipairs(popular_remotes) do
        lookforremote(replies[".git/config"].body, remote[1], remote[2], remote[3])
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
      { "/%.bundle", "Ruby on Rails application" }, -- More specific matches (MyFaces > JSF > Java) on top
      { "%.py[co]", "Python application" },
      { "%.jsp", "JSP webapp" },
      { "%.class", "Java application" },
    }
    local excludefile_that_matched = nil
    local app = nil
    -- We check every file against every fingerprint
    for _, file in ipairs(ignorefiles) do
      if ok(file) then -- we only test all fingerprints if we got the file
        for i, fingerprint in ipairs(fingerprints) do
          if string.match(replies[file].body, fingerprint[1]) then
            ap("Based on the file '" .. file .. "', this is a " .. fingerprint[2])
            --  Based on the file '.gitignore', this is a Ruby on Rails application"
            break -- we only want to print our first guess (the most specific one that matched)
          end
        end
      end
    end
  end

  -- Replace non-printing characters with asterisks
  if out then return string.gsub(stdnse.format_output(true, out), "[^%w%p%s]", "*")
  else return nil end
end
