local comm = require "comm"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

description = [[
Checks an IRC server for channels that are commonly used by malicious botnets.

Control the list of channel names with the <code>irc-botnet-channels.channels</code>
script argument. The default list of channels is
* loic
* Agobot
* Slackbot
* Mytob
* Rbot
* SdBot
* poebot
* IRCBot
* VanBot
* MPack
* Storm
* GTbot
* Spybot
* Phatbot
* Wargbot
* RxBot
]]

author = "David Fifield, Ange Gutek"

license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

categories = {"discovery", "vuln", "safe"}

---
-- @usage
-- nmap -p 6667 --script=irc-botnet-channels <target>
-- @usage
-- nmap -p 6667 --script=irc-botnet-channels --script-args 'irc-botnet-channels.channels={chan1,chan2,chan3}' <target>
--
-- @args irc-botnet-channels.channels a list of channel names to check for.
--
-- @output
-- | irc-botnet-channels:
-- |   #loic
-- |_  #RxBot


-- See RFC 2812 for protocol documentation.

-- Section 5.1 for protocol replies.
local RPL_TRYAGAIN = "263"
local RPL_LIST = "322"
local RPL_LISTEND = "323"

local DEFAULT_CHANNELS = {
  "loic",
  "Agobot",
  "Slackbot",
  "Mytob",
  "Rbot",
  "SdBot",
  "poebot",
  "IRCBot",
  "VanBot",
  "MPack",
  "Storm",
  "GTbot",
  "Spybot",
  "Phatbot",
  "Wargbot",
  "RxBot",
}

portrule = shortport.port_or_service({6666, 6667, 6697, 6679}, {"irc", "ircs"})

-- Parse an IRC message. Returns nil, errmsg in case of error. Otherwise returns
-- true, prefix, command, params. prefix may be nil. params is an array of
-- strings. The final param has the ':' stripped from the beginning.
--
-- The special return value true, nil indicates an empty message to be ignored.
--
-- See RFC 2812, section 2.3.1 for BNF of a message.
local function irc_parse_message(s)
  local prefix, command, params
  local _, p, t

  s = string.gsub(s, "\r?\n$", "")
  if string.match(s, "^ *$") then
    return true, nil
  end

  p = 0
  _, t, prefix = string.find(s, "^:([^ ]+) +", p + 1)
  if t then
    p = t
  end

  -- We do not check for any special format of the command name or
  -- number.
  _, p, command = string.find(s, "^([^ ]+)", p + 1)
  if not p then
    return nil, "Presumed message is missing a command."
  end

  params = {}
  while p + 1 <= #s do
    local param

    _, p = string.find(s, "^ +", p + 1)
    if not p then
      return nil, "Missing a space before param."
    end
    -- We don't do any checks on the contents of params.
    if #params == 14 then
      params[#params + 1] = string.sub(s, p + 1)
      break
    elseif string.match(s, "^:", p + 1) then
      params[#params + 1] = string.sub(s, p + 2)
      break
    else
      _, p, param = string.find(s, "^([^ ]+)", p + 1)
      if not p then
        return nil, "Missing a param."
      end
      params[#params + 1] = param
    end
  end

  return true, prefix, command, params
end

local function irc_compose_message(prefix, command, ...)
  local parts, params

  parts = {}
  if prefix then
    parts[#parts + 1] = prefix
  end

  if string.match(command, "^:") then
    return nil, "Command may not begin with ':'."
  end
  parts[#parts + 1] = command

  params = {...}
  for i, param in ipairs(params) do
    if not string.match(param, "^[^\0\r\n :][^\0\r\n ]*$") then
      if i < #params then
        return nil, "Bad format for param."
      else
        parts[#parts + 1] = ":" .. param
      end
    else
      parts[#parts + 1] = param
    end
  end

  return stdnse.strjoin(" ", parts) .. "\r\n"
end

local function random_nick()
  return stdnse.generate_random_string(9, "abcdefghijklmnopqrstuvwxyz")
end

local function splitlines(s)
  local lines = {}
  local _, i, j

  i = 1
  while i <= #s do
    _, j = string.find(s, "\r?\n", i)
    lines[#lines + 1] = string.sub(s, i, j)
    if not j then
      break
    end
    i = j + 1
  end

  return lines
end

local function irc_connect(host, port, nick, user, pass)
  local commands = {}
  local irc = {}
  local banner

  -- Section 3.1.1.
  if pass then
    commands[#commands + 1] = irc_compose_message(nil, "PASS", pass)
  end
  nick = nick or random_nick()
  commands[#commands + 1] = irc_compose_message(nil, "NICK", nick)
  user = user or nick
  commands[#commands + 1] = irc_compose_message(nil, "USER", user, "8", "*", user)

  irc.sd, banner = comm.tryssl(host, port, table.concat(commands))
  if not irc.sd then
    return nil, "Unable to open connection."
  end

  irc.sd:set_timeout(60 * 1000)

  -- Buffer these initial lines for irc_readline.
  irc.linebuf = splitlines(banner)

  irc.buf = stdnse.make_buffer(irc.sd, "\r?\n")

  return irc
end

local function irc_disconnect(irc)
  irc.sd:close()
end

local function irc_readline(irc)
  local line

  if next(irc.linebuf) then
    line = table.remove(irc.linebuf, 1)
    if string.match(line, "\r?\n$") then
      return line
    else
      -- We had only half a line buffered.
      return line .. irc.buf()
    end
  else
    return irc.buf()
  end
end

local function irc_read_message(irc)
  local line, err

  line, err = irc_readline(irc)
  if not line then
    return nil, err
  end

  return irc_parse_message(line)
end

local function irc_send_message(irc, prefix, command, ...)
  local line

  line = irc_compose_message(prefix, command, ...)
  irc.sd:send(line)
end

-- Prefix channel names with '#' if necessary and concatenate into a
-- comma-separated list.
local function concat_channel_list(channels)
  local mod = {}

  for _, channel in ipairs(channels) do
    if not string.match(channel, "^#") then
      channel = "#" .. channel
    end
    mod[#mod + 1] = channel
  end

  return stdnse.strjoin(",", mod)
end

function action(host, port)
  local irc
  local search_channels
  local channels
  local errorparams

  search_channels = stdnse.get_script_args(SCRIPT_NAME .. ".channels")
  if not search_channels then
    search_channels = DEFAULT_CHANNELS
  elseif type(search_channels) == "string" then
    search_channels = {search_channels}
  end

  irc = irc_connect(host, port)
  irc_send_message(irc, "LIST", concat_channel_list(search_channels))

  channels = {}
  while true do
    local status, prefix, code, params

    status, prefix, code, params = irc_read_message(irc)
    if not status then
      -- Error message from irc_read_message.
      errorparams = {prefix}
      break
    elseif code == "ERROR" then
      errorparams = params
      break
    elseif code == RPL_TRYAGAIN then
      errorparams = params
      break
    elseif code == RPL_LIST then
      if #params >= 2 then
        channels[#channels + 1] = params[2]
      else
        stdnse.debug1("Got short " .. RPL_LIST .. "response.")
      end
    elseif code == RPL_LISTEND then
      break
    end
  end
  irc_disconnect(irc)

  if errorparams then
    channels[#channels + 1] = "ERROR: " .. stdnse.strjoin(" ", errorparams)
  end

  return stdnse.format_output(true, channels)
end
