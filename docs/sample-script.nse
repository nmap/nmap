-- -*- mode: lua -*-
-- vim: set filetype=lua :
-- The preceding lines should be left intact to help vim/emacs do syntax
-- highlighting

description = [[
This is an example script for the Nmap Scripting Engine. It is intended to be a
quick way to get started on developing a script without having to find and
modify one that already exists. All important fields are defined here, simply
fill them in with your own details or, if it's an option field, remove. 

To start off, this description field should be a detailed description of what
your script does. The first paragraph will show up on the summary page, so
ensure it's a good high-level overview of your script. Following paragraphs
will appear when the user clicks on the script, and should outline what it
does, how it works, and any other relevant details. 

You should use <code>code tags</code> around any variable names or sample code.
Additionally, you can use:
* Lists
* of
* points
...which will show up as a proper list in the HTML version. 
]]

---
-- @usage
-- This section should simply be the Nmap command to run the script. eg:
-- nmap -p139,445 --script sample-script <host>
--
-- @output
-- This section should contain the output of your script, commented. The output
-- should be from the 'Host script results:' or port line to the bottom of the
-- output. If it's important to show the output from more than one run, put
-- them one after the other. eg:
-- PORT      STATE SERVICE REASON
-- 445/tcp   open  unknown syn-ack
-- | sample-script: 
-- |   This is some output
-- |_    Some more output
--
-- @args sample-script.arg1 Here, we document each argument, how it's used, and
--                          necessary, the default value.
-- @args sample-script.arg2 All arguments should start with the name of the script,
--                          a period, and the name of the argument. 
-- @args sample-script.arg3 This is a convention, not a requirement, but should be
--                          done. 
--

-- Change the 'author' field to your name and handle. We no longer include email
-- addresses. 
author = "<your name/handle goes here>"

-- Only change the license if you don't plan on submitting the plugin to be
-- included with Nmap. 
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"

-- All scripts should be in the category 'safe' or 'intrusive', but not both. 
--
-- Any script that uses external resources (besides the host being scanned) has
-- to be in 'external'. 
--
-- Other categories to consider:
-- * auth: Any script that deals with authentication, whether it's bruteforce or authentication bypass, should be in 'auth'.
-- * default: Any script that is safe, fast, reliable, and useful enough to run every time the user requests a script scan should be in 'default'.
-- * discovery: Any script that attempts to discover more about the network or services should be included in 'discovery'.
-- * dos: Any script that performs a denial of service should be in 'dos'.
-- * exploit: Any script that uses an exploit of some form should be in 'exploit'.
-- * fuzzer: Any script that behaves like a fuzzer (sends random data to a service in an attempt to crash it) should be in 'fuzzer'.
-- * malware: Any script that detects malware should be in the 'malware' category.
-- * version: Scripts in the 'version' category act as an extension to the version scan (-sV) command, are run every time a version scan is run, and supplement the version scan results.
-- * vuln: Scripts that check for specific, known vulnerabilities should be in the 'vuln' category.
categories = { "safe", "intrusive" } -- TODO: remove one or the other.

-- NSELib libraries should be included here.
require 'stdnse'
--require 'shortport' -- Uncomment if you want to use the 'shortport' rule.
--require 'nsedebug' -- Uncomment while you are debuggint to access debug functions.


-- The next section is rules that will cause the script to execute. These can
-- be any one or more of:
-- * portrule: triggered by a specific port being in a given state. Script will run for every port that matches. 
-- * hostrule: triggered by any characteristic about the host, including OS, ports, software version, etc. Runs once per host that matches. 
-- * prerule:  runs before a hostgroup
-- * postrule: runs after a hostgroup

--- 
-- Uncomment this function to use a manual portrule
-- portrule = function( host, port )
--   return true
-- end

---
-- Uncomment any of the following functions (as well as the 'require' line
-- above) to use a simple portrule. See the documentation for the shortport
-- library for more information: http://nmap.org/nsedoc/lib/shortport.html.
--
-- portrule = shortport.portnumber(161, "udp", {"open", "open|filtered"}
-- portrule = shortport.port_or_service({80, 443}, {"http","https"})
-- portrule = shortport.port_or_service(22, "ssh")
-- portrule = shortport.port_or_service(111, "rpcbind", {"tcp", "udp"} )
-- portrule = shortport.service("ftp")
-- portrule = shortport.http

---
-- Uncomment the following function to use a hostrule.
-- hostrule = function( host )
--   return true
-- end

---
-- Uncomment the following function to use a prerule.
-- prerule = function()
--   return true
-- end

---
-- Uncomment the following function to use a postrule.
-- postrule = function()
--   return true
-- end

---
-- Finally, the action function. This is called once for each time the rule
-- function returns true. The host and/or port may be nil depending on what
-- type of rule fired. If you need more than one rule type (for example, a
-- prerule then a hostrule), scroll past this function. 
action = function( host, port )
  -- To read script arguments from the user, use stdnse.get_script_args().
  -- All arguments should start with 'script-name.' - this is a convention
  -- that isn't enforced by the libraries. 
  local arg1, arg2, arg3 = stdnse.get_script_args("sample-script.arg1", "sample-script.arg2", "sample-script.arg3")

  -- To display debug output, use stdnse.print_debug(). All output should be
  -- prefixed with the name of your script.
  stdnse.print_debug(1, "sample-script: This will be displayed to the user")

  -- If your response is a single line, you can simply return it:
  -- return 'response'

  -- If your response is an error, you should return it with the
  -- stdnse.format_output() function (the string 'ERROR: ' will be appended,
  -- and it will only be displayed if debugging is enabled):
  -- return stdnse.format_output(false, "PC Load Letter")

  -- To create a socket, use the nmap.new_socket() function. See the online
  -- documentation here for more information on how to create and use sockets:
  -- http://nmap.org/nsedoc/lib/nmap.html#new_socket
  local s1 = nmap.new_socket('tcp')
  local s2 = nmap.new_socket('udp')

  -- Most socket functions, and many other library functions, return two
  -- values: a status and a result. The status should always be checked:
  local status, err = s1:connect(host, port)
  if(not(status)) then
    return stdnse.format_output(false, "Couldn't connect socket: " .. err)
  end
  
  -- To inspect any variable, use the nsedebug.tostr() function. This should
  -- only be used for debugging, not for actual output. 
  io.write(nsedebug.tostr(host))

  -- To display a string as hex, use the nsedebug.print_hex() function. This
  -- prints hex and, when possible, ASCII. 
  nsedebug.print_hex(host.bin_ip)

  -- If you want your script to add more targets to the Nmap scan, you can use
  -- the target module. First require 'target' above, then perform the
  -- following:
  if(target.ALLOW_NEW_TARGETS) then
    target.add('192.168.1.1')
  end

  -- If your response is more complicated, you can build a table, potentially
  -- with subtables, and pass it to stdnse.format_output(). Each table can have
  -- a list of output values, numerically, which will be displayed in order.
  -- Additionally, they can have the 'name' key, which will be displayed at the
  -- top, and the 'warning' key, which will only be displayed if debugging is
  -- enabled. For more information and examples, see the documentation for
  -- stdnse.format_output().
  --
  -- The following will display:
  -- | sample-script:
  -- |   value1
  -- |   value2
  -- |   This is a subtable
  -- |     subtable1
  -- |_    subtable2
  local response = {'value1', 'value2', {name="This is a subtable", 'subtable1', 'subtable2'}}
  return stdnse.format_output(true, response)
end


---
-- Uncomment the rest of the file and remove the action function above to use a
-- dispatch table instead of a single action. This lets you define different
-- actions for prerule, hostrule, etc.).
--
-- portaction = function(host, port)
-- end
--
-- hostaction = function(host)
-- end
--
-- preaction = function()
-- end
--
-- postaction = function()
-- end
--
--- Function dispatch table
-- local actions = {
--   prerule  = preaction,
--   hostrule = hostaction,
--   portrule = portaction,
--   postrule = postaction
-- }
--
-- function action (...) return actions[SCRIPT_TYPE](...) end
--
--

