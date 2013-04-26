local _G = require "_G"
local bit = require "bit"
local io = require "io"
local math = require "math"
local msrpc = require "msrpc"
local nmap = require "nmap"
local smb = require "smb"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

description = [[
Implements remote process execution similar to the Sysinternals' psexec tool, 
allowing a user to run a series of programs on a remote machine and read the output. This
is great for gathering information about servers, running the same tool on a range of 
system, or even installing a backdoor on a collection of computers. 

This script can run commands present on the remote machine, such as ping or tracert, 
or it can upload a program and run it, such as pwdump6 or a backdoor. Additionally, it 
can read the program's stdout/stderr and return it to the user (works well with ping, 
pwdump6, etc), or it can read a file that the process generated (fgdump, for example, 
generates a file), or it can just start the process and let it run headless (a backdoor
might run like this). 

To use this, a configuration file should be created and edited. Several configuration
files are included that you can customize, or you can write your own. This config file 
is placed in <code>nselib/data/psexec</code> (if you aren't sure where that is, search your system 
for <code>default.lua</code>), then is passed to Nmap as a script argument (for example, 
myconfig.lua would be passed as <code>--script-args=config=myconfig</code>. 

The configuration file consists mainly of a module list. Each module is defined by a lua
table, and contains fields for the name of the program, the executable and arguments 
for the program, and a score of other options. Modules also have an 'upload' field, which
determines whether or not the module is to be uploaded. Here is a simple example of how 
to run <code>net localgroup administrators</code>, which returns a list of users in the "administrators"
group (take a look at the <code>examples.lua</code> configuration file for these examples):

<code>
	mod = {}
	mod.upload           = false
	mod.name             = "Example 1: Membership of 'administrators'"
	mod.program          = "net.exe"
	mod.args             = "localgroup administrators"
	table.insert(modules, mod)
</code>

<code>mod.upload</code> is <code>false</code>, meaning the program should already be
present on the remote system (since 'net.exe' is on every version of Windows, this should
be the case). <code>mod.name</code> defines the name that the program will have in the 
output. <code>mod.program</code> and <code>mod.args</code> obviously define which program
is going to be run. The output for this script is this:

<code>
	|  Example 1: Membership of 'administrators'
	|  | Alias name     administrators
	|  | Comment        Administrators have complete and unrestricted access to the computer/domain
	|  | 
	|  | Members
	|  | 
	|  | -------------------------------------------------------------------------------
	|  | Administrator
	|  | ron
	|  | test
	|  | The command completed successfully.
	|  | 
	|  |_
</code>

That works, but it's really ugly. In general, we can use <code>mod.find</code>, 
<code>mod.replace</code>, <code>mod.remove</code>, and <code>mod.noblank</code> to clean up
the output. For this example, we're going to use <code>mod.remove</code> to remove a lot
of the useless lines, and <code>mod.noblank</code> to get rid of the blank lines that we
don't want:

<code>
	mod = {}
	mod.upload           = false
	mod.name             = "Example 2: Membership of 'administrators', cleaned"
	mod.program          = "net.exe"
	mod.args             = "localgroup administrators"
	mod.remove           = {"The command completed", "%-%-%-%-%-%-%-%-%-%-%-", "Members", "Alias name", "Comment"}
	mod.noblank          = true
	table.insert(modules, mod)
</code>

We can see that the output is now much cleaner:
<code>
|  Example 2: Membership of 'administrators', cleaned
|  | Administrator
|  | ron
|  |_test
</code>

For our next command, we're going to run Windows' ipconfig.exe, which outputs a significant
amount of unnecessary information, and what we do want isn't formatted very nicely. All we
want is the IP address and MAC address, and we get it using <code>mod.find</code> and 
<code>mod.replace</code>:

<code>
	mod = {}
	mod.upload           = false
	mod.name             = "Example 3: IP Address and MAC Address"
	mod.program          = "ipconfig.exe"
	mod.args             = "/all"
	mod.maxtime          = 1
	mod.find             = {"IP Address", "Physical Address", "Ethernet adapter"}
	mod.replace          = {{"%. ", ""}, {"-", ":"}, {"Physical Address", "MAC Address"}}
	table.insert(modules, mod)
</code>

This module searches for lines that contain "IP Address", "Physical Address", or "Ethernet adapter". 
In these lines, a ". " is replaced with nothing, a "-" is replaced with a colon, and the term
"Physical Address" is replaced with "MAC Address" (arguably unnecessary). Run ipconfig /all yourself
to see what we start with, but here's the final output:

<code>
|  Example 3: IP Address and MAC Address
|  | Ethernet adapter Local Area Connection:
|  |    MAC Address: 00:0C:29:12:E6:DB
|  |_   IP Address: 192.168.1.21|  Example 3: IP Address and MAC Address
</code>

Another interesting part of this script is that variables can be used in any script fields. There
are two types of variables: built-in and user-supplied. Built-in variables can be anything found
in the <code>config</code> table, most of which are listed below. The more interesting ones are:
* <code>$lhost</code>: The address of the scanner
* <code>$rhost</code>: The address being scanned
* <code>$path</code>: The path where the scripts are uploaded
* <code>$share</code>: The share where the script was uploaded

User-supplied arguments are given on the commandline, and can be controlled by <code>mod.req_args</code>
in the configuration file. Arguments are given by the user in --script-args; for example, to set $host 
to '1.2.3.4', the user would pass in --script-args=host=1.2.3.4. To ensure the user passes in the host
variable, <code>mod.req_args</code> would be set to <code>{'host'}</code>. 

Here is a module that pings the local ip address:
<code>
	mod = {}
	mod.upload           = false
	mod.name             = "Example 4: Can the host ping our address?"
	mod.program          = "ping.exe"
	mod.args             = "$lhost"
	mod.remove           = {"statistics", "Packet", "Approximate", "Minimum"}
	mod.noblank          = true
	mod.env              = "SystemRoot=c:\\WINDOWS" 
	table.insert(modules, mod)
</code>

And the output:
<code>
|  Example 4: Can the host ping our address?
|  | Pinging 192.168.1.100 with 32 bytes of data:
|  | Reply from 192.168.1.100: bytes=32 time<1ms TTL=64
|  | Reply from 192.168.1.100: bytes=32 time<1ms TTL=64
|  | Reply from 192.168.1.100: bytes=32 time<1ms TTL=64
|  |_Reply from 192.168.1.100: bytes=32 time<1ms TTL=64
</code>

And this module pings an arbitrary address that the user is expected to give:
<code>
	mod = {}
	mod.upload           = false
	mod.name             = "Example 5: Can the host ping $host?"
	mod.program          = "ping.exe"
	mod.args             = "$host"
	mod.remove           = {"statistics", "Packet", "Approximate", "Minimum"}
	mod.noblank          = true
	mod.env              = "SystemRoot=c:\\WINDOWS"
	mod.req_args         = {'host'}
	table.insert(modules, mod)
</code>

And the output (note that we had to up the timeout so this would complete; we'll talk about override
values later):
<code>
$ ./nmap -n -d -p445 --script=smb-psexec --script-args=smbuser=test,smbpass=test,config=examples,host=1.2.3.4 192.168.1.21
[...]
|  Example 5: Can the host ping 1.2.3.4?
|  | Pinging 1.2.3.4 with 32 bytes of data:
|  | Request timed out.
|  | Request timed out.
|  | Request timed out.
|  |_Request timed out.
</code>

For the final example, we'll use the <code>upload</code> command to upload <code>fgdump.exe</code>, run it, 
download its output file, and clean up its logfile. You'll have to put <code>fgdump.exe</code>
in the same folder as the script for this to work:
<code>
	mod = {}
	mod.upload           = true
	mod.name             = "Example 6: FgDump"
	mod.program          = "fgdump.exe"
	mod.args             = "-c -l fgdump.log"
	mod.url              = "http://www.foofus.net/fizzgig/fgdump/"
	mod.tempfiles        = {"fgdump.log"}
	mod.outfile          = "127.0.0.1.pwdump"
	table.insert(modules, mod)
</code>
The <code>-l</code> argument for fgdump supplies the name of the logfile. That file is listed in the 
<code>mod.tempfiles</code> field. What, exactly, does <code>mod.tempfiles</code> do? 
It simply gives the service a list of files to delete while cleaning up. The cleanup 
process will be discussed later. 

<code>mod.url</code> is displayed to the user if <code>mod.program</code> isn't found in
<code>nselib/data/psexec/</code>. And finally, <code>mod.outfile</code> is the file that is downloaded
from the system. This is required because fgdump writes to an output file instead of to 
stdout (pwdump6, for example, doesn't require <code>mod.outfile</code>. 

Now that we've seen a few possible combinations of fields, I present a complete list of all
fields available and what each of them do. Many of them will be familiar, but there are a 
few that aren't discussed in the examples:

* <code>upload</code>     (boolean)  true if it's a local file to upload, false if it's already on the host machine. If <code>upload</code> is true, <code>program</code> has to be in <code>nselib/data/psexec</code>. 
* <code>name</code>       (string)   The name to display above the output. If this isn't given, <code>program</code> .. <code>args</code> are used. 
* <code>program</code>    (string)   If <code>upload</code> is false, the name (fully qualified or relative) of the program on the remote system; if <code>upload</code> is true, the name of the local file that will be uploaded (stored in <code>nselib/data/psexec</code>). 
* <code>args</code>       (string)   Arguments to pass to the process. 
* <code>env</code>        (string)   Environmental variables to pass to the process, as name=value pairs, delimited, per Microsoft's spec, by NULL characters (<code>string.char(0)</code>). 
* <code>maxtime</code>    (integer)  The approximate amount of time to wait for this process to complete. The total timeout for the script before it gives up waiting for a response is the total of all <code>maxtime</code> fields. 
* <code>extrafiles</code> (string[]) Extra file(s) to upload before running the program. These will not be renamed (because, presumably, if they are then the program won't be able to find them), but they will be marked as hidden/system/etc. This may cause a race condition if multiple people are doing this at once, but there isn't much we can do. The files are also deleted afterwards as tempfiles would be. The files have to be in the same directory as programs (<code>nselib/data/psexec</code>), but the program doesn't necessarily need to be an uploaded one. 
* <code>tempfiles</code>  (string[]) A list of temporary files that the process is known to create (if the process does create files, using this field is recommended because it helps avoid making a mess on the remote system).
* <code>find</code>       (string[]) Only display lines that contain the given string(s) (for example, if you're searching for a line that contains "IP Address", set this to <code>{'IP Address'}</code>. This allows Lua-style patterns, see: http://lua-users.org/wiki/PatternsTutorial (don't forget to escape special characters with a <code>%</code>). Note that this is client-side only; the full output is still returned, the rest is removed while displaying. The line of output only needs to match one of the strings given here. 
* <code>remove</code>     (string[]) Opposite of <code>find</code>; this removes lines containing the given string(s) instead of displaying them. Like <code>find</code>, this is client-side only and uses Lua-style patterns. If <code>remove</code> and <code>find</code> are in conflict, then <code>remove</code> takes priority.
* <code>noblank</code>    (boolean)  Setting this to true removes all blank lines from the output.
* <code>replace</code>    (table)    A table of values to replace in the strings returned. Like <code>find</code> and <code>replace</code>, this is client-side only and uses Lua-style patterns. 
* <code>headless</code>   (boolean)  If <code>headless</code> is set to true, the program doesn't return any output; rather, it runs detached from the service so that, when the service ends, the program keeps going. This can be useful for, say, a monitoring program. Or a backdoor, if that's what you're into (a Metasploit payload should work nicely). Not compatible with: <code>find</code>, <code>remove</code>, <code>noblank</code>, <code>replace</code>, <code>maxtime</code>, <code>outfile</code>.
* <code>enabled</code>    (boolean)  Set to false, and optionally set <code>disabled_message</code>, if you don't want a module to run. Alternatively, you can comment out the process. 
* <code>disabled_message</code> (string) Displayed if the module is disabled. 
* <code>url</code>        (string)   A module where the user can download the uploadable file. Displayed if the uploadable file is missing. 
* <code>outfile</code>    (string)   If set, the specified file will be returned instead of stdout. 
* <code>req_args</code>   (string[]) An array of arguments that the user must set in <code>--script-args</code>. 


Any field in the configuration file can contain variables, as discussed. Here are some of the available built-in variables:
* <code>$lhost</code>: local IP address as a string.
* <code>$lport</code>: local port (meaningless; it'll change by the time the module is uploaded since multiple connections are made).
* <code>$rhost</code>: remote IP address as a string.
* <code>$rport</code>: remote port. 
* <code>$lmac</code>:  local MAC address as a string in the xx:xx:xx:xx:xx:xx format (note: requires root).
* <code>$path</code>:  the path where the file will be uploaded to. 
* <code>$service_name</code>: the name of the service that will be running this program
* <code>$service_file</code>: the name of the executable file for the service
* <code>$temp_output_file</code>: The (ciphered) file where the programs' output will be written before being renamed to $output_file
* <code>$output_file</code>: The final name of the (ciphered) output file. When this file appears, the script downloads it and stops the service
* <code>$timeout</code>: The total amount of time the script is going to run before it gives up and stops the process
* <code>$share</code>: The share that everything was uploaded to
* (script args): Any value passed as a script argument will be replaced (for example, if Nmap is run with <code>--script-args=var3=10</code>, then <code>$var3</code> in any field will be replaced with <code>10</code>. See the <code>req_args</code> field above. Script argument values take priority over config values. 

In addition to modules, the configuration file can also contain overrides. Most of these
aren't useful, so I'm not going to go into great detail. Search <code>smb-psexec.nse</code>
for any reference to the <code>config</code> table; any value in the <code>config</code> 
table can be overridden with the <code>overrides</code> table in the module. The most useful
value to override is probably <code>timeout</code>. 

Before and after scripts are run, and when there's an error, a cleanup is performed. in the 
cleanup, we attempt to stop the remote processes, delete all programs, output files, temporary
files, extra files, etc. A lot of effort was put into proper cleanup, since making a mess on 
remote systems is a bad idea. 


Now that I've talked at length about how to use this script, I'd like to spend some time
talking about how it works. 

Running a script happens in several stages:

1) An open fileshare is found that we can write to. Finding an open fileshare basically 
consists of enumerating all shares and seeing which one(s) we have access to. 

2) A "service wrapper", and all of the uploadable/extra files, are uploaded. Before 
they're uploaded, the name of each file is obfuscated. The obfuscation completely 
renames the file, is unique for each source system, and doesn't change between multiple
runs. This obfuscation has the benefit of preventing filenames from overlapping if 
multiple people are running this against the same computer, and also makes it more difficult
to determine their purposes. The reason for keeping them consistent for every run is to 
make cleanup possible: a random filename, if the script somehow fails, will be left on
the system. 

3) A new service is created and started. The new service has a random name for the same 
reason the files do, and points at the 'service wrapper' program that was uploaded. 

4) The service runs the processes.

One by one, the processes are run and their output is captured. The output is obfuscated
using a simple (and highly insecure) xor algorithm, which is designed to prevent casual
sniffing (but won't deter intelligent attackers). This data is put into a temporary output 
file. When all the programs have finished, the file is renamed to the final output file

5) The output file is downloaded, and the cleanup is performced. The file being renamed
triggers the final stage of the program, where the data is downloaded and all relevant
files are deleted. 

6) Output file, now decrypted, is formatted and displayed to the user. 

And that's how it works! 

Please post any questions, or suggestions for better modules, to dev@nmap.org. 

And, as usual, since this tool can be dangerous and can easily be viewed as a malicious 
tool -- use this responsibly, and don't break any laws with it. 

Some ideas for later versions (TODO):
* Set up a better environment for scripts (<code>PATH</code>, <code>SystemRoot</code>, etc). Without this, a lot of programs (especially ones that deal with network traffic) behave oddly. 
* Abstract the code required to run remote processes so other scripts can use it more easily (difficult, but will ultimately be well worth it later). (May actually not be possible. There is a lot of overhead and specialized code in this module. We'll see, though.)
* Let user specify an output file (per-script) so they can, for example, download binary files (don't think it's worthwhile).
* Consider running the external programs in parallel (not sure if the benefits outweigh the drawbacks).
* Let the config request the return code from the process instead of the output (not sure if doing this would be worth the effort).
* Check multiple shares in a single session to save packets (and see where else we can tighten up the amount of traffic).
]]

---
-- @usage
-- nmap --script smb-psexec.nse --script-args=smbuser=<username>,smbpass=<password>[,config=<config>] -p445 <host>
-- sudo nmap -sU -sS --script smb-psexec.nse --script-args=smbuser=<username>,smbpass=<password>[,config=<config>] -p U:137,T:139 <host>
--
-- @output
-- Host script results:
-- |  smb-psexec:
-- |  |  Windows version
-- |  |  |_ Microsoft Windows 2000 [Version 5.00.2195]
-- |  |  IP Address and MAC Address from 'ipconfig.exe'
-- |  |  |  Ethernet adapter Local Area Connection 2:
-- |  |  |         MAC Address: 00:50:56:A1:24:C2
-- |  |  |         IP Address: 10.0.0.30
-- |  |  |  Ethernet adapter Local Area Connection:
-- |  |  |_        MAC Address: 00:50:56:A1:00:65
-- |  |  User list from 'net user'
-- |  |  |  Administrator            TestUser3                Guest
-- |  |  |  IUSR_RON-WIN2K-TEST      IWAM_RON-WIN2K-TEST      nmap
-- |  |  |  rontest123               sshd                     SvcCOPSSH
-- |  |  |_ test1234                 Testing                  TsInternetUser
-- |  |  Membership of 'administrators' from 'net localgroup administrators'
-- |  |  |  Administrator
-- |  |  |  SvcCOPSSH
-- |  |  |  test1234
-- |  |  |_ Testing
-- |  |  Can the host ping our address?
-- |  |  |  Pinging 10.0.0.138 with 32 bytes of data:
-- |  |  |_ Reply from 10.0.0.138: bytes=32 time<10ms TTL=64
-- |  |  Traceroute back to the scanner
-- |  |  |_   1   <10 ms   <10 ms   <10 ms  10.0.0.138
-- |  |  ARP Cache from arp.exe
-- |  |  |    Internet Address      Physical Address      Type
-- |  |  |_   10.0.0.138            00-50-56-a1-27-4b     dynamic
-- |  |  List of listening and established connections (netstat -an)
-- |  |  |    Proto  Local Address          Foreign Address        State
-- |  |  |    TCP    0.0.0.0:22             0.0.0.0:0              LISTENING
-- |  |  |    TCP    0.0.0.0:25             0.0.0.0:0              LISTENING
-- |  |  |    TCP    0.0.0.0:80             0.0.0.0:0              LISTENING
-- |  |  |    TCP    0.0.0.0:135            0.0.0.0:0              LISTENING
-- |  |  |    TCP    0.0.0.0:443            0.0.0.0:0              LISTENING
-- |  |  |    TCP    0.0.0.0:445            0.0.0.0:0              LISTENING
-- |  |  |    TCP    0.0.0.0:1025           0.0.0.0:0              LISTENING
-- |  |  |    TCP    0.0.0.0:1028           0.0.0.0:0              LISTENING
-- |  |  |    TCP    0.0.0.0:1029           0.0.0.0:0              LISTENING
-- |  |  |    TCP    0.0.0.0:3389           0.0.0.0:0              LISTENING
-- |  |  |    TCP    0.0.0.0:4933           0.0.0.0:0              LISTENING
-- |  |  |    TCP    10.0.0.30:139          0.0.0.0:0              LISTENING
-- |  |  |    TCP    127.0.0.1:2528         127.0.0.1:2529         ESTABLISHED
-- |  |  |    TCP    127.0.0.1:2529         127.0.0.1:2528         ESTABLISHED
-- |  |  |    TCP    127.0.0.1:2531         127.0.0.1:2532         ESTABLISHED
-- |  |  |    TCP    127.0.0.1:2532         127.0.0.1:2531         ESTABLISHED
-- |  |  |    TCP    127.0.0.1:5152         0.0.0.0:0              LISTENING
-- |  |  |    TCP    127.0.0.1:5152         127.0.0.1:2530         CLOSE_WAIT
-- |  |  |    UDP    0.0.0.0:135            *:*
-- |  |  |    UDP    0.0.0.0:445            *:*
-- |  |  |    UDP    0.0.0.0:1030           *:*
-- |  |  |    UDP    0.0.0.0:3456           *:*
-- |  |  |    UDP    10.0.0.30:137          *:*
-- |  |  |    UDP    10.0.0.30:138          *:*
-- |  |  |    UDP    10.0.0.30:500          *:*
-- |  |  |    UDP    10.0.0.30:4500         *:*
-- |  |  |_   UDP    127.0.0.1:1026         *:*
-- |  |  Full routing table from 'netstat -nr'
-- |  |  |  ===========================================================================
-- |  |  |  Interface List
-- |  |  |  0x1 ........................... MS TCP Loopback interface
-- |  |  |  0x2 ...00 50 56 a1 00 65 ...... VMware Accelerated AMD PCNet Adapter
-- |  |  |  0x1000004 ...00 50 56 a1 24 c2 ...... VMware Accelerated AMD PCNet Adapter
-- |  |  |  ===========================================================================
-- |  |  |  ===========================================================================
-- |  |  |  Active Routes:
-- |  |  |  Network Destination        Netmask          Gateway       Interface  Metric
-- |  |  |           10.0.0.0    255.255.255.0        10.0.0.30       10.0.0.30      1
-- |  |  |          10.0.0.30  255.255.255.255        127.0.0.1       127.0.0.1      1
-- |  |  |     10.255.255.255  255.255.255.255        10.0.0.30       10.0.0.30      1
-- |  |  |          127.0.0.0        255.0.0.0        127.0.0.1       127.0.0.1      1
-- |  |  |          224.0.0.0        224.0.0.0        10.0.0.30       10.0.0.30      1
-- |  |  |    255.255.255.255  255.255.255.255        10.0.0.30               2      1
-- |  |  |  ===========================================================================
-- |  |  |  Persistent Routes:
-- |  |  |    None
-- |_ |_ |_ Route Table
-- 
--@args config  The config file to use (eg, default). Config files require a .lua extension, and are located in <code>nselib/data/psexec</code>. 
--@args nohide  Don't set the uploaded files to hidden/system/etc.
--@args cleanup Set to only clean up any mess we made (leftover files, processes, etc. on the host OS) on a previous run of the script. 
--              This will attempt to delete the files from every share, not just the first one. This is done to prevent leftover
--              files if the OS changes the ordering of the shares (there's no guarantee of shares coming back in any particular 
--              order)
--              Note that cleaning up is still fairly invasive, since it has to re-discover the proper share, connect to it, 
--              delete files, open the services manager, etc. 
--@args share   Set to override the share used for uploading. This also stops shares from being enumerated, and all other shares
--              will be ignored. No checks are done to determine whether or not this is a valid share before using it. Reqires 
--              <code>sharepath</code> to be set. 
--@args sharepath The full path to the share (eg, <code>"c:\windows"</code>). This is required when creating a service. 
--@args time    The minimum amount of time, in seconds, to wait for the external module to finish (default: <code>15</code>)
--
--@args nocleanup Set to not clean up at all; this leaves the files on the remote system and the wrapper 
--              service installed. This is bad in practice, but significantly reduces the network traffic and makes analysis 
--              easier. 
--@args nocipher Set to disable the ciphering of the returned text (useful for debugging). 
--@args key     Script uses this value instead of a random encryption key (useful for debugging the crypto). 
-----------------------------------------------------------------------

author = "Ron Bowes"
copyright = "Ron Bowes"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"intrusive"}
dependencies = {"smb-brute"}



-- Where we tell the user to get nmap_service.exe if it's not installed.
local NMAP_SERVICE_EXE_DOWNLOAD = "http://nmap.org/psexec/nmap_service.exe"


hostrule = function(host)
	return smb.get_port(host) ~= nil
end

---Get the random-ish filenames used by the service. 
--
--@param host The host table, which the names are based on. 
--@return Status: true or false. 
--@return Name of the remote service, or an error message if status is false. 
--@return Name of the executable file that's run by the service. 
--@return Name of the temporary output file. 
--@return Name of the final output file. 
local function get_service_files(host)
	local status, service_name, service_file, temp_output_file, output_file

	-- Get the name of the service
	status, service_name = smb.get_uniqueish_name(host)
	if(status == false) then
		return false, string.format("Error generating service name: %s", service_name)
	end
	stdnse.print_debug("smb-psexec: Generated static service name: %s", service_name)

	-- Get the name and service's executable file (with a .txt extension for fun)
	status, service_file = smb.get_uniqueish_name(host, "txt")
	if(status == false) then
		return false, string.format("Error generating remote filename: %s", service_file)
	end
	stdnse.print_debug("smb-psexec: Generated static service name: %s", service_name)

	-- Get the temporary output file
	status, temp_output_file = smb.get_uniqueish_name(host, "out.tmp")
	if(status == false) then
		return false, string.format("Error generating remote filename: %s", temp_output_file)
	end
	stdnse.print_debug("smb-psexec: Generated static service filename: %s", temp_output_file)

	-- Get the actual output file
	status, output_file = smb.get_uniqueish_name(host, "out")
	if(status == false) then
		return false, string.format("Error generating remote output file: %s", output_file) 
	end
	stdnse.print_debug("smb-psexec: Generated static output filename: %s", output_file)

	-- Return everything
	return true, service_name, service_file, temp_output_file, output_file
end

---Stop/delete the service and delete the service file.
--
--@param host         The host object. 
--@param config       The table of configuration values. 
function cleanup(host, config)
	local status, err

	-- Add a delay here. For some reason, calling this function too quickly causes SMB to close the connection, 
	-- but even a tiny delay makes that issue go away.  
	stdnse.sleep(.01)

	-- If the user doesn't want to clean up, don't
	if(stdnse.get_script_args( "nocleanup" )) then
		return
	end

	stdnse.print_debug(1, "smb-psexec: Entering cleanup() -- errors here can generally be ignored")
	-- Try stopping the service
	status, err = msrpc.service_stop(host, config.service_name)
	if(status == false) then
		stdnse.print_debug(1, "smb-psexec: [cleanup] Couldn't stop service: %s", err)
	end

	-- Try deleting the service
	status, err = msrpc.service_delete(host, config.service_name)
	if(status == false) then
		stdnse.print_debug(1, "smb-psexec: [cleanup] Couldn't delete service: %s", err)
	end

	-- Delete the files
	for _, share in ipairs(config.all_shares) do
		status, err = smb.file_delete(host, share, config.all_files)
	end

	stdnse.print_debug(1, "smb-psexec: Leaving cleanup()")

	return true
end

---Find the file on the system (checks both Nmap's directories and the current
-- directory). 
--
--@param filename  The name of the file. 
--@param extension The extension of the file (filename without the extension is tried first). 
--@return The full filename, or nil if it couldn't be found. 
local function locate_file(filename, extension)
	stdnse.print_debug(1, "smb-psexec: Attempting to find file: %s", filename)

	extension = extension or ""

	local filename_full = nmap.fetchfile(filename) or nmap.fetchfile(filename .. "." .. extension)

  if(filename_full == nil) then
    local psexecfile = "nselib/data/psexec/" .. filename
    filename_full = nmap.fetchfile(psexecfile) or nmap.fetchfile(psexecfile .. "." .. extension)
  end

  -- check for absolute path or relative to current directory
  if(filename_full == nil) then 
    f, err = io.open(filename, "rb")
    if f == nil then
      stdnse.print_debug(1, "%s: Error opening %s: %s", SCRIPT_NAME, filename, err)
      f, err = io.open(filename .. "." .. extension, "rb")
      if f == nil then
        stdnse.print_debug(1, "%s: Error opening %s.%s: %s", SCRIPT_NAME, filename, extension, err)
        return nil -- unnecessary, but explicit
      else
        f:close()
        return filename .. "." .. extension
      end
    else
      f:close()
      return filename
    end
  end

	return filename_full
end

---Generate an array of all files that will be uploaded/created, including 
-- the temporary file and the output file. This is done so the files can 
-- all be deleted during the cleanup phase. 
--
--@param config The config table. 
--@return The array of files. 
local function get_all_files(config)
	local files = {config.service_file, config.output_file, config.temp_output_file}
	for _, mod in ipairs(config.enabled_modules) do
		-- We're going to delete the module itself
		table.insert(files, mod.upload_name)

		-- We're also going to delete any temp files...
		if(mod.tempfiles) then
			for _, file in ipairs(mod.tempfiles) do
				table.insert(files, file)
			end
		end

		-- ... and any extra files we uploaded ,,,
		if(mod.extrafiles) then
			for _, file in ipairs(mod.extrafiles) do
				table.insert(files, file)
			end
		end

		-- ... not to mention the output file
		if(mod.outfile and mod.outfile ~= "") then
			table.insert(files, mod.outfile)
		end
	end

	return files
end

---Decide which share to use. Unless the user overrides it with the 'share' and 'sharepath' 
-- arguments, a the first writable share is used. 
--
--@param host The host object. 
--@return status true for success, false for failure
--@return share  The share we're going to use, or an error message. 
--@return path   The path on the remote system that points to the share. 
--@return shares A list of all shares on the system (used for cleaning up). 
local function find_share(host)
	local status, share, path, shares

	-- Determine which share to use
	if(nmap.registry.args.share ~= nil) then
		share = nmap.registry.args.share
		shares = {share}
		path = nmap.registry.args.sharepath
		if(path == nil) then
			return false, "Setting the 'share' script-arg requires the 'sharepath' to be set as well."
		end

		stdnse.print_debug(1, "smb-psexec: Using share chosen by the user: %s (%s)", share, path)
	else
		-- Try and find a share to use. 
		status, share, path, shares = smb.share_find_writable(host)
		if(status == false) then
			return false, share .. " (May not have an administrator account)"
		end
		if(path == nil) then
			return false, string.format("Couldn't find path to writable share (we probably don't have admin access): '%s'", share)
		end
		stdnse.print_debug(1, "smb-psexec: Found usable share %s (%s) (all writable shares: %s)", share, path, stdnse.strjoin(", ", shares))
	end

	return true, share, path, shares
end

---Recursively replace all variables in the 'setting' field with string variables
-- found in the 'config' field and in the script-args passed by the user. 
--
--@param config  The configuration table (used as a source of variables to replace). 
--@param setting The current setting field (generally a string or a table). 
--@return setting The setting with all values replaced. 
local function replace_variables(config, setting)
	if(type(setting) == "string") then
		-- Replace module fields with variables in the script-args argument
		for k, v in pairs(nmap.registry.args) do
			setting = string.gsub(setting, "$"..k, v)
		end

		-- Replace module fields with variables in the config file
		for k, v in pairs(config) do
			if((type(v) == "string" or type(v) == "boolean" or type(v) == "number") and k ~= "key") then
				setting = string.gsub(setting, "$"..k, v)
			end
		end
	elseif(type(setting) == "table") then
		for k, v in pairs(setting) do
			setting[k] = replace_variables(config, v)
		end
	end

	return setting
end

---Takes the 'overrides' field from a module and replace any configuration variables.
--
--@param config    The config table. 
--@param overrides The overrides we're replacing values with. 
--@return config   The new config table. 
local function do_overrides(config, overrides)
	if(overrides) then
		if(type(overrides) == 'string') then
			overrides = {overrides}
		end
	
		for i, v in pairs(overrides) do
			config[i] = v
		end
	end
	
	return config
end

---Reads, prepares, parses, sanity checks, and pre-processes the configuration file (either the 
-- default, or the file passed as a parameter). 
--
--@param host The host table.
--@param config A table to fill with configuration values.
--@return status true or false
--@return config The configuration table or an error message. 
local function get_config(host, config)
	local status
	local filename = nmap.registry.args.config
	config.enabled_modules  = {}
	config.disabled_modules = {}

	-- Find the config file
	filename = locate_file(filename or 'default', 'lua')
	if(filename == nil) then
		return false, "Couldn't locate config file: file not found (make sure it has a .lua extension and is in nselib/data/psexec/)"
	end

	-- Load the config file
	local env = setmetatable({modules = {}; overrides = {}; module = function() stdnse.print_debug(1, "WARNING: Selected config file contains an unnecessary call to module()") end}, {__index = _G})
	stdnse.print_debug(1, "smb-psexec: Attempting to load config file: %s", filename)
	local file = loadfile(filename, "t", env)
	if(not(file)) then
		return false, "Couldn't load module file:\n" .. filename
	end

	-- Run the config file
	file()
	local modules = env.modules
	local overrides = env.overrides

	-- Generate a cipher key
	if(stdnse.get_script_args( "nocipher" )) then
		config.key = ""
	elseif(nmap.registry.args.key) then
		config.key = nmap.registry.args.key
	else
		config.key = ""
		for i = 1, 127, 1 do
			config.key = config.key .. string.char(math.random(0x20, 0x7F))
		end
		config.key_index = 0
	end

	-- Initialize the timeout
	config.timeout = 0

	-- Figure out which share we're using (this is the first place in the script where a lot of traffic is generated -- 
	-- any possible sanity checking should be done before this)
	status, config.share, config.path, config.all_shares = find_share(host)
	if(not(status)) then
		return false, config.share
	end

	-- Get information about the socket; it's a bit out of place here, but it should go before the mod loop
	status, config.lhost, config.lport, config.rhost, config.rport, config.lmac = smb.get_socket_info(host)
	if(status == false) then
		return false, "Couldn't get socket information: " .. config.lhost
	end

	-- Get the names of the files we're going to need
	status, config.service_name, config.service_file, config.temp_output_file, config.output_file = get_service_files(host)
	if(not(status)) then
		return false, config.service_name
	end

	-- Make sure the modules loaded properly
	-- NOTE: If you're here because of an error that 'modules' is undefined, it's likely because your configuration file doesn't have a 
	-- proper modules table, or your configuration file has a module() declaration at the top. 
	if(not(modules) or #modules == 0) then
		return false, string.format("Configuration file (%s) doesn't have a proper 'modules' table.", filename)
	end

	-- Make sure we got a proper modules array
	if(type(modules) ~= "table") then
		return false, string.format("The chosen configuration file, %s.lua, doesn't have a proper 'modules' table. If possible, it should be modified to have a public array called 'modules' that contains a list of all modules that will be run.", filename)
	end

	-- Loop through the modules for some pre-processing
	stdnse.print_debug(1, "smb-psexec: Verifying uploadable executables exist")
	for i, mod in ipairs(modules) do
		local enabled = true
		-- Do some sanity checking
		if(mod.program == nil) then
			enabled = false
			if(mod.name) then
				mod.disabled_message = string.format("Configuration error: '%s': module doesn't have a program", mod.name)
			else
				mod.disabled_message = string.format("Configuration error: Module #%d doesn't have a program", i)
			end
		end

		-- Set some defaults, if the user didn't specify
		mod.name    = mod.name or (string.format("%s %s", mod.program, mod.args or ""))
		mod.maxtime = mod.maxtime or 1

		-- Check if they forgot the uploadbility
		if(mod.upload == nil) then
			enabled = false
			mod.disabled_message = string.format("Configuration error: '%s': 'upload' field is required", mod.name)
		end

		-- Check if the upload field is set wrong
		if(mod.upload ~= true and mod.upload ~= false) then
			enabled = false
			mod.disabled_message = string.format("Configuration error: '%s': 'upload' field has to be true or false", mod.name)
		end

		-- Check for incompatible fields with 'headless'
		if(mod.headless) then
			if(mod.find or mod.remove or mod.noblank or mod.replace or (mod.maxtime > 1) or mod.outfile) then
				enabled = false
				mod.disabled_message = string.format("Configuration error: '%s': 'headless' is incompatible with find, remove, noblank, replace, and maxtime", mod.name)
			end
		end

		-- Check for improperly formatted 'replace'
		if(mod.replace) then
			if(type(mod.replace) ~= "table") then
				enabled = false
				mod.disabled_message = string.format("Configuration error: '%s': 'replace' has to be a table of one-element tables (eg. replace = {{'a'='b'}, {'c'='d'}})", mod.name)
			end

			for _, v in ipairs(mod.replace) do
				if(type(v) ~= 'table') then
					enabled = false
					mod.disabled_message = string.format("Configuration error: '%s': 'replace' has to be a table of one-element tables (eg. replace = {{'a'='b'}, {'c'='d'}})", mod.name)
				end
			end
		end

		-- Set some default values
		if(mod.headless == nil) then
			mod.headless = false
		end
		if(mod.include_stderr == nil) then
			mod.include_stderr = true
		end

		-- Make sure required arguments are given
		if(mod.req_args) then
			if(type(mod.req_args) == 'string') then
				mod.req_args = {mod.req_args}
			end

			-- Keep a table of missing args so we can tell the user all the args they're missing at once
			local missing_args = {}
			for _, arg in ipairs(mod.req_args) do
				if(nmap.registry.args[arg] == nil) then
					table.insert(missing_args, arg)
				end
			end

			if(#missing_args > 0) then
				enabled = false
				mod.disabled_message = {}
				table.insert(mod.disabled_message, string.format("Configuration error: Required argument(s) ('%s') weren't given.", stdnse.strjoin("', '", missing_args)))
				table.insert(mod.disabled_message, string.format("Please add --script-args=[arg]=[value] to your commandline to run this module"))
				if(#missing_args == 1) then
					table.insert(mod.disabled_message, string.format("For example: --script-args=%s=123", missing_args[1]))
				else
					table.insert(mod.disabled_message, string.format("For example: --script-args=%s=123,%s=456...", missing_args[1], missing_args[2]))
				end
			end
		end

		-- Checks for the uploadable modules
		if(mod.upload) then
			-- Check if the module actually exists
			stdnse.print_debug(1, "smb-psexec: Looking for uploadable module: %s or %s.exe", mod.program, mod.program)
			mod.filename = locate_file(mod.program, "exe")
			if(mod.filename == nil) then
				enabled = false
				stdnse.print_debug(1, "Couldn't find uploadable module %s, disabling", mod.program)
				mod.disabled_message = {string.format("Couldn't find uploadable module %s, disabling", mod.program)}
				if(mod.url) then
					stdnse.print_debug(1, "You can try getting it from: %s", mod.url)
					table.insert(mod.disabled_message, string.format("You can try getting it from: %s", mod.url))
					table.insert(mod.disabled_message, "And placing it in Nmap's nselib/data/psexec/ directory")
				end
			else
				-- We found it
				stdnse.print_debug(1, "smb-psexec: Found: %s", mod.filename)

				-- Generate a name to upload them as (we don't upload with the original names)
				status, mod.upload_name = smb.get_uniqueish_name(host, "txt", mod.filename)
				if(not(status)) then
					return false, "Couldn't generate name for uploaded file: " .. mod.upload_name
				end
				stdnse.print_debug("smb-psexec: Will upload %s as %s", mod.filename, mod.upload_name)
			end
		end


		-- Prepare extra files
		if(enabled and mod.extrafiles) then	
			-- Make sure we have an array to help save on duplicate code
			if(type(mod.extrafiles) == "string") then
				mod.extrafiles = {mod.extrafiles}
			end

			-- Loop through all of the extra files
			mod.extrafiles_paths = {}
			for i, extrafile in ipairs(mod.extrafiles) do
				stdnse.print_debug(1, "smb-psexec: Looking for extra module: %s", extrafile)
				mod.extrafiles_paths[i] = locate_file(extrafile)
				if(mod.extrafiles_paths[i] == nil) then
					return false, string.format("Couldn't find required file to upload: %s", extrafile)
				end
				stdnse.print_debug(1, "smb-psexec: Found: %s", mod.extrafiles_paths[i])
			end
		end

		-- Add the timeout to the total
		config.timeout = config.timeout + mod.maxtime

		-- Add the module to the appropriate list
		if(enabled) then
			table.insert(config.enabled_modules, mod)
		else
			table.insert(config.disabled_modules, mod)
		end
	end

	-- Make a list of *all* files (used for cleaning up)
	config.all_files = get_all_files(config)

	-- Finalize the timeout
	local max_timeout = nmap.registry.args.timeout or 15
	config.timeout = math.max(config.timeout, max_timeout)
	stdnse.print_debug(1, "smb-psexec: Timeout waiting for a response is %d seconds", config.timeout)

	-- Do config overrides
	if(overrides) then
		config = do_overrides(config, overrides)
	end

	-- Replace variable values in the configuration (this has to go last)
	stdnse.print_debug(1, "smb-psexec: Replacing variables in the modules' fields")
	for i, mod in ipairs(config.enabled_modules) do
		for k, v in pairs(mod) do
			mod[k] = replace_variables(config, v)
		end
	end

	return true, config
end

---Cipher (or uncipher) a string with a weak xor-based encryption. 
--
--@args str    The string go cipher/uncipher.
--@args config The config file for this host (stores the encryption key).
--@return      The decrypted string. 
local function cipher(str, config)
	local result = ""
	if(config.key == "") then
		return str
	end

	for i = 1, #str, 1 do
		local c = string.byte(str, i)
		c = string.char(bit.bxor(c, string.byte(config.key, config.key_index + 1)))

		config.key_index = config.key_index + 1
		config.key_index = config.key_index % #config.key

		result = result .. c
	end

	return result
end

local function get_overrides()
	-- Create some overrides:
	-- 0x00004000 = Encrypted
	-- 0x00002000 = Don't index this file
	-- 0x00000100 = Temporary file
	-- 0x00000800 = Compressed file
	-- 0x00000002 = Hidden file
	-- 0x00000004 = System file
	local attr = bit.bor(0x00000004,0x00000002,0x00000800,0x00000100,0x00002000,0x00004000)

	-- Let the user override this behaviour
	if(stdnse.get_script_args( "nohide" )) then
		attr = 0
	end

	-- Create the overrides
	return {file_create_attributes=attr}
end

--- Check if an nmap_service.exe file is the XOR-encoded version from the 5.21
-- release. It works by checking the first few bytes against a known pattern.
-- Returns <code>true</code> or <code>false</code>, or else <code>nil</code> and
-- an error message.
-- @param filename the name of the file to check.
-- @return status
-- @return error message
local function service_file_is_xor_encoded(filename)
	local f, bytes, msg

	f, msg = io.open(filename)
	if not f then
		return nil, msg
	end
	bytes = f:read(2)
	f:close()
	if not bytes or #bytes < 2 then
		return nil, "Can't read from service file"
	end
	-- This is the XOR-inverse of "MZ".
	return bytes == string.char(0xb2, 0xa5)
end

---Upload all of the uploadable files to the remote system. 
--
--@param host The host table. 
--@param config The configuration table. 
--@return status true or false
--@return err    An error message if status is false. 
local function upload_everything(host, config)
	local is_xor_encoded, msg
	local overrides = get_overrides()

	-- In Nmap 5.20, it was discovered that nmap_service.exe file was
	-- causing false positives in antivirus software. In an effort to avoid
	-- this, in version 5.21 the file was obfuscated by XORing all its bytes
	-- with 0xFF. That didn't work, so now the file is not included in the
	-- distribution. But it means we must check if we are dealing with the
	-- original or XOR-encoded version of the file.
	is_xor_encoded, msg = service_file_is_xor_encoded(config.local_service_file)
	if is_xor_encoded == nil then
		return nil, msg
	elseif is_xor_encoded then
		stdnse.print_debug(2, "%s is the XOR-encoded version from the 5.21 release.", config.local_service_file)
	end

	-- Upload the service file
	stdnse.print_debug(1, "smb-psexec: Uploading: %s => \\\\%s\\%s", config.local_service_file, config.share, config.service_file)
	local status, err
	status, err = smb.file_upload(host, config.local_service_file, config.share, "\\" .. config.service_file, overrides, is_xor_encoded)
	if(status == false) then
		cleanup(host, config)
		return false, string.format("Couldn't upload the service file: %s\n", err)
	end
	stdnse.print_debug(1, "smb-psexec: Service file successfully uploaded!")

	-- Upload the modules and all their extras
	stdnse.print_debug(1, "smb-psexec: Attempting to upload the modules")
	for _, mod in ipairs(config.enabled_modules) do
		-- If it's an uploadable module, upload it
		if(mod.upload) then
			stdnse.print_debug(1, "smb-psexec: Uploading: %s => \\\\%s\\%s", mod.filename, config.share, mod.upload_name)
			status, err = smb.file_upload(host, mod.filename, config.share, "\\" .. mod.upload_name, overrides)
			if(status == false) then
				cleanup(host, config)
				return false, string.format("Couldn't upload module %s: %s\n", mod.program, err)
			end
		end

		-- If it requires extra files, upload them, too
		if(mod.extrafiles) then
			-- Convert to a table, if it's a string
			if(type(mod.extrafiles) == "string") then
				mod.extrafiles = {mod.extrafiles}
			end

			-- Loop over the files and upload them
			for i, extrafile in ipairs(mod.extrafiles) do
				local extrafile_local = mod.extrafiles_paths[i]

				stdnse.print_debug(1, "smb-psexec: Uploading extra file: %s => \\\\%s\\%s", extrafile_local, config.share, extrafile)
				status, err = smb.file_upload(host, extrafile_local, config.share, extrafile, overrides)
				if(status == false) then
					cleanup(host, config)
					return false, string.format("Couldn't upload extra file %s: %s\n", extrafile_local, err)
				end
			end
		end
	end
	stdnse.print_debug(1, "smb-psexec: Modules successfully uploaded!")

	return true
end

---Create the service on the remote system. 
--@param host   The host object.
--@param config The configuration table. 
--@return status true or false
--@return err    An error message if status is false. 
local function create_service(host, config)
	local status, err = msrpc.service_create(host, config.service_name, config.path .. "\\" .. config.service_file)
	if(status == false) then
		stdnse.print_debug(1, "smb-psexec: Couldn't create the service: %s", err)
		cleanup(host, config)

		if(string.find(err, "MARKED_FOR_DELETE")) then
			return false, string.format("Service is stuck in 'being deleted' phase on remote machine; try setting script-args=randomseed=abc for now", err)
		else
			return false, string.format("Couldn't create the service on the remote machine: %s", err)
		end
	end

	return true
end

---Create the list of parameters we're using to start the service. This consists
-- of a few global params, then a group of parameters with options for each process 
-- that's going to be started. 
--
--@param config The configuration table. 
--@return status true or false
--@return params A table of parameters if status is true, or an error message if status is false. 
local function get_params(config)
	local count = 0

	-- Build the table of parameters to pass to the service
	local params = {}
	table.insert(params, config.path .. "\\" .. config.output_file)
	table.insert(params, config.path .. "\\" .. config.temp_output_file)
	table.insert(params, tostring(#config.enabled_modules))
	table.insert(params, "0") 
	table.insert(params, config.key)
	table.insert(params, config.path)
	for _, mod in ipairs(config.enabled_modules) do
		if(mod.upload) then
			table.insert(params, config.path .. "\\" .. mod.upload_name .. " " .. (mod.args or ""))
		else
			table.insert(params, mod.program .. " " .. (mod.args or ""))
		end

		table.insert(params, (mod.env or ""))
		table.insert(params, tostring(mod.headless))
		table.insert(params, tostring(mod.include_stderr))
		table.insert(params, mod.outfile or "")
	end

	return true, params
end

---Start the service on the remote machine. 
--
--@param host   The host object.
--@param config The configuration table. 
--@param params The parameters to pass to the service, likely from the <code>get_params</code> function. 
--@return status true or false
--@return err    An error message if status is false. 
local function start_service(host, config, params)
	local status, err = msrpc.service_start(host, config.service_name, params)
	if(status == false) then
		stdnse.print_debug(1, "smb-psexec: Couldn't start the service: %s", err)
		return false, string.format("Couldn't start the service on the remote machine: %s", err)
	end

	return true
end

---Poll for the output file on the remote machine until either the file is created, or the timeout
-- expires. 
--
--@param host   The host object.
--@param config The configuration table. 
--@return status true or false
--@return result The file if status is true, or an error message if status is false. 

local function get_output_file(host, config)
	stdnse.print_debug(1, "smb-psexec: Waiting for output file to be created (timeout = %d seconds)", config.timeout)
	local status, result

	local i = config.timeout
	while true do
		status, result = smb.file_read(host, config.share, "\\" .. config.output_file, nil, {file_create_disposition=1})

		if(not(status) and result ~= "NT_STATUS_OBJECT_NAME_NOT_FOUND") then
			-- An unexpected error occurred
			stdnse.print_debug(1, "smb-psexec: Couldn't read the file: %s", result)
			cleanup(host, config)
   
			return false, string.format("Couldn't read the file from the remote machine: %s", result)
		end

		if(not(status) and result == "NT_STATUS_OBJECT_NAME_NOT_FOUND") then
			-- An expected error occurred; if this happens, we just wait
			if(i == 0) then
				stdnse.print_debug(1, "smb-psexec: Error in remote service: output file was never created!")
				cleanup(host, config)

				return false, string.format("Error in remote service: output file was never created")
			end

			stdnse.print_debug(1, "smb-psexec: Output file %s doesn't exist yet, waiting for %d more seconds", config.output_file, i)
			stdnse.sleep(1)
			i = i - 1
		end

		if(status) then
			break
		end
	end

	return true, result
end

---Decide whether or not a line should be included in the output file, based on the module's
-- find, remove, and noblank settings. 
local function should_be_included(mod, line)
	local removed, found

	-- Remove lines from the output, if the module requested it
	removed = false
	if(mod.remove and #mod.remove > 0) then
		-- Make a single string into a table to save code
		if(type(mod.remove) ~= 'table') then
			mod.remove = {mod.remove}
		end

		-- Loop through the module's find table to see if any of the lines match
		for _, remove in ipairs(mod.remove) do
			if(string.match(line, remove)) then
				removed = true
				break
			end
		end
	end

	-- Remove blank lines if we're supposed to
	if(mod.noblank and line == "") then	
		removed = true
	end

	-- If the line wasn't removed, and we are searching for specific text, do the search
	found   = false
	if(mod.find and #mod.find > 0 and not(removed)) then
		-- Make a single string a table to save duplicate code
		if(type(mod.find) ~= 'table') then
			mod.find = {mod.find}
		end

		-- Loop through the module's find table to see if any of the lines match
		for _, find in ipairs(mod.find) do
			if(string.match(line, find)) then
				found = true
				break
			end
		end
	else
		found = true
	end

	-- Only display the line if it's found and not removed
	return (found and not(removed))
end

---Alter a line based on the module's 'replace' setting. 
local function do_replacements(mod, line)
	if(mod.replace) then
		for _, v in pairs(mod.replace) do

			-- It looks like Lua doesn't like replacing the null character, so have a sidecase for it
			if(v[1] == string.char(0)) then
				local newline = ""
				for i = 1, #line, 1 do
					local char = string.sub(line, i, i)
					if(string.byte(char) == 0) then
						newline = newline .. v[2]
					else
						newline = newline .. char
					end
				end
				line = newline
			else
				line = string.gsub(line, v[1], v[2])
			end
		end
	end

	return line
end

---Parse the output file into a neat array. 
local function parse_output(config, data)
	-- Allow 'data' to be nil. This lets us skip most of the effort when all mods are disabled
	data = data or ""

	-- Split the result at newlines
	local lines = stdnse.strsplit("\n", data)

	local module_num = -1
	local mod = nil
	local result = nil

	-- Loop through the lines and parse them into the results table
	local results = {}
	for _, line in ipairs(lines) do
		if(line ~= "") then
			local this_module_num = tonumber(string.sub(line, 1, 1))

			-- Get the important part of the line
			line = string.sub(line, 2)

			-- Remove the Windows endline (0x0a) from the string (these are left in up to this point to maintain
			-- the ability to download binary files, if that ever comes up
			line = string.gsub(line, "\r", "")

			-- If the module_number has changed, increment to the next module
			if(this_module_num ~= (module_num % 10)) then
				-- Increment our module number
				if(module_num < 0) then
					module_num = 0
				else
					module_num = module_num + 1
				end


				-- Go to the next module, and make sure it exists
				mod = config.enabled_modules[module_num + 1]
				if(mod == nil) then
					stdnse.print_debug(1, "Server's response wasn't formatted properly (mod %d); if you can reproduce, place report to dev@nmap.org", module_num)
					stdnse.print_debug(1, "--\n" .. string.gsub("%%", "%%", data) .. "\n--")
					return false, "Server's response wasn't formatted properly; if you can reproduce, place report to dev@nmap.org"
				end

				-- Save this result
				if(result ~= nil) then
					table.insert(results, result)
				end
				result = {}
				result['name'] = "<no name>"
				result['lines'] = {}
					
				if(mod.name) then
					result['name'] = mod.name
				else
					result['name'] = string.format("'%s %s;", mod.program, (mod.args or ""))
				end
			end


			local include = should_be_included(mod, line)

			-- If we're including it, do the replacements
			if(include) then
				line = do_replacements(mod, line)
				table.insert(result, line)
			end
		end
	end

	table.insert(results, result)

	-- Loop through the disabled modules and print them out
	for _, mod in ipairs(config.disabled_modules) do
		local result = {}
		result['name'] = mod.name
		if(mod.disabled_message == nil) then
			mod.disabled_message = {"No reason for disabling the module was found"}
		end

		if(type(mod.disabled_message) == 'string') then
			mod.disabled_message = {mod.disabled_message}
		end

		for _, message in ipairs(mod.disabled_message) do
			table.insert(result, "WARNING: " .. message)
		end

		table.insert(results, result)
	end

	return true, results
end

action = function(host)
	local status, result, err
	local key

	local i

	local params

	local config = {}
	local files

	-- First check for nmap_service.exe; we can't do anything without it.
	stdnse.print_debug(1, "smb-psexec: Looking for the service file: nmap_service or nmap_service.exe")
	config.local_service_file = locate_file("nmap_service", "exe")
	if (config.local_service_file == nil) then
		if nmap.verbosity() > 0 then
			return string.format([[
Can't find the service file: nmap_service.exe (or nmap_service).
Due to false positives in antivirus software, this module is no
longer included by default. Please download it from
%s
and place it in nselib/data/psexec/ under the Nmap DATADIR.
]], NMAP_SERVICE_EXE_DOWNLOAD)
		else
			return
		end
	end

	-- Parse the configuration file
	status, config = get_config(host, config)
	if(not(status)) then
		return stdnse.format_output(false, config)
	end

	if(#config.enabled_modules > 0) then
		-- Start by cleaning up, just in case. 
		cleanup(host, config)
	
		-- If the user just wanted a cleanup, do it
		if(stdnse.get_script_args( "cleanup" )) then
			return stdnse.format_output(true, "Cleanup complete.")
		end
	
		-- Check if any of the files exist
		status, result, files = smb.files_exist(host, config.share, config.all_files, {})
		if(not(status)) then
			return stdnse.format_output(false, "Couldn't log in to check for remote files: " .. result)
		end
		if(result > 0) then
			local response = {}
			table.insert(response, "One or more output files already exist on the host, and couldn't be removed. Try:")
			table.insert(response, "* Running the script with --script-args=cleanup=1 to force a cleanup (passing -d and looking for error messages might help),")
			table.insert(response, "* Running the script with --script-args=randomseed=ABCD (or something) to change the name of the uploaded files,")
			table.insert(response, "* Changing the share and path using, for example, --script-args=share=C$,sharepath=C:, or")
			table.insert(response, "* Deleting the affected file(s) off the server manually (\\\\" .. config.share .. "\\" .. stdnse.strjoin(", \\\\" .. config.share .. "\\", files) .. ")")
			return stdnse.format_output(false, response)
		end
	
		-- Upload the modules
		status, err = upload_everything(host, config)
		if(not(status)) then
			cleanup(host, config)
			return stdnse.format_output(false, err)
		end
	
		-- Create the service
		status, err = create_service(host, config)
		if(not(status)) then
			cleanup(host, config)
			return stdnse.format_output(false, err)
		end
	
		-- Get the table of parameters to pass to the service when we start it
		status, params = get_params(config)
		if(not(status)) then
			cleanup(host, config)
			return stdnse.format_output(false, params)
		end
	
		-- Start the service
		status, params = start_service(host, config, params)
		if(not(status)) then
			cleanup(host, config)
			return stdnse.format_output(false, params)
		end

		-- Get the result
		status, result = get_output_file(host, config, config.share)
		if(not(status)) then
			cleanup(host, config)
			return stdnse.format_output(false, result)
		end

		-- Do a final cleanup
		cleanup(host, config)
	
		-- Uncipher the file
		result = cipher(result, config)
	end

	-- Build the output into a nice table
	local response
	status, response = parse_output(config, result)
	if(status == false) then
		return stdnse.format_output(false, "Couldn't parse output: " .. response)
	end

	-- Add a warning if nothing was enabled
	if(#config.enabled_modules == 0) then
		if(#response == 0) then
			response = {"No modules were enabled! Please check your configuration file."}
		else
			table.insert(response, "No modules were enabled! Please fix any errors displayed above, or check your configuration file.")
		end
	end

	-- Return the string
	return stdnse.format_output(true, response)
end

