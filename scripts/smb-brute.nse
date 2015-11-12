local bit = require "bit"
local math = require "math"
local msrpc = require "msrpc"
local nmap = require "nmap"
local smb = require "smb"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"
local unpwdb = require "unpwdb"

description = [[
Attempts to guess username/password combinations over SMB, storing discovered combinations
for use in other scripts. Every attempt will be made to get a valid list of users and to
verify each username before actually using them. When a username is discovered, besides
being printed, it is also saved in the Nmap registry so other Nmap scripts can use it. That
means that if you're going to run <code>smb-brute.nse</code>, you should run other <code>smb</code> scripts you want.
This checks passwords in a case-insensitive way, determining case after a password is found,
for Windows versions before Vista.

This script is specifically targeted towards security auditors or penetration testers.
One example of its use, suggested by Brandon Enright, was hooking up <code>smb-brute.nse</code> to the
database of usernames and passwords used by the Conficker worm (the password list can be
found at http://www.skullsecurity.org/wiki/index.php/Passwords, among other places.
Then, the network is scanned and all systems that would be infected by Conficker are
discovered.

From the penetration tester perspective its use is pretty obvious. By discovering weak passwords
on SMB, a protocol that's well suited for bruteforcing, access to a system can be gained.
Further, passwords discovered against Windows with SMB might also be used on Linux or MySQL
or custom Web applications. Discovering a password greatly beneficial for a pen-tester.

This script uses a lot of little tricks that I (Ron Bowes) describe in detail in a blog
posting, http://www.skullsecurity.org/blog/?p=164. The tricks will be summarized here, but
that blog is the best place to learn more.

Usernames and passwords are initially taken from the unpwdb library. If possible, the usernames
are verified as existing by taking advantage of Windows' odd behaviour with invalid username
and invalid password responses. As soon as it is able, this script will download a full list
of usernames from the server and replace the unpw usernames with those. This enables the
script to restrict itself to actual accounts only.

When an account is discovered, it's saved in the <code>smb</code> module (which uses the Nmap
registry). If an account is already saved, the account's privileges are checked; accounts
with administrator privileges are kept over accounts without. The specific method for checking
is by calling <code>GetShareInfo("IPC$")</code>, which requires administrative privileges. Once this script
is finished (all other smb scripts depend on it, it'll run first), other scripts will use the saved account
to perform their checks.

The blank password is always tried first, followed by "special passwords" (such as the username
and the username reversed). Once those are exhausted, the unpwdb password list is used.

One major goal of this script is to avoid account lockouts. This is done in a few ways. First,
when a lockout is detected, unless you user specifically overrides it with the <code>smblockout</code>
argument, the scan stops. Second, all usernames are checked with the most common passwords first,
so with not-too-strict lockouts (10 invalid attempts), the 10 most common passwords will still
be tried. Third, one account, called the canary, "goes out ahead"; that is, three invalid
attempts are made (by default) to ensure that it's locked out before others are.

In addition to active accounts, this script will identify valid passwords for accounts that
are disabled, guest-equivalent, and require password changes. Although these accounts can't
be used, it's good to know that the password is valid. In other cases, it's impossible to
tell a valid password (if an account is locked out, for example). These are displayed, too.
Certain accounts, such as guest or some guest-equivalent, will permit any password. This
is also detected. When possible, the SMB protocol is used to its fullest to get maximum
information.

When possible, checks are done using a case-insensitive password, then proper case is
determined with a fairly efficient bruteforce. For example, if the actual password is
"PassWord", then "password" will work and "PassWord" will be found afterwards (on the
14th attempt out of a possible 256 attempts, with the current algorithm).
]]
---
--@usage
-- nmap --script smb-brute.nse -p445 <host>
-- sudo nmap -sU -sS --script smb-brute.nse -p U:137,T:139 <host>
--
--@output
-- Host script results:
-- | smb-brute:
-- |   bad name:test => Valid credentials
-- |   consoletest:test => Valid credentials, password must be changed at next logon
-- |   guest:<anything> => Valid credentials, account disabled
-- |   mixcase:BuTTeRfLY1 => Valid credentials
-- |   test:password1 => Valid credentials, account expired
-- |   this:password => Valid credentials, account cannot log in at current time
-- |   thisisaverylong:password => Valid credentials
-- |   thisisaverylongname:password => Valid credentials
-- |   thisisaverylongnamev:password => Valid credentials
-- |_  web:TeSt => Valid credentials, account disabled
--
-- @args smblockout This argument will force the script to continue if it
--       locks out an account or thinks it will lock out an account.
-- @args brutelimit Limits the number of usernames checked in the script. In some domains,
--       it's possible to end up with 10,000+ usernames on each server. By default, this
--       will be <code>5000</code>, which should be higher than most servers and also prevent infinite
--       loops or other weird things. This will only affect the user list pulled from the
--       server, not the username list.
-- @args canaries Sets the number of tests to do to attempt to lock out the first account.
--       This will lock out the first account without locking out the rest of the accounts.
--       The default is 3, which will only trigger strict lockouts, but will also bump the
--       canary account up far enough to detect a lockout well before other accounts are
--       hit.
-----------------------------------------------------------------------


author = "Ron Bowes"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

categories = {"intrusive", "brute"}


---The maximum number of usernames to check (can be modified with smblimit argument)
-- The limit exists because domains may have hundreds of thousands of accounts,
-- potentially.
local LIMIT = 5000

hostrule = function(host)
  return smb.get_port(host) ~= nil
end

---The possible result codes. These are simplified from the actual codes that SMB returns.
local results =
{
  SUCCESS             =  1, -- Login was successful
  GUEST_ACCESS        =  2, -- Login was successful, but was granted guest access
  NOT_GRANTED         =  3, -- Password was correct, but user wasn't allowed to log in (often happens with blank passwords)
  DISABLED            =  4, -- Password was correct, but user's account is disabled
  EXPIRED             =  5, -- Password was correct, but user's account is expired
  CHANGE_PASSWORD     =  6, -- Password was correct, but user can't log in without changing it
  ACCOUNT_LOCKED      =  7, -- User's account is locked out (hopefully not by us!)
  ACCOUNT_LOCKED_NOW  =  8, -- User's account just became locked out (oops!)
  FAIL                =  9, -- User's password was incorrect
  INVALID_LOGON_HOURS = 10, -- Password was correct, but user's account has logon time restrictions in place
  INVALID_WORKSTATION = 11  -- Password was correct, but user's account has workstation restrictions in place
}

---Strings for debugging output
local result_short_strings = {}
result_short_strings[results.SUCCESS]             = "SUCCESS"
result_short_strings[results.GUEST_ACCESS]        = "GUEST_ACCESS"
result_short_strings[results.NOT_GRANTED]         = "NOT_GRANTED"
result_short_strings[results.DISABLED]            = "DISABLED"
result_short_strings[results.EXPIRED]             = "EXPIRED"
result_short_strings[results.CHANGE_PASSWORD]     = "CHANGE_PASSWORD"
result_short_strings[results.ACCOUNT_LOCKED]      = "LOCKED"
result_short_strings[results.ACCOUNT_LOCKED_NOW]  = "LOCKED_NOW"
result_short_strings[results.FAIL]                = "FAIL"
result_short_strings[results.INVALID_LOGON_HOURS] = "INVALID_LOGON_HOURS"
result_short_strings[results.INVALID_WORKSTATION] = "INVALID_WORKSTATION"


---The strings that the user will see
local result_strings = {}
result_strings[results.SUCCESS]              = "Valid credentials"
result_strings[results.GUEST_ACCESS]         = "Valid credentials, account granted guest access only"
result_strings[results.NOT_GRANTED]          = "Valid credentials, but account wasn't allowed to log in (often happens with blank passwords)"
result_strings[results.DISABLED]             = "Valid credentials, account disabled"
result_strings[results.EXPIRED]              = "Valid credentials, account expired"
result_strings[results.CHANGE_PASSWORD]      = "Valid credentials, password must be changed at next logon"
result_strings[results.ACCOUNT_LOCKED]       = "Valid credentials, account locked (hopefully not by us!)"
result_strings[results.ACCOUNT_LOCKED_NOW]   = "Valid credentials, account just became locked (oops!)"
result_strings[results.FAIL]                 = "Invalid credentials"
result_strings[results.INVALID_LOGON_HOURS]  = "Valid credentials, account cannot log in at current time"
result_strings[results.INVALID_WORKSTATION]  = "Valid credentials, account cannot log in from current host"

---Constants for special passwords. These each contain a null character, which is illegal in
-- actual passwords.
local USERNAME          = "\0username"
local USERNAME_REVERSED = "\0username reversed"
local special_passwords = { USERNAME, USERNAME_REVERSED }

---Generates a random string of the requested length. This can be used to check how hosts react to
-- weird username/password combinations.
--@param length (optional) The length of the string to return. Default: 8.
--@param set    (optional) The set of letters to choose from. Default: upper, lower, numbers, and underscore.
--@return The random string.
local function get_random_string(length, set)
  return stdnse.generate_random_string(length or 8,
    set or "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_")
end

---Splits a string in the form "domain\user" into domain and user.
--@param str The string to split
--@return (domain, username) The domain and the username. If no domain was given, nil is returned
--        for domain.
local function split_domain(str)
  local username, domain
  local split = stdnse.strsplit("\\", str)

  if(#split > 1) then
    domain = split[1]
    username = split[2]
  else
    domain   = nil
    username = str
  end

  return domain, username
end

---Formats a username/password pair with an optional result. Just a way to keep things consistent
-- throughout the program. Currently, the format is "username:password => result".
--@param username The username.
--@param password [optional] The password. Default: "<unknown>".
--@param result   [optional] The result, as a constant. Default: not used.
--@return A string representing the input values.
local function format_result(username, password, result)

  if(username == "") then
    username = "<blank>"
  end

  if(password == nil) then
    password = "<unknown>"
  elseif(password == "") then
    password = "<blank>"
  end

  if(result == nil) then
    return string.format("%s:%s", username, password)
  else
    return string.format("%s:%s => %s", username, password, result_strings[result])
  end
end

---Decides which login type to use (lanman, ntlm, or other). Designed to keep things consistent.
--@param hostinfo The hostinfo table.
--@return A string representing the login type to use (that can be passed to SMB functions).
local function get_type(hostinfo)
  -- Check if the user requested a specific type
  if(nmap.registry.args.smbtype ~= nil) then
    return nmap.registry.args.smbtype
  end

  -- Otherwise, base the type on the operating system (TODO: other versions of Windows (7, 2008))
  -- 2k8 example: "Windows Server (R) 2008 Datacenter without Hyper-V 6001 Service Pack 1"
  if(string.find(string.lower(hostinfo['os']), "vista") ~= nil) then
    return "ntlm"
  elseif(string.find(string.lower(hostinfo['os']), "2008") ~= nil) then
    return "ntlm"
  elseif(string.find(string.lower(hostinfo['os']), "Windows 7") ~= nil) then
    return "ntlm"
  end

  return "lm"
end

---Stops the session, if one exists. This can be called as frequently as needed, it'll just return if no
-- session is present, but it should generally be paired with a <code>restart_session</code> call.
--@param hostinfo The hostinfo table.
--@return (status, err) If status is false, err is a string corresponding to the error; otherwise, err is undefined.
local function stop_session(hostinfo)
  local status, err

  if(hostinfo['smbstate'] ~= nil) then
    stdnse.debug2("Stopping the SMB session")
    status, err = smb.stop(hostinfo['smbstate'])
    if(status == false) then
      return false, err
    end

    hostinfo['smbstate'] = nil
  end


  return true
end

---Starts or restarts a SMB session with the host. Although this will automatically stop a session if
-- one exists, it's a little cleaner to pair this with a <code>stop_session</code> call.
--@param hostinfo The hostinfo table.
--@return (status, err) If status is false, err is a string corresponding to the error; otherwise, err is undefined.
local function restart_session(hostinfo)
  local status, err, smbstate

  -- Stop the old session, if it exists
  stop_session(hostinfo)

  stdnse.debug2("Starting the SMB session")
  status, smbstate = smb.start_ex(hostinfo['host'], true, nil, nil, nil, true)
  if(status == false) then
    return false, smbstate
  end

  hostinfo['smbstate'] = smbstate

  return true
end

---Attempts to log into an account, returning one of the <code>results</code> constants. Will always return to the
-- state where another login can be attempted. Will also differentiate between a hash and a password, and choose the
-- proper login method (unless overridden). Will interpret the result as much as possible.
--
-- The session has to be active (ie, <code>restart_session</code> has to be called) before calling this function.
--
--@param hostinfo The hostinfo table.
--@param username The username to try.
--@param password The password to try.
--@param logintype [optional] The logintype to use. Default: <code>get_type</code> is called. If <code>password</code>
--       is a hash, this is ignored.
--@return Result, an integer value from the <code>results</code> constants.
local function check_login(hostinfo, username, password, logintype)
  local result
  local domain = ""
  local smbstate = hostinfo['smbstate']
  if(logintype == nil) then
    logintype = get_type(hostinfo)
  end

  -- Determine if we have a password hash or a password
  local status, err
  if(#password == 32 or #password == 64 or #password == 65) then
    -- It's a hash (note: we always use NTLM hashes)
    status, err = smb.start_session(smbstate, smb.get_overrides(username, domain, nil, password, "ntlm"), false)
  else
    status, err = smb.start_session(smbstate, smb.get_overrides(username, domain, password, nil, logintype), false)
  end

  if(status == true) then
    if(smbstate['is_guest'] == 1) then
      result = results.GUEST_ACCESS
    else
      result = results.SUCCESS
    end

    smb.logoff(smbstate)
  else
    if(err == "NT_STATUS_LOGON_TYPE_NOT_GRANTED") then
      result = results.NOT_GRANTED
    elseif(err == "NT_STATUS_ACCOUNT_LOCKED_OUT") then
      result = results.ACCOUNT_LOCKED
    elseif(err == "NT_STATUS_ACCOUNT_DISABLED") then
      result = results.DISABLED
    elseif(err == "NT_STATUS_PASSWORD_MUST_CHANGE") then
      result = results.CHANGE_PASSWORD
    elseif(err == "NT_STATUS_INVALID_LOGON_HOURS") then
      result = results.INVALID_LOGON_HOURS
    elseif(err == "NT_STATUS_INVALID_WORKSTATION") then
      result = results.INVALID_WORKSTATION
    elseif(err == "NT_STATUS_ACCOUNT_EXPIRED") then
      result = results.EXPIRED
    else
      result = results.FAIL
    end
  end

  --io.write(string.format("Result: %s\n\n", result_strings[result]))

  return result
end

---Determines whether or not a login was successful, based on what's known about the server's settings. This
-- is fairly straight forward, but has a couple little tricks.
--
--@param hostinfo The hostinfo table.
--@param result   The result code.
--@return <code>true</code> if the password used for logging in was correct, <code>false</code> otherwise. Keep
--        in mind that this doesn't imply the login was successful (only results.SUCCESS indicates that), rather
--        that the password was valid.

function is_positive_result(hostinfo, result)
  -- If result is a FAIL, it's always bad
  if(result == results.FAIL) then
    return false
  end

  -- If result matches what we discovered for invalid passwords, it's always bad
  if(result == hostinfo['invalid_password']) then
    return false
  end

  -- If result was ACCOUNT_LOCKED, it's always bad (locked accounts should already be taken care of, but this
  -- makes the function a bit more generic)
  if(result == results.ACCOUNT_LOCKED) then
    return false
  end

  -- Otherwise, it's good
  return true
end

---Determines whether or not a login was "bad". A bad login is one where an account becomes locked out.
--
--@param hostinfo The hostinfo table.
--@param result   The result code.
--@return <code>true</code> if the password used for logging in was correct, <code>false</code> otherwise. Keep
--        in mind that this doesn't imply the login was successful (only results.SUCCESS indicates that), rather
--        that the password was valid.

function is_bad_result(hostinfo, result)
  -- If result is LOCKED, it's always bad.
  if(result == results.ACCOUNT_LOCKED or result == results.ACCOUNT_LOCKED_NOW) then
    return true
  end

  -- Otherwise, it's good
  return false
end

---Count the number of one bits in a binary representation of the given number. This is used for case-sensitive
-- checks.
--
--@param num The number to count the ones for.
--@return The number of ones in the number
local function count_ones(num)
  local count = 0

  while num ~= 0 do
    if(bit.band(num, 1) == 1) then
      count = count + 1
    end
    num = bit.rshift(num, 1)
  end

  return count
end

---Converts a string's case based on a binary number. For every '1' bit, the character is uppercased, and for every '0'
-- bit it's lowercased. For example, "test" and 8 (1000) becomes "Test", while "test" and 11 (1011) becomes "TeST".
--
--@param str The string to convert.
--@param num The binary number representing the case. This value isn't checked, so if it's too large it's truncated, and if it's
--           too small it's effectively zero-padded.
--@return The converted string.
local function convert_case(str, num)
  local pos = #str

  -- Don't bother with blank strings (we probably won't get here anyway, but it doesn't hurt)
  if(str == "") then
    return ""
  end

  while(num ~= 0) do
    -- Check if the bit we're at is '1'
    if(bit.band(num, 1) == 1) then
      -- Check if we're at the beginning or end (or both) of the string -- those are special cases
      if(pos == #str and pos == 1) then
        str = string.upper(string.sub(str, pos, pos))
      elseif(pos == #str) then
        str = string.sub(str, 1, pos - 1) .. string.upper(string.sub(str, pos, pos))
      elseif(pos == 1) then
        str = string.upper(string.sub(str, pos, pos)) .. string.sub(str, pos + 1, #str)
      else
        str = string.sub(str, 1, pos - 1) .. string.upper(string.sub(str, pos, pos)) .. string.sub(str, pos + 1, #str)
      end
    end

    num = bit.rshift(num, 1)

    pos = pos - 1
  end

  return str
end

---Attempts to determine the case of a password. This is done by trying every possible combination of upper and lowercase
-- characters in the password, in the most efficient possible ordering, until the correct case is found.
--
-- A session has to be active when this function is called.
--
--@param hostinfo The hostinfo table.
--@param username The username.
--@param password The password (it's assumed that it's all lowercase already, but it doesn't matter)
--@return The password with the proper case, or the original password if it couldn't be determined (either the proper
--        case wasn't found or the login type is incorrect).
local function find_password_case(hostinfo, username, password)
  -- Only do this if we're using lanman, otherwise we already have the proper password
  if(get_type(hostinfo) ~= "lm") then
    return password
  end

  -- Figure out how many possibilities exist
  local max = math.pow(2, #password) - 1

  -- Create an array of them, starting with all the values whose binary representation has no ones, then one one, then two ones, etc.
  local ordered = {}

  -- Cheat a bit, by adding all lower then all upper right at the start
  ordered = {0, max}

  -- Loop backwards from the length of the password to 0. At each spot, put all numbers that have that many '1' bits
  for i = 1, #password - 1, 1 do
    for j = max, 0, -1 do
      if(count_ones(j) == i) then
        table.insert(ordered, j)
      end
    end
  end

  -- Create the list of converted passwords
  for i = 1, #ordered, 1 do
    local thispassword = convert_case(password, ordered[i])

    -- We specify "ntlm" for the login type because it's case sensitive
    local result = check_login(hostinfo, username, thispassword, 'ntlm')
    if(is_positive_result(hostinfo, result)) then
      return thispassword
    end
  end

  -- Print an error message
  stdnse.debug1("ERROR: smb-brute: Was unable to determine case of %s's password", username)

  -- If all else fails, just return the actual password (we probably shouldn't get here)
  return password
end

---Unless the user is ok with lockouts, check the lockout policy of the host. Take the most restrictive
-- portion among the domains. Returns true if lockouts could happen, false otherwise.
local function bad_lockout_policy(host)
  -- If the user is ok with locking out accounts, just return
  if(stdnse.get_script_args( "smblockout" )) then
    stdnse.debug1("Not checking server's lockout policy")
    return true, false
  end

  local status, result = msrpc.get_domains(host)
  if(not(status)) then
    stdnse.debug1("Couldn't detect lockout policy: %s", result)
    return false, "Couldn't retrieve lockout policy: " .. result
  end

  for domain, data in pairs(result) do
    if(data and data.lockout_threshold) then
      stdnse.debug1("Server's lockout policy: lock out after %d attempts", data.lockout_threshold)
      return true, true
    end
  end

  stdnse.debug1("Server has no lockout policy")
  return true, false
end

---Initializes and returns the hostinfo table. This includes queuing up the username and password lists, determining
-- the server's operating system,  and checking the server's response for invalid usernames/invalid passwords.
--
--@param host The host object.
local function initialize(host)
  local os, result
  local status, bad_lockout_policy_result
  local hostinfo = {}

  hostinfo['host'] = host
  hostinfo['invalid_usernames'] = {}
  hostinfo['locked_usernames'] = {}
  hostinfo['accounts'] = {}
  hostinfo['special_password'] = 1

  -- Get the OS (identifying windows versions tells us which hash to use)
  result, os = smb.get_os(host)
  if(result == false or os['os'] == nil) then
    hostinfo['os'] = "<Unknown>"
  else
    hostinfo['os'] = os['os']
  end
  stdnse.debug1("Remote operating system: %s", hostinfo['os'])

  -- Check lockout policy
  status, bad_lockout_policy_result = bad_lockout_policy(host)
  if(not(status)) then
    stdnse.debug1("WARNING: couldn't determine lockout policy: %s", bad_lockout_policy_result)
  else
    if(bad_lockout_policy_result) then
      return false, "Account lockouts are enabled on the host. To continue (and risk lockouts), add --script-args=smblockout=1 -- for more information, run smb-enum-domains."
    end
  end

  -- Attempt to enumerate users
  stdnse.debug1("Trying to get user list from server")
  local _
  hostinfo['have_user_list'], _, hostinfo['user_list'] = msrpc.get_user_list(host)
  hostinfo['user_list_index'] = 1
  if(hostinfo['have_user_list'] and #hostinfo['user_list'] == 0) then
    hostinfo['have_user_list'] = false
  end

  -- If the enumeration failed, try using the built-in list
  if(not(hostinfo['have_user_list'])) then
    stdnse.debug1("Couldn't enumerate users (normal for Windows XP and higher), using unpwdb initially")
    status, hostinfo['user_list_default'] = unpwdb.usernames()
    if(status == false) then
      return false, "Couldn't open username file"
    end
  end

  -- Open the password file
  stdnse.debug1("Opening password list")
  status, hostinfo['password_list'] = unpwdb.passwords()
  if(status == false) then
    return false, "Couldn't open password file"
  end

  -- Start the SMB session
  stdnse.debug1("Starting the initial SMB session")
  local err
  status, err = restart_session(hostinfo)
  if(status == false) then
    stop_session(hostinfo)
    return false, err
  end

  -- Some hosts will accept any username -- check for this by trying to log in with a totally random name. If the
  -- server accepts it, it'll be impossible to bruteforce; if it gives us a weird result code, we have to remember
  -- it.
  hostinfo['invalid_username'] = check_login(hostinfo, get_random_string(8), get_random_string(8), "ntlm")
  hostinfo['invalid_password'] = check_login(hostinfo, "Administrator",      get_random_string(8), "ntlm")

  stdnse.debug1("Server's response to invalid usernames: %s", result_short_strings[hostinfo['invalid_username']])
  stdnse.debug1("Server's response to invalid passwords: %s", result_short_strings[hostinfo['invalid_password']])

  -- If either of these comes back as success, there's no way to tell what's valid/invalid
  if(hostinfo['invalid_username'] == results.SUCCESS) then
    stop_session(hostinfo)
    return false, "Invalid username was accepted; unable to bruteforce"
  end
  if(hostinfo['invalid_password'] == results.SUCCESS) then
    stop_session(hostinfo)
    return false, "Invalid password was accepted; unable to bruteforce"
  end

  -- Print a message to the user if we can identify passwords
  if(hostinfo['invalid_username'] ~= hostinfo['invalid_password']) then
    stdnse.debug1("Invalid username and password response are different, so identifying valid accounts is possible")
  end

  -- Print a warning message if invalid_username and invalid_password go to the same thing that isn't FAIL
  if(hostinfo['invalid_username'] ~= results.FAIL and hostinfo['invalid_username'] == hostinfo['invalid_password']) then
    stdnse.debug1("WARNING: Difficult to recognize invalid usernames/passwords; may not get good results")
  end

  -- Restart the SMB connection so we have a clean slate
  stdnse.debug1("Restarting the session before the bruteforce")
  status, err = restart_session(hostinfo)
  if(status == false) then
    stop_session(hostinfo)
    return false, err
  end

  -- Stop the SMB session (we're going to let the scripts look after their own sessions)
  stop_session(hostinfo)

  -- Return the results
  return true, hostinfo
end

---Retrieves the next password in the password database we're using. Will never return the empty string.
-- May also return one of the <code>special_passwords</code> constants.
--
--@param hostinfo The hostinfo table (the password list is stored there).
--@return The new password, or nil if the end of the list has been reached.
local function get_next_password(hostinfo)
  local new_password

  -- If we're out of special passwords, move onto actual ones
  if(hostinfo['special_password'] > #special_passwords) then
    -- Pick the next non-blank password from the list
    repeat
      new_password = hostinfo['password_list']()
    until new_password ~= ''
  else
    -- Get the next non-blank password
    new_password = special_passwords[hostinfo['special_password']]
    hostinfo['special_password'] = hostinfo['special_password'] + 1
  end

  return new_password
end

---Reset to the first password. This is normally done when the user list changes.
--
--@param hostinfo The hostinfo table.
local function reset_password(hostinfo)
  hostinfo['password_list']("reset")
end

---Retrieves the next username. This can be from the username database, or from an array stored in the
-- hostinfo table. This won't return any names that have been determined to be invalid, locked, or
-- have already had their password found.
--
--@param hostinfo The hostinfo table
--@return The next username, or nil if the end of the list has been reached.
local function get_next_username(hostinfo)
  local username

  repeat
    if(hostinfo['have_user_list']) then
      local index = hostinfo['user_list_index']
      hostinfo['user_list_index'] = hostinfo['user_list_index'] + 1

      username = hostinfo['user_list'][index]
      if(username ~= nil) then
        local _
        _, username = split_domain(username)
      end

    else
      username = hostinfo['user_list_default']()
    end

    -- Make the username lowercase (usernames aren't case sensitive, so making it lower case prevents duplicates)
    if(username ~= nil) then
      username = string.lower(username)
    end

  until username == nil or (hostinfo['invalid_usernames'][username] ~= true and hostinfo['locked_usernames'][username] ~= true and hostinfo['accounts'][username] == nil)

  return username
end

---Reset to the first username.
--
--@param hostinfo The hostinfo table.
local function reset_username(hostinfo)
  if(hostinfo['have_user_list']) then
    hostinfo['user_list_index'] = 1
  else
    hostinfo['user_list_default']("reset")
  end
end

---Do a little trick to detect account lockouts without bringing every user to the lockout threshold -- bump the lockout counter of
-- the first user ahead. If lockouts are happening, this means that the first account will trigger before the rest of the accounts.
-- A canary in the mineshaft, in a way.
--
-- The number of checks defaults to three, but it can be controlled with the <code>canary</code> argument.
--
-- Times it'll fail are when:
-- * Accounts are locked out due to the initial checks (happens if the user runs smb-brute twice in a row, the canary won't help)
-- * A valid user list isn't pulled, and we create a canary that doesn't exist (won't be as bad, though, because it means we also
--   don't have every account on the server/domain
function test_lockouts(hostinfo)
  local i
  local username = get_next_username(hostinfo)

  -- It's possible that every username was accounted for already, so our list is empty.
  if(username == nil) then
    return
  end

  if(stdnse.get_script_args( "smblockout" )) then
    return
  end

  while(string.lower(username) == "administrator") do
    username = get_next_username(hostinfo)
    if(username == nil) then
      return
    end
  end

  if(username ~= nil) then
    -- Try logging in as the "canary" account
    local canaries = nmap.registry.args.canaries
    if(canaries == nil) then
      canaries = 3
    else
      canaries = tonumber(canaries)
    end

    if(canaries > 0) then
      stdnse.debug1("Detecting server lockout on '%s' with %d canaries", username, canaries)
    end

    local result
    for i=1, canaries, 1 do
      result = check_login(hostinfo, username, get_random_string(8), "ntlm")
    end

    -- If the account just became locked (it's already been put on the 'valid' list), we're in trouble
    if(result == results.LOCKED) then
      -- If the canary just became locked, we're one step from locking out every account. Loop through the usernames and invalidate them to
      -- prevent them from being locked out
      stdnse.debug1("Canary (%s) became locked out -- aborting", username)

      -- Add it to the locked username list (so it can be reported)
      hostinfo['locked_usernames'][username] = true

      -- Mark all the usernames as invalid (a bit of a hack, but it's safer this way)
      while(username ~= nil) do
        stdnse.debug1("Marking '%s' as 'invalid'", username)
        hostinfo['invalid_usernames'][username] = true
        username = get_next_username(hostinfo)
      end
    end
  end

  -- Go back to the beginning of the list
  reset_username(hostinfo)
end

---Attempts to validate the current list of usernames by logging in with a blank password, marking invalid ones (and ones that had
-- a blank password). Determining the validity of a username works best if invalid usernames are redirected to 'guest'.
--
-- If a username accepts the blank password, a random password is tested. If that's accepted as well, the account is marked as
-- accepting any password (the 'guest' account is normally like that).
--
-- This also checks whether the server locks out users, and raises the lockout threshold of the first user (see the
-- <code>check_lockouts</code> function for more information on that. If accounts on the system are locked out, they aren't
-- checked.
--
--@param hostinfo The hostinfo table.
--@return (status, err) If status is false, err is a string corresponding to the error; otherwise, err is undefined.
local function validate_usernames(hostinfo)
  local status, err
  local result
  local username, password

  stdnse.debug1("Checking which account names exist (based on what goes to the 'guest' account)")

  -- Start a session
  status, err = restart_session(hostinfo)
  if(status == false) then
    return false, err
  end

  -- Make sure we start at the beginning
  reset_username(hostinfo)

  username = get_next_username(hostinfo)
  while(username ~= nil) do
    result = check_login(hostinfo, username, "", "ntlm")

    if(result ~= hostinfo['invalid_password'] and result == hostinfo['invalid_username']) then
      -- If the account matches the value of 'invalid_username', but not the value of 'invalid_password', it's invalid
      stdnse.debug1("Blank password for '%s' -> '%s' (invalid account)", username, result_short_strings[result])
      hostinfo['invalid_usernames'][username] = true

    elseif(result == hostinfo['invalid_password']) then

      -- If the account matches the value of 'invalid_password', and 'invalid_password' is reliable, it's probably valid
      if(hostinfo['invalid_username'] ~= results.FAIL and hostinfo['invalid_username'] == hostinfo['invalid_password']) then
        stdnse.debug1("Blank password for '%s' => '%s' (can't determine validity)", username, result_short_strings[result])
      else
        stdnse.debug1("Blank password for '%s' => '%s' (probably valid)", username, result_short_strings[result])
      end

    elseif(result == results.ACCOUNT_LOCKED) then
      -- If the account is locked out, don't try it
      hostinfo['locked_usernames'][username] = true
      stdnse.debug1("Blank password for '%s' => '%s' (locked out)", username, result_short_strings[result])

    elseif(result == results.FAIL) then
      -- If none of the standard options work, check if it's FAIL. If it's FAIL, there's an error somewhere (probably, the
      -- 'administrator' username is changed so we're getting invalid data).
      stdnse.debug1("Blank password for '%s' => '%s' (may be valid)", username, result_short_strings[result])

    else
      -- If none of those came up, either the password is legitimately blank, or any account works. Figure out what!
      local new_result = check_login(hostinfo, username, get_random_string(14), "ntlm")
      if(new_result == result) then
        -- Any password works (often happens with 'guest' account)
        stdnse.debug1("All passwords accepted for %s (goes to %s)", username, result_short_strings[result])
        status, err = found_account(hostinfo, username, "<anything>", result)
        if(status == false) then
          return false, err
        end
      else
        -- Blank password worked, but not random one
        status, err = found_account(hostinfo, username, "", result)
        if(status == false) then
          return false, err
        end
      end
    end

    username = get_next_username(hostinfo)
  end

  -- Start back at the beginning of the list
  reset_username(hostinfo)

  -- Check for lockouts
  test_lockouts(hostinfo)

  -- Stop the session
  stop_session(hostinfo)

  return true
end

---Marks an account as discovered. The login with this account doesn't have to be successful, but <code>is_positive_result</code> should
-- return <code>true</code>.
--
-- If the result IS successful, and this hasn't been done before, this function will attempt to pull a userlist from the server.
--
-- The session should be stopped before entering this function, and restarted after -- that allows this function to make its own SMB calls.
--
--@param hostinfo The hostinfo table.
--@param username The username.
--@param password The password.
--@param result   The result, as an integer constant.
--@return (status, err) If status is false, err is a string corresponding to the error; otherwise, err is undefined.
function found_account(hostinfo, username, password, result)
  local status, err

  -- Save the username
  hostinfo['accounts'][username] = {}
  hostinfo['accounts'][username]['password'] = password
  hostinfo['accounts'][username]['result']   = result

  -- Save the account (smb will automatically decide if it's better than the account it already has)
  if(result == results.SUCCESS) then
    -- Stop the connection -- this lets us do some queries
    status, err = stop_session(hostinfo)
    if(status == false) then
      return false, err
    end

    -- Check if we have an 'admin' account
    -- Try getting information about "IPC$". This determines whether or not the user is administrator
    -- since only admins can get share info. Note that on Vista and up, unless UAC is disabled, all
    -- accounts are non-admin.
    local is_admin = smb.is_admin(hostinfo['host'], username, '', password, nil, nil)

    -- Add the account
    smb.add_account(hostinfo['host'], username, '', password, nil, nil, is_admin)

    -- Check lockout policy
    local status, bad_lockout_policy_result = bad_lockout_policy(hostinfo['host'])
    if(not(status)) then
      stdnse.debug1("WARNING: couldn't determine lockout policy: %s", bad_lockout_policy_result)
    else
      if(bad_lockout_policy_result) then
        return false, "Account lockouts are enabled on the host. To continue (and risk lockouts), add --script-args=smblockout=1 -- for more information, run smb-enum-domains."
      end
    end

    -- If we haven't retrieved the real user list yet, do so
    if(hostinfo['have_user_list'] == false) then
      -- Attempt to enumerate users
      stdnse.debug1("Trying to get user list from server using newly discovered account")
      local _
      hostinfo['have_user_list'], _, hostinfo['user_list'] = msrpc.get_user_list(hostinfo['host'])
      hostinfo['user_list_index'] = 1
      if(hostinfo['have_user_list'] and #hostinfo['user_list'] == 0) then
        hostinfo['have_user_list'] = false
      end

      -- If the list was found, let the user know and reset the password list
      if(hostinfo['have_user_list']) then
        stdnse.debug1("Found %d accounts to check!", #hostinfo['user_list'])
        reset_password(hostinfo)

        -- Validate them (pick out the ones that can't possibly log in)
        validate_usernames(hostinfo)
      end
    end

    -- Start the session again
    status, err = restart_session(hostinfo)
    if(status == false) then
      return false, err
    end

  end
end

---This is the main function that does all the work (loops through the lists and checks the results).
--
--@param host The host table.
--@return (status, accounts, locked_accounts) If status is false, accounts is an error message. Otherwise, accounts
--        is a table of passwords/results, indexed by the username and locked_accounts is a table indexed by locked
--        usernames.
local function go(host)
  local status, err
  local result, hostinfo
  local password, temp_password, username
  local response = {}

  -- Initialize the hostinfo object, which sets up the initial variables
  result, hostinfo = initialize(host)
  if(result == false) then
    return false, hostinfo
  end

  -- If invalid accounts don't give guest, we can determine the existence of users by trying to
  -- log in with an invalid password and checking the value
  status, err = validate_usernames(hostinfo)
  if(status == false) then
    return false, err
  end

  -- Start up the SMB session
  status, err = restart_session(hostinfo)
  if(status == false) then
    return false, err
  end

  -- Loop through the password list
  temp_password = get_next_password(hostinfo)
  while(temp_password ~= nil) do
    -- Loop through the user list
    username = get_next_username(hostinfo)
    while(username ~= nil) do
      -- Check if it's a special case (we do this every loop because special cases are often
      -- based on the username
      if(temp_password == USERNAME) then
        password = username
        --io.write(string.format("Trying matching username/password (%s:%s)\n", username, password))
      elseif(temp_password == USERNAME_REVERSED) then
        password = string.reverse(username)
        --io.write(string.format("Trying reversed username/password (%s:%s)\n", username, password))
      else
        password = temp_password
      end

      --io.write(string.format("%s:%s\n", username, password))
      local result = check_login(hostinfo, username, password, get_type(hostinfo))

      -- Check if the username was locked out
      if(is_bad_result(hostinfo, result)) then
        -- Add it to the list of locked usernames
        hostinfo['locked_usernames'][username] = true

        -- Unless the user requested to keep going, stop the check
        if(not(stdnse.get_script_args( "smblockout" ))) then
          -- Mark it as found, which is technically true
          status, err = found_account(hostinfo, username, nil, results.ACCOUNT_LOCKED_NOW)
          if(status == false) then
            return err
          end

          -- Let the user know that it went badly
          stdnse.debug1("'%s' became locked out; stopping", username)

          return true, hostinfo['accounts'], hostinfo['locked_usernames']
        else
          stdnse.debug1("'%s' became locked out; continuing", username)
        end
      end

      if(is_positive_result(hostinfo, result)) then
        -- Reset the connection
        stdnse.debug2("Found an account; resetting connection")
        status, err = restart_session(hostinfo)
        if(status == false) then
          return false, err
        end

        -- Find the case of the password, unless it's a hash
        local case_password
        if(not(#password == 32 or #password == 64 or #password == 65)) then
          stdnse.debug1("Determining password's case (%s)", format_result(username, password))
          case_password = find_password_case(hostinfo, username, password, result)
          stdnse.debug1("Result: %s", format_result(username, case_password))
        else
          case_password = password
        end

        -- Take normal actions for finding an account
        status, err = found_account(hostinfo, username, case_password, result)
        if(status == false) then
          return err
        end
      end
      username = get_next_username(hostinfo)
    end

    reset_username(hostinfo)
    temp_password = get_next_password(hostinfo)
  end

  stop_session(hostinfo)
  return true, hostinfo['accounts'], hostinfo['locked_usernames']
end

--_G.TRACEBACK = TRACEBACK or {}
action = function(host)
  -- TRACEBACK[coroutine.running()] = true;

  local status, result
  local response = {}

  local username
  local usernames = {}
  local locked = {}
  local i
  local locked_result

  status, result, locked_result = go(host)
  if(status == false) then
    return stdnse.format_output(false, result)
  end

  -- Put the usernames in their own table
  for username in pairs(result) do
    table.insert(usernames, username)
  end

  -- Sort the usernames alphabetically
  table.sort(usernames)

  -- Display the usernames
  if(#usernames == 0) then
    table.insert(response, "No accounts found")
  else
    for i=1, #usernames, 1 do
      local username = usernames[i]
      table.insert(response, format_result(username, result[username]['password'], result[username]['result']))
    end
  end

  -- Make a list of locked accounts
  for username in pairs(locked_result) do
    table.insert(locked, username)
  end
  if(#locked > 0) then
    -- Sort the list
    table.sort(locked)

    -- Display the list
    table.insert(response, string.format("Locked accounts found: %s", stdnse.strjoin(", ", locked)))
  end

  return stdnse.format_output(true, response)
end

