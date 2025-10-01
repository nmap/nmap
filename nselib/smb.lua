---
-- Implements functionality related to Server Message Block (SMB, an extension
-- of CIFS) traffic, which is a Windows protocol.
--
-- SMB traffic is normally sent to/from ports 139 or 445 of Windows systems. Other systems
-- implement SMB as well, including Samba and a lot of embedded devices. Some of them implement
-- it properly and many of them not. Although the protocol has been documented decently
-- well by Samba and others, many 3rd party implementations are broken or make assumptions.
-- Even Samba's and Windows' implementations aren't completely compatible. As a result,
-- creating an implementation that accepts everything is a bit of a minefield. Microsoft's
-- extensive documentation is available at the following URLs:
-- * SMB: http://msdn.microsoft.com/en-us/library/cc246231(v=prot.13).aspx
-- * CIFS: http://msdn.microsoft.com/en-us/library/ee442092(v=prot.13).aspx
--
-- Where possible, this implementation, since it's intended for scanning, will attempt to
-- accept any invalid implementations it can, and fail gracefully if it can't. This has
-- been tested against a great number of weird implementations, and it now works against
-- all of them.
--
-- The intention of this library is to eventually handle all aspects of the SMB protocol.
-- That being said, I'm only implementing the pieces that I (Ron Bowes) need. If you
-- require something more, let me know and I'll put it on my todo list.
--
-- A programmer using this library should already have some knowledge of the SMB protocol,
-- although a lot isn't necessary. You can pick up a lot by looking at the code. The basic
-- login/logoff is this:
--
-- <code>
-- [connect]
-- C->S SMB_COM_NEGOTIATE
-- S->C SMB_COM_NEGOTIATE
-- C->S SMB_COM_SESSION_SETUP_ANDX
-- S->C SMB_COM_SESSION_SETUP_ANDX
-- C->S SMB_COM_TREE_CONNECT_ANDX
-- S->C SMB_COM_TREE_CONNECT_ANDX
-- ...
-- C->S SMB_COM_TREE_DISCONNECT
-- S->C SMB_COM_TREE_DISCONNECT
-- C->S SMB_COM_LOGOFF_ANDX
-- S->C SMB_COM_LOGOFF_ANDX
-- [disconnect]
-- </code>
--
-- In terms of functions here, the protocol is:
--
-- <code>
-- status, smbstate = smb.start(host)
-- status, err      = smb.negotiate_protocol(smbstate, {})
-- status, err      = smb.start_session(smbstate, {})
-- status, err      = smb.tree_connect(smbstate, path, {})
-- ...
-- status, err      = smb.tree_disconnect(smbstate)
-- status, err      = smb.logoff(smbstate)
-- status, err      = smb.stop(smbstate)
-- </code>
--
-- The <code>stop</code> function will automatically call tree_disconnect and logoff,
-- cleaning up the session, if it hasn't been done already.
--
-- To initially begin the connection, there are two options:
--
-- 1) Attempt to start a raw session over 445, if it's open.
--
-- 2) Attempt to start a NetBIOS session over 139. Although the
--    protocol's the same, it requires a <code>session request</code> packet.
--    That packet requires the computer's name, which is requested
--    using a NBSTAT probe over UDP port 137.
--
-- Once it's connected, a <code>SMB_COM_NEGOTIATE</code> packet is sent, requesting the protocol
-- "NT LM 0.12", which is the most commonly supported one. Among other things, the server's
-- response contains the host's security level, the system time, and the computer/domain name.
-- Some systems will refuse to use that protocol and return "-1" or "1" instead of 0. If that's
-- detected, we kill the connection (because the protocol following won't work).
--
-- If that's successful, <code>SMB_COM_SESSION_SETUP_ANDX</code> is sent. It is essentially the logon
-- packet, where the username, domain, and password are sent to the server for verification.
-- The username and password are generally picked up from the program parameters, which are
-- set when running a script, or from the registry where it can be set by other scripts (for
-- example, <code>smb-brute.nse</code>). However, they can also be passed as parameters to the
-- function, which will override any other username/password set.
--
-- If a username and password are set, they are used for the first login attempt. If a login fails,
-- or they weren't set, a connection as the 'GUEST' account with a blank password is attempted. If
-- that fails, then a NULL session is established, which should always work. The username/password
-- will give the highest access level, GUEST will give lower access, and NULL will give the lowest
-- (often, NULL will give no access).
--
-- The actual login protocol used by <code>SMB_COM_SESSION_SETUP_ANDX</code> is explained in detail
-- in <code>smbauth.lua</code>.
--
-- Thanks go to Christopher R. Hertel and his book Implementing CIFS, which
-- taught me everything I know about Microsoft's protocols. Additionally, I used Samba's
-- list of error codes for my constants. Although I don't believe they would be covered
-- by GPL, since they're public now anyways, but I'm not a lawyer and, if somebody feels
-- differently, let me know and we can sort this out.
--
-- Scripts that use this module can use the script arguments listed below
-- example of using these script arguments:
-- <code>
-- nmap --script=smb-<script>.nse --script-args=smbuser=ron,smbpass=iagotest2k3,smbbasic=1,smbsign=force <host>
-- </code>
--
-- @args  smbbasic    Forces the authentication to use basic security, as opposed to "extended security".
--                   Against most modern systems, extended security should work, but there may be cases
--                   where you want to force basic. There's a chance that you'll get better results for
--                   enumerating users if you turn on basic authentication.
-- @args smbsign      Controls whether or not server signatures are checked in SMB packets. By default, on Windows,
--                   server signatures aren't enabled or required. By default, this library will always sign
--                   packets if it knows how, and will check signatures if the server says to. Possible values are:
-- * <code>force</code>:      Always check server signatures, even if server says it doesn't support them (will
--                           probably fail, but is technically more secure).
-- * <code>negotiate</code>: [default] Use signatures if server supports them.
-- * <code>ignore</code>:    Never check server signatures. Not recommended.
-- * <code>disable</code>:   Don't send signatures, at all, and don't check the server's. not recommended.
--                   More information on signatures can be found in <code>smbauth.lua</code>.
-- @args smbport      Override the default port choice. If <code>smbport</code> is open, it's used. It's assumed
--                   to be the same protocol as port 445, not port 139. Since it probably isn't possible to change
--                   Windows' ports normally, this is mostly useful if you're bouncing through a relay or something.
-- @args randomseed   Set to a value to change the filenames/service names that are randomly generated.
--
-- @author Ron Bowes <ron@skullsecurity.net>
-- @copyright Same as Nmap--See https://nmap.org/book/man-legal.html
-----------------------------------------------------------------------
local asn1 = require "asn1"
local datetime = require "datetime"
local io = require "io"
local math = require "math"
local match = require "match"
local netbios = require "netbios"
local nmap = require "nmap"
local smbauth = require "smbauth"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"
local tableaux = require "tableaux"
local unicode = require "unicode"
local smb2 = require "smb2"
_ENV = stdnse.module("smb", stdnse.seeall)

-- These arrays are filled in with constants at the bottom of this file
command_codes = {}
command_names = {}
status_codes = {}
status_names = {}
filetype_codes = {}
filetype_names = {}

local TIMEOUT = 10000

---Wrapper around <code>smbauth.add_account</code>.
function add_account(host, username, domain, password, password_hash, hash_type, is_admin)
  smbauth.add_account(host, username, domain, password, password_hash, hash_type, is_admin)
end

---Wrapper around <code>smbauth.get_account</code>.
function get_account(host)
  return smbauth.get_account(host)
end
---Create an 'overrides' table
function get_overrides(username, domain, password, password_hash, hash_type, overrides)
  if(not(overrides)) then
    return {username=username, domain=domain, password=password, password_hash=password_hash, hash_type=hash_type}
  else
    overrides['username'] = username
    overrides['domain'] = domain
    overrides['password'] = password
    overrides['password_hash'] = password_hash
    overrides['hash_type'] = hash_type
  end
end

---Get an 'overrides' table for the anonymous user
--
--@param overrides [optional] A base table of overrides. The appropriate fields will be added.
function get_overrides_anonymous(overrides)
  if(not(overrides)) then
    return {username='', domain='', password='', password_hash=nil, hash_type='none'}
  else
    overrides['username'] = ''
    overrides['domain'] = ''
    overrides['password'] = ''
    overrides['password_hash'] = ''
    overrides['hash_type'] = 'none'
  end
end

---Convert a status number from the SMB header into a status name, returning an error message (not nil) if
-- it wasn't found.
--
--@param status The numerical status.
--@return A string representing the error. Never nil.
function get_status_name(status)

  if(status_names[status] == nil) then
    -- If the name wasn't found in the array, do a linear search on it
    for i, v in pairs(status_names) do
      if(v == status) then
        return i
      end
    end

    return string.format("NT_STATUS_UNKNOWN (0x%08x)", status)
  else
    return status_names[status]
  end
end


--- Determines whether or not SMB checks are possible on this host, and, if they are,
--  which port is best to use. This is how it decides:
--
-- * If port tcp/445 is open, use it for a raw connection
-- * Otherwise, if ports tcp/139 and udp/137 are open, do a NetBIOS connection. Since UDP scanning isn't default, we're also ok with udp/137 in an unknown state.
--
--@param host The host object.
--@return The port number to use, or nil if we don't have an SMB port
function get_port(host)
  local port_u137 = nmap.get_port_state(host, {number=137, protocol="udp"})
  local port_t139 = nmap.get_port_state(host, {number=139, protocol="tcp"})
  local port_t445 = nmap.get_port_state(host, {number=445, protocol="tcp"})
  local custom_port = nil

  if(nmap.registry.args.smbport ~= nil) then
    custom_port = nmap.get_port_state(host, {number=tonumber(nmap.registry.args.smbport), protocol="tcp"})
  end

  -- Try a user-defined port first
  if(custom_port ~= nil and custom_port.state == "open") then
    return custom_port.number
  end

  if(port_t445 ~= nil and port_t445.state == "open") then
    -- tcp/445 is open, we're good
    return 445
  end

  if(port_t139 ~= nil and port_t139.state == "open") then
    -- tcp/139 is open, check uf udp/137 is open or unknown
    if(port_u137 == nil or port_u137.state == "open" or port_u137.state == "open|filtered") then
      return 139
    end
  end

  return nil
end

---Turn off extended security negotiations for this connection.
--
-- There are a few reasons you might want to do that, the main ones being that
-- extended security is going to be marginally slower and it's not going to
-- give the same level of information in some cases (namely, it doesn't present
-- the server's name).
--@param smb The SMB state table.
function disable_extended(smb)
  smb['extended_security'] = false
end

--- Begins a SMB session, automatically determining the best way to connect.
--
-- @param host The host object
-- @return (status, smb) if the status is true, result is the newly crated smb object;
--         otherwise, socket is the error message.
function start(host)
  local port = get_port(host)
  local status, result
  local state = {}

  state['uid']      = 0
  state['tid']      = 0
  state['mid']      = 1
  state['pid']      = math.random(32766) + 1
  state['host']     = host
  state['ip']       = host.ip
  state['sequence'] = -1

  -- Check whether or not the user requested basic authentication
  if(stdnse.get_script_args( "smbbasic" )) then
    state['extended_security'] = false
  else
    state['extended_security'] = true
  end

  -- Store the name of the server
  local nbcache_mutex = nmap.mutex("Netbios lookup mutex")
  nbcache_mutex "lock"
  if ( not(host.registry['netbios_name']) ) then
    status, result = netbios.get_server_name(host.ip)
    if(status == true) then
      host.registry['netbios_name'] = result
      state['name'] = result
    end
  else
    stdnse.debug2("SMB: Resolved netbios name from cache")
    state['name'] = host.registry['netbios_name']
  end
  nbcache_mutex "done"

  stdnse.debug2("SMB: Starting SMB session for %s (%s)", host.name, host.ip)

  if(port == nil) then
    return false, "SMB: Couldn't find a valid port to check"
  end

  -- Initialize the accounts for logging on
  smbauth.init_account(host)

  if(port ~= 139) then
    status, state['socket'] = start_raw(host, port)
    state['port'] = port

    if(status == false) then
      return false, state['socket']
    end
    return true, state

  else
    status, state['socket'] = start_netbios(host, port)
    state['port'] = port
    if(status == false) then
      return false, state['socket']
    end
    return true, state

  end

  return false, "SMB: Couldn't find a valid port to check"
end

---Initiates a SMB connection over whichever port it can, then optionally sends
-- the common initialization packets.
--
-- Note that each packet depends on the previous one, so if you want to go all
-- the way up to create_file, you have to set all parameters.
--
-- If anything fails, we back out of the connection and return an error, so the
-- calling function doesn't have to call smb.stop().
--
--@param host The host object.
--@param bool_negotiate_protocol [optional] If 'true', send the protocol
--                               negotiation. Default: false.
--@param bool_start_session [optional] If 'true', start the session. Default:
--                          false.
--@param str_tree_connect [optional] The tree to connect to, if given (eg.
--                        "IPC$" or "C$"). If not given, packet isn't sent.
--@param str_create_file [optional] The path and name of the file (or pipe)
--                       that's created, if given. If not given, packet isn't
--                       sent.
--@param overrides [optional] A table of overrides (for, for example, username,
--                 password, etc.) to pass to all functions.
--@param bool_disable_extended [optional] If set to true, disables extended
--                             security negotiations.
function start_ex(host, bool_negotiate_protocol, bool_start_session, str_tree_connect, str_create_file, bool_disable_extended, overrides)
  local smbstate
  local status, err

  -- Make sure we have overrides
  overrides = overrides or {}

  -- Begin the SMB session
  status, smbstate = start(host)
  if(status == false) then
    return false, smbstate
  end

  -- Disable extended security if it was requested
  if(bool_disable_extended == true) then
    disable_extended(smbstate)
  end

  if(bool_negotiate_protocol == true) then
    -- Negotiate the protocol
    status, err = negotiate_protocol(smbstate, overrides)
    if(status == false) then
      stop(smbstate)
      return false, err
    end

    if(bool_start_session == true) then
      -- Start up a session
      status, err = start_session(smbstate, overrides)
      if(status == false) then
        stop(smbstate)
        return false, err
      end

      if(str_tree_connect ~= nil) then
        -- Connect to share
        status, err = tree_connect(smbstate, str_tree_connect, overrides)
        if(status == false) then
          stop(smbstate)
          return false, err
        end

        if(str_create_file ~= nil) then
          -- Try to connect to requested pipe
          status, err = create_file(smbstate, str_create_file, overrides)
          if(status == false) then
            stop(smbstate)
            return false, err
          end
        end
      end
    end
  end

  -- Return everything
  return true, smbstate
end

--- Kills the SMB connection and closes the socket.
--
--  In addition to killing the connection, this function will log off the user and disconnect
--  the connected tree, if possible.
--
--@param smb    The SMB object associated with the connection
--@return (status, result) If status is false, result is an error message. Otherwise, result
--        is undefined.
function stop(smb)

  if(smb['tid'] ~= 0) then
    tree_disconnect(smb)
  end

  if(smb['uid'] ~= 0) then
    logoff(smb)
  end

  stdnse.debug2("SMB: Closing socket")
  if(smb['socket'] ~= nil) then
    local status, err = smb['socket']:close()

    if(status == false) then
      return false, "SMB: Failed to close socket: " .. err
    end
  end

  return true
end

--- Begins a raw SMB session, likely over port 445. Since nothing extra is required, this
--  function simply makes a connection and returns the socket.
--
--@param host The host object to check.
--@param port The port to use (most likely 445).
--@return (status, socket) if status is true, result is the newly created socket.
--        Otherwise, socket is the error message.
function start_raw(host, port)
  local status, err
  local socket = nmap.new_socket()

  socket:set_timeout(TIMEOUT)
  status, err = socket:connect(host, port, "tcp")

  if(status == false) then
    return false, "SMB: Failed to connect to host: " .. err
  end

  return true, socket
end

-- This function will take a string like "a.b.c.d" and return "a", "a.b", "a.b.c", and "a.b.c.d".
--
--  This is used for discovering NetBIOS names. If a NetBIOS name is unknown, the substrings of the
--  DNS name can be used in this way.
--
--@param name The name to take apart
--@return An array of the sub names
local function get_subnames(name)
  local i = -1
  local list = {}

  repeat
    local subname = name

    i = string.find(name, "[.]", i + 1)
    if(i ~= nil) then
      subname = string.sub(name, 1, i - 1)
    end

    list[#list + 1] = string.upper(subname)

  until i == nil

  return list
end

--- Begins a SMB session over NetBIOS.
--
-- This requires a NetBIOS Session Start message to be sent first, which in
-- turn requires the NetBIOS name. The name can be provided as a parameter, or
-- it can be automatically determined.
--
-- Automatically determining the name is interesting, to say the least. Here
-- are the names it tries, and the order it tries them in:
-- * The name the user provided, if present
-- * The name pulled from NetBIOS (udp/137), if possible
-- * The generic name "*SMBSERVER"
-- * Each subset of the domain name (for example, scanme.insecure.org would
--   attempt "scanme", "scanme.insecure", and "scanme.insecure.org")
--
-- This whole sequence is a little hackish, but it's the standard way of doing
-- it.
--
--@param host The host object to check.
--@param port The port to use (most likely 139).
--@param name [optional] The NetBIOS name of the host. Will attempt to
--            automatically determine if it isn't given.
--@return (status, socket) if status is true, result is the port
--        Otherwise, socket is the error message.
function start_netbios(host, port, name)
  local i
  local status, err
  local pos, result, flags, length
  local socket = nmap.new_socket()

  -- First, populate the name array with all possible names, in order of significance
  local names = {}

  -- Use the name parameter
  if(name ~= nil) then
    names[#names + 1] = name
  end

  -- Get the name of the server from NetBIOS
  status, name = netbios.get_server_name(host.ip)
  if(status == true) then
    names[#names + 1] = name
  end

  -- "*SMBSERVER" is a special name that any server should respond to
  names[#names + 1] = "*SMBSERVER"

  -- If all else fails, use each substring of the DNS name (this is a HUGE hack, but is actually
  -- a recommended way of doing this!)
  if(host.name ~= nil and host.name ~= "") then
    local new_names = get_subnames(host.name)
    for i = 1, #new_names, 1 do
      names[#names + 1] = new_names[i]
    end
  end

  -- This loop will try all the NetBIOS names we've collected, hoping one of them will work. Yes,
  -- this is a hackish way, but it's actually the recommended way.
  i = 1
  repeat

    -- Use the current name
    name = names[i]

    -- Some debug information
    stdnse.debug1("SMB: Trying to start NetBIOS session with name = '%s'", name)
    -- Request a NetBIOS session
    local session_request = string.pack(">BBI2zz",
      0x81,                        -- session request
      0x00,                        -- flags
      0x44,                        -- length
      netbios.name_encode(name),   -- server name
      netbios.name_encode("NMAP")  -- client name
      );

    stdnse.debug3("SMB: Connecting to %s", host.ip)
    socket:set_timeout(TIMEOUT)
    status, err = socket:connect(host, port, "tcp")
    if(status == false) then
      socket:close()
      return false, "SMB: Failed to connect: " .. err
    end

    -- Send the session request
    stdnse.debug3("SMB: Sending NetBIOS session request with name %s", name)
    status, err = socket:send(session_request)
    if(status == false) then
      socket:close()
      return false, "SMB: Failed to send: " .. err
    end
    socket:set_timeout(TIMEOUT)

    -- Receive the session response
    stdnse.debug3("SMB: Receiving NetBIOS session response")
    status, result = socket:receive_buf(match.numbytes(4), true);
    if(status == false) then
      socket:close()
      return false, "SMB: Failed to close socket: " .. result
    end
    result, flags, length, pos = string.unpack(">BBI2", result)

    -- Check for a positive session response (0x82)
    if result == 0x82 then
      stdnse.debug3("SMB: Successfully established NetBIOS session with server name %s", name)
      return true, socket
    end

    -- If the session failed, close the socket and try the next name
    stdnse.debug1("SMB: Session request failed, trying next name")
    socket:close()

    -- Try the next name
    i = i + 1

  until i > #names

  -- We reached the end of our names list
  stdnse.debug1("SMB: None of the NetBIOS names worked!")
  return false, "SMB: Couldn't find a NetBIOS name that works for the server. Sorry!"
end

--- Creates a string containing a SMB packet header. The header looks like this:
--
--<code>
-- --------------------------------------------------------------------------------------------------
-- | 31 30 29 28 27 26 25 24 23 22 21 20 19 18 17 16 15 14 13 12 11 10 9  8  7  6  5  4  3  2  1  0 |
-- --------------------------------------------------------------------------------------------------
-- |         0xFF           |          'S'          |        'M'            |         'B'           |
-- --------------------------------------------------------------------------------------------------
-- |        Command         |                             Status...                                 |
-- --------------------------------------------------------------------------------------------------
-- |    ...Status           |        Flags          |                    Flags2                     |
-- --------------------------------------------------------------------------------------------------
-- |                    PID_high                    |                  Signature.....               |
-- --------------------------------------------------------------------------------------------------
-- |                                        ....Signature....                                       |
-- --------------------------------------------------------------------------------------------------
-- |              ....Signature                     |                    Unused                     |
-- --------------------------------------------------------------------------------------------------
-- |                      TID                       |                     PID                       |
-- --------------------------------------------------------------------------------------------------
-- |                      UID                       |                     MID                       |
-- -------------------------------------------------------------------------------------------------
--</code>
--
-- All fields are, incidentally, encoded in little endian byte order.
--
-- For the purposes here, the program doesn't care about most of the fields so they're given default
-- values. The "command" field is the only one we ever have to set manually, in my experience. The TID
-- and UID need to be set, but those are stored in the smb state and don't require user intervention.
--
--@param smb     The smb state table.
--@param command The command to use.
--@param overrides The overrides table. Keep in mind that overriding things like flags is generally a very bad idea, unless you know what you're doing.
--@return A binary string containing the packed packet header.
function smb_encode_header(smb, command, overrides)
  -- Make sure we have an overrides array
  overrides = overrides or {}

  -- Used for the header
  local sig = "\xFFSMB"

  -- Pretty much every flags is deprecated. We set these two because they're required to be on.
  local flags  = (0x10 | 0x08) -- SMB_FLAGS_CANONICAL_PATHNAMES | SMB_FLAGS_CASELESS_PATHNAMES
  -- These flags are less deprecated. We negotiate 32-bit status codes and long names. We also don't include Unicode, which tells
  -- the server that we deal in ASCII.
  local flags2 = (0x4000 | 0x2000 | 0x0040 | 0x0001) -- SMB_FLAGS2_32BIT_STATUS | SMB_FLAGS2_EXECUTE_ONLY_READS | SMB_FLAGS2_IS_LONG_NAME | SMB_FLAGS2_KNOWS_LONG_NAMES

  -- Unless the user's disabled the security signature, add it
  if(nmap.registry.args.smbsign ~= "disable") then
    flags2 = (flags2 | 0x0004) -- SMB_FLAGS2_SECURITY_SIGNATURE
  end


  if(smb['extended_security'] == true) then
    flags2 = (flags2 | 0x0800) -- SMB_EXTENDED_SECURITY
  end

  -- TreeID should never ever be 'nil', but it seems to happen once in awhile so print an error
  if(smb['tid'] == nil) then
    return false, string.format("SMB: ERROR: TreeID value was set to nil on host %s", smb['ip'])
  end

  local header = string.pack("<BBBBB I4 B I2 I2 I8 I2 I2 I2 I2 I2",
    sig:byte(1),  -- Header
    sig:byte(2),  -- Header
    sig:byte(3),  -- Header
    sig:byte(4),  -- Header
    command,      -- Command
    (overrides['status'] or 0),        -- status
    (overrides['flags'] or flags),     -- flags
    (overrides['flags2'] or flags2),   -- flags2
    (overrides['pid_high'] or 0),      -- extra (pid_high)
    (overrides['signature'] or 0),     -- extra (signature)
    (overrides['extra'] or 0),         -- extra (unused)
    (overrides['tid'] or smb['tid']),  -- tid
    (overrides['pid'] or smb['pid']),  -- pid
    (overrides['uid'] or smb['uid']),  -- uid
    (overrides['mid'] or smb['mid'])   -- mid
    )

  return header
end

-- Converts a string containing the parameters section into the encoded
--  parameters string.
--
-- The encoding is simple:
-- * (1 byte)   The number of 2-byte values in the parameters section
-- * (variable) The parameter section
-- This is automatically done by <code>smb_send</code>.
--
-- @param parameters The parameters section.
-- @param overrides The overrides table. The only thing possible to override here is the length.
-- @return The encoded parameters.
local function smb_encode_parameters(parameters, overrides)
  -- Make sure we have an overrides array
  overrides = overrides or {}

  return string.pack("<B", overrides['parameters_length'] or (#parameters / 2)) .. parameters
end

-- Converts a string containing the data section into the encoded data string.
--
-- The encoding is simple:
-- * (2 bytes)  The number of bytes in the data section
-- * (variable) The data section
-- This is automatically done by <code>smb_send</code>.
--
-- @param data The data section.
-- @param overrides The overrides table. The only thing possible to override here is the length.
-- @return The encoded data.
local function smb_encode_data(data, overrides)
  -- Make sure we have an overrides array
  overrides = overrides or {}

  return string.pack("<I2", overrides['data_length'] or #data) .. data
end

--Sign the message, if possible. This is done by replacing the signature with the sequence
-- number, creating a hash, then putting that hash in the signature location.
--@param smb  The smb state object.
--@param body The body of the packet that's being signed.
--@return The body of the packet, with the signature in place.
local function message_sign(smb, body)
  smb['sequence'] = smb['sequence'] + 1

  if(smb['mac_key'] == nil) then
    stdnse.debug3("SMB: Not signing message (missing mac_key)")
    return body
  elseif(nmap.registry.args.smbsign == "disable") then
    stdnse.debug3("SMB: Not signing message (disabled by user)")

    return body
  end

  -- Convert the sequence number to a string
  local sequence = string.pack("<I8", smb['sequence'])
  -- Create a new string, with the sequence number in place
  local new_packet = string.sub(body, 1, 14) .. sequence .. string.sub(body, 23)
  -- Calculate the signature
  local signature = smbauth.calculate_signature(smb['mac_key'], new_packet)

  return string.sub(body, 1, 14) .. signature .. string.sub(body, 23)
end

--Check the signature of the message.
--
-- This is the opposite of <code>message_sign</code>, and works the same way
-- (replaces the signature with the sequence number, calculates hash, checks)
--@param smb  The smb state object.
--@param body The body of the packet that's being checked.
--@return A true/false value -- true if the packet was signed properly, false if it wasn't.
local function message_check_signature(smb, body)
  smb['sequence'] = smb['sequence'] + 1

  if(smb['mac_key'] == nil) then
    stdnse.debug3("SMB: Not signing message (missing mac_key)")
    return true
  elseif(nmap.registry.args.smbsign ~= "force" and (smb['security_mode'] & 0x0A) ~= 0) then
    stdnse.debug3("SMB: Not signing message (server doesn't support it -- default)")
    return true
  elseif(nmap.registry.args.smbsign == "disable" or nmap.registry.args.smbsign == "ignore") then
    stdnse.debug3("SMB: Not signing message (disabled by user)")
    return true
  end

  -- Pull out the signature that they used
  local signature  = string.sub(body, 15, 22)

  -- Turn the sequence into a string
  local sequence   = string.pack("<I8", smb['sequence'])
  -- Create a new string, with the sequence number in place
  local new_packet = string.sub(body, 1, 14) .. sequence .. string.sub(body, 23)

  -- Calculate the proper signature
  local real_signature = smbauth.calculate_signature(smb['mac_key'], new_packet)

  -- Validate the signature
  return signature == real_signature
end

--- Prepends the NetBIOS header to the packet, which is essentially the length, encoded
--  in 4 bytes of big endian, and sends it out.
--
--  The length field is actually 17 or 24 bits wide, depending on whether or
--  not we're using raw, but that shouldn't matter.
--
--@param smb        The SMB object associated with the connection
--@param header     The header, encoded with <code>smb_get_header</code>.
--@param parameters The parameters.
--@param data       The data.
--@param overrides  Overrides table.
--@return (result, err) If result is false, err is the error message. Otherwise, err is
--        undefined
function smb_send(smb, header, parameters, data, overrides)
  overrides = overrides or {}

  local encoded_parameters = smb_encode_parameters(parameters, overrides)
  local encoded_data       = smb_encode_data(data, overrides)
  local body               = header .. encoded_parameters .. encoded_data
  local status, err

  -- Calculate the message signature
  body = message_sign(smb, body)

  local out = string.pack(">s4", body)


  stdnse.debug3("SMB: Sending SMB packet (len: %d)", #out)
  status, err = smb['socket']:send(out)

  if not status then
    stdnse.debug1("SMB: Sending packet failed.")
  end

  return status, err
end

--- Reads the next packet from the socket, and parses it into the header, parameters,
--  and data.
--
--@param smb The SMB object associated with the connection
--@param read_data [optional] This function will read the data section if and only if
--       this value is true. This is a workaround for a bug in the tree connect packet,
--       where the length is set incorrectly. Default: true.
--@return (status, header, parameters, data) If status is true, the header,
--        parameters, and data are all the raw arrays (with the lengths already
--        removed). If status is false, header contains an error message and parameters/
--        data are undefined.
function smb_read(smb, read_data)
  local pos, netbios_data, netbios_length, length, header, parameter_length, parameters, data_length, data

  stdnse.debug3("SMB: Receiving SMB packet")

  -- Receive the response -- we make sure to receive at least 4 bytes, the length of the NetBIOS length
  smb['socket']:set_timeout(TIMEOUT)

  -- attempt to read the Netbios header
  local status, netbios_data = smb['socket']:receive_buf(match.numbytes(4), true);

  -- Make sure the connection is still alive
  if not status then
    return false, "SMB: Failed to receive bytes: " .. netbios_data
  end

  -- The length of the packet is 4 bytes of big endian (for our purposes).
  -- The NetBIOS header is 24 bits, big endian
  netbios_length, pos = string.unpack(">I4", netbios_data)
  -- Make the length 24 bits
  netbios_length = (netbios_length & 0x00FFFFFF)

  -- The total length is the netbios_length, plus 4 (for the length itself)
  length = netbios_length + 4

  local status, smb_data = smb['socket']:receive_buf(match.numbytes(netbios_length), true)

  -- Make sure the connection is still alive
  if not status then
    return false, "SMB: Failed to receive bytes: " .. smb_data
  end

  local result = netbios_data .. smb_data
  if(#result ~= length) then
    stdnse.debug1("SMB: ERROR: Received wrong number of bytes, there will likely be issues (received %d, expected %d)", #result, length)
    return false, string.format("SMB: ERROR: Didn't receive the expected number of bytes; received %d, expected %d. This will almost certainly cause some errors.", #result, length)
  end

  -- Check the message signature (ignoring the first four bytes, which are the netbios header)
  local good_signature = message_check_signature(smb, string.sub(result, 5))
  if(good_signature == false) then
    return false, "SMB: ERROR: Server returned invalid signature"
  end

  local header_format = "<c32 B"
  if (#result - pos + 1) < string.packsize(header_format) then
    return false, "SMB: ERROR: Server returned less data than needed for header"
  end
  header, parameter_length, pos = string.unpack("<c32 B", result, pos)

  -- Double the length parameter, since parameters are two-byte values.
  if (length - pos + 1) < (parameter_length * 2) then
    return false, "SMB: ERROR: parameter_length greater than response length"
  end
  parameters, pos = string.unpack(("<c%d"):format(parameter_length*2), result, pos)

  -- The data length is a 2-byte value.
  data_length, pos = string.unpack("<I2", result, pos)

  -- Read that many bytes of data.
  if(read_data == nil or read_data == true) then
    if (length - pos + 1) < data_length then
      return false, "SMB: ERROR: data_length greater than response length"
    end
    data = string.unpack("c" .. data_length, result, pos)
  else
    data = nil
  end

  stdnse.debug3("SMB: Received %d bytes", #result)
  return true, header, parameters, data
end

---
-- Negotiates SMBv1 connections
--
-- Sends the following:
-- * List of known protocols
--
-- This function adds to <code>smb</code>:
-- * 'security_mode'    Whether or not to use cleartext passwords, message signatures, etc.
-- * 'max_mpx'          Maximum number of multiplexed connections
-- * 'max_vc'           Maximum number of virtual circuits
-- * 'max_buffer'       Maximum buffer size
-- * 'max_raw_buffer'   Maximum buffer size for raw connections (considered obsolete)
-- * 'session_key'      A value that's basically just echoed back
-- * 'capabilities'     The server's capabilities
-- * 'time'             The server's time (in UNIX-style seconds since 1970)
-- * 'date'             The server's date in a user-readable format
-- * 'timezone'         The server's timezone, in hours from UTC
-- * 'timezone_str'     The server's timezone, as a string
-- * 'server_challenge' A random string used for challenge/response
-- * 'domain'           The server's primary domain or workgroup
-- * 'server'           The server's name
--
-- @param smb The SMB object associated with the connection.
-- @param overrides Overrides table.
-- @return Boolean status
-- @return The negotiated dialect in human readable form or an error message.
---
function negotiate_v1(smb, overrides)
  local header = smb_encode_header(smb, command_codes['SMB_COM_NEGOTIATE'], overrides)
  -- Make sure we have overrides
  overrides = overrides or {}

  -- Parameters are blank
  local parameters = ""
  local data = string.pack("<BzBz", 2, (overrides['dialect'] or "NT LM 0.12"), 2, "")

  -- Send the negotiate request
  stdnse.debug2("SMB: Sending SMB_COM_NEGOTIATE")
  local result, err = smb_send(smb, header, parameters, data, overrides)
  if(result == false) then
    return false, err
  end
  -- Read the result
  local status, header, parameters, data = smb_read(smb)
  if(status ~= true) then
    return false, header
  end

  -- Check if we fell off the packet
  local header_format = "<c4 B I4 B I2 I2 i8 I2 I2 I2 I2 I2"
  if #header < string.packsize(header_format) then
    return false, "SMB: ERROR: Server returned less data than it was supposed to (one or more fields are missing); aborting [8]"
  end

  -- Parse out the header
  local protocol_version, command, status, flags, flags2, pid_high, signature, unused, tid, pid, uid, mid, pos = string.unpack(header_format, header)

  -- Get the protocol version
  if(protocol_version == ("\xFESMB")) then
    return false, "SMB: Server returned a SMBv2 packet, don't know how to handle"
  end

  -- Since this is the first response seen, check any necessary flags here
  if((flags2 & 0x0800) ~= 0x0800) then
    smb['extended_security'] = false
  end

  -- Parse the parameter section
  local dialect_format = "<I2"
  local parameters_format = "<BI2 I2 I4 I4 I4 I4"
  if #parameters < (string.packsize(dialect_format) + string.packsize(parameters_format)) then
    return false, "SMB: ERROR: Server returned less data than it was supposed to (one or more fields are missing); aborting [9]"
  end
  smb['dialect'], pos = string.unpack(dialect_format, parameters)

  -- Check if the server didn't like our requested protocol
  if(smb['dialect'] ~= 0) then
    stdnse.debug2("Server negotiated an unknown protocol (#%d) -- aborting", smb['dialect'])
    return false, string.format("Server negotiated an unknown protocol (#%d) -- aborting", smb['dialect'])
  end

  smb.security_mode, smb.max_mpx, smb.max_vc, smb.max_buffer, smb.max_raw_buffer, smb.session_key, smb.capabilities, pos = string.unpack(parameters_format, parameters, pos)
  -- Some broken implementations of SMB don't send these variables
  smb.time = 0
  smb.timezone = 0
  smb.key_length = 0
  smb.byte_count = 0
  if (#parameters - pos + 1) >= 8 then
    smb.time, pos = string.unpack("<I8", parameters, pos)
    if (#parameters - pos + 1) >= 2 then
      smb.timezone, pos = string.unpack("<i2", parameters, pos)
      if (#parameters - pos + 1) >= 1 then
        smb.key_length, pos = string.unpack("B", parameters, pos)
        if (#parameters - pos + 1) >= 2 then
          smb.byte_count, pos = string.unpack("<I2", parameters, pos)
        end
      end
    end
  end

  -- Convert the time and timezone to more useful values
  smb['time'] = (smb['time'] // 10000000) - 11644473600
  smb['date'] = datetime.format_timestamp(smb['time'])
  smb['timezone'] = -(smb['timezone'] / 60)
  if(smb['timezone'] == 0) then
    smb['timezone_str'] = "UTC+0"
  elseif(smb['timezone'] < 0) then
    smb['timezone_str'] = "UTC-" .. math.abs(smb['timezone'])
  else
    smb['timezone_str'] = "UTC+" .. smb['timezone']
  end

  -- Data section
  if(smb['extended_security'] == true) then
    if #data < 16 then
      return false, "SMB: ERROR: not enough data for extended security"
    end
    smb.server_guid, pos = string.unpack("<c16", data)

    -- do we have a security blob?
    if ( #data - pos + 1 > 0 ) then
      smb.security_blob = data:sub(pos)
      pos = #data + 1
    end
  else
    if #data < smb.key_length then
      return false, "SMB: ERROR: not enough data for server_challenge"
    end
    smb.server_challenge, pos = string.unpack(string.format("<c%d", smb['key_length']), data)

    -- Get the (null-terminated) domain as a Unicode string
    smb['domain'] = ""
    smb['server'] = ""

    local remainder = unicode.utf16to8(string.sub(data, pos))
    pos, pos = string.find(remainder, "\0", 1, true)
    if pos == nil then
      return false, "SMB: ERROR: Server returned less data than it was supposed to (one or more fields are missing); aborting [14]"
    end
    smb['domain'] = string.sub(remainder, 1, pos)

    -- Get the server name as a Unicode string
    -- Note: This can be nil, Samba leaves this off
    local pos2 = pos + 1
    pos, pos = string.find(remainder, "\0", pos2, true)
    if pos ~= nil then
      smb['server'] = string.sub(remainder, pos2, pos)
    end
  end

  stdnse.debug2("SMB_COM_NEGOTIATE got status:%s", status)
  if status == 0 then
    return true, overrides['dialect'] or "NT LM 0.12"
  end
end

---
-- Wrapper function to negotiate the protocol to use in the SMB connection.
-- By default it attempts to negotiate with using following dialects:
-- * NT LM 12.0 (SMBv1)
-- @param smb The SMB object
-- @param overrides Overrides table
-- @return Boolean status
---
function negotiate_protocol(smb, overrides)
  local status, dialect
  status, dialect = negotiate_v1(smb, overrides)
  if status then
    return true
  else
    stdnse.debug1("Couldn't negotiate a SMBv1 connection:%s", dialect)
    return false, string.format("Could not negotiate a connection:%s", dialect)
  end
end

---
-- Returns list of supported dialects for SMBv1, SMBv2 and SMBv3.
-- @param host       The SMB host to connect to.
-- @param overrides [optional] Overrides for various fields.
-- @return Boolean status
-- @return Table of supported dialects or error message
---
function list_dialects(host, overrides)
  local supported_dialects = {}
  local status, smb1_dialect
  local smbstate

  overrides = tableaux.tcopy(overrides or {})

  -- Check for SMBv1 first
  stdnse.debug2("Checking if SMBv1 is supported")
  status, smbstate = start(host)
  if(status == false) then
    return false, smbstate
  end

  status, smb1_dialect = negotiate_v1(smbstate, overrides)
  if status then --Add SMBv1 as a dialect
    table.insert(supported_dialects, smb1_dialect)
  end
  stop(smbstate) -- Finish SMBv1 and close connection

  status, smbstate = start(host)
  if(status == false) then
    return false, smbstate
  end
  stdnse.debug2("Checking if SMB 2+ is supported in general")
  overrides['Dialects'] = nil
  local max_dialect
  status, max_dialect = smb2.negotiate_v2(smbstate, overrides)
  stop(smbstate)
  if not status then -- None of SMB2 dialects accepted by the target
    return true, supported_dialects
  end
  stdnse.debug2("SMB2: Dialect '%s' is the highest supported", smb2.dialect_name(max_dialect))

  -- Check individual SMB2 and SMB3 dialects
  for i, dialect in pairs(smb2.dialects()) do
    if dialect == max_dialect then
      break
    end
    local dialect_name = smb2.dialect_name(dialect)
    -- we need a clean connection for each negotiate request
    status, smbstate = start(host)
    if(status == false) then
      return false, smbstate
    end
    stdnse.debug2("SMB2: Checking if dialect '%s' is supported", dialect_name)
    overrides['Dialects'] = {dialect}
    status = smb2.negotiate_v2(smbstate, overrides)
    --clean smb connection
    stop(smbstate)
    if status then
      stdnse.debug2("SMB2: Dialect '%s' is supported", dialect_name)
      table.insert(supported_dialects, dialect_name)
    end
  end
  table.insert(supported_dialects, smb2.dialect_name(max_dialect))

  return true, supported_dialects
end

--- This is an internal function and should not be called externally. Use
--  the start_session() function instead.
local function start_session_basic(smb, log_errors, overrides)
  local i, err
  local status, result
  local header, parameters, data, domain
  local andx_command, andx_reserved, andx_offset, action
  local os, lanmanager
  local username, domain, password, password_hash, hash_type
  local busy_count = 0

  header = smb_encode_header(smb, command_codes['SMB_COM_SESSION_SETUP_ANDX'], overrides)

  -- Get the first account, unless they overrode it
  if(overrides ~= nil and overrides['username'] ~= nil) then
    result = true
    username      = overrides['username']
    domain        = overrides['domain']
    password      = overrides['password']
    password_hash = overrides['password_hash']
    hash_type     = overrides['hash_type']
  else
    result, username, domain, password, password_hash, hash_type = smbauth.get_account(smb['host'])
  end

  while result ~= false do
    local lanman, ntlm

    lanman, ntlm, smb['mac_key'] = smbauth.get_password_response(smb['ip'], username, domain, password, password_hash, hash_type, smb['server_challenge'], false)

    -- Parameters
    parameters = string.pack("<BBI2 I2I2 I2 I4 I2I2 I4I4",
      0xFF,               -- ANDX -- no further commands
      0x00,               -- ANDX -- Reserved (0)
      0x0000,             -- ANDX -- next offset
      0xFFFF,             -- Max buffer size
      0x0001,             -- Max multiplexes
      0x0001,             -- Virtual circuit num
      smb['session_key'], -- The session key
      #lanman,            -- ANSI/Lanman password length
      #ntlm,              -- Unicode/NTLM password length
      0x00000000,         -- Reserved
      0x00000050          -- Capabilities
      )

    -- Data is a list of strings, terminated by a blank one.
    data = lanman -- ANSI/Lanman password
    .. ntlm -- Unicode/NTLM password
    .. string.pack("<zzzz",
      username,               -- Account
      domain,                 -- Domain
      "Nmap",                 -- OS
      "Native Lanman"         -- Native LAN Manager
      )

    -- Send the session setup request
    stdnse.debug2("SMB: Sending SMB_COM_SESSION_SETUP_ANDX")
    result, err = smb_send(smb, header, parameters, data, overrides)
    if(result == false) then
      return false, err
    end

    -- Read the result
    status, header, parameters, data = smb_read(smb)
    if(status ~= true) then
      return false, header
    end

    local header_format = "<c4 B I4 B I2 I2 i8 I2 I2 I2 I2 I2"
    if #header < string.packsize(header_format) then
      return false, "SMB: ERROR: Server returned less data than it was supposed to (one or more fields are missing); aborting [17]"
    end
    -- Check if we were allowed in
    local protocol_version, command, flags, flags2, pid_high, signature, unused, tid, pid, uid, mid, pos
    protocol_version, command, status, flags, flags2, pid_high, signature, unused, tid, pid, uid, mid, pos = string.unpack(header_format, header)

    -- Check if we're successful
    if(status == 0) then

      -- Parse the parameters
      local parameters_format = "<BB I2 I2"
      if #parameters < string.packsize(parameters_format) then
        return false, "SMB: ERROR: Server returned less data than needed"
      end
      andx_command, andx_reserved, andx_offset, action, pos = string.unpack(parameters_format, parameters)

      -- Parse the data
      status, os, lanmanager, domain, pos = pcall(string.unpack, "<zzz", data)
      if not status then
        return false, "SMB: ERROR: Server returned less data than it was supposed to (one or more fields are missing); aborting [19]"
      end

      -- Fill in the smb object and smb string
      smb['uid']        = uid
      smb['is_guest']   = (action & 1)
      smb['os']         = os
      smb['lanmanager'] = lanmanager

      -- Check if they're using an un-supported system
      if(os == "" or lanmanager == "" or domain == "") then
        stdnse.debug1("SMB: WARNING: the server is using a non-standard SMB implementation; your mileage may vary (%s)", smb['ip'])
      elseif(os == "Unix" or string.sub(lanmanager, 1, 5) == "Samba") then
        stdnse.debug1("SMB: WARNING: the server appears to be Unix; your mileage may vary.")
      end

      -- Check if they were logged in as a guest
      if(log_errors == nil or log_errors == true) then
        if(smb['is_guest'] == 1) then
          stdnse.debug1("SMB: Login as %s\\%s failed, but was given guest access (username may be wrong, or system may only allow guest)", domain, stdnse.string_or_blank(username))
        else
          stdnse.debug2("SMB: Login as %s\\%s succeeded", domain, stdnse.string_or_blank(username))
        end
      end

      -- Set the initial sequence number
      smb['sequence'] = 1

      return true

    else
      -- Check if we got the error NT_STATUS_REQUEST_NOT_ACCEPTED
      if(status == 0xc00000d0) then
        busy_count = busy_count + 1

        if(busy_count > 9) then
          return false, "SMB: ERROR: Server has too many active connections; giving up."
        end

        local backoff = math.random() * 10
        stdnse.debug1("SMB: Server has too many active connections; pausing for %s seconds.", math.floor(backoff * 100) / 100)
        stdnse.sleep(backoff)
      else
        -- This username failed, print a warning and keep going
        if(log_errors == nil or log_errors == true) then
          stdnse.debug1("SMB: Login as %s\\%s failed (%s)", domain, stdnse.string_or_blank(username), get_status_name(status))
        end

        -- Go to the next account
        if(overrides == nil or overrides['username'] == nil) then
          smbauth.next_account(smb['host'])
          result, username, domain, password, password_hash, hash_type = smbauth.get_account(smb['host'])
        else
          result = false
        end
      end
    end
  end

  if(log_errors ~= false) then
    stdnse.debug1("SMB: ERROR: %s", username)
  end

  if (status ~= nil) then
    return false, get_status_name(status)
  else
    return false, username
  end
end

--- This is an internal function and should not be called externally. Use
--  the start_session() function instead.
local function start_session_extended(smb, log_errors, overrides)
  local i
  local status, status_name, result, err
  local header, parameters, data
  local andx_command, andx_reserved, andx_offset, action, security_blob_length
  local os, lanmanager
  local username, domain, password, password_hash, hash_type
  local busy_count = 0

  -- Set a default status_name, in case everything fails
  status_name = "An unknown error has occurred"

  -- Get the first account, unless they overrode it
  if(overrides ~= nil and overrides['username'] ~= nil) then
    result = true
    username      = overrides['username']
    domain        = overrides['domain']
    password      = overrides['password']
    password_hash = overrides['password_hash']
    hash_type     = overrides['hash_type']
  else
    result, username, domain, password, password_hash, hash_type = smbauth.get_account(smb['host'])
    if(not(result)) then
      return result, username
    end
  end

  -- check what kind of security blob we were given in the negotiate protocol request
  local sp_nego = false
  if ( smb['security_blob'] and #smb['security_blob'] > 11 ) then
    local oid, pos = string.unpack(">c6", smb['security_blob'], 5)
    sp_nego = ( oid == "\x2b\x06\x01\x05\x05\x02" or oid == "\x06\x06\x2b\x06\x01\x05" ) -- check for SPNEGO OID 1.3.6.1.5.5.2
  end

  local ntlm_challenge_accepted = false
  while result ~= false do
    -- These are loop variables
    local security_blob = nil
    local security_blob_length = 0

    -- This loop takes care of the multiple packets that "extended security" requires
    repeat
      -- Get the new security blob, passing the old security blob as a parameter. If there was no previous security blob, then nil is passed, which creates a new one
      if ( not(security_blob) ) then
        status, security_blob, smb['mac_key'] = smbauth.get_security_blob(security_blob, smb['ip'], username, domain, password, password_hash, hash_type, (sp_nego and 0x00088215))

        if ( sp_nego ) then
          local enc = asn1.ASN1Encoder:new()
          local mechtype = enc:encode( { type = 'A0', value = enc:encode( { type = '30', value = enc:encode( { type = '06', value = stdnse.fromhex("2b06010401823702020a") } ) } ) } )
          local oid = enc:encode( { type = '06', value = stdnse.fromhex("2b0601050502") } )

          security_blob = enc:encode(security_blob)
          security_blob = enc:encode( { type = 'A2', value = security_blob } )
          security_blob = mechtype .. security_blob
          security_blob = enc:encode( { type = '30', value = security_blob } )
          security_blob = enc:encode( { type = 'A0', value = security_blob } )
          security_blob = oid .. security_blob
          security_blob = enc:encode( { type = '60', value = security_blob } )
        end
      else
        if ( sp_nego ) then
          if (smb['domain'] or smb['server']) and (not domain or #domain == 0) then
            domain = smb['domain'] or smb['server']
          end
          hash_type = "ntlm"
        end

        status, security_blob, smb['mac_key'] = smbauth.get_security_blob(security_blob, smb['ip'], username, domain, password, password_hash, hash_type, (sp_nego and 0x00088215))

        if ( sp_nego ) then
          local enc = asn1.ASN1Encoder:new()
          security_blob = enc:encode(security_blob)
          security_blob = enc:encode( { type = 'A2', value = security_blob } )
          security_blob = enc:encode( { type = '30', value = security_blob } )
          security_blob = enc:encode( { type = 'A1', value = security_blob } )
        end

      end

      -- There was an error processing the security blob
      if(status == false) then
        return false, string.format("SMB: ERROR: Security blob: %s", security_blob)
      end

      header     = smb_encode_header(smb, command_codes['SMB_COM_SESSION_SETUP_ANDX'], overrides)

      -- Data is a list of strings, terminated by a blank one.
      data = security_blob -- Security blob
      .. string.pack("<zzz",
        "Nmap",                -- OS
        "Native Lanman",       -- Native LAN Manager
        ""                     -- Primary domain
        )

      -- Parameters
      parameters = string.pack("<BB I2 I2 I2 I2 I4 I2 I4 I4",
        0xFF,               -- ANDX -- no further commands
        0x00,               -- ANDX -- Reserved (0)
        #data + 24 + #header + 3, -- ANDX -- next offset
        0xFFFF,             -- Max buffer size
        0x0001,             -- Max multiplexes
        0x0001,             -- Virtual circuit num
        smb['session_key'], -- The session key
        #security_blob,     -- Security blob length
        0x00000000,         -- Reserved
        0x80000050          -- Capabilities
        )

      -- Send the session setup request
      stdnse.debug2("SMB: Sending SMB_COM_SESSION_SETUP_ANDX")
      result, err = smb_send(smb, header, parameters, data, overrides)
      if(result == false) then
        return false, err
      end

      -- Read the result
      status, header, parameters, data = smb_read(smb)
      if(status ~= true) then
        return false, header
      end

      local header_format = "<c4 B I4 B I2 I2 i8 I2 I2 I2 I2 I2"
      if #header < string.packsize(header_format) then
        return false, "SMB: ERROR: Server returned less data than it was supposed to (one or more fields are missing); aborting [8]"
      end

      -- Check if we were allowed in
      local protocol_version, command, status, flags, flags2, pid_high, signature, unused, tid, pid, uid, mid, pos = string.unpack(header_format, header)
      smb['uid'] = uid

      -- Get a human readable name
      status_name = get_status_name(status)

      -- Only parse the parameters if it's ok or if we're going to keep going
      if(status_name == "NT_STATUS_SUCCESS" or status_name == "NT_STATUS_MORE_PROCESSING_REQUIRED") then
        -- Parse the parameters
        local parameters_format = "<BBI2 I2 I2"
        if #parameters < string.packsize(parameters_format) then
          return false, "SMB: ERROR: Server returned less data than needed"
        end
        andx_command, andx_reserved, andx_offset, action, security_blob_length, pos = string.unpack(parameters_format, parameters)
        smb['is_guest']   = (action & 1)

        -- Parse the data
        if #data < security_blob_length then
          return false, "SMB: ERROR: Server returned less data than needed"
        end
        security_blob, pos = string.unpack(("<c%d"):format(security_blob_length), data)
        status, os, lanmanager, pos = pcall(string.unpack, "zz", data, pos)

        if not ntlm_challenge_accepted then
          if ( status_name == "NT_STATUS_MORE_PROCESSING_REQUIRED" and sp_nego ) then
            local start = security_blob:find("NTLMSSP")
            security_blob = security_blob:sub(start)
          end

          if not status or security_blob == nil then
            return false, "SMB: ERROR: NTLM challenge not accepted or lanmanager missing"
          end
          smb['os']         = os
          smb['lanmanager'] = lanmanager

          local host_info = smbauth.get_host_info_from_security_blob(security_blob)
          if ( host_info ) then
            smb['fqdn'] = host_info['fqdn']
            smb['domain_dns'] = host_info['dns_domain_name']
            smb['forest_dns'] = host_info['dns_forest_name']
            smb['server'] = host_info['netbios_computer_name']
            smb['domain'] = host_info['netbios_domain_name']
          end
          ntlm_challenge_accepted = true
        end


        -- If it's ok, do a cleanup and return true
        if(status_name == "NT_STATUS_SUCCESS") then
          -- Check if they're using an un-supported system
          if not status then
            stdnse.debug1("SMB: WARNING: the server is using a non-standard SMB implementation; your mileage may vary (%s)", smb['ip'])
          elseif(os == "Unix" or string.sub(lanmanager, 1, 5) == "Samba") then
            stdnse.debug1("SMB: WARNING: the server appears to be Unix; your mileage may vary.")
          end

          -- Check if they were logged in as a guest
          if(log_errors == nil or log_errors == true) then
            if(smb['is_guest'] == 1) then
              stdnse.debug1("SMB: Extended login to %s as %s\\%s failed, but was given guest access (username may be wrong, or system may only allow guest)", smb['ip'], domain, stdnse.string_or_blank(username))
            else
              stdnse.debug2("SMB: Extended login to %s as %s\\%s succeeded", smb['ip'], domain, stdnse.string_or_blank(username))
            end
          end

          -- Set the initial sequence number
          smb['sequence'] = 1

          return true
        end -- Status is ok
      end -- Should we parse the parameters/data?
    until status_name ~= "NT_STATUS_MORE_PROCESSING_REQUIRED"

    -- Check if we got the error NT_STATUS_REQUEST_NOT_ACCEPTED
    if(status == 0xc00000d0) then
      busy_count = busy_count + 1

      if(busy_count > 9) then
        return false, "SMB: ERROR: Server has too many active connections; giving up."
      end

      local backoff = math.random() * 10
      stdnse.debug1("SMB: Server has too many active connections; pausing for %s seconds.", math.floor(backoff * 100) / 100)
      stdnse.sleep(backoff)
    else
      -- Display a message to the user, and try the next account
      if(log_errors == nil or log_errors == true) then
        stdnse.debug1("SMB: Extended login to %s as %s\\%s failed (%s)", smb['ip'], domain, stdnse.string_or_blank(username), status_name)
      end

      -- Go to the next account
      if(overrides == nil or overrides['username'] == nil) then
        smbauth.next_account(smb['host'])
        result, username, domain, password, password_hash, hash_type = smbauth.get_account(smb['host'])
        if(not(result)) then
          return false, username
        end
      else
        result = false
      end
    end

    -- Reset the user id
    smb['uid'] = 0

  end -- Loop over the accounts

  if(log_errors == nil or log_errors == true) then
    stdnse.debug1("SMB: ERROR: All logins failed, sorry it didn't work out!")
  end

  return false, status_name
end

--- Sends out SMB_COM_SESSION_SETUP_ANDX, which attempts to log a user in.
--
-- Sends the following:
-- * Negotiated parameters (multiplexed connections, virtual circuit, capabilities)
-- * Passwords (plaintext, unicode, lanman, ntlm, lmv2, ntlmv2, etc)
-- * Account name
-- * OS (I just send "Nmap")
-- * Native LAN Manager (no clue what that is, but it seems to be ignored)
--
-- Receives the following:
-- * User ID
-- * Server OS
--
--@param smb          The SMB object associated with the connection
--@param overrides    [optional] A table of overrides for username, domain, password, password_hash, and hash_type.
--                    If any of these are given, it's used first. If they aren't, then Nmap parameters, Nmap registry entries,
--                    guest, and NULL sessions are used.
--@param log_errors   [optional] If set, will display login. Default: true.
--@return (status, result) If status is false, result is an error message. Otherwise, result is nil and the following
--        elements are added to the smb table:
--    *  'uid'         The UserID for the session
--    *  'is_guest'    If set, the username wasn't found so the user was automatically logged in as the guest account
--    *  'os'          The operating system
--    *  'lanmanager'  The server's LAN Manager
function start_session(smb, overrides, log_errors)
  -- Use a mutex to avoid some issues (see http://seclists.org/nmap-dev/2011/q1/464)
  local smb_auth_mutex = nmap.mutex( "SMB Authentication Mutex" )
  smb_auth_mutex( "lock" )

  local status, result
  if(smb['extended_security'] == true) then
    status, result = start_session_extended(smb, log_errors, overrides)
  else
    status, result = start_session_basic(smb, log_errors, overrides)
  end

  smb_auth_mutex( "done" )
  return status, result
end

--- Sends out <code>SMB_COM_SESSION_TREE_CONNECT_ANDX</code>, which attempts to
-- connect to a share.
--
-- Sends the following:
-- * Password (for share-level security, which we don't support)
-- * Share name
-- * Share type (or "?????" if it's unknown, that's what we do)
--
-- Receives the following:
-- * Tree ID
--
--@param smb       The SMB object associated with the connection
--@param path      The path to connect (eg, <code>"\\servername\C$"</code>)
--@param overrides [optional] Overrides for various fields
--@return (status, result) If status is false, result is an error message. Otherwise, result is a
--        table with the following elements:
--      * 'tid'         The TreeID for the session
function tree_connect(smb, path, overrides)
  local header, parameters, data, err, result
  local andx_command, andx_reserved, andx_offset, action
  local status

  -- Make sure we have overrides
  overrides = overrides or {}

  header = smb_encode_header(smb, command_codes['SMB_COM_TREE_CONNECT_ANDX'], overrides)
  parameters = string.pack("<BBI2 I2 I2",
    0xFF,   -- ANDX no further commands
    0x00,   -- ANDX reserved
    0x0000, -- ANDX offset
    (overrides['tree_connect_flags'] or 0x0000), -- flags
    0x0000 -- password length (for share-level security)
    )
  data = string.pack("zz",
    -- Share-level password
    path,   -- Path
    (overrides['tree_type'] or "?????") -- Type of tree ("?????" = any)
    )

  -- Send the tree connect request
  stdnse.debug2("SMB: Sending SMB_COM_TREE_CONNECT_ANDX")
  result, err = smb_send(smb, header, parameters, data, overrides)
  if(result == false) then
    return false, err
  end

  -- Read the result
  status, header, parameters, data = smb_read(smb)
  if(status ~= true) then
    return false, header
  end

  local header_format = "<c4 B I4 B I2 I2 i8 I2 I2 I2 I2 I2"
  if #header < string.packsize(header_format) then
    return false, "SMB: ERROR: Server returned less data than it was supposed to (one or more fields are missing); aborting [8]"
  end
  -- Check if we were allowed in
  local protocol_version, command, status, flags, flags2, pid_high, signature, unused, tid, pid, uid, mid, pos = string.unpack(header_format, header)

  if(status ~= 0) then
    return false, get_status_name(status)
  end

  if(tid == 0 or tonumber(tid) == 0) then
    return false, "SMB: ERROR: Server didn't establish a proper tree connection (likely an embedded system)"
  end

  smb['tid'] = tid

  return true

end

--- Disconnects a tree session. Should be called before logging off and disconnecting.
--@param smb    The SMB object associated with the connection
--@param overrides THe overrides table
--@return (status, result) If status is false, result is an error message. If status is true,
--              the disconnect was successful.
function tree_disconnect(smb, overrides)
  overrides = overrides or {}
  local header

  header = smb_encode_header(smb, command_codes['SMB_COM_TREE_DISCONNECT'], overrides)

  -- Send the tree disconnect request
  stdnse.debug2("SMB: Sending SMB_COM_TREE_DISCONNECT")
  local result, err = smb_send(smb, header, "", "", overrides)
  if(result == false) then
    return false, err
  end

  -- Read the result
  local status, header, parameters, data = smb_read(smb)
  if(status ~= true) then
    return false, header
  end

  local header_format = "<c4 B I4 B I2 I2 i8 I2 I2 I2 I2 I2"
  if #header < string.packsize(header_format) then
    return false, "SMB: ERROR: Server returned less data than it was supposed to (one or more fields are missing); aborting [8]"
  end

  -- Check if there was an error
  local protocol_version, command, status, flags, flags2, pid_high, signature, unused, tid, pid, uid, mid, pos = string.unpack(header_format, header)

  if(status ~= 0) then
    return false, get_status_name(status)
  end

  smb['tid'] = 0

  return true

end

---Logs off the current user. Strictly speaking this isn't necessary, but it's the polite thing to do.
--
--@param smb    The SMB object associated with the connection
--@param overrides THe overrides table
--@return (status, result) If status is false, result is an error message. If status is true,
--              the logoff was successful.
function logoff(smb, overrides)
  overrides = overrides or {}
  local header, parameters, data
  local status

  header = smb_encode_header(smb, command_codes['SMB_COM_LOGOFF_ANDX'], overrides)

  -- Parameters are a blank ANDX block
  parameters = string.pack("<BB I2",
    0xFF,   -- ANDX no further commands
    0x00,   -- ANDX reserved
    0x0000  -- ANDX offset
    )

  -- Send the tree disconnect request
  stdnse.debug2("SMB: Sending SMB_COM_LOGOFF_ANDX")
  local result, err = smb_send(smb, header, parameters, "", overrides)
  if(result == false) then
    return false, err
  end

  -- Read the result
  status, header, parameters, data = smb_read(smb)
  if(status ~= true) then
    return false, header
  end

  -- Reset session variables (note: this has to come after the smb_read(), otherwise the message signatures cause a problem
  smb['uid']      = 0
  smb['sequence'] = -1
  smb['mac_key']  = nil

  local header_format = "<c4 B I4 B I2 I2 i8 I2 I2 I2 I2 I2"
  if #header < string.packsize(header_format) then
    return false, "SMB: ERROR: Server returned less data than it was supposed to (one or more fields are missing); aborting [22]"
  end

  -- Check if there was an error
  local protocol_version, command, status, flags, flags2, pid_high, signature, unused, tid, pid, uid, mid, pos = string.unpack(header_format, header)

  if(status == 0xc0000022) then
    stdnse.debug1("SMB: ERROR: Access was denied in 'logoff', indicating a problem with your message signatures")
    return false, "SMB: ERROR: Access was denied in 'logoff', indicating a problem with your message signatures"
  end
  if(status ~= 0) then
    return false, get_status_name(status)
  end

  return true

end

--- This sends a SMB request to open or create a file.
--
--  Most of the parameters I pass here are used directly from a packetlog,
--  especially the various permissions fields and flags.  I might make this
--  more adjustable in the future, but this has been working for me.
--
--@param smb       The SMB object associated with the connection
--@param path      The path of the file or pipe to open
--@param overrides [optional] Overrides for various fields
--@return (status, result) If status is false, result is an error message. Otherwise, result is a table
--        containing a lot of different elements, the most important one being 'fid', the handle to the opened file.
function create_file(smb, path, overrides)
  local header, parameters, data
  local andx_command, andx_reserved, andx_offset
  local oplock_level, fid, create_action, created, last_access, last_write, last_change, attributes, allocation_size, end_of_file, filetype, ipc_state, is_directory
  local error_count = 0

  local status, pos
  repeat
    local mutex = nmap.mutex(smb['host'])
    mutex "lock"

    -- Make sure we have overrides
    overrides = overrides or {}

    header = smb_encode_header(smb, command_codes['SMB_COM_NT_CREATE_ANDX'], overrides)
    parameters = string.pack("<BBI2 B I2 I4 I4 I4 I8 I4 I4 I4 I4 I4 B",
      0xFF,   -- ANDX no further commands
      0x00,   -- ANDX reserved
      0x0000, -- ANDX offset
      0x00,   -- Reserved
      #path, -- Path length
      (overrides['file_create_flags']            or 0x00000016),         -- Create flags
      (overrides['file_create_root_fid']         or 0x00000000),         -- Root FID
      (overrides['file_create_access_mask']      or 0x02000000),         -- Access mask
      (overrides['file_create_allocation_size']  or 0x0000000000000000), -- Allocation size
      (overrides['file_create_attributes']       or 0x00000000),         -- File attributes
      (overrides['file_create_share_attributes'] or 0x00000007),         -- Share attributes
      (overrides['file_create_disposition']      or 0x00000000),         -- Disposition
      (overrides['file_create_options']          or 0x00000000),         -- Create options
      (overrides['file_create_impersonation']    or 0x00000002),         -- Impersonation
      (overrides['file_create_security_flags']   or 0x01)                -- Security flags
      )

    data = string.pack("z", path)

    -- Send the create file
    stdnse.debug2("SMB: Sending SMB_COM_NT_CREATE_ANDX")
    local result, err = smb_send(smb, header, parameters, data, overrides)
    if(result == false) then
      mutex "done"
      return false, err
    end

    -- Read the result
    status, header, parameters, data = smb_read(smb, false)
    mutex "done"
    if(status ~= true) then
      return false, header
    end

    local header_format = "<c4 B I4 B I2 I2 i8 I2 I2 I2 I2 I2"
    if #header < string.packsize(header_format) then
      return false, "SMB: ERROR: Server returned less data than it was supposed to (one or more fields are missing); aborting [23]"
    end

    -- Check if we were allowed in
    local protocol_version, command, flags, flags2, pid_high, signature, unused, tid, pid, uid, mid
    protocol_version, command, status, flags, flags2, pid_high, signature, unused, tid, pid, uid, mid, pos = string.unpack(header_format, header)

    if(status == 0xc00000ac) then
      error_count = error_count + 1
      if(error_count > 10) then
        return false, "SMB: ERROR: Server returned NT_STATUS_PIPE_NOT_AVAILABLE too many times; giving up."
      end
      stdnse.debug1("WARNING: Server refused connection with NT_STATUS_PIPE_NOT_AVAILABLE; trying again")
      stdnse.sleep(.2)
    end
  until (status ~= 0xc00000ac)

  if(status ~= 0) then
    return false, get_status_name(status)
  end

  -- Parse the parameters
  local parameters_format = "<BBI2 BI2 I4 I8 I8 I8 I8 I4 I8 I8 I2 I2 B"
  if #parameters < string.packsize(parameters_format) then
    return false, "SMB: ERROR: Server returned less data than needed"
  end
  andx_command, andx_reserved, andx_offset, oplock_level, fid, create_action, created, last_access, last_write, last_change, attributes, allocation_size, end_of_file, filetype, ipc_state, is_directory, pos = string.unpack(parameters_format, parameters)

  -- Fill in the smb table
  smb['oplock_level']    = oplock_level
  smb['fid']             = fid
  smb['create_action']   = create_action
  smb['created']         = created
  smb['last_access']     = last_access
  smb['last_write']      = last_write
  smb['last_change']     = last_change
  smb['attributes']      = attributes
  smb['allocation_size'] = allocation_size
  smb['end_of_file']     = end_of_file
  smb['filetype']        = filetype
  smb['ipc_state']       = ipc_state
  smb['is_directory']    = is_directory

  return true
end

--- This sends a SMB request to read from a file (or a pipe).
--
--@param smb    The SMB object associated with the connection
--@param offset The offset to read from (ignored if it's a pipe)
--@param count  The maximum number of bytes to read
--@param overrides The overrides table
--@return (status, result) If status is false, result is an error message. Otherwise, result is a table
--        containing a lot of different elements.
function read_file(smb, offset, count, overrides)
  overrides = overrides or {}
  local header, parameters, data
  local andx_command, andx_reserved, andx_offset
  local remaining, data_compaction_mode, reserved_1, data_length_low, data_offset, data_length_high, reserved_2, reserved_3
  local response = {}
  local status

  header = smb_encode_header(smb, command_codes['SMB_COM_READ_ANDX'], overrides)
  parameters = string.pack("<BBI2 I2 I4 I2 I2 I4 I2 I4",
    0xFF,   -- ANDX no further commands
    0x00,   -- ANDX reserved
    0x0000, -- ANDX offset
    smb['fid'], -- FID
    offset,     -- Offset
    count,      -- Max count low
    count,      -- Min count
    0xFFFFFFFF, -- Reserved
    0,          -- Remaining
    0x00000000  -- High offset
    )

  data = ""

  -- Send the create file
  stdnse.debug2("SMB: Sending SMB_COM_READ_ANDX")
  local result, err = smb_send(smb, header, parameters, data, overrides)
  if(result == false) then
    return false, err
  end

  -- Read the result
  status, header, parameters, data = smb_read(smb)
  if(status ~= true) then
    return false, header
  end

  local header_format = "<c4 B I4 B I2 I2 i8 I2 I2 I2 I2 I2"
  if #header < string.packsize(header_format) then
    return false, "SMB: ERROR: Server returned less data than it was supposed to (one or more fields are missing); aborting [25]"
  end

  -- Check if we were allowed in
  local protocol_version, command, status, flags, flags2, pid_high, signature, unused, tid, pid, uid, mid, pos = string.unpack(header_format, header)

  if(status ~= 0 and
      (status ~= status_codes.NT_STATUS_BUFFER_OVERFLOW and (smb['filetype'] == filetype_codes.FILE_TYPE_BYTE_MODE_PIPE or
      smb['filetype'] == filetype_codes.FILE_TYPE_MESSAGE_MODE_PIPE) ) ) then
    return false, get_status_name(status)
  end

  -- Parse the parameters
  local parameters_format = "<BBI2 I2 I2 I2 I2 I2 I4 I2 I4"
  if #parameters < string.packsize(parameters_format) then
    return false, "SMB: ERROR: Server returned less data than needed"
  end
  andx_command, andx_reserved, andx_offset, remaining, data_compaction_mode, reserved_1, data_length_low, data_offset, data_length_high, reserved_2, reserved_3, pos = string.unpack(parameters_format, parameters)

  response['remaining']   = remaining
  response['data_length'] = (data_length_low | (data_length_high << 16))
  response['status']      = status


  -- data_start is the offset of the beginning of the data section -- we use this to calculate where the read data lives
  if(response['data_length'] == 0) then
    response['data'] = 0
  else
    local data_start = #header + 1 + #parameters + 2
    if(data_offset < data_start) then
      return false, "SMB: Start of data isn't in data section"
    end

    -- Figure out the offset into the data section
    data_offset = data_offset - data_start

    -- Make sure we don't run off the edge of the packet
    if(data_offset + response['data_length'] > #data) then
      return false, "SMB: Data returned runs off the end of the packet"
    end

    -- Pull the data string out of the data
    response['data'] = string.sub(data, data_offset + 1, data_offset + response['data_length'])
  end

  return true, response
end

--- This sends a SMB request to write to a file (or a pipe).
--
--@param smb        The SMB object associated with the connection
--@param write_data The data to write
--@param offset     The offset to write it to (ignored for pipes)
--@param overrides  The overrides table
--@return (status, result) If status is false, result is an error message. Otherwise, result is a table
--        containing a lot of different elements, the most important one being 'fid', the handle to the opened file.
function write_file(smb, write_data, offset, overrides)
  overrides = overrides or {}
  local header, parameters, data
  local andx_command, andx_reserved, andx_offset
  local response = {}
  local status

  header = smb_encode_header(smb, command_codes['SMB_COM_WRITE_ANDX'], overrides)
  parameters = string.pack("<BBI2 I2 I4 I4 I2 I2 I2 I2 I2 I4",
    0xFF,   -- ANDX no further commands
    0x00,   -- ANDX reserved
    0x0000, -- ANDX offset
    smb['fid'], -- FID
    offset,     -- Offset
    0xFFFFFFFF, -- Reserved
    0x0008,     -- Write mode (Message start, don't write raw, don't return remaining, don't write through
    #write_data,-- Remaining
    0x0000,     -- Data length high
    #write_data,-- Data length low -- TODO: set this properly (to the 2-byte value)
    0x003F,     -- Data offset
    0x00000000  -- Data offset high
    )

  data = write_data

  -- Send the create file
  stdnse.debug2("SMB: Sending SMB_COM_WRITE_ANDX")
  local result, err = smb_send(smb, header, parameters, data, overrides)
  if(result == false) then
    return false, err
  end


  -- Read the result
  status, header, parameters, data = smb_read(smb)
  if(status ~= true) then
    return false, header
  end

  local header_format = "<c4 B I4 B I2 I2 i8 I2 I2 I2 I2 I2"
  if #header < string.packsize(header_format) then
    return false, "SMB: ERROR: Server returned less data than it was supposed to (one or more fields are missing); aborting [8]"
  end

  -- Check if we were allowed in
  local protocol_version, command, status, flags, flags2, pid_high, signature, unused, tid, pid, uid, mid, pos = string.unpack(header_format, header)

  if(status ~= 0) then
    return false, get_status_name(status)
  end

  -- Parse the parameters
  local parameters_format = "<BBI2 I2 I2 I2 I2"
  if #parameters < string.packsize(parameters_format) then
    return false, "SMB: ERROR: Server returned less data than needed"
  end
  local count_reserved, count_high, remaining, count_low
  andx_command, andx_reserved, andx_offset, count_low, remaining, count_high, count_reserved, pos = string.unpack(parameters_format, parameters)

  response['count_low']  = count_low
  response['remaining']  = remaining
  response['count_high'] = count_high
  response['reserved']   = count_reserved

  return true, response
end

--- This sends a SMB request to close a file (or a pipe).
--
--@param smb        The SMB object associated with the connection
--@param overrides  The overrides table
--@return (status, result) If status is false, result is an error message. Otherwise, result is undefined.
function close_file(smb, overrides)
  overrides = overrides or {}
  local header, parameters, data
  local pos
  local status
  local andx_command, andx_reserved, andx_offset
  local response = {}

  header = smb_encode_header(smb, command_codes['SMB_COM_CLOSE'], overrides)
  parameters = string.pack("<I2 I4",
    smb['fid'], -- FID
    0xFFFFFFFF  -- Last write (unspecified)
    )

  data = ""

  -- Send the close file
  stdnse.debug2("SMB: Sending SMB_CLOSE")
  local result, err = smb_send(smb, header, parameters, data, overrides)
  if(result == false) then
    return false, err
  end

  -- Read the result
  status, header, parameters, data = smb_read(smb)
  if(status ~= true) then
    return false, header
  end

  local header_format = "<c4 B I4 B I2 I2 i8 I2 I2 I2 I2 I2"
  if #header < string.packsize(header_format) then
    return false, "SMB: ERROR: Server returned less data than it was supposed to (one or more fields are missing); aborting [27]"
  end

  -- Check if the close was successful
  local protocol_version, command, status, flags, flags2, pid_high, signature, unused, tid, pid, uid, mid, pos = string.unpack(header_format, header)

  if(status ~= 0) then
    return false, get_status_name(status)
  end

  -- Close response has no parameters or data
  return true, response
end

--- This sends a SMB request to delete a file (or a pipe).
--
--@param smb    The SMB object associated with the connection
--@param path   The path of the file to delete
--@param overrides The overrides table
--@return (status, result) If status is false, result is an error message. Otherwise, result is undefined.
function delete_file(smb, path, overrides)
  overrides = overrides or {}
  local header, parameters, data
  local andx_command, andx_reserved, andx_offset
  local status

  header = smb_encode_header(smb, command_codes['SMB_COM_DELETE'], overrides)
  parameters = string.pack("<I2",
    0x0027 -- Search attributes (0x27 = include read only, hidden, system, and archive)
    )

  data = string.pack("<Bz",
    0x04, -- Ascii formatted filename
    path)

  -- Send the close file
  stdnse.debug2("SMB: Sending SMB_CLOSE")
  local result, err = smb_send(smb, header, parameters, data, overrides)
  if(result == false) then
    return false, err
  end

  -- Read the result
  status, header, parameters, data = smb_read(smb)
  if(status ~= true) then
    return false, header
  end

  local header_format = "<c4 B I4 B I2 I2 i8 I2 I2 I2 I2 I2"
  if #header < string.packsize(header_format) then
    return false, "SMB: ERROR: Server returned less data than it was supposed to (one or more fields are missing); aborting [8]"
  end

  -- Check if the close was successful
  local protocol_version, command, status, flags, flags2, pid_high, signature, unused, tid, pid, uid, mid, pos = string.unpack(header_format, header)

  if(status ~= 0) then
    return false, get_status_name(status)
  end

  -- Close response has no parameters or data
  return true
end

--
-- Implements SMB_COM_TRANSACTION2 to support the find_files function
-- This function has not been extensively tested
--
--@param smb           SMB object associated with the connection
--@param sub_command   code of a SMB_COM_TRANSACTION2 sub command
--@param trans2_param  Parameter data to pass to the function
--@param trans2_data   Data to send with the packet
--@param overrides     The overrides table
--@return status       Boolean outcome of the request
--@return error        error message if the status is false
local function send_transaction2(smb, sub_command, trans2_param, trans2_data, overrides)
  overrides = overrides or {}
  trans2_param = trans2_param or ""
  trans2_data = trans2_data or ""

  local header = smb_encode_header(smb, command_codes['SMB_COM_TRANSACTION2'], overrides)
  local pad1 = "\0\0\0" -- Name, Pad1
  local pad2 = ("\0"):rep((4 - #trans2_param % 4) % 4)

  local trans2_param_len = #trans2_param
    -- 68 = 32  SMB header
    --    + 31  SMB parameters
    --    +  2  SMB data ByteCount field
    --    +  3  #pad1
  local trans2_param_pos = 68
  local trans2_data_len = #trans2_data
  local trans2_data_pos = trans2_param_pos + trans2_param_len + #pad2
  if trans2_data_len == 0 then
    pad2 = ""
    trans2_data_pos = 0
  end

  -- SMB parameters are 31 bytes long, incl. initial WordCount field
  -- https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-cifs/f7d148cd-e3d5-49ae-8b37-9633822bfeac
  local parameters = string.pack("<I2 I2 I2 I2 BB I2 I4 I2 I2 I2 I2 I2 BB I2 ",
            trans2_param_len,    -- Total parameter count
            trans2_data_len,     -- Total data count
            0x000a,              -- Max parameter count
            0xff80,              -- Max data count
            0x00,                -- Max setup count
            0x00,                -- Reserved
            0x0000,              -- Flags (2-way transaction, don't disconnect TIDs)
            5000,                -- Timeout (ms)
            0x0000,              -- Reserved
            trans2_param_len,    -- Parameter count
            trans2_param_pos,    -- Parameter offset
            trans2_data_len,     -- Data count
            trans2_data_pos,     -- Data offset
            0x01,                -- Setup count
            0x00,                -- Reserved
            sub_command          -- Sub command
            )

  local data = pad1 .. trans2_param .. pad2 .. trans2_data

  -- Send the transaction request
  stdnse.debug2("SMB: Sending SMB_COM_TRANSACTION2")
  return smb_send(smb, header, parameters, data, overrides)
end

local function receive_transaction2(smb)

  -- Read the result
  local status, header, parameters, data = smb_read(smb)
  if(status ~= true) then
    return false, header
  end

  local header_format = "<c4 B I4 B I2 I2 i8 I2 I2 I2 I2 I2"
  if #header < string.packsize(header_format) then
    return false, "SMB: ERROR: Server returned less data than it was supposed to (one or more fields are missing); aborting [8]"
  end

  -- Check if it worked
  local protocol_version, command, status, flags, flags2, pid_high, signature, unused, tid, pid, uid, mid, pos = string.unpack(header_format, header)

  if(status ~= 0) then
    if(status_names[status] == nil) then
      return false, string.format("Unknown SMB error: 0x%08x\n", status)
    else
      return false, status_names[status]
    end
  end

  -- Parse the parameters
  local parameters_format = "<I2 I2 I2 I2 I2 I2 I2 I2 I2 BB"
  if #parameters < string.packsize(parameters_format) then
    return false, "SMB: ERROR: Server returned less data than needed"
  end
  local total_word_count, total_data_count, reserved1, parameter_count, parameter_offset, parameter_displacement, data_count, data_offset, data_displacement, setup_count, reserved2, pos = string.unpack(parameters_format, parameters)

  -- Convert the parameter/data offsets into something more useful (the offset into the data section)
  -- - 0x20 for the header, - 0x01 for the length.
  parameter_offset = parameter_offset - 0x20 - 0x01 - #parameters - 0x02;
  -- - 0x20 for the header, - 0x01 for parameter length, the parameter length, and - 0x02 for the data length.
  data_offset = data_offset - 0x20 - 0x01 - #parameters - 0x02;

  -- I'm not sure I entirely understand why the '+1' is here, but I think it has to do with the string starting at '1' and not '0'.
  local function_parameters = string.sub(data, parameter_offset + 1, parameter_offset + parameter_count)
  local function_data       = string.sub(data, data_offset      + 1, data_offset      + data_count)

  local response = {}
  response['parameters'] = function_parameters
  response['data']       = function_data

  return true, response
end



---This is the core of making MSRPC calls. It sends out a MSRPC packet with the
-- given parameters and data.
--
-- Don't confuse these parameters and data with SMB's concepts of parameters
-- and data -- they are completely different. In fact, these parameters and
-- data are both sent in the SMB packet's 'data' section.
--
-- It is probably best to think of this as another protocol layer. This
-- function will wrap SMB stuff around a MSRPC call, make the call, then unwrap
-- the SMB stuff from it before returning.
--
--@param smb The SMB object associated with the connection
--@param function_parameters The parameter data to pass to the function. This
--                           is untested, since none of the transactions I've
--                           done have required parameters.
--@param function_data The data to send with the packet. This is basically the
--                     next protocol layer
--@param pipe [optional] The pipe to transact on. Default: "\PIPE\".
--@param no_setup [optional] If set, the 'setup' is set to 0 and some
--                parameters are left off. This occurs while using the LANMAN
--                Remote API. Default: false.
--@param overrides The overrides table
--@return (status, result) If status is false, result is an error message.
--        Otherwise, result is a table containing 'parameters' and 'data',
--        representing the parameters and data returned by the server.
function send_transaction_named_pipe(smb, function_parameters, function_data, pipe, no_setup, overrides)
  overrides = overrides or {}
  local header, parameters, data
  local parameter_offset = 0
  local parameter_size   = 0
  local data_offset      = 0
  local data_size        = 0
  local total_word_count, total_data_count, reserved1, parameter_count, parameter_displacement, data_count, data_displacement, setup_count, reserved2
  local response = {}
  local status

  if(pipe == nil) then
    pipe = "\\PIPE\\"
  end

  -- Header is 0x20 bytes long (not counting NetBIOS header).
  header = smb_encode_header(smb, command_codes['SMB_COM_TRANSACTION'], overrides) -- 0x25 = SMB_COM_TRANSACTION

  -- 0x20 for SMB header, 0x01 for parameters header, 0x20 for parameters length, 0x02 for data header, 0x07 for "\PIPE\"
  if(function_parameters) then
    parameter_offset = 0x20 + 0x01 + 0x20 + 0x02 + (#pipe + 1)
    parameter_size = #function_parameters
  end

  if(function_data) then
    data_offset       = 0x20 + 0x01 + 0x20 + 0x02 + (#pipe + 1) + parameter_size
    data_size         = #function_data
  end

  local setup
  if(no_setup) then
    setup = string.pack("<BB",
      0x00,                            -- Number of 'setup' words (none)
      0x00                             -- Reserved.
      )
  else
    setup = string.pack("<BBI2 I2 ",
      0x02,                            -- Number of 'setup' words
      0x00,                            -- Reserved.
      0x0026,                          -- Function to call.
      smb['fid']                       -- Handle to open file
      )
  end

  -- Parameters are 0x20 bytes long.
  parameters = string.pack("<I2 I2 I2 I2 BBI2 I4 I2 I2 I2 I2 I2",
    parameter_size,                  -- Total parameter count.
    data_size,                       -- Total data count.
    0x0008,                          -- Max parameter count.
    0x3984,                          -- Max data count.
    0x00,                            -- Max setup count.
    0x00,                            -- Reserved.
    0x0000,                          -- Flags (0x0000 = 2-way transaction, don't disconnect TIDs).
    0x00001388,                      -- Timeout (0x00000000 = return immediately).
    0x0000,                          -- Reserved.
    parameter_size,                  -- Parameter bytes.
    parameter_offset,                -- Parameter offset.
    data_size,                       -- Data bytes.
    data_offset                      -- Data offset.
    ) .. setup

  data = string.pack("<zI4", pipe, 0) -- Padding
  .. (function_parameters or '')
  .. (function_data or '')

  -- Send the transaction request
  stdnse.debug2("SMB: Sending SMB_COM_TRANSACTION")
  local result, err = smb_send(smb, header, parameters, data, overrides)
  if(result == false) then
    return false, err
  end

  -- Read the result
  status, header, parameters, data = smb_read(smb)
  if(status ~= true) then
    return false, header
  end

  local header_format = "<c4 B I4 B I2 I2 i8 I2 I2 I2 I2 I2"
  if #header < string.packsize(header_format) then
    return false, "SMB: ERROR: Server returned less data than it was supposed to (one or more fields are missing); aborting [8]"
  end

  -- Check if it worked
  local protocol_version, command, status, flags, flags2, pid_high, signature, unused, tid, pid, uid, mid, pos = string.unpack(header_format, header)

  if(status ~= 0) then
    if(status_names[status] == nil) then
      return false, string.format("Unknown SMB error: 0x%08x\n", status)
    else
      return false, status_names[status]
    end
  end

  -- Parse the parameters
  local parameters_format = "<I2 I2 I2 I2 I2 I2 I2 I2 I2 BB"
  if #parameters < string.packsize(parameters_format) then
    return false, "SMB: ERROR: Server returned less data than needed"
  end
  total_word_count, total_data_count, reserved1, parameter_count, parameter_offset, parameter_displacement, data_count, data_offset, data_displacement, setup_count, reserved2, pos = string.unpack(parameters_format, parameters)

  -- Convert the parameter/data offsets into something more useful (the offset into the data section)
  -- - 0x20 for the header, - 0x01 for the length.
  parameter_offset = parameter_offset - 0x20 - 0x01 - #parameters - 0x02;
  -- - 0x20 for the header, - 0x01 for parameter length, the parameter length, and - 0x02 for the data length.
  data_offset = data_offset - 0x20 - 0x01 - #parameters - 0x02;

  -- I'm not sure I entirely understand why the '+1' is here, but I think it has to do with the string starting at '1' and not '0'.
  function_parameters = string.sub(data, parameter_offset + 1, parameter_offset + parameter_count)
  function_data       = string.sub(data, data_offset      + 1, data_offset      + data_count)

  response['parameters'] = function_parameters
  response['data']       = function_data

  return true, response
end

function send_transaction_waitnamedpipe(smb, priority, pipe, overrides)
  overrides = overrides or {}
  local header, parameters, data
  local parameter_offset, data_offset
  local total_word_count, total_data_count, reserved1, parameter_count, parameter_offset, parameter_displacement, data_count, data_offset, data_displacement, setup_count, reserved2
  local response = {}
  local padding = ""
  local status

  -- Header is 0x20 bytes long (not counting NetBIOS header).
  header = smb_encode_header(smb, command_codes['SMB_COM_TRANSACTION'], overrides) -- 0x25 = SMB_COM_TRANSACTION

  -- Parameters are 0x20 bytes long.
  parameters = string.pack("<I2 I2 I2 I2 BBI2 I4 I2 I2 I2 I2 I2 BBI2 I2 ",
    0,                               -- Total parameter count.
    0,                               -- Total data count.
    0x000,                           -- Max parameter count.
    0x400,                           -- Max data count.
    0x00,                            -- Max setup count.
    0x00,                            -- Reserved.
    0x0000,                          -- Flags (0x0000 = 2-way transaction, don't disconnect TIDs).
    30,                              -- Timeout (0x00000000 = return immediately).
    0x0000,                          -- Reserved.
    0,                               -- Parameter bytes.
    0,                               -- Parameter offset.
    0,                               -- Data bytes.
    0,                               -- Data offset.
    0x02,                            -- Number of 'setup' words (only ever seen '2').
    0x00,                            -- Reserved.
    0x0053,                          -- Function to call.
    priority                         -- Handle to open file
    )

  data = string.pack("z", pipe) .. string.rep('\0', (4 - ((#pipe+1) % 4)) % 4)

  -- Send the transaction request
  stdnse.debug2("SMB: Sending SMB_COM_TRANSACTION (WaitNamedPipe)")
  local result, err = smb_send(smb, header, parameters, data, overrides)
  if(result == false) then
    return false, err
  end

  -- Read the result
  status, header, parameters, data = smb_read(smb)
  if(status ~= true) then
    return false, header
  end

  local header_format = "<c4 B I4 B I2 I2 i8 I2 I2 I2 I2 I2"
  if #header < string.packsize(header_format) then
    return false, "SMB: ERROR: Server returned less data than it was supposed to (one or more fields are missing); aborting [8]"
  end

  -- Parse out the header
  local protocol_version, command, status, flags, flags2, pid_high, signature, unused, tid, pid, uid, mid, pos = string.unpack(header_format, header)

  if(status ~= 0) then
    if(status_names[status] == nil) then
      return false, string.format("Unknown SMB error: 0x%08x\n", status)
    else
      return false, status_names[status]
    end
  end

  -- Parse the parameters
  local parameters_format = "<I2 I2 I2 I2 I2 I2 I2 I2 I2 BB"
  if #parameters < string.packsize(parameters_format) then
    return false, "SMB: ERROR: Server returned less data than needed"
  end
  total_word_count, total_data_count, reserved1, parameter_count, parameter_offset, parameter_displacement, data_count, data_offset, data_displacement, setup_count, reserved2, pos = string.unpack(parameters_format, parameters)

  return true, response
end

---Upload a file from the local machine to the remote machine, on the given share.
--
--@param host       The host object
--@param localfile  The file on the local machine, relative to the nmap path
--@param share      The share to upload it to (eg, C$).
--@param remotefile The remote file on the machine. It is relative to the share's root.
--@param overrides  A table of override values that's passed to the smb functions.
--@param encoded    Set to 'true' if the file is encoded (xor'ed with 0xFF), It will be decoded before upload. Default: false
--@return (status, err) If status is false, err is an error message. Otherwise, err is undefined.
function file_upload(host, localfile, share, remotefile, overrides, encoded)
  local status, err, smbstate
  local chunk = 1024

  -- Attempt to open a handle to the file without adding a path to it
  local handle = io.open(localfile, "r")

  -- If the open failed, try to search for the file
  if(not(handle)) then
    stdnse.debug1("Couldn't open %s directly, searching Nmap's paths...", localfile)
    local filename = nmap.fetchfile(localfile)

    -- Check if it was found
    if(filename == nil) then
      return false, string.format("Couldn't find the file to upload (%s)", localfile)
    end
    handle = io.open(filename, "r")
  end

  -- Create the SMB session
  status, smbstate = start_ex(host, true, true, share, remotefile, nil, overrides)
  if(status == false) then
    return false, smbstate
  end


  local i = 0
  local data = handle:read(chunk)
  local new_data = {}
  while(data ~= nil and #data > 0) do

    if(encoded) then
      for j = 1, #data, 1 do
        new_data[j] = string.char(0xFF ~ string.byte(data, j))
      end
      data = table.concat(new_data, "", 1, #data)
    end

    status, err = write_file(smbstate, data, i)
    if(status == false) then
      stop(smbstate)
      return false, err
    end

    data = handle:read(chunk)
    i = i + chunk
  end

  handle:close()
  status, err = close_file(smbstate)
  if(status == false) then
    stop(smbstate)
    return false, err
  end

  -- Stop the session
  stop(smbstate)

  return true
end

---Write given data to the remote machine on the given share. This is similar to <code>file_upload</code>, except the
-- data is given as a string, not a file.
--
--@param host          The host object
--@param data          The string containing the data to be written
--@param share         The share to upload it to (eg, C$).
--@param remotefile    The remote file on the machine. It is relative to the share's root.
--@param use_anonymous [optional] If set to 'true', test is done by the anonymous user rather than the current user.
--@return (status, err) If status is false, err is an error message. Otherwise, err is undefined.
function file_write(host, data, share, remotefile, use_anonymous)
  local status, err, smbstate
  local chunk = 1024
  local overrides = nil

  -- If anonymous is being used, create some overrides
  if(use_anonymous) then
    overrides = get_overrides_anonymous()
  end

  -- Create the SMB session
  status, smbstate = start_ex(host, true, true, share, remotefile, nil, overrides)

  if(status == false) then
    return false, smbstate
  end

  local i = 1
  while(i <= #data) do
    local chunkdata = string.sub(data, i, i + chunk - 1)
    status, err = write_file(smbstate, chunkdata, i - 1)
    if(status == false) then
      stop(smbstate)
      return false, err
    end

    i = i + chunk
  end

  status, err = close_file(smbstate)
  if(status == false) then
    stop(smbstate)
    return false, err
  end

  -- Stop the session
  stop(smbstate)

  return true
end

---Write given data to the remote machine on the given share. This is similar to <code>file_upload</code>, except the
-- data is given as a string, not a file.
--
--@param host          The host object
--@param share         The share to read it from (eg, C$).
--@param remotefile    The remote file on the machine. It is relative to the share's root.
--@param use_anonymous [optional] If set to 'true', test is done by the anonymous user rather than the current user.
--@param overrides     [optional] Override various fields in the SMB packets.
--@return (status, err) If status is false, err is an error message. Otherwise, err is undefined.
function file_read(host, share, remotefile, use_anonymous, overrides)
  local status, err, smbstate
  local result
  local chunk = 1024
  local read = ""

  -- Make sure we got overrides
  overrides = overrides or {}

  -- If anonymous is being used, create some overrides
  if(use_anonymous) then
    overrides = get_overrides_anonymous(overrides)
  end

  -- Create the SMB session
  status, smbstate = start_ex(host, true, true, share, remotefile, nil, overrides)

  if(status == false) then
    return false, smbstate
  end

  local i = 1
  while true do
    status, result = read_file(smbstate, i - 1, chunk)
    if(status == false) then
      stop(smbstate)
      return false, result
    end

    if(result['data_length'] == 0) then
      break
    end

    read = read .. result['data']
    i = i + chunk
  end

  status, err = close_file(smbstate)
  if(status == false) then
    stop(smbstate)
    return false, err
  end

  -- Stop the session
  stop(smbstate)
  return true, read
end

---Check how many files, in a given list, exist on the given share.
--
--@param host          The host object
--@param share         The share to read it from (eg, C$).
--@param files         A list of files to look for; it is relative to the share's root.
--@param overrides     [optional] Override various fields in the SMB packets.
--@return status: A true/false value indicating success
--@return count:  The number of files that existed, or an error message if status is 'false'
--@return files:  A list of the files that existed.
function files_exist(host, share, files, overrides)
  local status, smbstate, result, err

  -- Make sure we got overrides
  overrides = overrides or {}

  -- We don't wan to be creating the files
  overrides['file_create_disposition'] = 1

  -- Create the SMB session
  status, smbstate = start_ex(host, true, true, share, nil, nil, overrides)

  if(status == false) then
    return false, smbstate
  end

  local exist = 0
  local list  = {}

  for _, file in ipairs(files) do
    -- Try and open the file
    status, result = create_file(smbstate, file, overrides)

    -- If there was an error other than 'file already exists', return an error
    if(not(status) and result ~= 'NT_STATUS_OBJECT_NAME_NOT_FOUND') then
      return false, result
    end

    -- If the file existed, count it and close it
    if(status) then
      exist = exist + 1
      table.insert(list, file)
      status, err = close_file(smbstate)
      if(status == false) then
        stop(smbstate)
        return false, err
      end
    end
  end

  -- Stop the session
  stop(smbstate)
  return true, exist, list
end

---Delete a file from the remote machine
--
--@param host       The host object
--@param share      The share to upload it to (eg, C$).
--@param remotefile The remote file on the machine. It is relative to the share's root. It can be a string, or an array.
--@return (status, err) If status is false, err is an error message. Otherwise, err is undefined.
function file_delete(host, share, remotefile)
  local status, smbstate, err

  -- Create the SMB session
  status, smbstate = start_ex(host, true, true, share)
  if(status == false) then
    return false, smbstate
  end

  -- Make sure the remotefile is always a table, to save on duplicate code
  if(type(remotefile) ~= "table") then
    remotefile = {remotefile}
  end


  for _, file in ipairs(remotefile) do
    status, err = delete_file(smbstate, file)
    if(status == false) then
      stdnse.debug1("SMB: Couldn't delete %s\\%s: %s", share, file, err)
      if(err ~= 'NT_STATUS_OBJECT_NAME_NOT_FOUND') then
        stop(smbstate)
        return false, err
      end
    end
  end

  -- Stop the session
  stop(smbstate)

  return true
end

-- Sends TRANS2_FIND_FIRST2 / TRANS2_FIND_NEXT2 request, takes care of
-- short/fragmented responses, and returns a list of file entries
--
-- @param smbstate the SMB object associated with the connection
-- @param srch_id of search to resume (for TRANS2_FIND_NEXT2) or nil
-- @param trans2_params string representing Trans2_Parameters
-- @return status of the request
-- @return srch_id of search to resume later, or nil if the search completed
--                 or the error message if status is false
-- @return list of file entries
local function send_and_receive_find_request(smbstate, srch_id, trans2_params)
  local TRANS2_FIND_FIRST2 = 1
  local TRANS2_FIND_NEXT2  = 2
  local sub_command = srch_id and TRANS2_FIND_NEXT2 or TRANS2_FIND_FIRST2
  local status = send_transaction2(smbstate, sub_command, trans2_params, "")
  if not status then
    return false, "Failed to send data to server: send_transaction2"
  end

  local resp
  status, resp = receive_transaction2(smbstate)
  if not status or #resp.parameters < 2 then
    return false, "Failed to receive data from server: receive_transaction2"
  end

  local param_pos = 1
  if sub_command == TRANS2_FIND_FIRST2 then
    srch_id, param_pos = string.unpack("<I2", resp.parameters, param_pos)
  end

  -- parse Trans2_Parameters
  -- https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-cifs/4e65d94e-09af-4511-a77a-b73adf1c52d6
  local param_fmt = "<I2 I2 xx I2"
  if #resp.parameters < param_pos - 1 + param_fmt:packsize() then
    return false, "Truncated response from server: receive_transaction2"
  end
  local srch_cnt, srch_end, last_name_pos = param_fmt:unpack(resp.parameters, param_pos)

  -- format of SMB_FIND_FILE_BOTH_DIRECTORY_INFO, without trailing FileName
  -- https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-cifs/2aa849f4-1bc0-42bf-9c8f-d09f11fccc4c
  local entry_fmt = "<I4 xxxx I8 I8 I8 I8 I8 I8 I4 I4 xxxx B x c24"
  local entry_len = entry_fmt:packsize()

  -- check if we need more packets to reassemble this transaction
  while #resp.data < last_name_pos + entry_len do
    local status, tmp = receive_transaction2(smbstate)
    if not status then
      return false, "Truncated response from receive_transaction2"
    end
    resp.data = resp.data .. tmp.data
  end

  -- parse response, based on SMB_FIND_FILE_BOTH_DIRECTORY_INFO
  local entries = {}
  local data_pos = 1
  while srch_cnt > 0 do
    if #resp.data - data_pos + 1 < entry_len then
      return false, "Truncated response from receive_transaction2"
    end
    local entry = {}
    local next_pos, fn_pos, fn_len, sfn_len
    next_pos, entry.created, entry.accessed, entry.write, entry.change,
      entry.eof, entry.alloc_size, entry.attrs, fn_len, sfn_len,
      entry.s_fname, fn_pos = entry_fmt:unpack(resp.data, data_pos)

    local time = entry.created
    time = (time // 10000000) - 11644473600
    entry.created = datetime.format_timestamp(time)

    if sfn_len > 0 then
      entry.s_fname = entry.s_fname:sub(1, sfn_len)
    else
      entry.s_fname = nil
    end

    if #resp.data - fn_pos + 1 < fn_len then
      return false, "Truncated response from receive_transaction2"
    end
    entry.fname = string.unpack("z", resp.data, fn_pos)
    table.insert(entries, entry)
    data_pos = data_pos + next_pos
    srch_cnt = srch_cnt - 1
  end
  return true, (srch_end == 0 and srch_id or nil), entries
end

---
-- List files based on a pattern within a given share and directory
--
-- @param smbstate the SMB object associated with the connection
-- @param fname filename to search for, relative to share path
-- @param options table containing none or more of the following
--        <code>maxfiles</code> how many files to request in a single Trans2 op
--        <code>srch_attrs</code> table containing one or more of the following boolean attributes:
--              <code>ro</code> - find read only files
--              <code>hidden</code> - find hidden files
--              <code>system</code> - find system files
--              <code>volid</code> - include volume ids in result
--              <code>dir</code> - find directories
--              <code>archive</code> - find archived files
-- @return iterator function retrieving the next result
function find_files (smbstate, fname, options)
  options = options or {}

  -- convert options.srch_attrs to a bitmap
  local xlat_srch_attrs = {ro      = "SMB_FILE_ATTRIBUTE_READONLY",
                           hidden  = "SMB_FILE_ATTRIBUTE_HIDDEN",
                           system  = "SMB_FILE_ATTRIBUTE_SYSTEM",
                           volid   = "SMB_FILE_ATTRIBUTE_VOLUME",
                           dir     = "SMB_FILE_ATTRIBUTE_DIRECTORY",
                           archive = "SMB_FILE_ATTRIBUTE_ARCHIVE"}
  local srch_attrs_mask = 0
  local srch_attrs = options.srch_attrs or {ro=true, hidden=false, system=true, dir=true}
  for k, v in pairs(srch_attrs) do
    if v then
      srch_attrs_mask = srch_attrs_mask | file_attributes[xlat_srch_attrs[k]]
    end
  end

  fname = fname or '\\*'
  if fname:sub(1,1) ~= '\\' then
    fname = '\\' .. fname
  end

  local srch_flags = 0x0002 | 0x0004 -- SMB_FIND_CLOSE_AT_EOS, SMB_FIND_RETURN_RESUME_KEYS
  local srch_info_lvl = 0x0104       -- SMB_FIND_FILE_BOTH_DIRECTORY_INFO
  local max_srch_cnt = tonumber(options.maxfiles)
  if max_srch_cnt and max_srch_cnt > 0 then
    max_srch_cnt = math.floor(4 + math.min(1020, max_srch_cnt))
  else
    max_srch_cnt = 1024
  end

  -- state variables for next_entry() iterator
  local first_run = true
  local srch_id = nil
  local last_fname = nil
  local entries = {}
  local entry_idx = 1

  local function next_entry()
    if entry_idx > #entries then  -- get more file entries from the target
      local trans2_params
      if first_run then -- TRANS2_FIND_FIRST2
        first_run = false
        -- https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-cifs/b2b2a730-9499-4f05-884e-d5bb7b9caf90
        trans2_params = string.pack("<I2 I2 I2 I2 I4 z",
                                  srch_attrs_mask, -- what types of files to return
                                  max_srch_cnt,    -- maximum number of returned entries
                                  srch_flags,      -- Flags
                                  srch_info_lvl,   -- level of returned file details
                                  0,               -- SearchStorageType
                                  fname)           -- file name to search for
      -- FIXME filename ASCII vs UNICODE
      else -- TRANS2_FIND_NEXT2
        if not srch_id then  -- the search is over
          return
        end
        -- https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-cifs/80dc980e-fe03-455c-ada6-7c5dd6c551ba
        trans2_params = string.pack("<I2 I2 I2 I4 I2 z",
                                  srch_id,         -- which search to resume
                                  max_srch_cnt,    -- maximum number of returned entries
                                  srch_info_lvl,   -- level of returned file details
                                  0,               -- ResumeKey
                                  srch_flags,      -- Flags
                                  last_fname)      -- last file name previously returned
        -- FIXME wtf is ResumeKey?
      end
      local status
      status, srch_id, entries = send_and_receive_find_request(smbstate, srch_id, trans2_params)
      if not status then
        stdnse.debug1("Routine find_files failed with error: %s", srch_id)
        srch_id = nil
        entries = {}
      end
      entry_idx = 1
      if #entries == 0 then
        return
      end
    end
    local entry = entries[entry_idx]
    last_fname = entry.fname
    entry_idx = entry_idx + 1
    return entry
  end
  return next_entry
end

---Determine whether or not the anonymous user has write access on the share. This is done by creating then
-- deleting a file.
--
--@param host     The host object
--@param share    The share to test
--@return (status, result) If status is false, result is an error message. The error message 'NT_STATUS_OBJECT_NAME_NOT_FOUND'
--        should be handled gracefully; it indicates that the share isn't a fileshare. Otherwise, result is a boolean value:
--        true if the file was successfully written, false if it was not.
function share_anonymous_can_write(host, share)
  local filename, status, err

  -- First, choose a filename. This should be random.
  filename = "nmap-test-file"

  -- Next, attempt to write to that file
  status, err = file_write(host, string.rep("ABCDEFGHIJKLMNOPQRSTUVWXYZ", 10), share, filename, true)
  if(status == false) then
    if(err == "NT_STATUS_OBJECT_NAME_NOT_FOUND") then
      return false, err
    end

    if(err == "NT_STATUS_ACCESS_DENIED" or err == "NT_STATUS_INVALID_PARAMETER") then
      return true, false
    end

    return false, "Error writing test file to disk as anonymous: " .. err
  end

  -- Now the important part: delete it
  status, err = file_delete(host, share, filename)
  if(status == false) then
    return false, "Error deleting test file as anonymous: " .. err
  end

  return true, true
end


---Determine whether or not the current user has read or read/write access on the share. This is done by creating then
-- deleting a file.
--
--@param host     The host object
--@param share    The share to test
--@return (status, result) If status is false, result is an error message. The error message 'NT_STATUS_OBJECT_NAME_NOT_FOUND'
--        should be handled gracefully; it indicates that the share isn't a fileshare. Otherwise, result is a boolean value:
--        true if the file was successfully written, false if it was not.
function share_user_can_write(host, share)

  local filename, status, err

  -- First, choose a filename. This should be random.
  filename = "nmap-test-file"

  -- Next, attempt to write to that file
  status, err = file_write(host, string.rep("ABCDEFGHIJKLMNOPQRSTUVWXYZ", 10), share, filename)
  if(status == false) then
    if(err == "NT_STATUS_OBJECT_NAME_NOT_FOUND") then
      return false, err
    end

    if(err == "NT_STATUS_ACCESS_DENIED" or err == "NT_STATUS_INVALID_PARAMETER") then
      return true, false
    end

    return false, "Error writing test file to disk as user: " .. err
  end

  -- Now the important part: delete it
  status, err = file_delete(host, share, filename)
  if(status == false) then
    return false, "Error deleting test file as user: " .. err
  end

  return true, true
end

---Check whether or not a share is accessible by the anonymous user. Assumes that <code>share_host_returns_proper_error</code>
-- has been called and returns <code>true</code>.
--
--@param host     The host object
--@param share    The share to test
--@return (status, result) If status is false, result is an error message. Otherwise, result is a boolean value:
--        true if anonymous access is permitted, false otherwise.
function share_anonymous_can_read(host, share)
  local status, smbstate, err
  local overrides = get_overrides_anonymous()

  -- Begin the SMB session
  status, smbstate = start(host)
  if(status == false) then
    return false, smbstate
  end

  -- Negotiate the protocol
  status, err = negotiate_protocol(smbstate, overrides)
  if(status == false) then
    stop(smbstate)
    return false, err
  end

  -- Start up a null session
  status, err = start_session(smbstate, overrides)

  if(status == false) then
    stop(smbstate)
    return false, err
  end

  -- Attempt a connection to the share
  status, err = tree_connect(smbstate, share, overrides)
  if(status == false) then

    -- Stop the session
    stop(smbstate)

    -- ACCESS_DENIED is the expected error: it tells us that the connection failed
    if(err == 0xc0000022 or err == 'NT_STATUS_ACCESS_DENIED') then
      return true, false
    else
      return false, err
    end
  end



  stop(smbstate)
  return true, true
end

---Check whether or not a share is accessible by the current user. Assumes that <code>share_host_returns_proper_error</code>
-- has been called and returns <code>true</code>.
--
--@param host     The host object
--@param share    The share to test
--@return (status, result) If status is false, result is an error message. Otherwise, result is a boolean value:
--        true if anonymous access is permitted, false otherwise.
function share_user_can_read(host, share)
  local status, smbstate, err
  local overrides = {}

  -- Begin the SMB session
  status, smbstate = start(host)
  if(status == false) then
    return false, smbstate
  end

  -- Negotiate the protocol
  status, err = negotiate_protocol(smbstate, overrides)
  if(status == false) then
    stop(smbstate)
    return false, err
  end

  -- Start up a null session
  status, err = start_session(smbstate, overrides)
  if(status == false) then
    stop(smbstate)
    return false, err
  end

  -- Attempt a connection to the share
  status, err = tree_connect(smbstate, share, overrides)
  if(status == false) then

    -- Stop the session
    stop(smbstate)

    -- ACCESS_DENIED is the expected error: it tells us that the connection failed
    if(err == 0xc0000022 or err == 'NT_STATUS_ACCESS_DENIED') then
      return true, false
    else
      return false, err
    end
  end

  stop(smbstate)
  return true, true
end

---Determine whether or not a host will accept any share name (I've seen this on certain systems; it's
-- bad, because it means we cannot tell whether or not a share exists).
--
--@param host     The host object
--@param use_anonymous [optional] If set to 'true', test is done by the anonymous user rather than the current user.
--@return (status, result) If status is false, result is an error message. Otherwise, result is a boolean value:
--        true if the file was successfully written, false if it was not.
function share_host_returns_proper_error(host, use_anonymous)
  local status, smbstate, err
  local share = "nmap-share-test"
  local overrides

  if ( use_anonymous ) then
    overrides = get_overrides_anonymous()
  end

  -- Begin the SMB session
  status, smbstate = start(host)
  if(status == false) then
    return false, smbstate
  end

  -- Negotiate the protocol
  status, err = negotiate_protocol(smbstate, overrides)
  if(status == false) then
    stop(smbstate)
    return false, err
  end

  -- Start up a null session
  status, err = start_session(smbstate, overrides)
  if(status == false) then
    stop(smbstate)
    return false, err
  end

  -- Connect to the share
  stdnse.debug1("SMB: Trying a random share to see if server responds properly: %s", share)
  status, err = tree_connect(smbstate, share, overrides)

  if(status == false) then
    -- If the error is NT_STATUS_ACCESS_DENIED (0xc0000022), that's bad -- we don't want non-existent shares
    -- showing up as 'access denied'. Any other error is ok.
    if(err == 0xc0000022 or err == 'NT_STATUS_ACCESS_DENIED') then
      stdnse.debug1("SMB: Server doesn't return proper value for non-existent shares (returns ACCESS_DENIED)")
      stop(smbstate)
      return true, false
    end
  else
    -- If we were actually able to connect to this share, then there's probably a serious issue
    stdnse.debug1("SMB: Server doesn't return proper value for non-existent shares (accepts the connection)")
    stop(smbstate)
    return true, false
  end

  stop(smbstate)
  return true, true
end

---Get all the details we can about the share. These details are stored in a table and returned.
--
--@param host   The host object.
--@param share An array of shares to check.
--@return (status, result) If status is false, result is an error message. Otherwise, result is a boolean value:
--        true if the file was successfully written, false if it was not.
function share_get_details(host, share)
  local msrpc = require "msrpc" -- avoid require cycle
  local smbstate, status, result
  local i
  local details = {}

  --Transform name to FQPN form
  status, share = get_fqpn(host, share)
  if not status then
    stdnse.debug1("SMB:Couldn't obtain FQPN share name. Trying with '%s'", share)
  end

  -- Save the name
  details['name'] = share

  -- Check if the current user can read the share
  stdnse.debug1("SMB: Checking if share %s can be read by the current user", share)
  status, result = share_user_can_read(host, share)
  if(status == false) then
    return false, result
  end
  details['user_can_read'] = result

  -- Check if the anonymous reader can read the share
  stdnse.debug1("SMB: Checking if share %s can be read by the anonymous user", share)
  status, result = share_anonymous_can_read(host, share)
  if(status == true) then
    details['anonymous_can_read'] = result
  end

  -- Check if the current user can write to the share
  stdnse.debug1("SMB: Checking if share %s can be written by the current user", share)
  status, result = share_user_can_write(host, share)
  if(status == false) then
    if(result == "NT_STATUS_OBJECT_NAME_NOT_FOUND") then
      details['user_can_write'] = "NT_STATUS_OBJECT_NAME_NOT_FOUND"
    else
      return false, result
    end
  end
  details['user_can_write'] = result

  -- Check if the anonymous user can write to the share
  stdnse.debug1("SMB: Checking if share %s can be written by the anonymous user", share)
  status, result = share_anonymous_can_write(host, share)
  if(status == false and result == "NT_STATUS_OBJECT_NAME_NOT_FOUND") then
    details['anonymous_can_write'] = "NT_STATUS_OBJECT_NAME_NOT_FOUND"
  elseif( status == true ) then
    details['anonymous_can_write'] = result
  end

  -- Try and get full details about the share
  status, result = msrpc.get_share_info(host, share)
  if(status == false) then
    -- We don't stop for this error (it's pretty common since administrative privileges are required here)
    stdnse.debug1("SMB: Failed to get share info for %s: %s", share, result)
    details['details'] = result
  else
    -- Process the result a bit
    result = result['info']
    if(result['max_users'] == 0xFFFFFFFF) then
      result['max_users'] = "<unlimited>"
    end
    details['details'] = result
  end

  return true, details
end

---Retrieve a list of fileshares, along with any details that could be pulled. This is the core of smb-enum-shares.nse, but
-- can also be used by any script that needs to find an open share.
--
-- In the best care, the shares are determined by calling <code>msrpc.enum_shares</code>, and information is gathered by calling
-- <code>msrpc.get_share_info</code>. These require a certain level of access, though, so as a fallback, a pre-programmed list of
-- shares is used, and these are verified by attempting a connection.
--
--@param host The host object.
--@return (status, result, extra) If status is false, result is an error message. Otherwise, result is an array of shares with as much
--        detail as we could get. If extra isn't nil, it is set to extra information that should be displayed (such as a warning).
function share_get_list(host)
  local msrpc = require "msrpc" -- avoid require cycle
  local status, result
  local enum_status
  local extra = ""
  local shares = {}
  local share_details = {}

  -- Try and do this the good way, make a MSRPC call to get the shares
  stdnse.debug1("SMB: Attempting to log into the system to enumerate shares")
  enum_status, shares = msrpc.enum_shares(host)

  -- If that failed, try doing it with brute force. This almost certainly won't find everything, but it's the
  -- best we can do.
  if(enum_status == false) then
    stdnse.debug1("SMB: Enumerating shares failed, guessing at common ones (%s)", shares)
    extra = string.format("ERROR: Enumerating shares failed, guessing at common ones (%s)", shares)

    -- Take some common share names I've seen (thanks to Brandon Enright for most of these, except the last few)
    shares = {"ADMIN", "BACKUP", "DATA", "DESKTOP", "DOCS", "FILES", "GROUPS", "HD", "HOME", "INFO", "IPC", "MEDIA", "MY DOCUMENTS", "NETLOGON", "PICTURES", "PORN", "PR0N", "PRINT", "PROGRAMS", "PRON", "PUBLIC", "SHARE", "SHARED", "SOFTWARE", "STMP", "TEMP", "TEST", "TMP", "USERS", "WEB DOCUMENTS","WEBSERVER", "WWW", "XSERVE" }

    -- Try every alphabetic share
    for i = string.byte("A", 1), string.byte("Z", 1), 1 do
      shares[#shares + 1] = string.char(i)
    end

    -- For each share, add one with the same name and a trailing '$'
    local sharesLength = #shares
    for shareItr = 1, sharesLength, 1 do
      shares[ sharesLength + shareItr ] = shares[ shareItr ] .. '$'
    end
  else
    stdnse.debug1("SMB: Found %d shares, will attempt to find more information", #shares)
  end

  -- Sort the shares
  table.sort(shares)

  -- Ensure that the server returns the proper error message
  -- first try anonymously, then using a user account (in case anonymous connections are not supported)
  for _, anon in ipairs({true, false}) do
    status, result = share_host_returns_proper_error(host, anon)

    if(status == true and result == false) then
      return false, "Server doesn't return proper value for non-existent shares; can't enumerate shares"
    end
  end

  if(status == false) then
    return false, result
  end

  -- Get more information on each share
  for i = 1, #shares, 1 do
    local status, result
    stdnse.debug1("SMB: Getting information for share: %s", shares[i])
    status, result = share_get_details(host, shares[i])
    if(status == false and result == 'NT_STATUS_BAD_NETWORK_NAME') then
      stdnse.debug1("SMB: Share doesn't exist: %s", shares[i])
    elseif(status == false) then
      stdnse.debug1("SMB: Error while getting share details: %s", result)
    else
      -- Save the share details
      table.insert(share_details, result)
    end
  end

  return true, share_details, extra
end

---Find a share that the current user can write to. Return it, along with its path. If no share could be found,
-- an error is returned. If the path cannot be determined, the returned path is nil.
--
--@param host The host object.
--@return (status, name, path, names) If status is false, result is an error message. Otherwise, name is the name of the share,
--        path is its path, if it could be determined, and names is a list of all writable shares.
function share_find_writable(host)
  local i
  local status, shares
  local main_name, main_path
  local names = {}
  local writable = {}

  status, shares = share_get_list(host)
  if(status == false) then
    return false, shares
  end

  for i = 1, #shares, 1 do
    if(shares[i]['user_can_write'] == true) then
      if(main_name == nil) then
        main_name = shares[i]['name']

        if(shares[i]['details'] ~= nil) then
          main_path = shares[i]['details']['path']
        end
      end

      table.insert(names, shares[i]['name'])
    end
  end

  if(main_name == nil) then
    return false, "Couldn't find a writable share!"
  else
    return true, main_name, main_path, names
  end
end

--- Converts numbered Windows version strings (<code>"Windows 5.0"</code>, <code>"Windows 5.1"</code>) to names (<code>"Windows 2000"</code>, <code>"Windows XP"</code>).
--@param os The numbered OS version.
--@return The actual name of the OS (or the same as the <code>os</code> parameter if no match was found).
function get_windows_version(os)

  if(os == "Windows 5.0") then
    return "Windows 2000"
  elseif(os == "Windows 5.1")then
    return "Windows XP"
  end

  return os

end

---Retrieve information about the host's operating system. This should always be possible to call, as long as there isn't already
-- a SMB session established.
--
-- The returned table has the following keys (shown here with sample values).
-- * <code>os</code>: <code>"Windows 7 Professional 7601 Service Pack 1"</code>
-- * <code>lanmanager</code>: <code>"Windows 7 Professional 6.1"</code>
-- * <code>domain</code>: <code>"WORKGROUP"</code>
-- * <code>server</code>: <code>"COMPUTERNAME"</code>
-- * <code>time</code>: <code>1347121470.0462</code>
-- * <code>date</code>: <code>"2012-09-08 09:24:30"</code>
-- * <code>timezone</code>: <code>-7</code>
-- * <code>timezone_str</code>: <code>UTC-7</code>
-- * <code>port</code>: <code>445</code>
-- The table may also contain these additional keys:
-- * <code>fqdn</code>: <code>"Sql2008.lab.test.local"</code>
-- * <code>domain_dns</code>: <code>"lab.test.local"</code>
-- * <code>forest_dns</code>: <code>"test.local"</code>
-- * <code>workgroup</code>
--
--@param host The host object
--@return (status, data) If status is true, data is a table of values; otherwise, data is an error message.
function get_os(host)
  local state
  local status, smbstate

  local response = {}

  -- Start up SMB
  status, smbstate = start_ex(host, true, true, nil, nil, true)
  if(status == false) then
    return false, smbstate
  end

  -- See if we actually got something
  if(smbstate['os'] == nil and smbstate['lanmanager'] == nil) then
    return false, "Server didn't return OS details"
  end

  response['os']           = smbstate['os']
  response['lanmanager']   = smbstate['lanmanager']
  response['domain']       = smbstate['domain']
  response['server']       = smbstate['server']
  response['date']         = smbstate['date']
  response['time']         = smbstate['time']
  response['timezone_str'] = smbstate['timezone_str']
  response['timezone']     = smbstate['timezone']
  response['port']         = smbstate['port']

  -- Kill SMB
  stop(smbstate)


  -- Start another session with extended security. This will allow us to get
  -- additional information about the target.
  status, smbstate = start_ex(host, true, true, nil, nil, false)
  if(status == true) then
    -- See if we actually got something
    if (smbstate['fqdn'] or smbstate['domain_dns'] or smbstate['forest_dns']) then
      response['fqdn']         = smbstate['fqdn']
      response['domain_dns']   = smbstate['domain_dns']
      response['forest_dns']   = smbstate['forest_dns']
      -- After a non-extended security negotiation, smbstate['domain'] will
      -- contain the NetBIOS domain name, or the workgroup name. However,
      -- after an extended-security session setup, smbstate['domain'] will
      -- contain the NetBIOS domain name. For hosts in a workgroup, Windows
      -- uses the NetBIOS hostname as the NetBIOS domain name. Comparing the
      -- two will reveal whether the target is in a domain or a workgroup.
      if ( smbstate['domain'] ~= nil and response['domain'] ~= smbstate['domain'] ) then
        response['workgroup']    = response['domain']
        response['domain']       = nil
      end
    end

    -- Kill SMB again
    stop(smbstate)
  end

  return true, response
end

---Basically a wrapper around <code>socket:get_info</code>, except that it also makes a SMB connection before calling the
-- <code>get_info</code> function. Returns the mac address as well, for convenience.
--
--@param host The host object
--@return status: true for successful, false otherwise.
--@return If status is true, the local ip address; otherwise, an error message.
--@return The local port (not really meaningful, since it'll change next time).
--@return The remote ip address.
--@return The report port.
--@return The mac address, if possible; nil otherwise.
function get_socket_info(host)
  local status, lhost, lport, rhost, rport
  local smbstate, socket

  -- Start SMB (we need a socket to get the proper local ip
  status, smbstate = start_ex(host)
  if(status == false) then
    return false, smbstate
  end

  socket = smbstate['socket']
  status, lhost, lport, rhost, rport = socket:get_info()
  if(status == false) then
    return false, lhost
  end

  -- Stop SMB
  stop(smbstate)

  -- Get the mac in hex format, if possible
  local lmac = nil
  if(host.mac_addr_src) then
    lmac = stdnse.tohex(host.mac_addr_src, {separator = ":"})
  end

  return true, lhost, lport, rhost, rport, lmac
end

---Generate a string that's somewhat unique, but is based on factors that won't
-- change on a host.
--
-- At the moment, this is a very simple hash based on the IP address. This hash
-- is *very* likely to have collisions, and that's by design -- while it should
-- be somewhat unique, I don't want it to be trivial to uniquely determine who
-- it originated from.
--
-- TODO: At some point, I should re-do this function properly, with a method of
-- hashing that's somewhat proven.
--
--@param host      The host object
--@param extension [optional] The extension to add on the end of the file.
--                 Default: none.
--@param seed [optional] Some randomness on which to base the name. If you want
--            to do multiple files, each with its own uniqueish name, this can
--            be used.
--@return (status, data) If status is true, data is a table of values;
--        otherwise, data is an error message. Can be any kind of string.
function get_uniqueish_name(host, extension, seed)

  local status
  local lhost, lport, rhost, rport
  if(type(host) == "table") then
    status, lhost = get_socket_info(host)
  else
    lhost = host
  end

  -- Create our ultra-weak hash by using a simple xor/shift algorithm
  -- I tested this, and in 255 tests, there were roughly 10 collisions. That's about what I'm looking for.
  local hash = 0
  local i
  local str = lhost .. (seed or "") .. (extension or "") .. (nmap.registry.args.randomseed or "")

  for i = 1, #str, 1 do
    local chr = str:byte(i)
    hash = hash ~ chr
    hash = (hash << 3) | (hash >> 29)
    hash = hash ~ 3
    hash = hash & 0xFFFFFFFF
  end

  local response
  if(extension) then
    response = string.format("%x.%s", hash, extension)
  else
    response = string.format("%x", hash)
  end

  return true, response
end

---Determines, as accurately as possible, whether or not an account is an administrator. If there is an error,
-- 'false' is simply returned.
function is_admin(host, username, domain, password, password_hash, hash_type)
  local msrpc = require "msrpc" -- avoid require cycle
  local overrides = get_overrides(username, domain, password, password_hash, hash_type)

  stdnse.debug1("SMB: Checking if %s is an administrator", username)

  local status, smbstate = start(host)
  if(status == false) then
    stdnse.debug1("SMB; is_admin: Failed to start SMB: %s [%s]", smbstate, username)
    stop(smbstate)
    return false
  end

  local status, err      = negotiate_protocol(smbstate, overrides)
  if(status == false) then
    stdnse.debug1("SMB; is_admin: Failed to negotiate protocol: %s [%s]", err, username)
    stop(smbstate)
    return false
  end

  status, err      = start_session(smbstate, overrides)
  if(status == false) then
    stdnse.debug1("SMB; is_admin: Failed to start session %s [%s]", err, username)
    stop(smbstate)
    return false
  end

  local _, fqpn_share = get_fqpn(host, "IPC$")
  status, err      = tree_connect(smbstate, fqpn_share, overrides)
  if(status == false) then
    stdnse.debug1("SMB; is_admin: Failed to connect tree: %s [%s]", err, username)
    stop(smbstate)
    return false
  end

  status, err      = create_file(smbstate, msrpc.SRVSVC_PATH, overrides)
  if(status == false) then
    stdnse.debug1("SMB; is_admin: Failed to create file: %s [%s]", err, username)
    stop(smbstate)
    return false
  end

  status, err      = msrpc.bind(smbstate, msrpc.SRVSVC_UUID, msrpc.SRVSVC_VERSION, nil)
  if(status == false) then
    stdnse.debug1("SMB; is_admin: Failed to bind: %s [%s]", err, username)
    stop(smbstate)
    return false
  end

  -- Call netservergetstatistics for 'server'
  status, err = msrpc.srvsvc_netservergetstatistics(smbstate, host.ip)
  if(status == false) then
    stdnse.debug1("SMB; is_admin: Couldn't get server stats (may be normal): %s [%s]", err, username)
    stop(smbstate)
    return false
  end

  stop(smbstate)

  return true
end

---
-- Returns the fully qualified path name (FQPN) for shares.
-- This is required for modern versions of Windows.
-- Returns \\<ip>\<sharename> when successful. Otherwise, returns the same share name.
---
function get_fqpn(host, sharename)
  if host.ip and sharename then
    return true, string.format("\\\\%s\\%s", host.ip, sharename)
  end
  stdnse.debug1("SMB: get_fqpn: Couldn't determine server IP address")
  return false, sharename
end

command_codes =
{
  SMB_COM_CREATE_DIRECTORY          = 0x00,
  SMB_COM_DELETE_DIRECTORY          = 0x01,
  SMB_COM_OPEN                      = 0x02,
  SMB_COM_CREATE                    = 0x03,
  SMB_COM_CLOSE                     = 0x04,
  SMB_COM_FLUSH                     = 0x05,
  SMB_COM_DELETE                    = 0x06,
  SMB_COM_RENAME                    = 0x07,
  SMB_COM_QUERY_INFORMATION         = 0x08,
  SMB_COM_SET_INFORMATION           = 0x09,
  SMB_COM_READ                      = 0x0A,
  SMB_COM_WRITE                     = 0x0B,
  SMB_COM_LOCK_BYTE_RANGE           = 0x0C,
  SMB_COM_UNLOCK_BYTE_RANGE         = 0x0D,
  SMB_COM_CREATE_TEMPORARY          = 0x0E,
  SMB_COM_CREATE_NEW                = 0x0F,
  SMB_COM_CHECK_DIRECTORY           = 0x10,
  SMB_COM_PROCESS_EXIT              = 0x11,
  SMB_COM_SEEK                      = 0x12,
  SMB_COM_LOCK_AND_READ             = 0x13,
  SMB_COM_WRITE_AND_UNLOCK          = 0x14,
  SMB_COM_READ_RAW                  = 0x1A,
  SMB_COM_READ_MPX                  = 0x1B,
  SMB_COM_READ_MPX_SECONDARY        = 0x1C,
  SMB_COM_WRITE_RAW                 = 0x1D,
  SMB_COM_WRITE_MPX                 = 0x1E,
  SMB_COM_WRITE_MPX_SECONDARY       = 0x1F,
  SMB_COM_WRITE_COMPLETE            = 0x20,
  SMB_COM_QUERY_SERVER              = 0x21,
  SMB_COM_SET_INFORMATION2          = 0x22,
  SMB_COM_QUERY_INFORMATION2        = 0x23,
  SMB_COM_LOCKING_ANDX              = 0x24,
  SMB_COM_TRANSACTION               = 0x25,
  SMB_COM_TRANSACTION_SECONDARY     = 0x26,
  SMB_COM_IOCTL                     = 0x27,
  SMB_COM_IOCTL_SECONDARY           = 0x28,
  SMB_COM_COPY                      = 0x29,
  SMB_COM_MOVE                      = 0x2A,
  SMB_COM_ECHO                      = 0x2B,
  SMB_COM_WRITE_AND_CLOSE           = 0x2C,
  SMB_COM_OPEN_ANDX                 = 0x2D,
  SMB_COM_READ_ANDX                 = 0x2E,
  SMB_COM_WRITE_ANDX                = 0x2F,
  SMB_COM_NEW_FILE_SIZE             = 0x30,
  SMB_COM_CLOSE_AND_TREE_DISC       = 0x31,
  SMB_COM_TRANSACTION2              = 0x32,
  SMB_COM_TRANSACTION2_SECONDARY    = 0x33,
  SMB_COM_FIND_CLOSE2               = 0x34,
  SMB_COM_FIND_NOTIFY_CLOSE         = 0x35,
  SMB_COM_TREE_CONNECT              = 0x70,
  SMB_COM_TREE_DISCONNECT           = 0x71,
  SMB_COM_NEGOTIATE                 = 0x72,
  SMB_COM_SESSION_SETUP_ANDX        = 0x73,
  SMB_COM_LOGOFF_ANDX               = 0x74,
  SMB_COM_TREE_CONNECT_ANDX         = 0x75,
  SMB_COM_QUERY_INFORMATION_DISK    = 0x80,
  SMB_COM_SEARCH                    = 0x81,
  SMB_COM_FIND                      = 0x82,
  SMB_COM_FIND_UNIQUE               = 0x83,
  SMB_COM_FIND_CLOSE                = 0x84,
  SMB_COM_NT_TRANSACT               = 0xA0,
  SMB_COM_NT_TRANSACT_SECONDARY     = 0xA1,
  SMB_COM_NT_CREATE_ANDX            = 0xA2,
  SMB_COM_NT_CANCEL                 = 0xA4,
  SMB_COM_NT_RENAME                 = 0xA5,
  SMB_COM_OPEN_PRINT_FILE           = 0xC0,
  SMB_COM_WRITE_PRINT_FILE          = 0xC1,
  SMB_COM_CLOSE_PRINT_FILE          = 0xC2,
  SMB_COM_GET_PRINT_QUEUE           = 0xC3,
  SMB_COM_READ_BULK                 = 0xD8,
  SMB_COM_WRITE_BULK                = 0xD9,
  SMB_COM_WRITE_BULK_DATA           = 0xDA,
  SMB_NO_FURTHER_COMMANDS           = 0xFF
}

for i, v in pairs(command_codes) do
  command_names[v] = i
end


-- https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-cifs/2198f480-e047-4df0-ba64-f28eadef00b9
file_attributes =
{
  SMB_FILE_ATTRIBUTE_NORMAL      = 0x0000,
  SMB_FILE_ATTRIBUTE_READONLY    = 0x0001,
  SMB_FILE_ATTRIBUTE_HIDDEN      = 0x0002,
  SMB_FILE_ATTRIBUTE_SYSTEM      = 0x0004,
  SMB_FILE_ATTRIBUTE_VOLUME      = 0x0008,
  SMB_FILE_ATTRIBUTE_DIRECTORY   = 0x0010,
  SMB_FILE_ATTRIBUTE_ARCHIVE     = 0x0020,
  SMB_SEARCH_ATTRIBUTE_READONLY  = 0x0100,
  SMB_SEARCH_ATTRIBUTE_HIDDEN    = 0x0200,
  SMB_SEARCH_ATTRIBUTE_SYSTEM    = 0x0400,
  SMB_SEARCH_ATTRIBUTE_DIRECTORY = 0x1000,
  SMB_SEARCH_ATTRIBUTE_ARCHIVE   = 0x2000
}


-- see http://msdn.microsoft.com/en-us/library/cc231196(v=prot.10).aspx
status_codes =
{
  NT_STATUS_SUCCESS                           = 0x00000000,
  NT_STATUS_WERR_BADFILE                      = 0x00000002,
  NT_STATUS_WERR_ACCESS_DENIED                = 0x00000005,
  NT_STATUS_WERR_INVALID_PARAMETER            = 0x00000057,
  NT_STATUS_WERR_INVALID_NAME                 = 0x0000007b,
  NT_STATUS_WERR_UNKNOWN_LEVEL                = 0x0000007c,
  NT_STATUS_WERR_MORE_DATA                    = 0x000000ea,
  NT_STATUS_NO_MORE_ITEMS                     = 0x00000103,
  NT_STATUS_MORE_ENTRIES                      = 0x00000105,
  NT_STATUS_SOME_NOT_MAPPED                   = 0x00000107,
  NT_STATUS_SERVICE_REQUEST_TIMEOUT           = 0x0000041D,
  NT_STATUS_SERVICE_NO_THREAD                 = 0x0000041E,
  NT_STATUS_SERVICE_DATABASE_LOCKED           = 0x0000041F,
  NT_STATUS_SERVICE_ALREADY_RUNNING           = 0x00000420,
  NT_STATUS_INVALID_SERVICE_ACCOUNT           = 0x00000421,
  NT_STATUS_SERVICE_DISABLED                  = 0x00000422,
  NT_STATUS_CIRCULAR_DEPENDENCY               = 0x00000423,
  NT_STATUS_SERVICE_DOES_NOT_EXIST            = 0x00000424,
  NT_STATUS_SERVICE_CANNOT_ACCEPT_CTRL        = 0x00000425,
  NT_STATUS_SERVICE_NOT_ACTIVE                = 0x00000426,
  NT_STATUS_FAILED_SERVICE_CONTROLLER_CONNECT = 0x00000427,
  NT_STATUS_EXCEPTION_IN_SERVICE              = 0x00000428,
  NT_STATUS_DATABASE_DOES_NOT_EXIST           = 0x00000429,
  NT_STATUS_SERVICE_SPECIFIC_ERROR            = 0x0000042a,
  NT_STATUS_PROCESS_ABORTED                   = 0x0000042b,
  NT_STATUS_SERVICE_DEPENDENCY_FAIL           = 0x0000042c,
  NT_STATUS_SERVICE_LOGON_FAILED              = 0x0000042d,
  NT_STATUS_SERVICE_START_HANG                = 0x0000042e,
  NT_STATUS_INVALID_SERVICE_LOCK              = 0x0000042f,
  NT_STATUS_SERVICE_MARKED_FOR_DELETE         = 0x00000430,
  NT_STATUS_SERVICE_EXISTS                    = 0x00000431,
  NT_STATUS_ALREADY_RUNNING_LKG               = 0x00000432,
  NT_STATUS_SERVICE_DEPENDENCY_DELETED        = 0x00000433,
  NT_STATUS_BOOT_ALREADY_ACCEPTED             = 0x00000434,
  NT_STATUS_SERVICE_NEVER_STARTED             = 0x00000435,
  NT_STATUS_DUPLICATE_SERVICE_NAME            = 0x00000436,
  NT_STATUS_DIFFERENT_SERVICE_ACCOUNT         = 0x00000437,
  NT_STATUS_CANNOT_DETECT_DRIVER_FAILURE      = 0x00000438,
  DOS_STATUS_UNKNOWN_ERROR                    = 0x00010001,
  DOS_STATUS_NONSPECIFIC_ERROR                = 0x00010002,
  DOS_STATUS_DIRECTORY_NOT_FOUND              = 0x00030001,
  DOS_STATUS_ACCESS_DENIED                    = 0x00050001,
  DOS_STATUS_INVALID_FID                      = 0x00060001,
  DOS_STATUS_INVALID_NETWORK_NAME             = 0x00060002,
  NT_STATUS_BUFFER_OVERFLOW                   = 0x80000005,
  NT_STATUS_UNSUCCESSFUL                      = 0xc0000001,
  NT_STATUS_NOT_IMPLEMENTED                   = 0xc0000002,
  NT_STATUS_INVALID_INFO_CLASS                = 0xc0000003,
  NT_STATUS_INFO_LENGTH_MISMATCH              = 0xc0000004,
  NT_STATUS_ACCESS_VIOLATION                  = 0xc0000005,
  NT_STATUS_IN_PAGE_ERROR                     = 0xc0000006,
  NT_STATUS_PAGEFILE_QUOTA                    = 0xc0000007,
  NT_STATUS_INVALID_HANDLE                    = 0xc0000008,
  NT_STATUS_BAD_INITIAL_STACK                 = 0xc0000009,
  NT_STATUS_BAD_INITIAL_PC                    = 0xc000000a,
  NT_STATUS_INVALID_CID                       = 0xc000000b,
  NT_STATUS_TIMER_NOT_CANCELED                = 0xc000000c,
  NT_STATUS_INVALID_PARAMETER                 = 0xc000000d,
  NT_STATUS_NO_SUCH_DEVICE                    = 0xc000000e,
  NT_STATUS_NO_SUCH_FILE                      = 0xc000000f,
  NT_STATUS_INVALID_DEVICE_REQUEST            = 0xc0000010,
  NT_STATUS_END_OF_FILE                       = 0xc0000011,
  NT_STATUS_WRONG_VOLUME                      = 0xc0000012,
  NT_STATUS_NO_MEDIA_IN_DEVICE                = 0xc0000013,
  NT_STATUS_UNRECOGNIZED_MEDIA                = 0xc0000014,
  NT_STATUS_NONEXISTENT_SECTOR                = 0xc0000015,
  NT_STATUS_MORE_PROCESSING_REQUIRED          = 0xc0000016,
  NT_STATUS_NO_MEMORY                         = 0xc0000017,
  NT_STATUS_CONFLICTING_ADDRESSES             = 0xc0000018,
  NT_STATUS_NOT_MAPPED_VIEW                   = 0xc0000019,
  NT_STATUS_UNABLE_TO_FREE_VM                 = 0xc000001a,
  NT_STATUS_UNABLE_TO_DELETE_SECTION          = 0xc000001b,
  NT_STATUS_INVALID_SYSTEM_SERVICE            = 0xc000001c,
  NT_STATUS_ILLEGAL_INSTRUCTION               = 0xc000001d,
  NT_STATUS_INVALID_LOCK_SEQUENCE             = 0xc000001e,
  NT_STATUS_INVALID_VIEW_SIZE                 = 0xc000001f,
  NT_STATUS_INVALID_FILE_FOR_SECTION          = 0xc0000020,
  NT_STATUS_ALREADY_COMMITTED                 = 0xc0000021,
  NT_STATUS_ACCESS_DENIED                     = 0xc0000022,
  NT_STATUS_BUFFER_TOO_SMALL                  = 0xc0000023,
  NT_STATUS_OBJECT_TYPE_MISMATCH              = 0xc0000024,
  NT_STATUS_NONCONTINUABLE_EXCEPTION          = 0xc0000025,
  NT_STATUS_INVALID_DISPOSITION               = 0xc0000026,
  NT_STATUS_UNWIND                            = 0xc0000027,
  NT_STATUS_BAD_STACK                         = 0xc0000028,
  NT_STATUS_INVALID_UNWIND_TARGET             = 0xc0000029,
  NT_STATUS_NOT_LOCKED                        = 0xc000002a,
  NT_STATUS_PARITY_ERROR                      = 0xc000002b,
  NT_STATUS_UNABLE_TO_DECOMMIT_VM             = 0xc000002c,
  NT_STATUS_NOT_COMMITTED                     = 0xc000002d,
  NT_STATUS_INVALID_PORT_ATTRIBUTES           = 0xc000002e,
  NT_STATUS_PORT_MESSAGE_TOO_LONG             = 0xc000002f,
  NT_STATUS_INVALID_PARAMETER_MIX             = 0xc0000030,
  NT_STATUS_INVALID_QUOTA_LOWER               = 0xc0000031,
  NT_STATUS_DISK_CORRUPT_ERROR                = 0xc0000032,
  NT_STATUS_OBJECT_NAME_INVALID               = 0xc0000033,
  NT_STATUS_OBJECT_NAME_NOT_FOUND             = 0xc0000034,
  NT_STATUS_OBJECT_NAME_COLLISION             = 0xc0000035,
  NT_STATUS_HANDLE_NOT_WAITABLE               = 0xc0000036,
  NT_STATUS_PORT_DISCONNECTED                 = 0xc0000037,
  NT_STATUS_DEVICE_ALREADY_ATTACHED           = 0xc0000038,
  NT_STATUS_OBJECT_PATH_INVALID               = 0xc0000039,
  NT_STATUS_OBJECT_PATH_NOT_FOUND             = 0xc000003a,
  NT_STATUS_OBJECT_PATH_SYNTAX_BAD            = 0xc000003b,
  NT_STATUS_DATA_OVERRUN                      = 0xc000003c,
  NT_STATUS_DATA_LATE_ERROR                   = 0xc000003d,
  NT_STATUS_DATA_ERROR                        = 0xc000003e,
  NT_STATUS_CRC_ERROR                         = 0xc000003f,
  NT_STATUS_SECTION_TOO_BIG                   = 0xc0000040,
  NT_STATUS_PORT_CONNECTION_REFUSED           = 0xc0000041,
  NT_STATUS_INVALID_PORT_HANDLE               = 0xc0000042,
  NT_STATUS_SHARING_VIOLATION                 = 0xc0000043,
  NT_STATUS_QUOTA_EXCEEDED                    = 0xc0000044,
  NT_STATUS_INVALID_PAGE_PROTECTION           = 0xc0000045,
  NT_STATUS_MUTANT_NOT_OWNED                  = 0xc0000046,
  NT_STATUS_SEMAPHORE_LIMIT_EXCEEDED          = 0xc0000047,
  NT_STATUS_PORT_ALREADY_SET                  = 0xc0000048,
  NT_STATUS_SECTION_NOT_IMAGE                 = 0xc0000049,
  NT_STATUS_SUSPEND_COUNT_EXCEEDED            = 0xc000004a,
  NT_STATUS_THREAD_IS_TERMINATING             = 0xc000004b,
  NT_STATUS_BAD_WORKING_SET_LIMIT             = 0xc000004c,
  NT_STATUS_INCOMPATIBLE_FILE_MAP             = 0xc000004d,
  NT_STATUS_SECTION_PROTECTION                = 0xc000004e,
  NT_STATUS_EAS_NOT_SUPPORTED                 = 0xc000004f,
  NT_STATUS_EA_TOO_LARGE                      = 0xc0000050,
  NT_STATUS_NONEXISTENT_EA_ENTRY              = 0xc0000051,
  NT_STATUS_NO_EAS_ON_FILE                    = 0xc0000052,
  NT_STATUS_EA_CORRUPT_ERROR                  = 0xc0000053,
  NT_STATUS_FILE_LOCK_CONFLICT                = 0xc0000054,
  NT_STATUS_LOCK_NOT_GRANTED                  = 0xc0000055,
  NT_STATUS_DELETE_PENDING                    = 0xc0000056,
  NT_STATUS_CTL_FILE_NOT_SUPPORTED            = 0xc0000057,
  NT_STATUS_UNKNOWN_REVISION                  = 0xc0000058,
  NT_STATUS_REVISION_MISMATCH                 = 0xc0000059,
  NT_STATUS_INVALID_OWNER                     = 0xc000005a,
  NT_STATUS_INVALID_PRIMARY_GROUP             = 0xc000005b,
  NT_STATUS_NO_IMPERSONATION_TOKEN            = 0xc000005c,
  NT_STATUS_CANT_DISABLE_MANDATORY            = 0xc000005d,
  NT_STATUS_NO_LOGON_SERVERS                  = 0xc000005e,
  NT_STATUS_NO_SUCH_LOGON_SESSION             = 0xc000005f,
  NT_STATUS_NO_SUCH_PRIVILEGE                 = 0xc0000060,
  NT_STATUS_PRIVILEGE_NOT_HELD                = 0xc0000061,
  NT_STATUS_INVALID_ACCOUNT_NAME              = 0xc0000062,
  NT_STATUS_USER_EXISTS                       = 0xc0000063,
  NT_STATUS_NO_SUCH_USER                      = 0xc0000064,
  NT_STATUS_GROUP_EXISTS                      = 0xc0000065,
  NT_STATUS_NO_SUCH_GROUP                     = 0xc0000066,
  NT_STATUS_MEMBER_IN_GROUP                   = 0xc0000067,
  NT_STATUS_MEMBER_NOT_IN_GROUP               = 0xc0000068,
  NT_STATUS_LAST_ADMIN                        = 0xc0000069,
  NT_STATUS_WRONG_PASSWORD                    = 0xc000006a,
  NT_STATUS_ILL_FORMED_PASSWORD               = 0xc000006b,
  NT_STATUS_PASSWORD_RESTRICTION              = 0xc000006c,
  NT_STATUS_LOGON_FAILURE                     = 0xc000006d,
  NT_STATUS_ACCOUNT_RESTRICTION               = 0xc000006e,
  NT_STATUS_INVALID_LOGON_HOURS               = 0xc000006f,
  NT_STATUS_INVALID_WORKSTATION               = 0xc0000070,
  NT_STATUS_PASSWORD_EXPIRED                  = 0xc0000071,
  NT_STATUS_ACCOUNT_DISABLED                  = 0xc0000072,
  NT_STATUS_NONE_MAPPED                       = 0xc0000073,
  NT_STATUS_TOO_MANY_LUIDS_REQUESTED          = 0xc0000074,
  NT_STATUS_LUIDS_EXHAUSTED                   = 0xc0000075,
  NT_STATUS_INVALID_SUB_AUTHORITY             = 0xc0000076,
  NT_STATUS_INVALID_ACL                       = 0xc0000077,
  NT_STATUS_INVALID_SID                       = 0xc0000078,
  NT_STATUS_INVALID_SECURITY_DESCR            = 0xc0000079,
  NT_STATUS_PROCEDURE_NOT_FOUND               = 0xc000007a,
  NT_STATUS_INVALID_IMAGE_FORMAT              = 0xc000007b,
  NT_STATUS_NO_TOKEN                          = 0xc000007c,
  NT_STATUS_BAD_INHERITANCE_ACL               = 0xc000007d,
  NT_STATUS_RANGE_NOT_LOCKED                  = 0xc000007e,
  NT_STATUS_DISK_FULL                         = 0xc000007f,
  NT_STATUS_SERVER_DISABLED                   = 0xc0000080,
  NT_STATUS_SERVER_NOT_DISABLED               = 0xc0000081,
  NT_STATUS_TOO_MANY_GUIDS_REQUESTED          = 0xc0000082,
  NT_STATUS_GUIDS_EXHAUSTED                   = 0xc0000083,
  NT_STATUS_INVALID_ID_AUTHORITY              = 0xc0000084,
  NT_STATUS_AGENTS_EXHAUSTED                  = 0xc0000085,
  NT_STATUS_INVALID_VOLUME_LABEL              = 0xc0000086,
  NT_STATUS_SECTION_NOT_EXTENDED              = 0xc0000087,
  NT_STATUS_NOT_MAPPED_DATA                   = 0xc0000088,
  NT_STATUS_RESOURCE_DATA_NOT_FOUND           = 0xc0000089,
  NT_STATUS_RESOURCE_TYPE_NOT_FOUND           = 0xc000008a,
  NT_STATUS_RESOURCE_NAME_NOT_FOUND           = 0xc000008b,
  NT_STATUS_ARRAY_BOUNDS_EXCEEDED             = 0xc000008c,
  NT_STATUS_FLOAT_DENORMAL_OPERAND            = 0xc000008d,
  NT_STATUS_FLOAT_DIVIDE_BY_ZERO              = 0xc000008e,
  NT_STATUS_FLOAT_INEXACT_RESULT              = 0xc000008f,
  NT_STATUS_FLOAT_INVALID_OPERATION           = 0xc0000090,
  NT_STATUS_FLOAT_OVERFLOW                    = 0xc0000091,
  NT_STATUS_FLOAT_STACK_CHECK                 = 0xc0000092,
  NT_STATUS_FLOAT_UNDERFLOW                   = 0xc0000093,
  NT_STATUS_INTEGER_DIVIDE_BY_ZERO            = 0xc0000094,
  NT_STATUS_INTEGER_OVERFLOW                  = 0xc0000095,
  NT_STATUS_PRIVILEGED_INSTRUCTION            = 0xc0000096,
  NT_STATUS_TOO_MANY_PAGING_FILES             = 0xc0000097,
  NT_STATUS_FILE_INVALID                      = 0xc0000098,
  NT_STATUS_ALLOTTED_SPACE_EXCEEDED           = 0xc0000099,
  NT_STATUS_INSUFFICIENT_RESOURCES            = 0xc000009a,
  NT_STATUS_DFS_EXIT_PATH_FOUND               = 0xc000009b,
  NT_STATUS_DEVICE_DATA_ERROR                 = 0xc000009c,
  NT_STATUS_DEVICE_NOT_CONNECTED              = 0xc000009d,
  NT_STATUS_DEVICE_POWER_FAILURE              = 0xc000009e,
  NT_STATUS_FREE_VM_NOT_AT_BASE               = 0xc000009f,
  NT_STATUS_MEMORY_NOT_ALLOCATED              = 0xc00000a0,
  NT_STATUS_WORKING_SET_QUOTA                 = 0xc00000a1,
  NT_STATUS_MEDIA_WRITE_PROTECTED             = 0xc00000a2,
  NT_STATUS_DEVICE_NOT_READY                  = 0xc00000a3,
  NT_STATUS_INVALID_GROUP_ATTRIBUTES          = 0xc00000a4,
  NT_STATUS_BAD_IMPERSONATION_LEVEL           = 0xc00000a5,
  NT_STATUS_CANT_OPEN_ANONYMOUS               = 0xc00000a6,
  NT_STATUS_BAD_VALIDATION_CLASS              = 0xc00000a7,
  NT_STATUS_BAD_TOKEN_TYPE                    = 0xc00000a8,
  NT_STATUS_BAD_MASTER_BOOT_RECORD            = 0xc00000a9,
  NT_STATUS_INSTRUCTION_MISALIGNMENT          = 0xc00000aa,
  NT_STATUS_INSTANCE_NOT_AVAILABLE            = 0xc00000ab,
  NT_STATUS_PIPE_NOT_AVAILABLE                = 0xc00000ac,
  NT_STATUS_INVALID_PIPE_STATE                = 0xc00000ad,
  NT_STATUS_PIPE_BUSY                         = 0xc00000ae,
  NT_STATUS_ILLEGAL_FUNCTION                  = 0xc00000af,
  NT_STATUS_PIPE_DISCONNECTED                 = 0xc00000b0,
  NT_STATUS_PIPE_CLOSING                      = 0xc00000b1,
  NT_STATUS_PIPE_CONNECTED                    = 0xc00000b2,
  NT_STATUS_PIPE_LISTENING                    = 0xc00000b3,
  NT_STATUS_INVALID_READ_MODE                 = 0xc00000b4,
  NT_STATUS_IO_TIMEOUT                        = 0xc00000b5,
  NT_STATUS_FILE_FORCED_CLOSED                = 0xc00000b6,
  NT_STATUS_PROFILING_NOT_STARTED             = 0xc00000b7,
  NT_STATUS_PROFILING_NOT_STOPPED             = 0xc00000b8,
  NT_STATUS_COULD_NOT_INTERPRET               = 0xc00000b9,
  NT_STATUS_FILE_IS_A_DIRECTORY               = 0xc00000ba,
  NT_STATUS_NOT_SUPPORTED                     = 0xc00000bb,
  NT_STATUS_REMOTE_NOT_LISTENING              = 0xc00000bc,
  NT_STATUS_DUPLICATE_NAME                    = 0xc00000bd,
  NT_STATUS_BAD_NETWORK_PATH                  = 0xc00000be,
  NT_STATUS_NETWORK_BUSY                      = 0xc00000bf,
  NT_STATUS_DEVICE_DOES_NOT_EXIST             = 0xc00000c0,
  NT_STATUS_TOO_MANY_COMMANDS                 = 0xc00000c1,
  NT_STATUS_ADAPTER_HARDWARE_ERROR            = 0xc00000c2,
  NT_STATUS_INVALID_NETWORK_RESPONSE          = 0xc00000c3,
  NT_STATUS_UNEXPECTED_NETWORK_ERROR          = 0xc00000c4,
  NT_STATUS_BAD_REMOTE_ADAPTER                = 0xc00000c5,
  NT_STATUS_PRINT_QUEUE_FULL                  = 0xc00000c6,
  NT_STATUS_NO_SPOOL_SPACE                    = 0xc00000c7,
  NT_STATUS_PRINT_CANCELLED                   = 0xc00000c8,
  NT_STATUS_NETWORK_NAME_DELETED              = 0xc00000c9,
  NT_STATUS_NETWORK_ACCESS_DENIED             = 0xc00000ca,
  NT_STATUS_BAD_DEVICE_TYPE                   = 0xc00000cb,
  NT_STATUS_BAD_NETWORK_NAME                  = 0xc00000cc,
  NT_STATUS_TOO_MANY_NAMES                    = 0xc00000cd,
  NT_STATUS_TOO_MANY_SESSIONS                 = 0xc00000ce,
  NT_STATUS_SHARING_PAUSED                    = 0xc00000cf,
  NT_STATUS_REQUEST_NOT_ACCEPTED              = 0xc00000d0,
  NT_STATUS_REDIRECTOR_PAUSED                 = 0xc00000d1,
  NT_STATUS_NET_WRITE_FAULT                   = 0xc00000d2,
  NT_STATUS_PROFILING_AT_LIMIT                = 0xc00000d3,
  NT_STATUS_NOT_SAME_DEVICE                   = 0xc00000d4,
  NT_STATUS_FILE_RENAMED                      = 0xc00000d5,
  NT_STATUS_VIRTUAL_CIRCUIT_CLOSED            = 0xc00000d6,
  NT_STATUS_NO_SECURITY_ON_OBJECT             = 0xc00000d7,
  NT_STATUS_CANT_WAIT                         = 0xc00000d8,
  NT_STATUS_PIPE_EMPTY                        = 0xc00000d9,
  NT_STATUS_CANT_ACCESS_DOMAIN_INFO           = 0xc00000da,
  NT_STATUS_CANT_TERMINATE_SELF               = 0xc00000db,
  NT_STATUS_INVALID_SERVER_STATE              = 0xc00000dc,
  NT_STATUS_INVALID_DOMAIN_STATE              = 0xc00000dd,
  NT_STATUS_INVALID_DOMAIN_ROLE               = 0xc00000de,
  NT_STATUS_NO_SUCH_DOMAIN                    = 0xc00000df,
  NT_STATUS_DOMAIN_EXISTS                     = 0xc00000e0,
  NT_STATUS_DOMAIN_LIMIT_EXCEEDED             = 0xc00000e1,
  NT_STATUS_OPLOCK_NOT_GRANTED                = 0xc00000e2,
  NT_STATUS_INVALID_OPLOCK_PROTOCOL           = 0xc00000e3,
  NT_STATUS_INTERNAL_DB_CORRUPTION            = 0xc00000e4,
  NT_STATUS_INTERNAL_ERROR                    = 0xc00000e5,
  NT_STATUS_GENERIC_NOT_MAPPED                = 0xc00000e6,
  NT_STATUS_BAD_DESCRIPTOR_FORMAT             = 0xc00000e7,
  NT_STATUS_INVALID_USER_BUFFER               = 0xc00000e8,
  NT_STATUS_UNEXPECTED_IO_ERROR               = 0xc00000e9,
  NT_STATUS_UNEXPECTED_MM_CREATE_ERR          = 0xc00000ea,
  NT_STATUS_UNEXPECTED_MM_MAP_ERROR           = 0xc00000eb,
  NT_STATUS_UNEXPECTED_MM_EXTEND_ERR          = 0xc00000ec,
  NT_STATUS_NOT_LOGON_PROCESS                 = 0xc00000ed,
  NT_STATUS_LOGON_SESSION_EXISTS              = 0xc00000ee,
  NT_STATUS_INVALID_PARAMETER_1               = 0xc00000ef,
  NT_STATUS_INVALID_PARAMETER_2               = 0xc00000f0,
  NT_STATUS_INVALID_PARAMETER_3               = 0xc00000f1,
  NT_STATUS_INVALID_PARAMETER_4               = 0xc00000f2,
  NT_STATUS_INVALID_PARAMETER_5               = 0xc00000f3,
  NT_STATUS_INVALID_PARAMETER_6               = 0xc00000f4,
  NT_STATUS_INVALID_PARAMETER_7               = 0xc00000f5,
  NT_STATUS_INVALID_PARAMETER_8               = 0xc00000f6,
  NT_STATUS_INVALID_PARAMETER_9               = 0xc00000f7,
  NT_STATUS_INVALID_PARAMETER_10              = 0xc00000f8,
  NT_STATUS_INVALID_PARAMETER_11              = 0xc00000f9,
  NT_STATUS_INVALID_PARAMETER_12              = 0xc00000fa,
  NT_STATUS_REDIRECTOR_NOT_STARTED            = 0xc00000fb,
  NT_STATUS_REDIRECTOR_STARTED                = 0xc00000fc,
  NT_STATUS_STACK_OVERFLOW                    = 0xc00000fd,
  NT_STATUS_NO_SUCH_PACKAGE                   = 0xc00000fe,
  NT_STATUS_BAD_FUNCTION_TABLE                = 0xc00000ff,
  NT_STATUS_DIRECTORY_NOT_EMPTY               = 0xc0000101,
  NT_STATUS_FILE_CORRUPT_ERROR                = 0xc0000102,
  NT_STATUS_NOT_A_DIRECTORY                   = 0xc0000103,
  NT_STATUS_BAD_LOGON_SESSION_STATE           = 0xc0000104,
  NT_STATUS_LOGON_SESSION_COLLISION           = 0xc0000105,
  NT_STATUS_NAME_TOO_LONG                     = 0xc0000106,
  NT_STATUS_FILES_OPEN                        = 0xc0000107,
  NT_STATUS_CONNECTION_IN_USE                 = 0xc0000108,
  NT_STATUS_MESSAGE_NOT_FOUND                 = 0xc0000109,
  NT_STATUS_PROCESS_IS_TERMINATING            = 0xc000010a,
  NT_STATUS_INVALID_LOGON_TYPE                = 0xc000010b,
  NT_STATUS_NO_GUID_TRANSLATION               = 0xc000010c,
  NT_STATUS_CANNOT_IMPERSONATE                = 0xc000010d,
  NT_STATUS_IMAGE_ALREADY_LOADED              = 0xc000010e,
  NT_STATUS_ABIOS_NOT_PRESENT                 = 0xc000010f,
  NT_STATUS_ABIOS_LID_NOT_EXIST               = 0xc0000110,
  NT_STATUS_ABIOS_LID_ALREADY_OWNED           = 0xc0000111,
  NT_STATUS_ABIOS_NOT_LID_OWNER               = 0xc0000112,
  NT_STATUS_ABIOS_INVALID_COMMAND             = 0xc0000113,
  NT_STATUS_ABIOS_INVALID_LID                 = 0xc0000114,
  NT_STATUS_ABIOS_SELECTOR_NOT_AVAILABLE      = 0xc0000115,
  NT_STATUS_ABIOS_INVALID_SELECTOR            = 0xc0000116,
  NT_STATUS_NO_LDT                            = 0xc0000117,
  NT_STATUS_INVALID_LDT_SIZE                  = 0xc0000118,
  NT_STATUS_INVALID_LDT_OFFSET                = 0xc0000119,
  NT_STATUS_INVALID_LDT_DESCRIPTOR            = 0xc000011a,
  NT_STATUS_INVALID_IMAGE_NE_FORMAT           = 0xc000011b,
  NT_STATUS_RXACT_INVALID_STATE               = 0xc000011c,
  NT_STATUS_RXACT_COMMIT_FAILURE              = 0xc000011d,
  NT_STATUS_MAPPED_FILE_SIZE_ZERO             = 0xc000011e,
  NT_STATUS_TOO_MANY_OPENED_FILES             = 0xc000011f,
  NT_STATUS_CANCELLED                         = 0xc0000120,
  NT_STATUS_CANNOT_DELETE                     = 0xc0000121,
  NT_STATUS_INVALID_COMPUTER_NAME             = 0xc0000122,
  NT_STATUS_FILE_DELETED                      = 0xc0000123,
  NT_STATUS_SPECIAL_ACCOUNT                   = 0xc0000124,
  NT_STATUS_SPECIAL_GROUP                     = 0xc0000125,
  NT_STATUS_SPECIAL_USER                      = 0xc0000126,
  NT_STATUS_MEMBERS_PRIMARY_GROUP             = 0xc0000127,
  NT_STATUS_FILE_CLOSED                       = 0xc0000128,
  NT_STATUS_TOO_MANY_THREADS                  = 0xc0000129,
  NT_STATUS_THREAD_NOT_IN_PROCESS             = 0xc000012a,
  NT_STATUS_TOKEN_ALREADY_IN_USE              = 0xc000012b,
  NT_STATUS_PAGEFILE_QUOTA_EXCEEDED           = 0xc000012c,
  NT_STATUS_COMMITMENT_LIMIT                  = 0xc000012d,
  NT_STATUS_INVALID_IMAGE_LE_FORMAT           = 0xc000012e,
  NT_STATUS_INVALID_IMAGE_NOT_MZ              = 0xc000012f,
  NT_STATUS_INVALID_IMAGE_PROTECT             = 0xc0000130,
  NT_STATUS_INVALID_IMAGE_WIN_16              = 0xc0000131,
  NT_STATUS_LOGON_SERVER_CONFLICT             = 0xc0000132,
  NT_STATUS_TIME_DIFFERENCE_AT_DC             = 0xc0000133,
  NT_STATUS_SYNCHRONIZATION_REQUIRED          = 0xc0000134,
  NT_STATUS_DLL_NOT_FOUND                     = 0xc0000135,
  NT_STATUS_OPEN_FAILED                       = 0xc0000136,
  NT_STATUS_IO_PRIVILEGE_FAILED               = 0xc0000137,
  NT_STATUS_ORDINAL_NOT_FOUND                 = 0xc0000138,
  NT_STATUS_ENTRYPOINT_NOT_FOUND              = 0xc0000139,
  NT_STATUS_CONTROL_C_EXIT                    = 0xc000013a,
  NT_STATUS_LOCAL_DISCONNECT                  = 0xc000013b,
  NT_STATUS_REMOTE_DISCONNECT                 = 0xc000013c,
  NT_STATUS_REMOTE_RESOURCES                  = 0xc000013d,
  NT_STATUS_LINK_FAILED                       = 0xc000013e,
  NT_STATUS_LINK_TIMEOUT                      = 0xc000013f,
  NT_STATUS_INVALID_CONNECTION                = 0xc0000140,
  NT_STATUS_INVALID_ADDRESS                   = 0xc0000141,
  NT_STATUS_DLL_INIT_FAILED                   = 0xc0000142,
  NT_STATUS_MISSING_SYSTEMFILE                = 0xc0000143,
  NT_STATUS_UNHANDLED_EXCEPTION               = 0xc0000144,
  NT_STATUS_APP_INIT_FAILURE                  = 0xc0000145,
  NT_STATUS_PAGEFILE_CREATE_FAILED            = 0xc0000146,
  NT_STATUS_NO_PAGEFILE                       = 0xc0000147,
  NT_STATUS_INVALID_LEVEL                     = 0xc0000148,
  NT_STATUS_WRONG_PASSWORD_CORE               = 0xc0000149,
  NT_STATUS_ILLEGAL_FLOAT_CONTEXT             = 0xc000014a,
  NT_STATUS_PIPE_BROKEN                       = 0xc000014b,
  NT_STATUS_REGISTRY_CORRUPT                  = 0xc000014c,
  NT_STATUS_REGISTRY_IO_FAILED                = 0xc000014d,
  NT_STATUS_NO_EVENT_PAIR                     = 0xc000014e,
  NT_STATUS_UNRECOGNIZED_VOLUME               = 0xc000014f,
  NT_STATUS_SERIAL_NO_DEVICE_INITED           = 0xc0000150,
  NT_STATUS_NO_SUCH_ALIAS                     = 0xc0000151,
  NT_STATUS_MEMBER_NOT_IN_ALIAS               = 0xc0000152,
  NT_STATUS_MEMBER_IN_ALIAS                   = 0xc0000153,
  NT_STATUS_ALIAS_EXISTS                      = 0xc0000154,
  NT_STATUS_LOGON_NOT_GRANTED                 = 0xc0000155,
  NT_STATUS_TOO_MANY_SECRETS                  = 0xc0000156,
  NT_STATUS_SECRET_TOO_LONG                   = 0xc0000157,
  NT_STATUS_INTERNAL_DB_ERROR                 = 0xc0000158,
  NT_STATUS_FULLSCREEN_MODE                   = 0xc0000159,
  NT_STATUS_TOO_MANY_CONTEXT_IDS              = 0xc000015a,
  NT_STATUS_LOGON_TYPE_NOT_GRANTED            = 0xc000015b,
  NT_STATUS_NOT_REGISTRY_FILE                 = 0xc000015c,
  NT_STATUS_NT_CROSS_ENCRYPTION_REQUIRED      = 0xc000015d,
  NT_STATUS_DOMAIN_CTRLR_CONFIG_ERROR         = 0xc000015e,
  NT_STATUS_FT_MISSING_MEMBER                 = 0xc000015f,
  NT_STATUS_ILL_FORMED_SERVICE_ENTRY          = 0xc0000160,
  NT_STATUS_ILLEGAL_CHARACTER                 = 0xc0000161,
  NT_STATUS_UNMAPPABLE_CHARACTER              = 0xc0000162,
  NT_STATUS_UNDEFINED_CHARACTER               = 0xc0000163,
  NT_STATUS_FLOPPY_VOLUME                     = 0xc0000164,
  NT_STATUS_FLOPPY_ID_MARK_NOT_FOUND          = 0xc0000165,
  NT_STATUS_FLOPPY_WRONG_CYLINDER             = 0xc0000166,
  NT_STATUS_FLOPPY_UNKNOWN_ERROR              = 0xc0000167,
  NT_STATUS_FLOPPY_BAD_REGISTERS              = 0xc0000168,
  NT_STATUS_DISK_RECALIBRATE_FAILED           = 0xc0000169,
  NT_STATUS_DISK_OPERATION_FAILED             = 0xc000016a,
  NT_STATUS_DISK_RESET_FAILED                 = 0xc000016b,
  NT_STATUS_SHARED_IRQ_BUSY                   = 0xc000016c,
  NT_STATUS_FT_ORPHANING                      = 0xc000016d,
  NT_STATUS_PARTITION_FAILURE                 = 0xc0000172,
  NT_STATUS_INVALID_BLOCK_LENGTH              = 0xc0000173,
  NT_STATUS_DEVICE_NOT_PARTITIONED            = 0xc0000174,
  NT_STATUS_UNABLE_TO_LOCK_MEDIA              = 0xc0000175,
  NT_STATUS_UNABLE_TO_UNLOAD_MEDIA            = 0xc0000176,
  NT_STATUS_EOM_OVERFLOW                      = 0xc0000177,
  NT_STATUS_NO_MEDIA                          = 0xc0000178,
  NT_STATUS_NO_SUCH_MEMBER                    = 0xc000017a,
  NT_STATUS_INVALID_MEMBER                    = 0xc000017b,
  NT_STATUS_KEY_DELETED                       = 0xc000017c,
  NT_STATUS_NO_LOG_SPACE                      = 0xc000017d,
  NT_STATUS_TOO_MANY_SIDS                     = 0xc000017e,
  NT_STATUS_LM_CROSS_ENCRYPTION_REQUIRED      = 0xc000017f,
  NT_STATUS_KEY_HAS_CHILDREN                  = 0xc0000180,
  NT_STATUS_CHILD_MUST_BE_VOLATILE            = 0xc0000181,
  NT_STATUS_DEVICE_CONFIGURATION_ERROR        = 0xc0000182,
  NT_STATUS_DRIVER_INTERNAL_ERROR             = 0xc0000183,
  NT_STATUS_INVALID_DEVICE_STATE              = 0xc0000184,
  NT_STATUS_IO_DEVICE_ERROR                   = 0xc0000185,
  NT_STATUS_DEVICE_PROTOCOL_ERROR             = 0xc0000186,
  NT_STATUS_BACKUP_CONTROLLER                 = 0xc0000187,
  NT_STATUS_LOG_FILE_FULL                     = 0xc0000188,
  NT_STATUS_TOO_LATE                          = 0xc0000189,
  NT_STATUS_NO_TRUST_LSA_SECRET               = 0xc000018a,
  NT_STATUS_NO_TRUST_SAM_ACCOUNT              = 0xc000018b,
  NT_STATUS_TRUSTED_DOMAIN_FAILURE            = 0xc000018c,
  NT_STATUS_TRUSTED_RELATIONSHIP_FAILURE      = 0xc000018d,
  NT_STATUS_EVENTLOG_FILE_CORRUPT             = 0xc000018e,
  NT_STATUS_EVENTLOG_CANT_START               = 0xc000018f,
  NT_STATUS_TRUST_FAILURE                     = 0xc0000190,
  NT_STATUS_MUTANT_LIMIT_EXCEEDED             = 0xc0000191,
  NT_STATUS_NETLOGON_NOT_STARTED              = 0xc0000192,
  NT_STATUS_ACCOUNT_EXPIRED                   = 0xc0000193,
  NT_STATUS_POSSIBLE_DEADLOCK                 = 0xc0000194,
  NT_STATUS_NETWORK_CREDENTIAL_CONFLICT       = 0xc0000195,
  NT_STATUS_REMOTE_SESSION_LIMIT              = 0xc0000196,
  NT_STATUS_EVENTLOG_FILE_CHANGED             = 0xc0000197,
  NT_STATUS_NOLOGON_INTERDOMAIN_TRUST_ACCOUNT = 0xc0000198,
  NT_STATUS_NOLOGON_WORKSTATION_TRUST_ACCOUNT = 0xc0000199,
  NT_STATUS_NOLOGON_SERVER_TRUST_ACCOUNT      = 0xc000019a,
  NT_STATUS_DOMAIN_TRUST_INCONSISTENT         = 0xc000019b,
  NT_STATUS_FS_DRIVER_REQUIRED                = 0xc000019c,
  NT_STATUS_NO_USER_SESSION_KEY               = 0xc0000202,
  NT_STATUS_USER_SESSION_DELETED              = 0xc0000203,
  NT_STATUS_RESOURCE_LANG_NOT_FOUND           = 0xc0000204,
  NT_STATUS_INSUFF_SERVER_RESOURCES           = 0xc0000205,
  NT_STATUS_INVALID_BUFFER_SIZE               = 0xc0000206,
  NT_STATUS_INVALID_ADDRESS_COMPONENT         = 0xc0000207,
  NT_STATUS_INVALID_ADDRESS_WILDCARD          = 0xc0000208,
  NT_STATUS_TOO_MANY_ADDRESSES                = 0xc0000209,
  NT_STATUS_ADDRESS_ALREADY_EXISTS            = 0xc000020a,
  NT_STATUS_ADDRESS_CLOSED                    = 0xc000020b,
  NT_STATUS_CONNECTION_DISCONNECTED           = 0xc000020c,
  NT_STATUS_CONNECTION_RESET                  = 0xc000020d,
  NT_STATUS_TOO_MANY_NODES                    = 0xc000020e,
  NT_STATUS_TRANSACTION_ABORTED               = 0xc000020f,
  NT_STATUS_TRANSACTION_TIMED_OUT             = 0xc0000210,
  NT_STATUS_TRANSACTION_NO_RELEASE            = 0xc0000211,
  NT_STATUS_TRANSACTION_NO_MATCH              = 0xc0000212,
  NT_STATUS_TRANSACTION_RESPONDED             = 0xc0000213,
  NT_STATUS_TRANSACTION_INVALID_ID            = 0xc0000214,
  NT_STATUS_TRANSACTION_INVALID_TYPE          = 0xc0000215,
  NT_STATUS_NOT_SERVER_SESSION                = 0xc0000216,
  NT_STATUS_NOT_CLIENT_SESSION                = 0xc0000217,
  NT_STATUS_CANNOT_LOAD_REGISTRY_FILE         = 0xc0000218,
  NT_STATUS_DEBUG_ATTACH_FAILED               = 0xc0000219,
  NT_STATUS_SYSTEM_PROCESS_TERMINATED         = 0xc000021a,
  NT_STATUS_DATA_NOT_ACCEPTED                 = 0xc000021b,
  NT_STATUS_NO_BROWSER_SERVERS_FOUND          = 0xc000021c,
  NT_STATUS_VDM_HARD_ERROR                    = 0xc000021d,
  NT_STATUS_DRIVER_CANCEL_TIMEOUT             = 0xc000021e,
  NT_STATUS_REPLY_MESSAGE_MISMATCH            = 0xc000021f,
  NT_STATUS_MAPPED_ALIGNMENT                  = 0xc0000220,
  NT_STATUS_IMAGE_CHECKSUM_MISMATCH           = 0xc0000221,
  NT_STATUS_LOST_WRITEBEHIND_DATA             = 0xc0000222,
  NT_STATUS_CLIENT_SERVER_PARAMETERS_INVALID  = 0xc0000223,
  NT_STATUS_PASSWORD_MUST_CHANGE              = 0xc0000224,
  NT_STATUS_NOT_FOUND                         = 0xc0000225,
  NT_STATUS_NOT_TINY_STREAM                   = 0xc0000226,
  NT_STATUS_RECOVERY_FAILURE                  = 0xc0000227,
  NT_STATUS_STACK_OVERFLOW_READ               = 0xc0000228,
  NT_STATUS_FAIL_CHECK                        = 0xc0000229,
  NT_STATUS_DUPLICATE_OBJECTID                = 0xc000022a,
  NT_STATUS_OBJECTID_EXISTS                   = 0xc000022b,
  NT_STATUS_CONVERT_TO_LARGE                  = 0xc000022c,
  NT_STATUS_RETRY                             = 0xc000022d,
  NT_STATUS_FOUND_OUT_OF_SCOPE                = 0xc000022e,
  NT_STATUS_ALLOCATE_BUCKET                   = 0xc000022f,
  NT_STATUS_PROPSET_NOT_FOUND                 = 0xc0000230,
  NT_STATUS_MARSHALL_OVERFLOW                 = 0xc0000231,
  NT_STATUS_INVALID_VARIANT                   = 0xc0000232,
  NT_STATUS_DOMAIN_CONTROLLER_NOT_FOUND       = 0xc0000233,
  NT_STATUS_ACCOUNT_LOCKED_OUT                = 0xc0000234,
  NT_STATUS_HANDLE_NOT_CLOSABLE               = 0xc0000235,
  NT_STATUS_CONNECTION_REFUSED                = 0xc0000236,
  NT_STATUS_GRACEFUL_DISCONNECT               = 0xc0000237,
  NT_STATUS_ADDRESS_ALREADY_ASSOCIATED        = 0xc0000238,
  NT_STATUS_ADDRESS_NOT_ASSOCIATED            = 0xc0000239,
  NT_STATUS_CONNECTION_INVALID                = 0xc000023a,
  NT_STATUS_CONNECTION_ACTIVE                 = 0xc000023b,
  NT_STATUS_NETWORK_UNREACHABLE               = 0xc000023c,
  NT_STATUS_HOST_UNREACHABLE                  = 0xc000023d,
  NT_STATUS_PROTOCOL_UNREACHABLE              = 0xc000023e,
  NT_STATUS_PORT_UNREACHABLE                  = 0xc000023f,
  NT_STATUS_REQUEST_ABORTED                   = 0xc0000240,
  NT_STATUS_CONNECTION_ABORTED                = 0xc0000241,
  NT_STATUS_BAD_COMPRESSION_BUFFER            = 0xc0000242,
  NT_STATUS_USER_MAPPED_FILE                  = 0xc0000243,
  NT_STATUS_AUDIT_FAILED                      = 0xc0000244,
  NT_STATUS_TIMER_RESOLUTION_NOT_SET          = 0xc0000245,
  NT_STATUS_CONNECTION_COUNT_LIMIT            = 0xc0000246,
  NT_STATUS_LOGIN_TIME_RESTRICTION            = 0xc0000247,
  NT_STATUS_LOGIN_WKSTA_RESTRICTION           = 0xc0000248,
  NT_STATUS_IMAGE_MP_UP_MISMATCH              = 0xc0000249,
  NT_STATUS_INSUFFICIENT_LOGON_INFO           = 0xc0000250,
  NT_STATUS_BAD_DLL_ENTRYPOINT                = 0xc0000251,
  NT_STATUS_BAD_SERVICE_ENTRYPOINT            = 0xc0000252,
  NT_STATUS_LPC_REPLY_LOST                    = 0xc0000253,
  NT_STATUS_IP_ADDRESS_CONFLICT1              = 0xc0000254,
  NT_STATUS_IP_ADDRESS_CONFLICT2              = 0xc0000255,
  NT_STATUS_REGISTRY_QUOTA_LIMIT              = 0xc0000256,
  NT_STATUS_PATH_NOT_COVERED                  = 0xc0000257,
  NT_STATUS_NO_CALLBACK_ACTIVE                = 0xc0000258,
  NT_STATUS_LICENSE_QUOTA_EXCEEDED            = 0xc0000259,
  NT_STATUS_PWD_TOO_SHORT                     = 0xc000025a,
  NT_STATUS_PWD_TOO_RECENT                    = 0xc000025b,
  NT_STATUS_PWD_HISTORY_CONFLICT              = 0xc000025c,
  NT_STATUS_PLUGPLAY_NO_DEVICE                = 0xc000025e,
  NT_STATUS_UNSUPPORTED_COMPRESSION           = 0xc000025f,
  NT_STATUS_INVALID_HW_PROFILE                = 0xc0000260,
  NT_STATUS_INVALID_PLUGPLAY_DEVICE_PATH      = 0xc0000261,
  NT_STATUS_DRIVER_ORDINAL_NOT_FOUND          = 0xc0000262,
  NT_STATUS_DRIVER_ENTRYPOINT_NOT_FOUND       = 0xc0000263,
  NT_STATUS_RESOURCE_NOT_OWNED                = 0xc0000264,
  NT_STATUS_TOO_MANY_LINKS                    = 0xc0000265,
  NT_STATUS_QUOTA_LIST_INCONSISTENT           = 0xc0000266,
  NT_STATUS_FILE_IS_OFFLINE                   = 0xc0000267,
  NT_STATUS_DS_NO_MORE_RIDS                   = 0xc00002a8,
  NT_STATUS_NOT_A_REPARSE_POINT               = 0xc0000275,
  NT_STATUS_NO_SUCH_JOB                       = 0xc0000EDE
}

for i, v in pairs(status_codes) do
  status_names[v] = i
end


local NP_LIBRARY_NAME = "PIPE"

namedpipes =
{
  get_pipe_subpath = function( pipeName, writeToDebugLog )
    local status, pipeSubPath
    if not pipeName then return false end

    local _, _, match = pipeName:match( "^(\\+)(.-)\\pipe(\\.-)$" )
    if match then
      pipeSubPath = match
      status = true
      if writeToDebugLog then
        stdnse.debug2("%s: Converting %s to subpath %s", NP_LIBRARY_NAME, pipeName, match )
      end
    else
      status = false
      pipeSubPath = pipeName
    end

    return status, pipeSubPath
  end,


  make_pipe_name = function( hostnameOrIp, pipeSubPath )
    if pipeSubPath:sub(1,1) ~= "\\" then
      pipeSubPath = "\\" .. pipeSubPath
    end

    return string.format( "\\\\%s\\pipe%s", hostnameOrIp, pipeSubPath )
  end,


  named_pipe = {

    _smbstate = nil,
    _host = nil,
    _pipeSubPath = nil,
    _overrides = nil,
    name = nil,

    new = function(self,o)
      o = o or {}
      setmetatable(o, self)
      self.__index = self
      return o
    end,


    connect = function( self, host, pipeSubPath, overrides )

      stdnse.debug2("%s: connect() called with %s", NP_LIBRARY_NAME, tostring( pipeSubPath ) )
      self._overrides = overrides or {}
      self._host = host
      self._pipeSubPath = pipeSubPath
      if not host and not host.ip then return false, "host table is required" end
      if not pipeSubPath then return false, "pipeSubPath is required" end

      -- If we got a full pipe name, not a sub-path, fix it
      if ( pipeSubPath:match( "^\\\\(.-)$" ) ) then
        local status
        status, self._pipeSubPath = namedpipes.get_pipe_subpath( self._pipeSubPath, true )
        if ( not status ) then
          stdnse.debug1("%s: Attempt to connect to invalid pipe name: %s", NP_LIBRARY_NAME, tostring( pipeSubPath ) )
          return false, "Invalid pipe name"
        end
      end
      self.name = namedpipes.make_pipe_name( self._host.ip, self._pipeSubPath )

      stdnse.debug2("%s: Connecting to named pipe: %s", NP_LIBRARY_NAME, self.name )
      local errorMessage
      local bool_negotiate_protocol, bool_start_session, bool_disable_extended = true, true, false
      local _, fqpn_share = get_fqpn(host, "IPC$")
      local status, result = start_ex( self._host, bool_negotiate_protocol, bool_start_session,
        fqpn_share, self._pipeSubPath, bool_disable_extended, self._overrides )

      if status then
        self._smbstate = result
      else
        errorMessage = string.format( "Connection failed: %s", result )
        stdnse.debug2("%s: Connection to named pipe (%s) failed: %s",
          NP_LIBRARY_NAME, self.name, errorMessage )
      end

      return status, errorMessage, result
    end,


    disconnect = function( self )
      if ( self._smbstate ) then
        stdnse.debug2("%s: Disconnecting named pipe: %s", NP_LIBRARY_NAME, self.name )
        return stop( self._smbstate )
      else
        stdnse.debug2("%s: disconnect() called, but SMB connection is already closed: %s", NP_LIBRARY_NAME, self.name )
      end
    end,


    send = function( self, messageData )
      if not self._smbstate then
        stdnse.debug2("%s: send() called on closed pipe (%s)", NP_LIBRARY_NAME, self.name )
        return false, "Failed to send message on named pipe"
      end

      local offset = 0 -- offset is actually ignored for named pipes, but we'll define the argument for clarity
      local status, result, errorMessage

      status, result = write_file( self._smbstate, messageData, offset, self._overrides )

      -- if status is true, result is data that we don't need to pay attention to
      if not status then
        stdnse.debug2("%s: Write to named pipe (%s) failed: %s",
          NP_LIBRARY_NAME, self.name, result )
        errorMessage = "Failed to send message on named pipe", result
      end

      return status, errorMessage
    end,


    receive = function( self )
      if not self._smbstate then
        stdnse.debug2("%s: receive() called on closed pipe (%s)", NP_LIBRARY_NAME, self.name )
        return false, "Failed to read from named pipe"
      end

      local status, result, messageData
      -- Packet header values
      local offset = 0 -- offset is actually ignored for named pipes, but we'll define the argument for clarity
      local MAX_BYTES_PER_READ = 4096

      status, result = read_file( self._smbstate, offset, MAX_BYTES_PER_READ, self._overrides )

      if status and result.data then
        messageData = result.data
      else
        stdnse.debug2("%s: Read from named pipe (%s) failed: %s",
          NP_LIBRARY_NAME, self.name, result )
        return false, "Failed to read from named pipe", result
      end

      while (result["status"] == status_codes.NT_STATUS_BUFFER_OVERFLOW) do
        status, result = read_file( self._smbstate, offset, MAX_BYTES_PER_READ, self._overrides )

        if status and result.data then
          messageData = messageData .. result.data
        else
          stdnse.debug2("%s: Read additional data from named pipe (%s) failed: %s",
            NP_LIBRARY_NAME, self.name, result )
          return false, "Failed to read from named pipe", result
        end
      end

      return status, messageData
    end,
  }

}

filetype_codes =
{
  FILE_TYPE_DISK              = 0x00,
  FILE_TYPE_BYTE_MODE_PIPE    = 0x01,
  FILE_TYPE_MESSAGE_MODE_PIPE = 0x02,
  FILE_TYPE_PRINTER           = 0x03,
  FILE_TYPE_UNKNOWN           = 0xFF
}

for i, v in pairs(filetype_codes) do
  filetype_names[v] = i
end

return _ENV;
