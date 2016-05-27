---
-- Functions for the SSH-2 protocol.
--
-- @author Sven Klemm <sven@c3d2.de>
-- @copyright Same as Nmap--See https://nmap.org/book/man-legal.html

local base64 = require "base64"
local bin = require "bin"
local nmap = require "nmap"
local stdnse = require "stdnse"
local openssl = stdnse.silent_require "openssl"
_ENV = stdnse.module("ssh2", stdnse.seeall)

-- table holding transport layer functions
transport = {}

-- table of SSH-2 constants
local SSH2

--- Retrieve the size of the packet that is being received
--  and checks if it is fully received
--
--  This function is very similar to the function generated
--  with match.numbytes(num) function, except that this one
--  will check for the number of bytes on-the-fly, based on
--  the written on the SSH packet.
--
--  @param buffer The receive buffer
--  @return packet_length, packet_length or nil
--  the return is similar to the lua function string:find()
check_packet_length = function( buffer )
  if #buffer < 4 then return nil end -- not enough data in buffer for int
  local packet_length, offset
  offset, packet_length = bin.unpack( ">I", buffer )
  assert(packet_length)
  if packet_length + 4 > buffer:len() then return nil end
  return packet_length+4, packet_length+4
end

--- Receives a complete SSH packet, even if fragmented
--
--  This function is an abstraction layer to deal with
--  checking the packet size to know if there is any more
--  data to receive.
--
--  @param socket The socket used to receive the data
--  @return status True or false
--  @return packet The packet received
transport.receive_packet = function( socket )
  local status, packet = socket:receive_buf(check_packet_length, true)
  return status, packet
end

--- Pack a multiprecision integer for sending.
-- @param bn <code>openssl</code> bignum.
-- @return Packed multiprecision integer.
transport.pack_mpint = function( bn )
  local bytes, packed
  bytes = bn:num_bytes()
  packed = bn:tobin()
  if bytes % 8 == 0 then
    bytes = bytes + 1
    packed = '\0' .. packed
  end
  return bin.pack( ">IA", bytes, packed )
end

--- Build an SSH-2 packet.
-- @param payload Payload of the packet.
-- @return Packet to send on the wire.
transport.build = function( payload )
  local packet_length, padding_length
  padding_length = 8 - ( (payload:len() + 1 + 4 ) % 8 )
  -- padding length must be at least 4 bytes and is a multiple
  -- of the cipher block size or 8
  if padding_length < 4 then
    padding_length = padding_length + 8
  end
  packet_length = payload:len() + padding_length + 1
  return bin.pack( ">IcAA", packet_length, padding_length, payload, openssl.rand_pseudo_bytes( padding_length ) )
end

--- Extract the payload from a received SSH-2 packet.
-- @param packet Received SSH-2 packet.
-- @return Payload of the SSH-2 packet.
transport.payload = function( packet )
  local packet_length, padding_length, payload_length, payload, offset
  offset, packet_length = bin.unpack( ">I", packet )
  packet = packet:sub(offset);
  offset, padding_length = bin.unpack( ">c", packet )
  assert(packet_length and padding_length)
  payload_length = packet_length - padding_length - 1
  if packet_length ~= packet:len() then
    stdnse.debug1("SSH-2 packet doesn't match length: payload_length is %d but total length is only %d.", packet_length, packet:len())
    return nil
  end
  offset, payload = bin.unpack( ">A" .. payload_length, packet, offset )
  return payload
end

--- Build a <code>kexdh_init</code> packet.
transport.kexdh_init = function( e )
  return bin.pack( ">cA", SSH2.SSH_MSG_KEXDH_INIT, transport.pack_mpint( e ) )
end

--- Build a <code>kexdh_gex_init</code> packet.
transport.kexdh_gex_init = function( e )
  return bin.pack( ">cA", SSH2.SSH_MSG_KEX_DH_GEX_INIT, transport.pack_mpint( e ) )
end

--- Build a <code>kex_init</code> packet.
transport.kex_init = function( options )
  options = options or {}
  local cookie = options['cookie'] or openssl.rand_bytes( 16 )
  local kex_algorithms = options['kex_algorithms'] or "diffie-hellman-group1-sha1"
  local host_key_algorithms = options['host_key_algorithms'] or "ssh-dss,ssh-rsa"
  local encryption_algorithms = options['encryption_algorithms'] or "aes128-cbc,3des-cbc,blowfish-cbc,aes192-cbc,aes256-cbc,aes128-ctr,aes192-ctr,aes256-ctr"
  local mac_algorithms = options['mac_algorithms'] or "hmac-md5,hmac-sha1,hmac-ripemd160"
  local compression_algorithms = options['compression_algorithms'] or "none"
  local languages = options['languages'] or ""

  local payload = bin.pack( ">cAaa", SSH2.SSH_MSG_KEXINIT, cookie, kex_algorithms, host_key_algorithms )
  .. bin.pack( ">aa", encryption_algorithms, encryption_algorithms )
  .. bin.pack( ">aa", mac_algorithms, mac_algorithms )
  .. bin.pack( ">aa", compression_algorithms, compression_algorithms )
  .. bin.pack( ">aa", languages, languages )
  .. bin.pack( ">cI", 0, 0 )

  return payload
end

--- Parse a <code>kexinit</code> package.
--
-- Returns an empty table in case of an error
transport.parse_kex_init = function( payload )
  local _, offset, msg_code, parsed, fields, fieldname
  parsed = {}

  -- check for proper msg code
  offset, msg_code = bin.unpack( ">c", payload )
  if msg_code ~= SSH2.SSH_MSG_KEXINIT then return {} end

  offset, parsed.cookie = bin.unpack( ">A16", payload, offset )

  fields = {'kex_algorithms','server_host_key_algorithms',
    'encryption_algorithms_client_to_server','encryption_algorithms_server_to_client',
    'mac_algorithms_client_to_server','mac_algorithms_server_to_client',
    'compression_algorithms_client_to_server','compression_algorithms_server_to_client',
    'languages_client_to_server','languages_server_to_client'}
  for _, fieldname in pairs( fields ) do
    offset, parsed[fieldname] = bin.unpack( ">a", payload, offset )
  end

  return parsed
end


--- Fetch an SSH-2 host key.
-- @param host Nmap host table.
-- @param port Nmap port table.
-- @param key_type key type to fetch.
-- @return A table with the following fields: <code>key</code>,
-- <code>key_type</code>, <code>fp_input</code>, <code>bits</code>,
-- <code>full_key</code>, <code>algorithm</code>, and <code>fingerprint</code>.
fetch_host_key = function( host, port, key_type )
  local socket = nmap.new_socket()
  local status

  -- oakley group 2 prime taken from rfc 2409
  local prime2 = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1\z
    29024E088A67CC74020BBEA63B139B22514A08798E3404DD\z
    EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245\z
    E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED\z
    EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381\z
    FFFFFFFFFFFFFFFF"
  -- oakley group 14 prime taken from rfc 3526
  local prime14 = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1\z
    29024E088A67CC74020BBEA63B139B22514A08798E3404DD\z
    EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245\z
    E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED\z
    EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D\z
    C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F\z
    83655D23DCA3AD961C62F356208552BB9ED529077096966D\z
    670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B\z
    E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9\z
    DE2BCBF6955817183995497CEA956AE515D2261898FA0510\z
    15728E5A8AACAA68FFFFFFFFFFFFFFFF"


  status = socket:connect(host, port)
  if not status then return end
  -- fetch banner
  status = socket:receive_lines(1)
  if not status then socket:close(); return end
  -- send our banner
  status = socket:send("SSH-2.0-Nmap-SSH2-Hostkey\r\n")
  if not status then socket:close(); return end

  local packet = transport.build( transport.kex_init( {
        host_key_algorithms=key_type,
        kex_algorithms="diffie-hellman-group1-sha1,diffie-hellman-group14-sha1,diffie-hellman-group-exchange-sha1,diffie-hellman-group-exchange-sha256",
    } ) )
  status = socket:send( packet )
  if not status then socket:close(); return end

  local kex_init
  status, kex_init = transport.receive_packet( socket )
  if not status then socket:close(); return end
  kex_init = transport.parse_kex_init( transport.payload( kex_init ) )

  if not tostring(kex_init.server_host_key_algorithms):find( key_type, 1, true ) then
    -- server does not support host key type
    stdnse.debug2("Hostkey type '%s' not supported by server.", key_type )
    return
  end

  local kex_algs = tostring( kex_init.kex_algorithms )
  local kexdh_gex_used = false
  local prime, q, gen
  if kex_algs:find("diffie-hellman-group1-", 1, true) then
    prime = prime2
    q = 1024
    gen = "2"
  elseif kex_algs:find("diffie-hellman-group14-", 1, true) then
    prime = prime14
    q = 2048
    gen = "2"
  elseif kex_algs:find("diffie-hellman-group-exchange-", 1, true) then
    local min, n, max
    min = 1024
    n = 1024
    max = 8192
    packet = transport.build( bin.pack( ">cIII", SSH2.SSH_MSG_KEX_DH_GEX_REQUEST, min, n, max ) )
    status = socket:send( packet )
    if not status then socket:close(); return end

    local gex_reply
    status, gex_reply = transport.receive_packet( socket )
    if not status then socket:close(); return end
    gex_reply = transport.payload( gex_reply )
    -- check for proper msg code
    if gex_reply:byte(1) ~= SSH2.SSH_MSG_KEX_DH_GEX_GROUP then
      socket:close()
      return
    end
    local _
    _, _, prime, gen = bin.unpack( ">caa", gex_reply )

    prime = openssl.bignum_bin2bn( prime ):tohex()
    q = 1024
    gen = openssl.bignum_bin2bn( gen ):todec()

    kexdh_gex_used = true
  else
    stdnse.debug2("No shared KEX methods supported by server")
    return
  end

  local e, g, x, p
  -- e = g^x mod p
  g = openssl.bignum_dec2bn( gen )
  p = openssl.bignum_hex2bn( prime )
  x = openssl.bignum_pseudo_rand( q )
  e = openssl.bignum_mod_exp( g, x, p )

  -- if kexdh_gex_used then
  --   e = openssl.bignum_pseudo_rand( 1024 )
  -- end

  local payload
  if kexdh_gex_used == true then
    payload = transport.kexdh_gex_init( e )
  else
    payload = transport.kexdh_init( e )
  end

  packet = transport.build( payload )
  status = socket:send( packet )
  if not status then socket:close(); return end

  local kexdh_reply
  status, kexdh_reply = transport.receive_packet( socket )
  if not status then socket:close(); return end
  kexdh_reply = transport.payload( kexdh_reply )
  -- check for proper msg code
  local msg_code = kexdh_reply:byte(1)

  if ( kexdh_gex_used == true and msg_code ~= SSH2.SSH_MSG_KEX_DH_GEX_REPLY )
    or ( kexdh_gex_used == false and msg_code ~= SSH2.SSH_MSG_KEXDH_REPLY )
  then
    socket:close()
    return
  end

  local _,public_host_key,bits,algorithm
  _, _, public_host_key = bin.unpack( ">ca", kexdh_reply )

  if key_type == 'ssh-dss' then
    algorithm = "DSA"
    local p
    _, _, p = bin.unpack( ">aa", public_host_key )
    bits = openssl.bignum_bin2bn( p ):num_bits()
  elseif key_type == 'ssh-rsa' then
    algorithm = "RSA"
    local n
    _, _, _, n = bin.unpack( ">aaa", public_host_key )
    bits = openssl.bignum_bin2bn( n ):num_bits()
  elseif key_type == 'ecdsa-sha2-nistp256' then
    algorithm = "ECDSA"
    bits = "256"
  elseif key_type == 'ecdsa-sha2-nistp384' then
    algorithm = "ECDSA"
    bits = "384"
  elseif key_type == 'ecdsa-sha2-nistp521' then
    algorithm = "ECDSA"
    bits = "521"
  else
    stdnse.debug1("Unsupported key type: %s", key_type )
  end

  socket:close()
  return { key=base64.enc(public_host_key), key_type=key_type, fp_input=public_host_key, bits=bits,
           full_key=('%s %s'):format(key_type,base64.enc(public_host_key)),
           algorithm=algorithm, fingerprint=openssl.md5(public_host_key) }
end

-- constants

SSH2 = {
  SSH_MSG_DISCONNECT = 1,
  SSH_MSG_IGNORE = 2,
  SSH_MSG_UNIMPLEMENTED = 3,
  SSH_MSG_DEBUG = 4,
  SSH_MSG_SERVICE_REQUEST = 5,
  SSH_MSG_SERVICE_ACCEPT = 6,
  SSH_MSG_KEXINIT = 20,
  SSH_MSG_NEWKEYS = 21,
  SSH_MSG_KEXDH_INIT = 30,
  SSH_MSG_KEXDH_REPLY = 31,

  SSH_MSG_KEX_DH_GEX_REQUEST_OLD = 30,
  SSH_MSG_KEX_DH_GEX_REQUEST = 34,
  SSH_MSG_KEX_DH_GEX_GROUP = 31,
  SSH_MSG_KEX_DH_GEX_INIT = 32,
  SSH_MSG_KEX_DH_GEX_REPLY = 33,
}


return _ENV;
