---
-- Functions for the SSH-1 protocol. This module also contains functions for
-- formatting key fingerprints.
--
-- @author Sven Klemm <sven@c3d2.de>
-- @copyright Same as Nmap--See https://nmap.org/book/man-legal.html


local io = require "io"
local math = require "math"
local nmap = require "nmap"
local os = require "os"
local stdnse = require "stdnse"
local string = require "string"
local stringaux = require "stringaux"
local table = require "table"
local base64 = require "base64"
local openssl = stdnse.silent_require "openssl"
_ENV = stdnse.module("ssh1", stdnse.seeall)

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
  if #buffer < 4 then return nil end
  local payload_length = string.unpack( ">I4", buffer )
  local padding = 8 - payload_length % 8
  assert(payload_length)
  local total = 4+payload_length+padding;
  if total > #buffer then return nil end
  return total, total;
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
receive_ssh_packet = function( socket )
  local status, packet = socket:receive_buf(check_packet_length, true)
  return status, packet
end

local function unpack_with_padding(len_bytes, data, offset)
  local length, offset = string.unpack( ">I".. len_bytes, data, offset )
  return string.unpack( ">c" .. math.ceil( length / 8 ), data, offset )
end

--- Fetch an SSH-1 host key.
-- @param host Nmap host table.
-- @param port Nmap port table.
-- @return A table with the following fields: <code>exp</code>,
-- <code>mod</code>, <code>bits</code>, <code>key_type</code>,
-- <code>fp_input</code>, <code>full_key</code>, <code>algorithm</code>, and
-- <code>fingerprint</code>.
fetch_host_key = function(host, port)
  local socket = nmap.new_socket()
  local status, _

  status = socket:connect(host, port)
  if not status then return end
  -- fetch banner
  status = socket:receive_lines(1)
  if not status then socket:close(); return end
  -- send our banner
  status = socket:send("SSH-1.5-Nmap-SSH1-Hostkey\r\n")
  if not status then socket:close(); return end

  local data, packet_length, padding, offset
  status,data = receive_ssh_packet( socket )
  socket:close()
  if not status then return end

  packet_length, offset = string.unpack( ">I4", data )
  padding = 8 - packet_length % 8
  offset = offset + padding

  if padding + packet_length + 4 == #data then
    -- seems to be a proper SSH1 packet
    local msg_code,host_key_bits,exp,mod,length,fp_input
    msg_code, offset = string.unpack( ">B", data, offset )
    if msg_code == 2 then -- 2 => SSH_SMSG_PUBLIC_KEY
      -- ignore cookie and server key bits
      offset = offset + 8 + 4
      -- skip server key exponent and modulus
      _, offset = unpack_with_padding(2, data, offset)
      _, offset = unpack_with_padding(2, data, offset)

      host_key_bits, offset = string.unpack( ">I4", data, offset )
      exp, offset = unpack_with_padding(2, data, offset)
      exp = openssl.bignum_bin2bn( exp )
      mod, offset = unpack_with_padding(2, data, offset)
      mod = openssl.bignum_bin2bn( mod )

      fp_input = mod:tobin()..exp:tobin()

      return {exp=exp,mod=mod,bits=host_key_bits,key_type='rsa1',fp_input=fp_input,
              full_key=('%d %s %s'):format(host_key_bits, exp:todec(), mod:todec()),
              key=('%s %s'):format(exp:todec(), mod:todec()), algorithm="RSA1",
              fingerprint=openssl.md5(fp_input), fp_sha256=openssl.digest("sha256",fp_input)}
    end
  end
end

--- Format a key fingerprint in hexadecimal.
-- @param fingerprint Key fingerprint.
-- @param algorithm Key algorithm.
-- @param bits Key size in bits.
fingerprint_hex = function( fingerprint, algorithm, bits )
  fingerprint = stdnse.tohex(fingerprint,{separator=":",group=2})
  return ("%d %s (%s)"):format( bits, fingerprint, algorithm )
end

--- Format a key fingerprint in base64.
-- @param fingerprint Key fingerprint.
-- @param hash The hashing algorithm used
-- @param algorithm Key algorithm.
-- @param bits Key size in bits.
fingerprint_base64 = function( fingerprint, hash, algorithm, bits )
  fingerprint = base64.enc(fingerprint)
  return ("%d %s:%s (%s)"):format( bits, hash, fingerprint:match("[^=]+"), algorithm )
end

--- Format a key fingerprint in Bubble Babble.
-- @param fingerprint Key fingerprint.
-- @param algorithm Key algorithm.
-- @param bits Key size in bits.
fingerprint_bubblebabble = function( fingerprint, algorithm, bits )
  local vowels = {'a','e','i','o','u','y'}
  local consonants = {'b','c','d','f','g','h','k','l','m','n','p','r','s','t','v','z','x'}
  local s = "x"
  local seed = 1

  for i=1,#fingerprint+2,2 do
    local in1,in2,idx1,idx2,idx3,idx4,idx5
    if i < #fingerprint or #fingerprint / 2 % 2 ~= 0 then
      in1 = fingerprint:byte(i)
      idx1 = (((in1 >> 6) & 3) + seed) % 6 + 1
      idx2 = ((in1 >> 2) & 15) + 1
      idx3 = ((in1 & 3) + math.floor(seed/6)) % 6 + 1
      s = s .. vowels[idx1] .. consonants[idx2] .. vowels[idx3]
      if i < #fingerprint then
        in2 = fingerprint:byte(i+1)
        idx4 = ((in2 >> 4) & 15) + 1
        idx5 = (in2 & 15) + 1
        s = s .. consonants[idx4] .. '-' .. consonants[idx5]
        seed = (seed * 5 + in1 * 7 + in2) % 36
      end
    else
      idx1 = seed % 6 + 1
      idx2 = 16 + 1
      idx3 = math.floor(seed/6) + 1
      s = s .. vowels[idx1] .. consonants[idx2] .. vowels[idx3]
    end
  end
  s = s .. 'x'
  return ("%d %s (%s)"):format( bits, s, algorithm )
end

--- Format a key fingerprint into a visual ASCII art representation.
--
-- Ported from http://www.openbsd.org/cgi-bin/cvsweb/~checkout~/src/usr.bin/ssh/key.c.
-- @param fingerprint Key fingerprint.
-- @param algorithm Key algorithm.
-- @param bits Key size in bits.
fingerprint_visual = function( fingerprint, algorithm, bits )
  local i,j,field,characters,input,fieldsize_x,fieldsize_y,s
  fieldsize_x, fieldsize_y = 17, 9
  characters = {' ','.','o','+','=','*','B','O','X','@','%','&','#','/','^','S','E'}

  -- initialize drawing area
  field = {}
  for i=1,fieldsize_x do
    field[i]={}
    for j=1,fieldsize_y do field[i][j]=1 end
  end

  -- we start in the center and mark it
  local x, y = math.ceil(fieldsize_x/2), math.ceil(fieldsize_y/2)
  field[x][y] = #characters - 1;

  -- iterate over fingerprint
  for i=1,#fingerprint do
    input = fingerprint:byte(i)
    -- each byte conveys four 2-bit move commands
    for j=1,4 do
      if (input & 1) == 1 then x = x + 1 else x = x - 1 end
      if (input & 2) == 2 then y = y + 1 else y = y - 1 end

      x = math.max(x,1); x = math.min(x,fieldsize_x)
      y = math.max(y,1); y = math.min(y,fieldsize_y)

      if field[x][y] < #characters - 2 then
        field[x][y] = field[x][y] + 1
      end
      input = input >> 2
    end
  end

  -- mark end point
  field[x][y] = #characters;

  -- build output
  s = ('\n+--[%4s %4d]----+\n'):format( algorithm, bits )
  for i=1,fieldsize_y do
    s = s .. '|'
    for j=1,fieldsize_x do s = s .. characters[ field[j][i] ] end
    s = s .. '|\n'
  end
  s = s .. '+-----------------+\n'
  return s
end

-- A lazy parsing function for known_hosts_file.
-- The script checks for the known_hosts file in this order:
--
-- (1) If known_hosts is specified in a script arg, use that. If turned
-- off (false), then don't do any known_hosts checking.
-- (2) Look at ~/.ssh/config to see if user known_hosts is in an
-- alternate location*. Look for "UserKnownHostsFile". If
-- UserKnownHostsFile is specified, open that known_hosts.
-- (3) Otherwise, open ~/.ssh/known_hosts.
parse_known_hosts_file = function(path)
    local common_paths = {}
    local f, knownhostspath

    if path and io.open(path) then
        knownhostspath = path
    end

    if not knownhostspath then
        for l in io.lines(os.getenv("HOME") .. "/.ssh/config") do
            if l and string.find(l, "UserKnownHostsFile") then
                knownhostspath = string.match(l, "UserKnownHostsFile%s(.*)")
                if string.sub(knownhostspath,1,1)=="~" then
                    knownhostspath = os.getenv("HOME") .. string.sub(knownhostspath, 2)
                end
            end
        end
    end

    if not knownhostspath then
        knownhostspath = os.getenv("HOME") .."/.ssh/known_hosts"
    end

    if not knownhostspath then
        return
    end

    local known_host_entries = {}
    local lnumber = 0

    for l in io.lines(knownhostspath) do
        lnumber = lnumber + 1
        if l and string.sub(l, 1, 1) ~= "#" then
            local parts = stringaux.strsplit(" ", l)
            table.insert(known_host_entries, {entry=parts, linenumber=lnumber})
        end
    end
    return known_host_entries
end

return _ENV;
