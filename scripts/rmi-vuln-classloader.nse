local bin = require "bin"
local rmi = require "rmi"
local shortport = require "shortport"
local string = require "string"
local vulns = require "vulns"

description = [[
Tests whether Java rmiregistry allows class loading.  The default
configuration of rmiregistry allows loading classes from remote URLs,
which can lead to remote code execution. The vendor (Oracle/Sun)
classifies this as a design feature.


Based on original Metasploit module by mihi.

References:
* https://github.com/rapid7/metasploit-framework/blob/master/modules/exploits/multi/misc/java_rmi_server.rb
]];

---
-- @usage
-- nmap --script=rmi-vuln-classloader -p 1099 <target>
--
-- @output
-- PORT     STATE SERVICE
-- 1099/tcp open  rmiregistry
-- | rmi-vuln:
-- |   VULNERABLE:
-- |   RMI registry default configuration remote code execution vulnerability
-- |     State: VULNERABLE
-- |     Description:
-- |               Default configuration of RMI registry allows loading classes from remote URLs which can lead to remote code executeion.
-- |
-- |     References:
-- |_      https://github.com/rapid7/metasploit-framework/blob/master/modules/exploits/multi/misc/java_rmi_server.rb

author = "Aleksandar Nikolic";
license = "Same as Nmap--See https://nmap.org/book/man-legal.html";
categories = {
  "intrusive",
  "vuln"
};



portrule = shortport.port_or_service({
    1099
  }, {
    "rmiregistry"
  });

action = function (host, port)
  local registry = rmi.Registry:new(host, port);
  registry:_handshake();
  local rmiArgs = rmi.Arguments:new();
  local argsRaw = "75" ..  --TC_ARRAY
   "72" ..  -- TC_CLASSDESC
   "0018" ..  -- string len
   "5B4C6A6176612E726D692E7365727665722E4F626A49443B" ..  -- class name "[Ljava.rmi.server.ObjID;"
   "871300B8D02C647E" ..  -- serial id
   "02" ..  -- FLAGS (serializable)
   "0000" ..  -- FIELD COUNT
   "70787000000000" ..  --TC_NULL TC_BLOCKEND TC_NULL
   "77080000000000000000" ..  -- TC_BLOCKDATA
   "73" ..  -- TC_OBJECT
   "72" ..  -- TC_CLASSDESC
   "0005" ..  -- string len
   "64756D6D79" ..  -- class name "dummy"
   "A16544BA26F9C2F4" ..  -- serial id
   "02" ..  -- FLAGS (serializable)
   "0000" ..  -- FIELD COUNT
   "74" ..  -- TC_STRING
   "0010" ..  -- string len
   "66696C653A2E2F64756D6D792E6A6172" ..  -- annotation "file:./dummy.jar"
   "78" ..  -- TC_ENDBLOCKDATA
   "70" ..  -- TC_NULL
   "7701000A"; -- TC_BLOCKDATA
  local rmi_vuln = {
    title = "RMI registry default configuration remote code execution vulnerability",

    description = [[
Default configuration of RMI registry allows loading classes from remote URLs which can lead to remote code execution.
]],
    references = {
      'https://github.com/rapid7/metasploit-framework/blob/master/modules/exploits/multi/misc/java_rmi_server.rb',
    },
    exploit_results = {},
  };

  local report = vulns.Report:new(SCRIPT_NAME, host, port);
  rmi_vuln.state = vulns.STATE.NOT_VULN;

  rmiArgs:addRaw(bin.pack("H", argsRaw));

  -- reference: java/rmi/dgc/DGCImpl_Stub.java and java/rmi/dgc/DGCImpl_Skel.java
  -- we are calling DGC's (its objectId is 2) method with opnum 0
  -- DCG's hashcode is f6b6898d8bf28643 hex or -669196253586618813 dec
  local status, j_array = registry.out:writeMethodCall(registry.out, 2, "f6b6898d8bf28643", 0, rmiArgs);
  local status, retByte = registry.out.dis:readByte();
  if not status then
    return false, "No return data received from server";
  end

  if 0x51 ~= retByte then
    -- 0x51 : Returndata
    return false, "No return data received from server";
  end
  local data = registry.out.dis.bReader.readBuffer;

  if string.find(data, "RMI class loader disabled") == nil then
    rmi_vuln.state = vulns.STATE.VULN;
    return report:make_output(rmi_vuln);
  end

  return report:make_output(rmi_vuln);
end;
