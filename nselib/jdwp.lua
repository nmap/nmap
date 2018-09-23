--- JDWP (Java Debug Wire Protocol) library implementing a set of commands needed to
--  use remote debugging port and inject java bytecode.
--
-- There are two basic packet types in JDWP protocol.
-- Command packet and reply packet. Command packets are sent by
-- a debugger to a remote port which replies with a reply packet.
--
-- Simple handshake is needed to start the communication.
-- The debugger sends a "JDWP-Handshake" string and gets the same as a reply.
-- Each (command and reply packet) has an id field since communication can be asynchronous.
-- Packet id can be monotonicaly increasing.
-- Although communication can be asynchronous, it is not (at least in my tests) so the same
-- packet id can be used for all communication.
--
-- To start the connection, script should call <code>jdwp.connect()</code> which returns success
-- status and a socket. All other protocol functions require a socket as their first parameter.
--
-- Example of initiating connection:
-- <code>
-- local status,socket = jdwp.connect(host,port)
-- if not status then
--   stdnse.debug1("error, %s",socket)
-- end
-- local version_info
-- status, version_info = jdwp.getVersion(socket,0)
-- </code>
--
-- References:
-- * http://docs.oracle.com/javase/6/docs/technotes/guides/jpda/jdwp-spec.html
--
--@copyright Same as Nmap--See https://nmap.org/book/man-legal.html
--@author Aleksandar Nikolic
--
-- Version 0.1
-- Created 08/10/2012 - v0.1 - Created by Aleksandar Nikolic

local stdnse = require "stdnse"
local string = require "string"
local table = require "table"
local nmap = require "nmap"

_ENV = stdnse.module("jdwp", stdnse.seeall)

-- JDWP protocol specific constants
JDWP_CONSTANTS = {
  handshake = "JDWP-Handshake" -- Connection initialization handshake
}

-- List of error codes from:
-- http://docs.oracle.com/javase/1.5.0/docs/guide/jpda/jdwp/jdwp-protocol.html#JDWP_Error
ERROR_CODES = {
  [0] = "NONE No error has occurred.",
  [10] = "INVALID_THREAD Passed thread is null, is not a valid thread or has exited.",
  [11] = "INVALID_THREAD_GROUP Thread group invalid.",
  [12] = "INVALID_PRIORITY Invalid priority.",
  [13] = "THREAD_NOT_SUSPENDED If the specified thread has not been suspended by an event.",
  [14] = "THREAD_SUSPENDED Thread already suspended.",
  [20] = "INVALID_OBJECT If this reference type has been unloaded and garbage collected.",
  [21] = "INVALID_CLASS Invalid class.",
  [22] = "CLASS_NOT_PREPARED Class has been loaded but not yet prepared.",
  [23] = "INVALID_METHODID Invalid method.",
  [24] = "INVALID_LOCATION Invalid location.",
  [25] = "INVALID_FIELDID Invalid field.",
  [30] = "INVALID_FRAMEID Invalid jframeID.",
  [31] = "NO_MORE_FRAMES There are no more Java or JNI frames on the call stack.",
  [32] = "OPAQUE_FRAME Information about the frame is not available.",
  [33] = "NOT_CURRENT_FRAME Operation can only be performed on current frame.",
  [34] = "TYPE_MISMATCH The variable is not an appropriate type for the function used.",
  [35] = "INVALID_SLOT Invalid slot.",
  [40] = "DUPLICATE Item already set.",
  [41] = "NOT_FOUND Desired element not found.",
  [50] = "INVALID_MONITOR Invalid monitor.",
  [51] = "NOT_MONITOR_OWNER This thread doesn't own the monitor.",
  [52] = "INTERRUPT The call has been interrupted before completion.",
  [60] = "INVALID_CLASS_FORMAT The virtual machine attempted to read a class file and determined that the file is malformed or otherwise cannot be interpreted as a class file.",
  [61] = "CIRCULAR_CLASS_DEFINITION A circularity has been detected while initializing a class.",
  [62] = "FAILS_VERIFICATION The verifier detected that a class file, though well formed, contained some sort of internal inconsistency or security problem.",
  [63] = "ADD_METHOD_NOT_IMPLEMENTED Adding methods has not been implemented.",
  [64] = "SCHEMA_CHANGE_NOT_IMPLEMENTED Schema change has not been implemented.",
  [65] = "INVALID_TYPESTATE The state of the thread has been modified, and is now inconsistent.",
  [66] = "HIERARCHY_CHANGE_NOT_IMPLEMENTED A direct superclass is different for the new class version, or the set of directly implemented interfaces is different and canUnrestrictedlyRedefineClasses is false.",
  [67] = "DELETE_METHOD_NOT_IMPLEMENTED The new class version does not declare a method declared in the old class version and canUnrestrictedlyRedefineClasses is false.",
  [68] = "UNSUPPORTED_VERSION A class file has a version number not supported by this VM.",
  [69] = "NAMES_DONT_MATCH The class name defined in the new class file is different from the name in the old class object.",
  [70] = "CLASS_MODIFIERS_CHANGE_NOT_IMPLEMENTED The new class version has different modifiers and and canUnrestrictedlyRedefineClasses is false.",
  [71] = "METHOD_MODIFIERS_CHANGE_NOT_IMPLEMENTED A method in the new class version has different modifiers than its counterpart in the old class version and and canUnrestrictedlyRedefineClasses is false.",
  [99] = "NOT_IMPLEMENTED The functionality is not implemented in this virtual machine.",
  [100] = "NULL_POINTER Invalid pointer.",
  [101] = "ABSENT_INFORMATION Desired information is not available.",
  [102] = "INVALID_EVENT_TYPE The specified event type id is not recognized.",
  [103] = "ILLEGAL_ARGUMENT Illegal argument.",
  [110] = "OUT_OF_MEMORY The function needed to allocate memory and no more memory was available for allocation.",
  [111] = "ACCESS_DENIED Debugging has not been enabled in this virtual machine. JVMDI cannot be used.",
  [112] = "VM_DEAD The virtual machine is not running.",
  [113] = "INTERNAL An unexpected internal error has occurred.",
  [115] = "UNATTACHED_THREAD The thread being used to call this function is not attached to the virtual machine. Calls must be made from attached threads.",
  [500] = "INVALID_TAG object type id or class tag.",
  [502] = "ALREADY_INVOKING Previous invoke not complete.",
  [503] = "INVALID_INDEX Index is invalid.",
  [504] = "INVALID_LENGTH The length is invalid.",
  [506] = "INVALID_STRING The string is invalid.",
  [507] = "INVALID_CLASS_LOADER The class loader is invalid.",
  [508] = "INVALID_ARRAY The array is invalid.",
  [509] = "TRANSPORT_LOAD Unable to load the transport.",
  [510] = "TRANSPORT_INIT Unable to initialize the transport.",
  [511] = "NATIVE_METHOD",
  [512] = "INVALID_COUNT The count is invalid."
}

-- JDWP protocol Command packet as described at
-- http://docs.oracle.com/javase/6/docs/technotes/guides/jpda/jdwp-spec.html
-- Each command packet has a Command Set number, Command Number and data required
-- for that command.
JDWPCommandPacket = {

  new = function(self,id,command_set,command, data)
    local o = {
      id = id,
      flags = 0, -- current specification has no flags defined for Command Packets
      command_set = command_set,
      command = command,
      data = data
    }
    setmetatable(o, self)
    self.__index = self
    return o
  end,

  -- Packs command packet as a string od bytes, ready to be sent
  -- to the target debuggee.
  pack = function(self)
    local data = self.data or ""
    return string.pack(">I4I4BBB",
      11 + #data, -- length - minimal header is 11 bytes
      self.id,
      0, -- flag
      self.command_set,
      self.command)
      .. data
  end
}

-- JDWP protocol Reply packet as described at
-- http://docs.oracle.com/javase/6/docs/technotes/guides/jpda/jdwp-spec.html
-- Reply packets are recognized by 0x80 in flag field.
JDWPReplyPacket = {

  new = function(self,length,id,error_code,data)
    local o = {
      length = length,
      id = id,
      flags = 0x80, -- no other flag is currently specified in the specification
      error_code = error_code, -- see ERROR_CODES table
      data = data -- reply data, contents depend on the command
    }
    setmetatable(o, self)
    self.__index = self
    return o
  end,

  -- Parses the reply into JDWPReplyPacket table.
  parse_reply = function(self,reply_packet)
    local length, id, flags, error_code, pos = string.unpack(">I4I4BI2", reply_packet)
    local data = string.sub(reply_packet, pos)
    if flags == 0x80 then
      return true, JDWPReplyPacket:new(length,id,error_code,data)
    end
    stdnse.debug2("JDWP error parsing reply. Wrong reply packet flag. Raw data: %s", stdnse.tohex(reply_packet))
    return false, "JDWP error parsing reply."
  end

}

--- Negotiates the initial debugger-debuggee handshake.
--
--@param host Host to connect to.
--@param port Port to connect to.
--@return (status,socket) If status is false, socket is error message, otherwise socket is
-- a newly created socket with initial handshake finished.
function connect(host,port)
  local status, result,err
  local socket = nmap.new_socket("tcp")
  socket:set_timeout(10000)
  local status, err = socket:connect(host, port)
  if not status then
    stdnse.debug2("JDWP could not connect: %s",err)
    return status, err
  end
  status, err = socket:send(JDWP_CONSTANTS.handshake)
  if not status then
    stdnse.debug2("JDWP could not send handshake: %s",err)
    return status, err
  end
  status, result = socket:receive()
  if not status then
    stdnse.debug2("JDWP could not receive handshake: %s",result)
    return status, result
  end
  if result == JDWP_CONSTANTS.handshake then
    stdnse.debug1("JDWP handshake successful.")
    return true, socket
  end
  return false, "JDWP handshake unsuccessful."
end

--- Helper function to pack regular string into UTF-8 string.
--
--@param data String to pack into UTF-8.
--@return utf8_string UTF-8 packed string. Four bytes length followed by the string its self.
function toUTF8(data)
  local utf8_string = string.pack(">s4", data)
  return utf8_string
end

--- Helper function to read all Reply packed data which might be fragmented
--  over multiple packets.
--
--@param socket Socket to receive from.
--@return (status,data) If status is false, error string is returned, else data contains read ReplyPacket bytes.
function receive_all(socket)
  local status, result = socket:receive_bytes(4)
  if not status then
    return false,result
  end
  local data = result
  local expected_length = string.unpack(">I4",result) -- first 4 bytes of packet data is the ReplyPacket length
  while expected_length > #data do -- read until we get all the ReplyPacket data
    status,result = socket:receive_bytes(expected_length - #data)
    if not status then
      return true, data -- if something is wrong, return partial data
    end
    data = data .. result
  end
  return true,data
end

--- Helper function to extract ascii string from UTF-8
--
-- Written in this way so it can be used interchangeably with bin\.unpack().
--
--@param data Data from which to extract the string.
--@param pos  Offset into data string where to begin.
--@return (pos,ascii_string) Returns position where the string extraction ended and actual ascii string.
local function extract_string(data,pos)
  local string_size
  if pos > #data then
    stdnse.debug2("JDWP extract_string() position higher than data length, probably incomplete data received.")
    return pos, nil
  end
  string_size, pos = string.unpack(">I4",data,pos)
  local ascii_string = string.sub(data,pos,pos+string_size)
  local new_pos = pos+string_size
  return new_pos,ascii_string
end


--- Helper function that sends the Command packet and parses the reply.
--
--@param socket Socket to use to send the command.
--@param command <code>JDWPCommandPacket</code> to send.
--@return (status,data) If status is false, data contains specified error code message. If true, data contains data from the reply.
function executeCommand(socket,command)
  socket:send(command:pack())
  local status, result = receive_all(socket)
  if not status then
    return false, "JDWP executeCommand() didn't get a reply."
  end
  local reply_packet
  status, reply_packet = JDWPReplyPacket:parse_reply(result)
  if not status then
    return false, reply_packet
  end
  if not (reply_packet.error_code == 0) then -- we have a packet with error , error code 0 means no error occurred
    return false, ERROR_CODES[reply_packet.error_code]
  end
  local data = reply_packet.data
  return true, data
end

--- VirtualMachine Command Set (1)
--  Commands targeted at the debuggee virtual machine.
--  http://docs.oracle.com/javase/1.5.0/docs/guide/jpda/jdwp/jdwp-protocol.html#JDWP_VirtualMachine


--- Version Command (1)
--  Returns the JDWP version implemented by the target VM as a table.
--
--  Returns a table with following values:
--  * 'description' Debugger vm verbose description.
--  * 'jdwpMajor'   Number representing major JDWP version.
--  * 'jdwpMinor'   Number representing minor JDWP version.
--  * 'vmVersion'   String representing version of the debuggee VM.
--  * 'vmName'      Name of the debuggee VM.
--  http://docs.oracle.com/javase/1.5.0/docs/guide/jpda/jdwp/jdwp-protocol.html#JDWP_VirtualMachine_Version
--
--@param socket Socket to use to send the command.
--@param id     Packet id.
--@return (status,version_info) If status is false, version_info is an error string, else it contains remote VM version info.
function getVersion(socket,id)
  local command = JDWPCommandPacket:new(id,1,1,nil) -- Version Command (1)
  local status, data = executeCommand(socket,command)
  if not status then
    stdnse.debug2("JDWP getVersion() error : %s",data)
    return false,data
  end
  -- parse data
  local version_info = {description = "",
    jdwpMajor = 0,
    jdwpMinor = 0,
    vmVersion = "",
    vmName = ""}
  local vmVersionSize
  local pos
  pos, version_info.description = extract_string(data,0)
  version_info.jdwpMajor, version_info.jdwpMinor, pos = string.unpack(">i4i4", data, pos)
  pos, version_info.vmVersion = extract_string(data,pos)
  pos, version_info.vmName = extract_string(data,pos)
  return true, version_info
end

--- Classes by Signature command (2)
--  Returns reference types for all the classes loaded by the target VM which match the given signature.
--
--  Given the class signature (like "Ljava/lang/Class") returns its reference ID which can be used to reference that class
--  in other commands. Returns a list of tables containing following values:
--  * 'refTypeTag' JNI type tag
--  * 'referenceTypeID' Reference type of the class
--  * 'status' Current class status.
-- http://docs.oracle.com/javase/1.5.0/docs/guide/jpda/jdwp/jdwp-protocol.html#JDWP_VirtualMachine_ClassesBySignature
--
--@param socket Socket to use to send the command.
--@param id     Packet id.
--@param signature Signature of the class.
--@return (status,classes) If status is false, classes is an error string, else it contains list of found classes.
function getClassBySignature(socket,id,signature)
  local command = JDWPCommandPacket:new(id,1,2,toUTF8(signature))
  local status, data = executeCommand(socket,command)
  if not status then
    stdnse.debug2("JDWP getClassBySignature() error : %s",data)
    return false,data
  end
  -- parse data
  local classes = {}
  local number_of_classes, pos = string.unpack(">i4", data)

  for i = 1, number_of_classes do
    local class_info = {
      refTypeTag = nil,
      referenceTypeID = nil,
      status = nil
    }
    class_info.refTypeTag, class_info.referenceTypeID, class_info.status, pos = string.unpack(">bI8i4", data, pos)
    table.insert(classes,class_info)
  end
  return true, classes
end

--- AllThreads Command (4)
--  Returns all threads currently running in the target VM .
--
-- http://docs.oracle.com/javase/1.5.0/docs/guide/jpda/jdwp/jdwp-protocol.html#JDWP_VirtualMachine_AllThreads
--
--@param socket Socket to use to send the command.
--@param id     Packet id.
--@return (status, threads) If status is false threads contains an error string, else it contains a list of all threads in the debuggee VM.
function getAllThreads(socket,id)
  local command = JDWPCommandPacket:new(id,1,4,nil)
  local status, data = executeCommand(socket,command)
  if not status then
    stdnse.debug2("JDWP getAllThreads() error: %s", data)
    return false,data
  end
  -- parse data
  local number_of_threads, pos = string.unpack(">i4", data)
  local threads = {}
  for i = 1, number_of_threads do
    local thread
    thread, pos = string.unpack(">I8", data, pos)
    table.insert(threads,thread)
  end
  return true, threads
end

--- Resume Command (9)
--  Resumes execution of the application after the suspend command or an event has stopped it.
--
--  http://docs.oracle.com/javase/1.5.0/docs/guide/jpda/jdwp/jdwp-protocol.html#JDWP_VirtualMachine_Resume
--
--@param socket Socket to use to send the command.
--@param id     Packet id.
--@return (status, nil) If status is false error string is returned, else it's null since this command has no data in the reply.
function resumeVM(socket,id)
  local command = JDWPCommandPacket:new(id,1,9,nil)
  local status, data = executeCommand(socket,command)
  if not status then
    stdnse.debug2("JDWP resumeVM() error: %s", data)
    return false,data
  end
  -- wait for event notification
  status, data = receive_all(socket)
  if not status then
    stdnse.debug2("JDWP resumeVM() event notification failed: %s", data)
  end
  return true, nil
end

--- CreateString Command (11)
--  Creates new string object in the debuggee VM.
--
--  http://docs.oracle.com/javase/1.5.0/docs/guide/jpda/jdwp/jdwp-protocol.html#JDWP_VirtualMachine_CreateString
--
--@param socket Socket to use to send the command.
--@param id     Packet id.
--@param ascii_string String to create.
--@return (status, stringID) If status is false error string is returned, else stringID is newly created string.
function createString(socket,id,ascii_string)
  local command = JDWPCommandPacket:new(id,1,11,toUTF8(ascii_string))
  local status, data = executeCommand(socket,command)
  if not status then
    stdnse.debug2("JDWP createString() error: %s", data)
    return false,data
  end
  local stringID = string.unpack(">I8", data)
  return true, stringID
end

--- AllClassesWithGeneric Command (20)
--  Returns reference types and signatures for all classes currently loaded by the target VM.
--
--  Returns a list of tables containing following info:
--  * 'refTypeTag'       Kind of following reference type.
--  * 'typeID'           Loaded reference type
--  * 'signature'        The JNI signature of the loaded reference type.
--  * 'genericSignature' The generic signature of the loaded reference type or an empty string if there is none.
--  * 'status'           The current class status.
--  http://docs.oracle.com/javase/1.5.0/docs/guide/jpda/jdwp/jdwp-protocol.html#JDWP_VirtualMachine_AllClassesWithGeneric
--
--@param socket Socket to use to send the command.
--@param id     Packet id.
--@return (status, all_classes) If status is false all_classes contains an error string, else it is a list of loaded classes information.
function getAllClassesWithGeneric(socket,id)
  local command = JDWPCommandPacket:new(id,1,20,nil)
  local status, data = executeCommand(socket,command)
  if not status then
    stdnse.debug2("JDWP getAllClassesWithGeneric() error: %s", data)
    return false,data
  end
  -- parse data
  local all_classes = {}
  local number_of_classes, pos = string.unpack(">i4", data)

  for i = 0 , number_of_classes do
    local class = {
      refTypeTag = nil,
      typeID = nil,
      signature = nil,
      genericSignature = nil,
      status = nil
    }
    if pos > #data then break end
    class.refTypeTag, class.typeID, pos = string.unpack(">BI8", data, pos)
    pos, class.signature = extract_string(data,pos)
    pos, class.genericSignature = extract_string(data,pos)
    class.status, pos = string.unpack(">i4", data, pos)
    table.insert(all_classes,class)
  end
  return true, all_classes
end

--- ReferenceType Command Set (2)
--  http://docs.oracle.com/javase/1.5.0/docs/guide/jpda/jdwp/jdwp-protocol.html#JDWP_ReferenceType


--- SignatureWithGeneric Command (13)
--  Returns the JNI signature of a reference type.
--
-- http://docs.oracle.com/javase/1.5.0/docs/guide/jpda/jdwp/jdwp-protocol.html#JDWP_ReferenceType_SignatureWithGeneric
--
--@param socket Socket to use to send the command.
--@param id     Packet id.
--@param classID Reference type id of the class to get the signature from.
--@return (status, signature) If status is false signature contains an error string, else it is class signature (like "Ljava/lang/Class").
function getSignatureWithGeneric(socket,id,classID)
  local command = JDWPCommandPacket:new(id, 2, 13, string.pack(">I8", classID)) -- Version Command (1)
  local status, data = executeCommand(socket,command)
  if not status then
    stdnse.debug2("JDWP getVersion() error : %s",data)
    return false,data
  end
  local _,signature = extract_string(data,0)
  -- parse data
  return true,signature
end

--- MethodsWithGeneric Command (15)
--  Returns information, including the generic signature if any, for each method in a reference type.
--
--  Returns a list of tables containing following fields for each method:
--  * 'methodID'          Method ID which can be used to call the method.
--  * 'name'              The name of the method.
--  * 'signature'         The JNI signature of the method.
--  * 'generic_signature' The generic signature of the method, or an empty string if there is none.
--  * 'modBits'           The modifier bit flags (also known as access flags) which provide additional information on the method declaration.
--  http://docs.oracle.com/javase/1.5.0/docs/guide/jpda/jdwp/jdwp-protocol.html#JDWP_ReferenceType_MethodsWithGeneric
--
--@param socket Socket to use to send the command.
--@param id     Packet id.
--@param classID   Reference type id of the class to get the list of methods.
--@return (status, signature) If status is false methods contains an error string, else it a list of methods information.
function getMethodsWithGeneric(socket,id,classID)
  local command = JDWPCommandPacket:new(id, 2, 15, string.pack(">I8", classID))
  local status, data = executeCommand(socket,command)
  if not status then
    stdnse.debug2("JDWP getMethodsWithGeneric() error : %s",data)
    return false,data
  end
  -- parse data
  local methods = {}
  local number_of_methods, pos = string.unpack(">i4", data)

  for i = 1, number_of_methods do
    local method_info = {
      methodID = nil,
      name = nil,
      signature = nil,
      generic_signature = nil,
      modBits = nil
    }
    method_info.methodID, pos = string.unpack(">i4", data, pos)
    pos,method_info.name = extract_string(data,pos)
    pos, method_info.signature = extract_string(data,pos)
    pos,method_info.generic_signature = extract_string(data,pos)
    method_info.modBits, pos = string.unpack(">i4", data, pos)
    table.insert(methods,method_info)
  end
  return true, methods
end

--- ClassType Command Set (3)
--  http://docs.oracle.com/javase/1.5.0/docs/guide/jpda/jdwp/jdwp-protocol.html#JDWP_ClassType

--- InvokeMethod Command (3)
--  Invokes a class' static method and returns the reply data.
--
--  Reply data can vary so parsing is left to the function caller.
--  http://docs.oracle.com/javase/1.5.0/docs/guide/jpda/jdwp/jdwp-protocol.html#JDWP_ClassType_InvokeMethod
--
--@param socket Socket to use to send the command.
--@param id  Packet id.
--@param classID Reference type id of the class.
--@param methodID ID of the static method to call.
--@numberOfArguments Number of method arguments.
--@arguments Already packed arguments.
--@options Invocation options.
--@return (status, data) If status is false data contains an error string, else it contains a reply data and needs to be parsed manually.
function invokeStaticMethod(socket,id,classID,methodID,numberOfArguments,arguments,options)
  local params
  if numberOfArguments == 0 then
    params = string.pack(">I8i4i4i4", classID, methodID, numberOfArguments, options)
  else
    params = string.pack(">I8i4i4", classID, methodID, numberOfArguments) .. arguments .. string.pack(">i4", options)
  end

  local command = JDWPCommandPacket:new(id,3,3,params)
  local status, data = executeCommand(socket,command)
  if not status then
    stdnse.debug2("JDWP invokeStaticMethod() error: %s", data)
    return false,data
  end
  return true,data
end

--- NewInstance Command (4)
--
--  Creates a new object of this type, invoking the specified constructor.
--  The constructor method ID must be a member of the class type.
--
--  http://docs.oracle.com/javase/1.5.0/docs/guide/jpda/jdwp/jdwp-protocol.html#JDWP_ClassType_NewInstance
--
--@param socket Socket to use to send the command.
--@param id Packet id.
--@param classID Reference type id of the class.
--@param threadID The thread in which to invoke the constructor.
--@param methodID The constructor to invoke.
--@numberOfArguments Number of constructor arguments.
--@arguments Already packed arguments.
--@return (status, objectID) If status is false data contains an error string, else it contains a reference ID of the newly created object.
function newClassInstance(socket,id,classID,threadID,methodID,numberOfArguments,arguments)
  local params
  if numberOfArguments == 0 then
    params = string.pack(">I8I8i4i4i4", classID, threadID, methodID, numberOfArguments, 0)
  else
    params = string.pack(">I8I8i4i4", classID, threadID, methodID, numberOfArguments) .. arguments
  end

  local command = JDWPCommandPacket:new(id,3,4,params)
  local status, data = executeCommand(socket,command)
  if not status then
    stdnse.debug2("JDWP newClassInstance() error: %s", data)
    return false,data
  end
  -- parse data
  stdnse.debug1("newClassInstance data: %s",stdnse.tohex(data))
  local tag, pos = string.unpack(">B", data)
  local objectID
  objectID, pos = string.unpack(">I8", data, pos)
  return true,objectID
end

--- ArrayType Command Set (4)
--  http://docs.oracle.com/javase/1.5.0/docs/guide/jpda/jdwp/jdwp-protocol.html#JDWP_ArrayType

--- NewInstance Command (1)
--  Creates a new array object of the specified type with a given length.
--
--  http://docs.oracle.com/javase/1.5.0/docs/guide/jpda/jdwp/jdwp-protocol.html#JDWP_ArrayType_NewInstance
--
--@param socket Socket to use to send the command.
--@param id Packet id.
--@param arrayType The array type of the new instance as per JNI (http://docs.oracle.com/javase/6/docs/technotes/guides/jni/spec/types.html#wp9502).
--@param length Length of the new array.
--@return (status, arrayID) If status is false data contains an error string, else it contains a reference ID of the newly created array.
function newArrayInstance(socket,id,arrayType,length)
  local params = string.pack(">I8i4", arrayType, length)
  local command = JDWPCommandPacket:new(id,4,1,params)
  local status, data = executeCommand(socket,command)
  if not status then
    stdnse.debug2("JDWP newArrayInstance() error: %s", data)
    return false,data
  end
  local tag, arrayID, pos = string.unpack(">BI8", data)
  return true, arrayID
end

--- ObjectReference Command Set (9)
--  http://docs.oracle.com/javase/1.5.0/docs/guide/jpda/jdwp/jdwp-protocol.html#JDWP_ObjectReference

--- ReferenceType Command (1)
--  Returns the runtime type of the object. The runtime type will be a class or an array.
--
-- http://docs.oracle.com/javase/1.5.0/docs/guide/jpda/jdwp/jdwp-protocol.html#JDWP_ObjectReference_ReferenceType
--
--@param socket Socket to use to send the command.
--@param id Packet id.
--@param objectID The ID of an object.
--@return (status, runtime_type) If status is false runtime_type contains an error string, else it contains runtime type of an object.
function getRuntimeType(socket,id,objectID)
  local command = JDWPCommandPacket:new(id, 9, 1, string.pack(">I8", objectID))
  local status, data = executeCommand(socket,command)
  if not status then
    stdnse.debug2("JDWP resumeVM() error: %s", data)
    return false,data
  end
  local tag, runtime_type = string.unpack(">BI8", data)
  stdnse.debug1("runtime type: %d",runtime_type)
  return true,runtime_type
end

--- InvokeMethod Command (6)
--  Invokes a instance method with specified parameters.
--
--  http://docs.oracle.com/javase/1.5.0/docs/guide/jpda/jdwp/jdwp-protocol.html#JDWP_ObjectReference_InvokeMethod
--
--@param socket Socket to use to send the command.
--@param id Packet id.
--@param objectID The ID of an object.
--@param threadID The thread in which to invoke.
--@param classID The class type.
--@param methodID ID of the method to invoke.
--@param numberOfArguments Number of method arguments.
--@arguments Already packed arguments.
--@return (status, data) If status is false data contains an error string, else it contains a reply data and needs to be parsed manually.
function invokeObjectMethod(socket,id,objectID,threadID,classID,methodID,numberOfArguments,arguments)
  local params

  if numberOfArguments == 0 then
    params = string.pack(">I8I8I8i4i4", objectID, threadID, classID, methodID, numberOfArguments)
  else
    params = string.pack(">I8I8I8i4i4", objectID, threadID, classID, methodID, numberOfArguments) .. arguments
  end

  local command = JDWPCommandPacket:new(id,9,6,params)
  local status, data = executeCommand(socket,command)
  if not status then
    stdnse.debug2("JDWP invokeObjectMethod() error: %s", data)
    return false,data
  end
  stdnse.debug1("invoke obj method data: %s ",stdnse.tohex(data))
  return true,data
end

--- StringReference Command Set (10)
--  http://docs.oracle.com/javase/1.5.0/docs/guide/jpda/jdwp/jdwp-protocol.html#JDWP_StringReference

--- Value Command (1)
--  Returns the characters contained in the string.
--
--  http://docs.oracle.com/javase/1.5.0/docs/guide/jpda/jdwp/jdwp-protocol.html#JDWP_StringReference_Value
--
--@param socket Socket to use to send the command.
--@param id Packet id.
--@param stringID The ID of a string to read.
--@return (status, data) If status is false result contains an error string, else it contains read string.
function readString(socket,id,stringID)
  local command = JDWPCommandPacket:new(id, 10, 1, string.pack(">I8", stringID))
  local status, data = executeCommand(socket,command)
  if not status then
    stdnse.debug2("JDWP readString() error: %s", data)
    return false,data
  end
  local _,result = extract_string(data,0)
  return true,result
end

--- ThreadReference Command Set (11)
--  http://docs.oracle.com/javase/1.5.0/docs/guide/jpda/jdwp/jdwp-protocol.html#JDWP_ThreadReference


--- Name Command (1)
--  Returns the thread name.
--
--  http://docs.oracle.com/javase/1.5.0/docs/guide/jpda/jdwp/jdwp-protocol.html#JDWP_ThreadReference_Name
--
--@param socket Socket to use to send the command.
--@param id Packet id.
--@param threadID The ID of a thread.
--@return (status, thread_name) If status is false thread_name contains an error string, else it contains thread's name.
function getThreadName(socket,id,threadID)
  local params = string.pack(">I8", threadID)
  local command = JDWPCommandPacket:new(id,11,1,params)
  local status, data = executeCommand(socket,command)
  if not status then
    stdnse.debug2("JDWP getThreadName() error: %s", data)
    return false,data
  end
  -- parse data
  local _,thread_name = extract_string(data,0)
  return true, thread_name
end

--- Suspend Command (2)
--  Suspends the thread.
--
--  http://docs.oracle.com/javase/1.5.0/docs/guide/jpda/jdwp/jdwp-protocol.html#JDWP_ThreadReference_Suspend
--
--@param socket Socket to use to send the command.
--@param id Packet id.
--@param threadID The ID of a thread.
--@return (status, thread_name) If status is false an error string is returned, else it's nil.
function suspendThread(socket,id,threadID)
  local params = string.pack(">I8", threadID)
  local command = JDWPCommandPacket:new(id,11,2,params)
  local status, data = executeCommand(socket,command)
  if not status then
    stdnse.debug2("JDWP suspendThread() error: %s", data)
    return false,data
  end
  return true, nil
end

--- Status Command (4)
--  Returns the current status of a thread.
--
--  Thread status is described with ThreadStatus and SuspendStatus constants (http://docs.oracle.com/javase/1.5.0/docs/guide/jpda/jdwp/jdwp-protocol.html#JDWP_ThreadStatus).
--  http://docs.oracle.com/javase/1.5.0/docs/guide/jpda/jdwp/jdwp-protocol.html#JDWP_ThreadReference_Status
--
--@param socket Socket to use to send the command.
--@param id Packet id.
--@param threadID The ID of a thread.
--@return (status, thread_name) If status is false an error string is returned, else unparsed thread status data.
function threadStatus(socket,id,threadID)
  local params = string.pack(">I8", threadID)
  local command = JDWPCommandPacket:new(id,11,4,params)
  local status, data = executeCommand(socket,command)
  if not status then
    stdnse.debug2("JDWP threadStatus() error: %s", data)
    return false,data
  end
  stdnse.debug1("threadStatus %s",stdnse.tohex(data))
  return true, data
end

--- ArrayReference Command Set (13)
--  http://docs.oracle.com/javase/1.5.0/docs/guide/jpda/jdwp/jdwp-protocol.html#JDWP_ArrayReference

--- SetValues Command (3)
--  Sets a range of array components.
--
-- http://docs.oracle.com/javase/1.5.0/docs/guide/jpda/jdwp/jdwp-protocol.html#JDWP_ArrayReference_SetValues
--
--@param socket Socket to use to send the command.
--@param id Packet id.
--@param objectID The ID of an array object.
--@return (status, data) If status is false an error string is returned, else it's nil.
function setArrayValues(socket,id,objectID,idx,values)
  local params = string.pack(">I8i4s4", objectID, idx, values)
  local command = JDWPCommandPacket:new(id,13,3,params)
  local status, data = executeCommand(socket,command)
  if not status then
    stdnse.debug2("JDWP setArrayValues() error: %s", data)
    return false,data
  end
  return true, nil
end

--- EventRequest Command Set (15)
--  http://docs.oracle.com/javase/1.5.0/docs/guide/jpda/jdwp/jdwp-protocol.html#JDWP_EventRequest

--- Uses Set Command (1) to set singlesteping to specified thread.
--
-- http://docs.oracle.com/javase/1.5.0/docs/guide/jpda/jdwp/jdwp-protocol.html#JDWP_EventRequest_Set
--
--@param socket Socket to use to send the command.
--@param id Packet id.
--@param threadID The ID of the thread.
--@return (status, requestID) If status is false an error string is returned, else it contains assigned request id.
function setThreadSinglestep(socket,id,threadID)
  local params = string.pack(">BBi4BI8i4i4", 1, 2, 1, 10, threadID, 0, 0) -- event options see http://docs.oracle.com/javase/1.5.0/docs/guide/jpda/jdwp/jdwp-protocol.html#JDWP_EventRequest_Set
  local command = JDWPCommandPacket:new(id,15,1,params)
  local status, data = executeCommand(socket,command)
  if not status then
    stdnse.debug2("JDWP setThreadSinglestep() error: %s", data)
    return false,data
  end
  local requestID = string.unpack(">i4", data)
  return true, requestID
end

--- Uses Clear Command (2) to unset singlesteping from a thread by specified event.
--
--  http://docs.oracle.com/javase/1.5.0/docs/guide/jpda/jdwp/jdwp-protocol.html#JDWP_EventRequest_Clear
--
--@param socket Socket to use to send the command.
--@param id  Packet id.
--@param eventID The ID of the thread.
--@return (status, requestID) If status is false an error string is returned, else it's nil.
function clearThreadSinglestep(socket,id,eventID)
  local params = string.pack(">Bi4", 1, eventID)
  local command = JDWPCommandPacket:new(id,15,2,params)
  local status, data = executeCommand(socket,command)
  if not status then
    stdnse.debug2("JDWP clearThreadSinglestep() error: %s", data)
    return false,data
  end
  return true,nil
end

--- ClassObjectReference Command Set (17)
--  http://docs.oracle.com/javase/1.5.0/docs/guide/jpda/jdwp/jdwp-protocol.html#JDWP_ClassObjectReference


--- ReflectedType Command (1)
--  Returns the reference type reflected by this class object.
--
--  http://docs.oracle.com/javase/1.5.0/docs/guide/jpda/jdwp/jdwp-protocol.html#JDWP_ClassObjectReference_ReflectedType
--
--@param socket Socket to use to send the command.
--@param id  Packet id.
--@param classObjectID The ID of the object.
--@return (status, reflected_type) If status is false an error string is returned, else reflected_type is object's reference type.
function getReflectedType(socket,id,classObjectID)
  local _, param
  local command = JDWPCommandPacket:new(id, 17, 1, string.pack(">I8", classObjectID))
  local status, data = executeCommand(socket,command)
  if not status then
    stdnse.debug2("JDWP getReflectedType() error: %s", data)
    return false,data
  end
  local reflected_type = {
    refTypeTag = nil,
    typeID = nil
  }
  reflected_type.refTypeTag, reflected_type.typeID = string.unpack(">BI8", data)

  return true, reflected_type
end

--- Helper function to find a method ID by its name.
--
-- @param socket Socket to use for communication.
-- @param class ID of the class whose method we seek.
-- @param methodName Name of the method.
-- @param skipFirst Skip first found method.
function findMethod(socket,class,methodName,skipFirst)
  local methodID
  local status, methods = getMethodsWithGeneric(socket,0,class)
  if not status then
    return false
  end
  for _, method in ipairs(methods) do -- find first constructor and first defineClass() method
    stdnse.debug2("Method name: %s", method.name)
    if methodID == nil then
      if string.find(method.name,methodName) then
        if skipFirst then
          skipFirst = false
        else
          methodID = method.methodID
        end
      end
    end
  end
  return methodID
end

--- Tries to inject specified bytes as a java class and create its instance.
--
--  Returns a table containing following fields:
--  * 'id' Injected class reference ID.
--  * 'instance' Injected calss' instance reference ID.
--  * 'thread' Thread in which the class was injected and instantiated.
--
-- @param socket Socket to use for communication.
-- @param class_bytes String of bytes of a java class file to inject.
-- @return (status,injectedClass) If status is false, an error message is returned, else returns a table with injected class info.
function injectClass(socket,class_bytes)
  local classes,status
  -- find byte array class id needed to create new array to load our bytecode into
  status,classes = getAllClassesWithGeneric(socket,0)
  if not status then
    stdnse.debug1("getAllClassesWithGeneric failed: %s", classes)
    return false
  end
  local byteArrayID
  for _,class in ipairs(classes) do
    if string.find(class.signature,"%[B") then
      byteArrayID = class.typeID
      break
    end
  end
  if byteArrayID == nil then
    stdnse.debug1("finding byte array id failed")
    return false
  end
  stdnse.debug1("Found byte[] id %d",byteArrayID)

  -- find SecureClassLoader id by signature
  status, classes = getClassBySignature(socket,0,"Ljava/security/SecureClassLoader;")
  if not status then
    return false
  end
  local secureClassLoader = classes[1].referenceTypeID
  stdnse.debug1("Found SecureClassLoader id %d",secureClassLoader)
  -- find SecureClassLoader() constructor
  local constructorMethodID = findMethod(socket,secureClassLoader,"<init>",true)
  -- find ClassLoader id by signature
  status, classes = getClassBySignature(socket,0,"Ljava/lang/ClassLoader;")
  if not status then
    return false
  end
  local classLoader = classes[1].referenceTypeID
  stdnse.debug1("Found ClassLoader id %d",classes[1].referenceTypeID)
  -- find ClassLoader's defineClass() method
  local defineClassMethodID = findMethod(socket,classLoader,"defineClass",false)
  -- find ClassLoader's resolveClass() method
  local resolveClassMethodID = findMethod(socket,classLoader,"resolveClass",false)
  if constructorMethodID == nil or defineClassMethodID == nil or resolveClassMethodID == nil then
    stdnse.debug1("Either constructor, defineClass or resolveClass method could not be found %s,%s,%s", type(constructorMethodID), type(defineClassMethodID),type(resolveClassMethodID))
    return false
  end


  -- create array to load bytecode into
  local arrayID
  status, arrayID = newArrayInstance(socket,0,byteArrayID,#class_bytes)
  if not status then
    stdnse.debug1("New array failed: %s", arrayID)
    return false
  end
  stdnse.debug1("Created new byte array of length %d",#class_bytes)
  -- set array values
  local temp
  status, temp = setArrayValues(socket,0,arrayID,0,class_bytes)
  if not status then
    stdnse.debug1("Set values failed: %s", temp)
    return
  end
  stdnse.debug1("Set array values to injected class bytes")

  -- get main thread id
  -- in order to load a new class file, thread must be suspended by an event
  -- so we set it to singlestep, let it run and it get suspended right away
  local threads
  status,threads = getAllThreads(socket,0)
  if not status then
    stdnse.debug1("get threads failed: %s", threads)
    return false
  end
  local main_thread
  local eventID
  stdnse.debug1("Looking for main thread...")
  for _,thread in ipairs(threads) do
    local thread_name
    status, thread_name = getThreadName(socket,0,thread)
    if not status then
      stdnse.debug1("getThreadName failed: %s", thread_name)
      return false
    end
    if thread_name == "main" then
      stdnse.debug1("Setting singlesteping to main thread.")
      status, eventID = setThreadSinglestep(socket,0,thread)
      main_thread = thread
      break
    end
  end
  if main_thread == nil then
    stdnse.debug1("couldn't find main thread")
    return false
  end
  -- to trigger the singlestep event, VM must be resumed
  stdnse.debug1("Resuming VM and waiting for single step event from main thread...")
  local status, _ = resumeVM(socket,0)
  -- clear singlestep since we need to run our code in this thread and we don't want it to stop after each instruction
  clearThreadSinglestep(socket,0,eventID)
  stdnse.debug1("Cleared singlesteping from main thread.")

  -- instantiate new class loader
  local class_loader_instance
  status, class_loader_instance = newClassInstance(socket,0,secureClassLoader,main_thread,constructorMethodID,0,nil)
  if not status then
    stdnse.debug1("newClassInstance failed: %s", class_loader_instance)
    return false
  end
  stdnse.debug1("Created new instance of SecureClassLoader.")

  local injectedClass
  -- invoke defineClass with byte array that contains our bytecode
  local defineClassArgs = string.pack(">BI8Bi4Bi4", 0x5b, arrayID, 0x49, 0, 0x49, #class_bytes) -- argument tags taken from http://docs.oracle.com/javase/6/docs/technotes/guides/jni/spec/types.html#wp9502
  stdnse.debug1("Calling secureClassLoader.defineClass(byte[],int,int) ...")
  status, injectedClass = invokeObjectMethod(socket,0,class_loader_instance,main_thread,secureClassLoader,defineClassMethodID,3,defineClassArgs)
  if not status then
    stdnse.debug1("invokeObjectMethod failed: %s", injectedClass)
  end
  -- resolve (Java's way of saying link) loaded class
  status, _ = invokeObjectMethod(socket,0,class_loader_instance,main_thread,secureClassLoader,resolveClassMethodID,1,injectedClass) -- call with injectedClass which still has a tag
  if not status then
    stdnse.debug1("invokeObjectMethod failed:")
  end
  -- extract the injected class' ID
  local tag,injectedClassID
  tag, injectedClassID = string.unpack(">BI8", injectedClass)

  -- our class is now injected, but we need to find its methods by calling Class.getMethods() on it
  -- and for that we need its runtime_type which is Class
  local runtime_type
  status, runtime_type = getRuntimeType(socket,0,injectedClassID) -- should be Class
  -- find the getMethods() id
  local getMethodsMethod = findMethod(socket,runtime_type,"getMethods",false)
  status, _ = invokeObjectMethod(socket,0,injectedClassID,main_thread,runtime_type,getMethodsMethod,0,nil)


  stdnse.debug1("New class defined. Injected class id : %d",injectedClassID)
  local sig, reflected_type
  status, sig = getSignatureWithGeneric(socket,0,injectedClassID)
  stdnse.debug1("Injected class signature: %s", sig)
  status, reflected_type = getReflectedType(socket,0,injectedClassID)

  -- find injected class constructor
  local injectedConstructor = findMethod(socket,injectedClassID,"<init>",false)

  if injectedConstructor == nil then
    stdnse.debug1("Couldn't find either evil method or constructor")
    return false
  end

  -- instantiate our evil class
  local injectedClassInstance
  status, injectedClassInstance = newClassInstance(socket,0,injectedClassID,main_thread,injectedConstructor,0,nil)
  if not status then
    return false, injectedClassInstance
  end
  local injected_class = {
    id = injectedClassID,
    instance = injectedClassInstance,
    thread = main_thread
  }
  return true, injected_class
end

return _ENV;
