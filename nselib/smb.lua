--- A library for SMB (Server Message Block) (aka CIFS) traffic.
-- \n\n
-- This traffic is normally
--  sent to/from ports 139 or 445 of Windows systems, although it's also implemented by
--  others (the most notable one being Samba). \n
--\n
-- The intention of this library is toe ventually handle all aspects of the SMB protocol,
-- A programmer using this library must already have some knowledge of the SMB protocol, 
-- although a lot isn't necessary. You can pick up a lot by looking at the code that uses
-- this. The basic login is this:\n
--\n
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
-- </code>
--\n\n
-- In terms of functions here, the protocol is:\n
-- <code>
-- status, socket            = smb.start(host)
-- status, negotiate_result  = smb.negotiate_protocol(socket)
-- status, session_result    = smb.start_session(socket, username, negotiate_result['session_key'], negotiate_result['capabilities'])
-- status, tree_result       = smb.tree_connect(socket, path, session_result['uid'])
-- status, disconnect_result = smb.tree_disconnect(socket, session_result['uid'], tree_result['tid'])
-- status, logoff_result     = smb.logoff(socket, session_result['uid'])
-- status, err               = smb.stop(socket)
-- </code>
--\n
-- Optionally, the <code>stop</code> function can also call <code>tree_disconnect</code> and <code>logoff</code>, by giving it extra parameters:\n
-- <code>
-- status, err               = smb.stop(socket, session_result['uid'], tree_result['tid'])
-- </code>
-- 
-- To initially begin the connection, there are two options:\n
-- 1) Attempt to start a raw session over 445, if it's open. \n
-- 2) Attempt to start a NetBIOS session over 139. Although the 
--    protocol's the same, it requires a "session request" packet. 
--    That packet requires the computer's name, which is requested
--    using a NBSTAT probe over UDP port 137. \n
--
-- Once it's connected, a <code>SMB_COM_NEGOTIATE</code> packet is sent, 
-- requesting the protocol "NT LM 0.12", which is the most commonly
-- supported one. Among other things, the server's response contains
-- the host's security level, the system time, and the computer/domain
-- name.\n
--\n
-- If that's successful, <code>SMB_COM_SESSION_SETUP_ANDX</code> is sent. It is essentially the logon
-- packet, where the username, domain, and password are sent to the server for verification. 
-- The response to <code>SMB_COM_SESSION_SETUP_ANDX</code> is fairly simple, containing a boolean for 
-- success, along with the operating system and the lan manager name. \n
--\n
-- After a successful <code>SMB_COM_SESSION_SETUP_ANDX</code> has been made, a 
<code>--</code> SMB_COM_TREE_CONNECT_ANDX packet can be sent. This is what connects to a share. 
-- The server responds to this with a boolean answer, and little more information. \n
--\n
-- Each share will either return <code>STATUS_BAD_NETWORK_NAME</code> if the share doesn't exist, <code>STATUS_ACCESS_DENIED</code> if it exists but we don't have access, or 
-- <code>STATUS_SUCCESS</code> if exists and we do have access. \n
--\n
-- Thanks go to Christopher R. Hertel and Implementing CIFS, which 
-- taught me everything I know about Microsoft's protocols. \n
--
--@author Ron Bowes <ron@skullsecurity.net>
-- @copyright Same as Nmap--See http://nmap.org/book/man-legal.html
-----------------------------------------------------------------------
module(... or "smb", package.seeall)

require 'bit'
require 'bin'
require 'netbios'
require 'stdnse'

local mutex = nmap.mutex("SMB")

local command_codes = {}
local command_names = {}
command_codes['SMB_COM_CREATE_DIRECTORY']          = 0x00
command_codes['SMB_COM_DELETE_DIRECTORY']          = 0x01
command_codes['SMB_COM_OPEN']                      = 0x02
command_codes['SMB_COM_CREATE']                    = 0x03
command_codes['SMB_COM_CLOSE']                     = 0x04
command_codes['SMB_COM_FLUSH']                     = 0x05
command_codes['SMB_COM_DELETE']                    = 0x06
command_codes['SMB_COM_RENAME']                    = 0x07
command_codes['SMB_COM_QUERY_INFORMATION']         = 0x08
command_codes['SMB_COM_SET_INFORMATION']           = 0x09
command_codes['SMB_COM_READ']                      = 0x0A
command_codes['SMB_COM_WRITE']                     = 0x0B
command_codes['SMB_COM_LOCK_BYTE_RANGE']           = 0x0C
command_codes['SMB_COM_UNLOCK_BYTE_RANGE']         = 0x0D
command_codes['SMB_COM_CREATE_TEMPORARY']          = 0x0E
command_codes['SMB_COM_CREATE_NEW']                = 0x0F
command_codes['SMB_COM_CHECK_DIRECTORY']           = 0x10
command_codes['SMB_COM_PROCESS_EXIT']              = 0x11
command_codes['SMB_COM_SEEK']                      = 0x12
command_codes['SMB_COM_LOCK_AND_READ']             = 0x13
command_codes['SMB_COM_WRITE_AND_UNLOCK']          = 0x14
command_codes['SMB_COM_READ_RAW']                  = 0x1A
command_codes['SMB_COM_READ_MPX']                  = 0x1B
command_codes['SMB_COM_READ_MPX_SECONDARY']        = 0x1C
command_codes['SMB_COM_WRITE_RAW']                 = 0x1D
command_codes['SMB_COM_WRITE_MPX']                 = 0x1E
command_codes['SMB_COM_WRITE_MPX_SECONDARY']       = 0x1F
command_codes['SMB_COM_WRITE_COMPLETE']            = 0x20
command_codes['SMB_COM_QUERY_SERVER']              = 0x21
command_codes['SMB_COM_SET_INFORMATION2']          = 0x22
command_codes['SMB_COM_QUERY_INFORMATION2']        = 0x23
command_codes['SMB_COM_LOCKING_ANDX']              = 0x24
command_codes['SMB_COM_TRANSACTION']               = 0x25
command_codes['SMB_COM_TRANSACTION_SECONDARY']     = 0x26
command_codes['SMB_COM_IOCTL']                     = 0x27
command_codes['SMB_COM_IOCTL_SECONDARY']           = 0x28
command_codes['SMB_COM_COPY']                      = 0x29
command_codes['SMB_COM_MOVE']                      = 0x2A
command_codes['SMB_COM_ECHO']                      = 0x2B
command_codes['SMB_COM_WRITE_AND_CLOSE']           = 0x2C
command_codes['SMB_COM_OPEN_ANDX']                 = 0x2D
command_codes['SMB_COM_READ_ANDX']                 = 0x2E
command_codes['SMB_COM_WRITE_ANDX']                = 0x2F
command_codes['SMB_COM_NEW_FILE_SIZE']             = 0x30
command_codes['SMB_COM_CLOSE_AND_TREE_DISC']       = 0x31
command_codes['SMB_COM_TRANSACTION2']              = 0x32
command_codes['SMB_COM_TRANSACTION2_SECONDARY']    = 0x33
command_codes['SMB_COM_FIND_CLOSE2']               = 0x34
command_codes['SMB_COM_FIND_NOTIFY_CLOSE']         = 0x35
command_codes['SMB_COM_TREE_CONNECT']              = 0x70
command_codes['SMB_COM_TREE_DISCONNECT']           = 0x71
command_codes['SMB_COM_NEGOTIATE']                 = 0x72
command_codes['SMB_COM_SESSION_SETUP_ANDX']        = 0x73
command_codes['SMB_COM_LOGOFF_ANDX']               = 0x74
command_codes['SMB_COM_TREE_CONNECT_ANDX']         = 0x75
command_codes['SMB_COM_QUERY_INFORMATION_DISK']    = 0x80
command_codes['SMB_COM_SEARCH']                    = 0x81
command_codes['SMB_COM_FIND']                      = 0x82
command_codes['SMB_COM_FIND_UNIQUE']               = 0x83
command_codes['SMB_COM_FIND_CLOSE']                = 0x84
command_codes['SMB_COM_NT_TRANSACT']               = 0xA0
command_codes['SMB_COM_NT_TRANSACT_SECONDARY']     = 0xA1
command_codes['SMB_COM_NT_CREATE_ANDX']            = 0xA2
command_codes['SMB_COM_NT_CANCEL']                 = 0xA4
command_codes['SMB_COM_NT_RENAME']                 = 0xA5
command_codes['SMB_COM_OPEN_PRINT_FILE']           = 0xC0
command_codes['SMB_COM_WRITE_PRINT_FILE']          = 0xC1
command_codes['SMB_COM_CLOSE_PRINT_FILE']          = 0xC2
command_codes['SMB_COM_GET_PRINT_QUEUE']           = 0xC3
command_codes['SMB_COM_READ_BULK']                 = 0xD8
command_codes['SMB_COM_WRITE_BULK']                = 0xD9
command_codes['SMB_COM_WRITE_BULK_DATA']           = 0xDA
command_codes['SMB_NO_FURTHER_COMMANDS']           = 0xFF

for i, v in pairs(command_codes) do
	command_names[v] = i
end



local status_codes = {}
local status_names = {}
status_codes['NT_STATUS_OK'] = 0x0000
status_codes['NT_STATUS_BUFFER_OVERFLOW'] = 0x80000005
status_codes['NT_STATUS_UNSUCCESSFUL'] = 0xc0000001
status_codes['NT_STATUS_NOT_IMPLEMENTED'] = 0xc0000002
status_codes['NT_STATUS_INVALID_INFO_CLASS'] = 0xc0000003
status_codes['NT_STATUS_INFO_LENGTH_MISMATCH'] = 0xc0000004
status_codes['NT_STATUS_ACCESS_VIOLATION'] = 0xc0000005
status_codes['NT_STATUS_IN_PAGE_ERROR'] = 0xc0000006
status_codes['NT_STATUS_PAGEFILE_QUOTA'] = 0xc0000007
status_codes['NT_STATUS_INVALID_HANDLE'] = 0xc0000008
status_codes['NT_STATUS_BAD_INITIAL_STACK'] = 0xc0000009
status_codes['NT_STATUS_BAD_INITIAL_PC'] = 0xc000000a
status_codes['NT_STATUS_INVALID_CID'] = 0xc000000b
status_codes['NT_STATUS_TIMER_NOT_CANCELED'] = 0xc000000c
status_codes['NT_STATUS_INVALID_PARAMETER'] = 0xc000000d
status_codes['NT_STATUS_NO_SUCH_DEVICE'] = 0xc000000e
status_codes['NT_STATUS_NO_SUCH_FILE'] = 0xc000000f
status_codes['NT_STATUS_INVALID_DEVICE_REQUEST'] = 0xc0000010
status_codes['NT_STATUS_END_OF_FILE'] = 0xc0000011
status_codes['NT_STATUS_WRONG_VOLUME'] = 0xc0000012
status_codes['NT_STATUS_NO_MEDIA_IN_DEVICE'] = 0xc0000013
status_codes['NT_STATUS_UNRECOGNIZED_MEDIA'] = 0xc0000014
status_codes['NT_STATUS_NONEXISTENT_SECTOR'] = 0xc0000015
status_codes['NT_STATUS_MORE_PROCESSING_REQUIRED'] = 0xc0000016
status_codes['NT_STATUS_NO_MEMORY'] = 0xc0000017
status_codes['NT_STATUS_CONFLICTING_ADDRESSES'] = 0xc0000018
status_codes['NT_STATUS_NOT_MAPPED_VIEW'] = 0xc0000019
status_codes['NT_STATUS_UNABLE_TO_FREE_VM'] = 0xc000001a
status_codes['NT_STATUS_UNABLE_TO_DELETE_SECTION'] = 0xc000001b
status_codes['NT_STATUS_INVALID_SYSTEM_SERVICE'] = 0xc000001c
status_codes['NT_STATUS_ILLEGAL_INSTRUCTION'] = 0xc000001d
status_codes['NT_STATUS_INVALID_LOCK_SEQUENCE'] = 0xc000001e
status_codes['NT_STATUS_INVALID_VIEW_SIZE'] = 0xc000001f
status_codes['NT_STATUS_INVALID_FILE_FOR_SECTION'] = 0xc0000020
status_codes['NT_STATUS_ALREADY_COMMITTED'] = 0xc0000021
status_codes['NT_STATUS_ACCESS_DENIED'] = 0xc0000022
status_codes['NT_STATUS_BUFFER_TOO_SMALL'] = 0xc0000023
status_codes['NT_STATUS_OBJECT_TYPE_MISMATCH'] = 0xc0000024
status_codes['NT_STATUS_NONCONTINUABLE_EXCEPTION'] = 0xc0000025
status_codes['NT_STATUS_INVALID_DISPOSITION'] = 0xc0000026
status_codes['NT_STATUS_UNWIND'] = 0xc0000027
status_codes['NT_STATUS_BAD_STACK'] = 0xc0000028
status_codes['NT_STATUS_INVALID_UNWIND_TARGET'] = 0xc0000029
status_codes['NT_STATUS_NOT_LOCKED'] = 0xc000002a
status_codes['NT_STATUS_PARITY_ERROR'] = 0xc000002b
status_codes['NT_STATUS_UNABLE_TO_DECOMMIT_VM'] = 0xc000002c
status_codes['NT_STATUS_NOT_COMMITTED'] = 0xc000002d
status_codes['NT_STATUS_INVALID_PORT_ATTRIBUTES'] = 0xc000002e
status_codes['NT_STATUS_PORT_MESSAGE_TOO_LONG'] = 0xc000002f
status_codes['NT_STATUS_INVALID_PARAMETER_MIX'] = 0xc0000030
status_codes['NT_STATUS_INVALID_QUOTA_LOWER'] = 0xc0000031
status_codes['NT_STATUS_DISK_CORRUPT_ERROR'] = 0xc0000032
status_codes['NT_STATUS_OBJECT_NAME_INVALID'] = 0xc0000033
status_codes['NT_STATUS_OBJECT_NAME_NOT_FOUND'] = 0xc0000034
status_codes['NT_STATUS_OBJECT_NAME_COLLISION'] = 0xc0000035
status_codes['NT_STATUS_HANDLE_NOT_WAITABLE'] = 0xc0000036
status_codes['NT_STATUS_PORT_DISCONNECTED'] = 0xc0000037
status_codes['NT_STATUS_DEVICE_ALREADY_ATTACHED'] = 0xc0000038
status_codes['NT_STATUS_OBJECT_PATH_INVALID'] = 0xc0000039
status_codes['NT_STATUS_OBJECT_PATH_NOT_FOUND'] = 0xc000003a
status_codes['NT_STATUS_OBJECT_PATH_SYNTAX_BAD'] = 0xc000003b
status_codes['NT_STATUS_DATA_OVERRUN'] = 0xc000003c
status_codes['NT_STATUS_DATA_LATE_ERROR'] = 0xc000003d
status_codes['NT_STATUS_DATA_ERROR'] = 0xc000003e
status_codes['NT_STATUS_CRC_ERROR'] = 0xc000003f
status_codes['NT_STATUS_SECTION_TOO_BIG'] = 0xc0000040
status_codes['NT_STATUS_PORT_CONNECTION_REFUSED'] = 0xc0000041
status_codes['NT_STATUS_INVALID_PORT_HANDLE'] = 0xc0000042
status_codes['NT_STATUS_SHARING_VIOLATION'] = 0xc0000043
status_codes['NT_STATUS_QUOTA_EXCEEDED'] = 0xc0000044
status_codes['NT_STATUS_INVALID_PAGE_PROTECTION'] = 0xc0000045
status_codes['NT_STATUS_MUTANT_NOT_OWNED'] = 0xc0000046
status_codes['NT_STATUS_SEMAPHORE_LIMIT_EXCEEDED'] = 0xc0000047
status_codes['NT_STATUS_PORT_ALREADY_SET'] = 0xc0000048
status_codes['NT_STATUS_SECTION_NOT_IMAGE'] = 0xc0000049
status_codes['NT_STATUS_SUSPEND_COUNT_EXCEEDED'] = 0xc000004a
status_codes['NT_STATUS_THREAD_IS_TERMINATING'] = 0xc000004b
status_codes['NT_STATUS_BAD_WORKING_SET_LIMIT'] = 0xc000004c
status_codes['NT_STATUS_INCOMPATIBLE_FILE_MAP'] = 0xc000004d
status_codes['NT_STATUS_SECTION_PROTECTION'] = 0xc000004e
status_codes['NT_STATUS_EAS_NOT_SUPPORTED'] = 0xc000004f
status_codes['NT_STATUS_EA_TOO_LARGE'] = 0xc0000050
status_codes['NT_STATUS_NONEXISTENT_EA_ENTRY'] = 0xc0000051
status_codes['NT_STATUS_NO_EAS_ON_FILE'] = 0xc0000052
status_codes['NT_STATUS_EA_CORRUPT_ERROR'] = 0xc0000053
status_codes['NT_STATUS_FILE_LOCK_CONFLICT'] = 0xc0000054
status_codes['NT_STATUS_LOCK_NOT_GRANTED'] = 0xc0000055
status_codes['NT_STATUS_DELETE_PENDING'] = 0xc0000056
status_codes['NT_STATUS_CTL_FILE_NOT_SUPPORTED'] = 0xc0000057
status_codes['NT_STATUS_UNKNOWN_REVISION'] = 0xc0000058
status_codes['NT_STATUS_REVISION_MISMATCH'] = 0xc0000059
status_codes['NT_STATUS_INVALID_OWNER'] = 0xc000005a
status_codes['NT_STATUS_INVALID_PRIMARY_GROUP'] = 0xc000005b
status_codes['NT_STATUS_NO_IMPERSONATION_TOKEN'] = 0xc000005c
status_codes['NT_STATUS_CANT_DISABLE_MANDATORY'] = 0xc000005d
status_codes['NT_STATUS_NO_LOGON_SERVERS'] = 0xc000005e
status_codes['NT_STATUS_NO_SUCH_LOGON_SESSION'] = 0xc000005f
status_codes['NT_STATUS_NO_SUCH_PRIVILEGE'] = 0xc0000060
status_codes['NT_STATUS_PRIVILEGE_NOT_HELD'] = 0xc0000061
status_codes['NT_STATUS_INVALID_ACCOUNT_NAME'] = 0xc0000062
status_codes['NT_STATUS_USER_EXISTS'] = 0xc0000063
status_codes['NT_STATUS_NO_SUCH_USER'] = 0xc0000064
status_codes['NT_STATUS_GROUP_EXISTS'] = 0xc0000065
status_codes['NT_STATUS_NO_SUCH_GROUP'] = 0xc0000066
status_codes['NT_STATUS_MEMBER_IN_GROUP'] = 0xc0000067
status_codes['NT_STATUS_MEMBER_NOT_IN_GROUP'] = 0xc0000068
status_codes['NT_STATUS_LAST_ADMIN'] = 0xc0000069
status_codes['NT_STATUS_WRONG_PASSWORD'] = 0xc000006a
status_codes['NT_STATUS_ILL_FORMED_PASSWORD'] = 0xc000006b
status_codes['NT_STATUS_PASSWORD_RESTRICTION'] = 0xc000006c
status_codes['NT_STATUS_LOGON_FAILURE'] = 0xc000006d
status_codes['NT_STATUS_ACCOUNT_RESTRICTION'] = 0xc000006e
status_codes['NT_STATUS_INVALID_LOGON_HOURS'] = 0xc000006f
status_codes['NT_STATUS_INVALID_WORKSTATION'] = 0xc0000070
status_codes['NT_STATUS_PASSWORD_EXPIRED'] = 0xc0000071
status_codes['NT_STATUS_ACCOUNT_DISABLED'] = 0xc0000072
status_codes['NT_STATUS_NONE_MAPPED'] = 0xc0000073
status_codes['NT_STATUS_TOO_MANY_LUIDS_REQUESTED'] = 0xc0000074
status_codes['NT_STATUS_LUIDS_EXHAUSTED'] = 0xc0000075
status_codes['NT_STATUS_INVALID_SUB_AUTHORITY'] = 0xc0000076
status_codes['NT_STATUS_INVALID_ACL'] = 0xc0000077
status_codes['NT_STATUS_INVALID_SID'] = 0xc0000078
status_codes['NT_STATUS_INVALID_SECURITY_DESCR'] = 0xc0000079
status_codes['NT_STATUS_PROCEDURE_NOT_FOUND'] = 0xc000007a
status_codes['NT_STATUS_INVALID_IMAGE_FORMAT'] = 0xc000007b
status_codes['NT_STATUS_NO_TOKEN'] = 0xc000007c
status_codes['NT_STATUS_BAD_INHERITANCE_ACL'] = 0xc000007d
status_codes['NT_STATUS_RANGE_NOT_LOCKED'] = 0xc000007e
status_codes['NT_STATUS_DISK_FULL'] = 0xc000007f
status_codes['NT_STATUS_SERVER_DISABLED'] = 0xc0000080
status_codes['NT_STATUS_SERVER_NOT_DISABLED'] = 0xc0000081
status_codes['NT_STATUS_TOO_MANY_GUIDS_REQUESTED'] = 0xc0000082
status_codes['NT_STATUS_GUIDS_EXHAUSTED'] = 0xc0000083
status_codes['NT_STATUS_INVALID_ID_AUTHORITY'] = 0xc0000084
status_codes['NT_STATUS_AGENTS_EXHAUSTED'] = 0xc0000085
status_codes['NT_STATUS_INVALID_VOLUME_LABEL'] = 0xc0000086
status_codes['NT_STATUS_SECTION_NOT_EXTENDED'] = 0xc0000087
status_codes['NT_STATUS_NOT_MAPPED_DATA'] = 0xc0000088
status_codes['NT_STATUS_RESOURCE_DATA_NOT_FOUND'] = 0xc0000089
status_codes['NT_STATUS_RESOURCE_TYPE_NOT_FOUND'] = 0xc000008a
status_codes['NT_STATUS_RESOURCE_NAME_NOT_FOUND'] = 0xc000008b
status_codes['NT_STATUS_ARRAY_BOUNDS_EXCEEDED'] = 0xc000008c
status_codes['NT_STATUS_FLOAT_DENORMAL_OPERAND'] = 0xc000008d
status_codes['NT_STATUS_FLOAT_DIVIDE_BY_ZERO'] = 0xc000008e
status_codes['NT_STATUS_FLOAT_INEXACT_RESULT'] = 0xc000008f
status_codes['NT_STATUS_FLOAT_INVALID_OPERATION'] = 0xc0000090
status_codes['NT_STATUS_FLOAT_OVERFLOW'] = 0xc0000091
status_codes['NT_STATUS_FLOAT_STACK_CHECK'] = 0xc0000092
status_codes['NT_STATUS_FLOAT_UNDERFLOW'] = 0xc0000093
status_codes['NT_STATUS_INTEGER_DIVIDE_BY_ZERO'] = 0xc0000094
status_codes['NT_STATUS_INTEGER_OVERFLOW'] = 0xc0000095
status_codes['NT_STATUS_PRIVILEGED_INSTRUCTION'] = 0xc0000096
status_codes['NT_STATUS_TOO_MANY_PAGING_FILES'] = 0xc0000097
status_codes['NT_STATUS_FILE_INVALID'] = 0xc0000098
status_codes['NT_STATUS_ALLOTTED_SPACE_EXCEEDED'] = 0xc0000099
status_codes['NT_STATUS_INSUFFICIENT_RESOURCES'] = 0xc000009a
status_codes['NT_STATUS_DFS_EXIT_PATH_FOUND'] = 0xc000009b
status_codes['NT_STATUS_DEVICE_DATA_ERROR'] = 0xc000009c
status_codes['NT_STATUS_DEVICE_NOT_CONNECTED'] = 0xc000009d
status_codes['NT_STATUS_DEVICE_POWER_FAILURE'] = 0xc000009e
status_codes['NT_STATUS_FREE_VM_NOT_AT_BASE'] = 0xc000009f
status_codes['NT_STATUS_MEMORY_NOT_ALLOCATED'] = 0xc00000a0
status_codes['NT_STATUS_WORKING_SET_QUOTA'] = 0xc00000a1
status_codes['NT_STATUS_MEDIA_WRITE_PROTECTED'] = 0xc00000a2
status_codes['NT_STATUS_DEVICE_NOT_READY'] = 0xc00000a3
status_codes['NT_STATUS_INVALID_GROUP_ATTRIBUTES'] = 0xc00000a4
status_codes['NT_STATUS_BAD_IMPERSONATION_LEVEL'] = 0xc00000a5
status_codes['NT_STATUS_CANT_OPEN_ANONYMOUS'] = 0xc00000a6
status_codes['NT_STATUS_BAD_VALIDATION_CLASS'] = 0xc00000a7
status_codes['NT_STATUS_BAD_TOKEN_TYPE'] = 0xc00000a8
status_codes['NT_STATUS_BAD_MASTER_BOOT_RECORD'] = 0xc00000a9
status_codes['NT_STATUS_INSTRUCTION_MISALIGNMENT'] = 0xc00000aa
status_codes['NT_STATUS_INSTANCE_NOT_AVAILABLE'] = 0xc00000ab
status_codes['NT_STATUS_PIPE_NOT_AVAILABLE'] = 0xc00000ac
status_codes['NT_STATUS_INVALID_PIPE_STATE'] = 0xc00000ad
status_codes['NT_STATUS_PIPE_BUSY'] = 0xc00000ae
status_codes['NT_STATUS_ILLEGAL_FUNCTION'] = 0xc00000af
status_codes['NT_STATUS_PIPE_DISCONNECTED'] = 0xc00000b0
status_codes['NT_STATUS_PIPE_CLOSING'] = 0xc00000b1
status_codes['NT_STATUS_PIPE_CONNECTED'] = 0xc00000b2
status_codes['NT_STATUS_PIPE_LISTENING'] = 0xc00000b3
status_codes['NT_STATUS_INVALID_READ_MODE'] = 0xc00000b4
status_codes['NT_STATUS_IO_TIMEOUT'] = 0xc00000b5
status_codes['NT_STATUS_FILE_FORCED_CLOSED'] = 0xc00000b6
status_codes['NT_STATUS_PROFILING_NOT_STARTED'] = 0xc00000b7
status_codes['NT_STATUS_PROFILING_NOT_STOPPED'] = 0xc00000b8
status_codes['NT_STATUS_COULD_NOT_INTERPRET'] = 0xc00000b9
status_codes['NT_STATUS_FILE_IS_A_DIRECTORY'] = 0xc00000ba
status_codes['NT_STATUS_NOT_SUPPORTED'] = 0xc00000bb
status_codes['NT_STATUS_REMOTE_NOT_LISTENING'] = 0xc00000bc
status_codes['NT_STATUS_DUPLICATE_NAME'] = 0xc00000bd
status_codes['NT_STATUS_BAD_NETWORK_PATH'] = 0xc00000be
status_codes['NT_STATUS_NETWORK_BUSY'] = 0xc00000bf
status_codes['NT_STATUS_DEVICE_DOES_NOT_EXIST'] = 0xc00000c0
status_codes['NT_STATUS_TOO_MANY_COMMANDS'] = 0xc00000c1
status_codes['NT_STATUS_ADAPTER_HARDWARE_ERROR'] = 0xc00000c2
status_codes['NT_STATUS_INVALID_NETWORK_RESPONSE'] = 0xc00000c3
status_codes['NT_STATUS_UNEXPECTED_NETWORK_ERROR'] = 0xc00000c4
status_codes['NT_STATUS_BAD_REMOTE_ADAPTER'] = 0xc00000c5
status_codes['NT_STATUS_PRINT_QUEUE_FULL'] = 0xc00000c6
status_codes['NT_STATUS_NO_SPOOL_SPACE'] = 0xc00000c7
status_codes['NT_STATUS_PRINT_CANCELLED'] = 0xc00000c8
status_codes['NT_STATUS_NETWORK_NAME_DELETED'] = 0xc00000c9
status_codes['NT_STATUS_NETWORK_ACCESS_DENIED'] = 0xc00000ca
status_codes['NT_STATUS_BAD_DEVICE_TYPE'] = 0xc00000cb
status_codes['NT_STATUS_BAD_NETWORK_NAME'] = 0xc00000cc
status_codes['NT_STATUS_TOO_MANY_NAMES'] = 0xc00000cd
status_codes['NT_STATUS_TOO_MANY_SESSIONS'] = 0xc00000ce
status_codes['NT_STATUS_SHARING_PAUSED'] = 0xc00000cf
status_codes['NT_STATUS_REQUEST_NOT_ACCEPTED'] = 0xc00000d0
status_codes['NT_STATUS_REDIRECTOR_PAUSED'] = 0xc00000d1
status_codes['NT_STATUS_NET_WRITE_FAULT'] = 0xc00000d2
status_codes['NT_STATUS_PROFILING_AT_LIMIT'] = 0xc00000d3
status_codes['NT_STATUS_NOT_SAME_DEVICE'] = 0xc00000d4
status_codes['NT_STATUS_FILE_RENAMED'] = 0xc00000d5
status_codes['NT_STATUS_VIRTUAL_CIRCUIT_CLOSED'] = 0xc00000d6
status_codes['NT_STATUS_NO_SECURITY_ON_OBJECT'] = 0xc00000d7
status_codes['NT_STATUS_CANT_WAIT'] = 0xc00000d8
status_codes['NT_STATUS_PIPE_EMPTY'] = 0xc00000d9
status_codes['NT_STATUS_CANT_ACCESS_DOMAIN_INFO'] = 0xc00000da
status_codes['NT_STATUS_CANT_TERMINATE_SELF'] = 0xc00000db
status_codes['NT_STATUS_INVALID_SERVER_STATE'] = 0xc00000dc
status_codes['NT_STATUS_INVALID_DOMAIN_STATE'] = 0xc00000dd
status_codes['NT_STATUS_INVALID_DOMAIN_ROLE'] = 0xc00000de
status_codes['NT_STATUS_NO_SUCH_DOMAIN'] = 0xc00000df
status_codes['NT_STATUS_DOMAIN_EXISTS'] = 0xc00000e0
status_codes['NT_STATUS_DOMAIN_LIMIT_EXCEEDED'] = 0xc00000e1
status_codes['NT_STATUS_OPLOCK_NOT_GRANTED'] = 0xc00000e2
status_codes['NT_STATUS_INVALID_OPLOCK_PROTOCOL'] = 0xc00000e3
status_codes['NT_STATUS_INTERNAL_DB_CORRUPTION'] = 0xc00000e4
status_codes['NT_STATUS_INTERNAL_ERROR'] = 0xc00000e5
status_codes['NT_STATUS_GENERIC_NOT_MAPPED'] = 0xc00000e6
status_codes['NT_STATUS_BAD_DESCRIPTOR_FORMAT'] = 0xc00000e7
status_codes['NT_STATUS_INVALID_USER_BUFFER'] = 0xc00000e8
status_codes['NT_STATUS_UNEXPECTED_IO_ERROR'] = 0xc00000e9
status_codes['NT_STATUS_UNEXPECTED_MM_CREATE_ERR'] = 0xc00000ea
status_codes['NT_STATUS_UNEXPECTED_MM_MAP_ERROR'] = 0xc00000eb
status_codes['NT_STATUS_UNEXPECTED_MM_EXTEND_ERR'] = 0xc00000ec
status_codes['NT_STATUS_NOT_LOGON_PROCESS'] = 0xc00000ed
status_codes['NT_STATUS_LOGON_SESSION_EXISTS'] = 0xc00000ee
status_codes['NT_STATUS_INVALID_PARAMETER_1'] = 0xc00000ef
status_codes['NT_STATUS_INVALID_PARAMETER_2'] = 0xc00000f0
status_codes['NT_STATUS_INVALID_PARAMETER_3'] = 0xc00000f1
status_codes['NT_STATUS_INVALID_PARAMETER_4'] = 0xc00000f2
status_codes['NT_STATUS_INVALID_PARAMETER_5'] = 0xc00000f3
status_codes['NT_STATUS_INVALID_PARAMETER_6'] = 0xc00000f4
status_codes['NT_STATUS_INVALID_PARAMETER_7'] = 0xc00000f5
status_codes['NT_STATUS_INVALID_PARAMETER_8'] = 0xc00000f6
status_codes['NT_STATUS_INVALID_PARAMETER_9'] = 0xc00000f7
status_codes['NT_STATUS_INVALID_PARAMETER_10'] = 0xc00000f8
status_codes['NT_STATUS_INVALID_PARAMETER_11'] = 0xc00000f9
status_codes['NT_STATUS_INVALID_PARAMETER_12'] = 0xc00000fa
status_codes['NT_STATUS_REDIRECTOR_NOT_STARTED'] = 0xc00000fb
status_codes['NT_STATUS_REDIRECTOR_STARTED'] = 0xc00000fc
status_codes['NT_STATUS_STACK_OVERFLOW'] = 0xc00000fd
status_codes['NT_STATUS_NO_SUCH_PACKAGE'] = 0xc00000fe
status_codes['NT_STATUS_BAD_FUNCTION_TABLE'] = 0xc00000ff
status_codes['NT_STATUS_DIRECTORY_NOT_EMPTY'] = 0xc0000101
status_codes['NT_STATUS_FILE_CORRUPT_ERROR'] = 0xc0000102
status_codes['NT_STATUS_NOT_A_DIRECTORY'] = 0xc0000103
status_codes['NT_STATUS_BAD_LOGON_SESSION_STATE'] = 0xc0000104
status_codes['NT_STATUS_LOGON_SESSION_COLLISION'] = 0xc0000105
status_codes['NT_STATUS_NAME_TOO_LONG'] = 0xc0000106
status_codes['NT_STATUS_FILES_OPEN'] = 0xc0000107
status_codes['NT_STATUS_CONNECTION_IN_USE'] = 0xc0000108
status_codes['NT_STATUS_MESSAGE_NOT_FOUND'] = 0xc0000109
status_codes['NT_STATUS_PROCESS_IS_TERMINATING'] = 0xc000010a
status_codes['NT_STATUS_INVALID_LOGON_TYPE'] = 0xc000010b
status_codes['NT_STATUS_NO_GUID_TRANSLATION'] = 0xc000010c
status_codes['NT_STATUS_CANNOT_IMPERSONATE'] = 0xc000010d
status_codes['NT_STATUS_IMAGE_ALREADY_LOADED'] = 0xc000010e
status_codes['NT_STATUS_ABIOS_NOT_PRESENT'] = 0xc000010f
status_codes['NT_STATUS_ABIOS_LID_NOT_EXIST'] = 0xc0000110
status_codes['NT_STATUS_ABIOS_LID_ALREADY_OWNED'] = 0xc0000111
status_codes['NT_STATUS_ABIOS_NOT_LID_OWNER'] = 0xc0000112
status_codes['NT_STATUS_ABIOS_INVALID_COMMAND'] = 0xc0000113
status_codes['NT_STATUS_ABIOS_INVALID_LID'] = 0xc0000114
status_codes['NT_STATUS_ABIOS_SELECTOR_NOT_AVAILABLE'] = 0xc0000115
status_codes['NT_STATUS_ABIOS_INVALID_SELECTOR'] = 0xc0000116
status_codes['NT_STATUS_NO_LDT'] = 0xc0000117
status_codes['NT_STATUS_INVALID_LDT_SIZE'] = 0xc0000118
status_codes['NT_STATUS_INVALID_LDT_OFFSET'] = 0xc0000119
status_codes['NT_STATUS_INVALID_LDT_DESCRIPTOR'] = 0xc000011a
status_codes['NT_STATUS_INVALID_IMAGE_NE_FORMAT'] = 0xc000011b
status_codes['NT_STATUS_RXACT_INVALID_STATE'] = 0xc000011c
status_codes['NT_STATUS_RXACT_COMMIT_FAILURE'] = 0xc000011d
status_codes['NT_STATUS_MAPPED_FILE_SIZE_ZERO'] = 0xc000011e
status_codes['NT_STATUS_TOO_MANY_OPENED_FILES'] = 0xc000011f
status_codes['NT_STATUS_CANCELLED'] = 0xc0000120
status_codes['NT_STATUS_CANNOT_DELETE'] = 0xc0000121
status_codes['NT_STATUS_INVALID_COMPUTER_NAME'] = 0xc0000122
status_codes['NT_STATUS_FILE_DELETED'] = 0xc0000123
status_codes['NT_STATUS_SPECIAL_ACCOUNT'] = 0xc0000124
status_codes['NT_STATUS_SPECIAL_GROUP'] = 0xc0000125
status_codes['NT_STATUS_SPECIAL_USER'] = 0xc0000126
status_codes['NT_STATUS_MEMBERS_PRIMARY_GROUP'] = 0xc0000127
status_codes['NT_STATUS_FILE_CLOSED'] = 0xc0000128
status_codes['NT_STATUS_TOO_MANY_THREADS'] = 0xc0000129
status_codes['NT_STATUS_THREAD_NOT_IN_PROCESS'] = 0xc000012a
status_codes['NT_STATUS_TOKEN_ALREADY_IN_USE'] = 0xc000012b
status_codes['NT_STATUS_PAGEFILE_QUOTA_EXCEEDED'] = 0xc000012c
status_codes['NT_STATUS_COMMITMENT_LIMIT'] = 0xc000012d
status_codes['NT_STATUS_INVALID_IMAGE_LE_FORMAT'] = 0xc000012e
status_codes['NT_STATUS_INVALID_IMAGE_NOT_MZ'] = 0xc000012f
status_codes['NT_STATUS_INVALID_IMAGE_PROTECT'] = 0xc0000130
status_codes['NT_STATUS_INVALID_IMAGE_WIN_16'] = 0xc0000131
status_codes['NT_STATUS_LOGON_SERVER_CONFLICT'] = 0xc0000132
status_codes['NT_STATUS_TIME_DIFFERENCE_AT_DC'] = 0xc0000133
status_codes['NT_STATUS_SYNCHRONIZATION_REQUIRED'] = 0xc0000134
status_codes['NT_STATUS_DLL_NOT_FOUND'] = 0xc0000135
status_codes['NT_STATUS_OPEN_FAILED'] = 0xc0000136
status_codes['NT_STATUS_IO_PRIVILEGE_FAILED'] = 0xc0000137
status_codes['NT_STATUS_ORDINAL_NOT_FOUND'] = 0xc0000138
status_codes['NT_STATUS_ENTRYPOINT_NOT_FOUND'] = 0xc0000139
status_codes['NT_STATUS_CONTROL_C_EXIT'] = 0xc000013a
status_codes['NT_STATUS_LOCAL_DISCONNECT'] = 0xc000013b
status_codes['NT_STATUS_REMOTE_DISCONNECT'] = 0xc000013c
status_codes['NT_STATUS_REMOTE_RESOURCES'] = 0xc000013d
status_codes['NT_STATUS_LINK_FAILED'] = 0xc000013e
status_codes['NT_STATUS_LINK_TIMEOUT'] = 0xc000013f
status_codes['NT_STATUS_INVALID_CONNECTION'] = 0xc0000140
status_codes['NT_STATUS_INVALID_ADDRESS'] = 0xc0000141
status_codes['NT_STATUS_DLL_INIT_FAILED'] = 0xc0000142
status_codes['NT_STATUS_MISSING_SYSTEMFILE'] = 0xc0000143
status_codes['NT_STATUS_UNHANDLED_EXCEPTION'] = 0xc0000144
status_codes['NT_STATUS_APP_INIT_FAILURE'] = 0xc0000145
status_codes['NT_STATUS_PAGEFILE_CREATE_FAILED'] = 0xc0000146
status_codes['NT_STATUS_NO_PAGEFILE'] = 0xc0000147
status_codes['NT_STATUS_INVALID_LEVEL'] = 0xc0000148
status_codes['NT_STATUS_WRONG_PASSWORD_CORE'] = 0xc0000149
status_codes['NT_STATUS_ILLEGAL_FLOAT_CONTEXT'] = 0xc000014a
status_codes['NT_STATUS_PIPE_BROKEN'] = 0xc000014b
status_codes['NT_STATUS_REGISTRY_CORRUPT'] = 0xc000014c
status_codes['NT_STATUS_REGISTRY_IO_FAILED'] = 0xc000014d
status_codes['NT_STATUS_NO_EVENT_PAIR'] = 0xc000014e
status_codes['NT_STATUS_UNRECOGNIZED_VOLUME'] = 0xc000014f
status_codes['NT_STATUS_SERIAL_NO_DEVICE_INITED'] = 0xc0000150
status_codes['NT_STATUS_NO_SUCH_ALIAS'] = 0xc0000151
status_codes['NT_STATUS_MEMBER_NOT_IN_ALIAS'] = 0xc0000152
status_codes['NT_STATUS_MEMBER_IN_ALIAS'] = 0xc0000153
status_codes['NT_STATUS_ALIAS_EXISTS'] = 0xc0000154
status_codes['NT_STATUS_LOGON_NOT_GRANTED'] = 0xc0000155
status_codes['NT_STATUS_TOO_MANY_SECRETS'] = 0xc0000156
status_codes['NT_STATUS_SECRET_TOO_LONG'] = 0xc0000157
status_codes['NT_STATUS_INTERNAL_DB_ERROR'] = 0xc0000158
status_codes['NT_STATUS_FULLSCREEN_MODE'] = 0xc0000159
status_codes['NT_STATUS_TOO_MANY_CONTEXT_IDS'] = 0xc000015a
status_codes['NT_STATUS_LOGON_TYPE_NOT_GRANTED'] = 0xc000015b
status_codes['NT_STATUS_NOT_REGISTRY_FILE'] = 0xc000015c
status_codes['NT_STATUS_NT_CROSS_ENCRYPTION_REQUIRED'] = 0xc000015d
status_codes['NT_STATUS_DOMAIN_CTRLR_CONFIG_ERROR'] = 0xc000015e
status_codes['NT_STATUS_FT_MISSING_MEMBER'] = 0xc000015f
status_codes['NT_STATUS_ILL_FORMED_SERVICE_ENTRY'] = 0xc0000160
status_codes['NT_STATUS_ILLEGAL_CHARACTER'] = 0xc0000161
status_codes['NT_STATUS_UNMAPPABLE_CHARACTER'] = 0xc0000162
status_codes['NT_STATUS_UNDEFINED_CHARACTER'] = 0xc0000163
status_codes['NT_STATUS_FLOPPY_VOLUME'] = 0xc0000164
status_codes['NT_STATUS_FLOPPY_ID_MARK_NOT_FOUND'] = 0xc0000165
status_codes['NT_STATUS_FLOPPY_WRONG_CYLINDER'] = 0xc0000166
status_codes['NT_STATUS_FLOPPY_UNKNOWN_ERROR'] = 0xc0000167
status_codes['NT_STATUS_FLOPPY_BAD_REGISTERS'] = 0xc0000168
status_codes['NT_STATUS_DISK_RECALIBRATE_FAILED'] = 0xc0000169
status_codes['NT_STATUS_DISK_OPERATION_FAILED'] = 0xc000016a
status_codes['NT_STATUS_DISK_RESET_FAILED'] = 0xc000016b
status_codes['NT_STATUS_SHARED_IRQ_BUSY'] = 0xc000016c
status_codes['NT_STATUS_FT_ORPHANING'] = 0xc000016d
status_codes['NT_STATUS_PARTITION_FAILURE'] = 0xc0000172
status_codes['NT_STATUS_INVALID_BLOCK_LENGTH'] = 0xc0000173
status_codes['NT_STATUS_DEVICE_NOT_PARTITIONED'] = 0xc0000174
status_codes['NT_STATUS_UNABLE_TO_LOCK_MEDIA'] = 0xc0000175
status_codes['NT_STATUS_UNABLE_TO_UNLOAD_MEDIA'] = 0xc0000176
status_codes['NT_STATUS_EOM_OVERFLOW'] = 0xc0000177
status_codes['NT_STATUS_NO_MEDIA'] = 0xc0000178
status_codes['NT_STATUS_NO_SUCH_MEMBER'] = 0xc000017a
status_codes['NT_STATUS_INVALID_MEMBER'] = 0xc000017b
status_codes['NT_STATUS_KEY_DELETED'] = 0xc000017c
status_codes['NT_STATUS_NO_LOG_SPACE'] = 0xc000017d
status_codes['NT_STATUS_TOO_MANY_SIDS'] = 0xc000017e
status_codes['NT_STATUS_LM_CROSS_ENCRYPTION_REQUIRED'] = 0xc000017f
status_codes['NT_STATUS_KEY_HAS_CHILDREN'] = 0xc0000180
status_codes['NT_STATUS_CHILD_MUST_BE_VOLATILE'] = 0xc0000181
status_codes['NT_STATUS_DEVICE_CONFIGURATION_ERROR'] = 0xc0000182
status_codes['NT_STATUS_DRIVER_INTERNAL_ERROR'] = 0xc0000183
status_codes['NT_STATUS_INVALID_DEVICE_STATE'] = 0xc0000184
status_codes['NT_STATUS_IO_DEVICE_ERROR'] = 0xc0000185
status_codes['NT_STATUS_DEVICE_PROTOCOL_ERROR'] = 0xc0000186
status_codes['NT_STATUS_BACKUP_CONTROLLER'] = 0xc0000187
status_codes['NT_STATUS_LOG_FILE_FULL'] = 0xc0000188
status_codes['NT_STATUS_TOO_LATE'] = 0xc0000189
status_codes['NT_STATUS_NO_TRUST_LSA_SECRET'] = 0xc000018a
status_codes['NT_STATUS_NO_TRUST_SAM_ACCOUNT'] = 0xc000018b
status_codes['NT_STATUS_TRUSTED_DOMAIN_FAILURE'] = 0xc000018c
status_codes['NT_STATUS_TRUSTED_RELATIONSHIP_FAILURE'] = 0xc000018d
status_codes['NT_STATUS_EVENTLOG_FILE_CORRUPT'] = 0xc000018e
status_codes['NT_STATUS_EVENTLOG_CANT_START'] = 0xc000018f
status_codes['NT_STATUS_TRUST_FAILURE'] = 0xc0000190
status_codes['NT_STATUS_MUTANT_LIMIT_EXCEEDED'] = 0xc0000191
status_codes['NT_STATUS_NETLOGON_NOT_STARTED'] = 0xc0000192
status_codes['NT_STATUS_ACCOUNT_EXPIRED'] = 0xc0000193
status_codes['NT_STATUS_POSSIBLE_DEADLOCK'] = 0xc0000194
status_codes['NT_STATUS_NETWORK_CREDENTIAL_CONFLICT'] = 0xc0000195
status_codes['NT_STATUS_REMOTE_SESSION_LIMIT'] = 0xc0000196
status_codes['NT_STATUS_EVENTLOG_FILE_CHANGED'] = 0xc0000197
status_codes['NT_STATUS_NOLOGON_INTERDOMAIN_TRUST_ACCOUNT'] = 0xc0000198
status_codes['NT_STATUS_NOLOGON_WORKSTATION_TRUST_ACCOUNT'] = 0xc0000199
status_codes['NT_STATUS_NOLOGON_SERVER_TRUST_ACCOUNT'] = 0xc000019a
status_codes['NT_STATUS_DOMAIN_TRUST_INCONSISTENT'] = 0xc000019b
status_codes['NT_STATUS_FS_DRIVER_REQUIRED'] = 0xc000019c
status_codes['NT_STATUS_NO_USER_SESSION_KEY'] = 0xc0000202
status_codes['NT_STATUS_USER_SESSION_DELETED'] = 0xc0000203
status_codes['NT_STATUS_RESOURCE_LANG_NOT_FOUND'] = 0xc0000204
status_codes['NT_STATUS_INSUFF_SERVER_RESOURCES'] = 0xc0000205
status_codes['NT_STATUS_INVALID_BUFFER_SIZE'] = 0xc0000206
status_codes['NT_STATUS_INVALID_ADDRESS_COMPONENT'] = 0xc0000207
status_codes['NT_STATUS_INVALID_ADDRESS_WILDCARD'] = 0xc0000208
status_codes['NT_STATUS_TOO_MANY_ADDRESSES'] = 0xc0000209
status_codes['NT_STATUS_ADDRESS_ALREADY_EXISTS'] = 0xc000020a
status_codes['NT_STATUS_ADDRESS_CLOSED'] = 0xc000020b
status_codes['NT_STATUS_CONNECTION_DISCONNECTED'] = 0xc000020c
status_codes['NT_STATUS_CONNECTION_RESET'] = 0xc000020d
status_codes['NT_STATUS_TOO_MANY_NODES'] = 0xc000020e
status_codes['NT_STATUS_TRANSACTION_ABORTED'] = 0xc000020f
status_codes['NT_STATUS_TRANSACTION_TIMED_OUT'] = 0xc0000210
status_codes['NT_STATUS_TRANSACTION_NO_RELEASE'] = 0xc0000211
status_codes['NT_STATUS_TRANSACTION_NO_MATCH'] = 0xc0000212
status_codes['NT_STATUS_TRANSACTION_RESPONDED'] = 0xc0000213
status_codes['NT_STATUS_TRANSACTION_INVALID_ID'] = 0xc0000214
status_codes['NT_STATUS_TRANSACTION_INVALID_TYPE'] = 0xc0000215
status_codes['NT_STATUS_NOT_SERVER_SESSION'] = 0xc0000216
status_codes['NT_STATUS_NOT_CLIENT_SESSION'] = 0xc0000217
status_codes['NT_STATUS_CANNOT_LOAD_REGISTRY_FILE'] = 0xc0000218
status_codes['NT_STATUS_DEBUG_ATTACH_FAILED'] = 0xc0000219
status_codes['NT_STATUS_SYSTEM_PROCESS_TERMINATED'] = 0xc000021a
status_codes['NT_STATUS_DATA_NOT_ACCEPTED'] = 0xc000021b
status_codes['NT_STATUS_NO_BROWSER_SERVERS_FOUND'] = 0xc000021c
status_codes['NT_STATUS_VDM_HARD_ERROR'] = 0xc000021d
status_codes['NT_STATUS_DRIVER_CANCEL_TIMEOUT'] = 0xc000021e
status_codes['NT_STATUS_REPLY_MESSAGE_MISMATCH'] = 0xc000021f
status_codes['NT_STATUS_MAPPED_ALIGNMENT'] = 0xc0000220
status_codes['NT_STATUS_IMAGE_CHECKSUM_MISMATCH'] = 0xc0000221
status_codes['NT_STATUS_LOST_WRITEBEHIND_DATA'] = 0xc0000222
status_codes['NT_STATUS_CLIENT_SERVER_PARAMETERS_INVALID'] = 0xc0000223
status_codes['NT_STATUS_PASSWORD_MUST_CHANGE'] = 0xc0000224
status_codes['NT_STATUS_NOT_FOUND'] = 0xc0000225
status_codes['NT_STATUS_NOT_TINY_STREAM'] = 0xc0000226
status_codes['NT_STATUS_RECOVERY_FAILURE'] = 0xc0000227
status_codes['NT_STATUS_STACK_OVERFLOW_READ'] = 0xc0000228
status_codes['NT_STATUS_FAIL_CHECK'] = 0xc0000229
status_codes['NT_STATUS_DUPLICATE_OBJECTID'] = 0xc000022a
status_codes['NT_STATUS_OBJECTID_EXISTS'] = 0xc000022b
status_codes['NT_STATUS_CONVERT_TO_LARGE'] = 0xc000022c
status_codes['NT_STATUS_RETRY'] = 0xc000022d
status_codes['NT_STATUS_FOUND_OUT_OF_SCOPE'] = 0xc000022e
status_codes['NT_STATUS_ALLOCATE_BUCKET'] = 0xc000022f
status_codes['NT_STATUS_PROPSET_NOT_FOUND'] = 0xc0000230
status_codes['NT_STATUS_MARSHALL_OVERFLOW'] = 0xc0000231
status_codes['NT_STATUS_INVALID_VARIANT'] = 0xc0000232
status_codes['NT_STATUS_DOMAIN_CONTROLLER_NOT_FOUND'] = 0xc0000233
status_codes['NT_STATUS_ACCOUNT_LOCKED_OUT'] = 0xc0000234
status_codes['NT_STATUS_HANDLE_NOT_CLOSABLE'] = 0xc0000235
status_codes['NT_STATUS_CONNECTION_REFUSED'] = 0xc0000236
status_codes['NT_STATUS_GRACEFUL_DISCONNECT'] = 0xc0000237
status_codes['NT_STATUS_ADDRESS_ALREADY_ASSOCIATED'] = 0xc0000238
status_codes['NT_STATUS_ADDRESS_NOT_ASSOCIATED'] = 0xc0000239
status_codes['NT_STATUS_CONNECTION_INVALID'] = 0xc000023a
status_codes['NT_STATUS_CONNECTION_ACTIVE'] = 0xc000023b
status_codes['NT_STATUS_NETWORK_UNREACHABLE'] = 0xc000023c
status_codes['NT_STATUS_HOST_UNREACHABLE'] = 0xc000023d
status_codes['NT_STATUS_PROTOCOL_UNREACHABLE'] = 0xc000023e
status_codes['NT_STATUS_PORT_UNREACHABLE'] = 0xc000023f
status_codes['NT_STATUS_REQUEST_ABORTED'] = 0xc0000240
status_codes['NT_STATUS_CONNECTION_ABORTED'] = 0xc0000241
status_codes['NT_STATUS_BAD_COMPRESSION_BUFFER'] = 0xc0000242
status_codes['NT_STATUS_USER_MAPPED_FILE'] = 0xc0000243
status_codes['NT_STATUS_AUDIT_FAILED'] = 0xc0000244
status_codes['NT_STATUS_TIMER_RESOLUTION_NOT_SET'] = 0xc0000245
status_codes['NT_STATUS_CONNECTION_COUNT_LIMIT'] = 0xc0000246
status_codes['NT_STATUS_LOGIN_TIME_RESTRICTION'] = 0xc0000247
status_codes['NT_STATUS_LOGIN_WKSTA_RESTRICTION'] = 0xc0000248
status_codes['NT_STATUS_IMAGE_MP_UP_MISMATCH'] = 0xc0000249
status_codes['NT_STATUS_INSUFFICIENT_LOGON_INFO'] = 0xc0000250
status_codes['NT_STATUS_BAD_DLL_ENTRYPOINT'] = 0xc0000251
status_codes['NT_STATUS_BAD_SERVICE_ENTRYPOINT'] = 0xc0000252
status_codes['NT_STATUS_LPC_REPLY_LOST'] = 0xc0000253
status_codes['NT_STATUS_IP_ADDRESS_CONFLICT1'] = 0xc0000254
status_codes['NT_STATUS_IP_ADDRESS_CONFLICT2'] = 0xc0000255
status_codes['NT_STATUS_REGISTRY_QUOTA_LIMIT'] = 0xc0000256
status_codes['NT_STATUS_PATH_NOT_COVERED'] = 0xc0000257
status_codes['NT_STATUS_NO_CALLBACK_ACTIVE'] = 0xc0000258
status_codes['NT_STATUS_LICENSE_QUOTA_EXCEEDED'] = 0xc0000259
status_codes['NT_STATUS_PWD_TOO_SHORT'] = 0xc000025a
status_codes['NT_STATUS_PWD_TOO_RECENT'] = 0xc000025b
status_codes['NT_STATUS_PWD_HISTORY_CONFLICT'] = 0xc000025c
status_codes['NT_STATUS_PLUGPLAY_NO_DEVICE'] = 0xc000025e
status_codes['NT_STATUS_UNSUPPORTED_COMPRESSION'] = 0xc000025f
status_codes['NT_STATUS_INVALID_HW_PROFILE'] = 0xc0000260
status_codes['NT_STATUS_INVALID_PLUGPLAY_DEVICE_PATH'] = 0xc0000261
status_codes['NT_STATUS_DRIVER_ORDINAL_NOT_FOUND'] = 0xc0000262
status_codes['NT_STATUS_DRIVER_ENTRYPOINT_NOT_FOUND'] = 0xc0000263
status_codes['NT_STATUS_RESOURCE_NOT_OWNED'] = 0xc0000264
status_codes['NT_STATUS_TOO_MANY_LINKS'] = 0xc0000265
status_codes['NT_STATUS_QUOTA_LIST_INCONSISTENT'] = 0xc0000266
status_codes['NT_STATUS_FILE_IS_OFFLINE'] = 0xc0000267
status_codes['NT_STATUS_DS_NO_MORE_RIDS'] = 0xc00002a8
status_codes['NT_STATUS_NOT_A_REPARSE_POINT'] = 0xc0000275
status_codes['NT_STATUS_NO_SUCH_JOB'] = 0xc000EDE
for i, v in pairs(status_codes) do
	status_names[v] = i
end
local function get_status_name(status)
	if(status_names[status] == nil) then
		return string.format("NT_STATUS_UNKNOWN (0x%08x)", status)
	else
		return status_names[status]
	end
end



--- Determines whether or not SMB checks are possible on this host, and, if they are, 
--  which port is best to use. This is how it decides:\n
--\n
-- a) If port tcp/445 is open, use it for a raw connection\n
-- b) Otherwise, if ports tcp/139 and udp/137 are open, do a NetBIOS connection. Since
--    UDP scanning isn't default, we're also ok with udp/137 in an unknown state. 
--
--@param host The host object. 
--@return The port number to use, or nil if we don't have an SMB port
function get_port(host)
	local port_u137 = nmap.get_port_state(host, {number=137, protocol="udp"})
	local port_t139 = nmap.get_port_state(host, {number=139, protocol="tcp"})
	local port_t445 = nmap.get_port_state(host, {number=445, protocol="tcp"})

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

--- Begins a SMB session, automatically determining the best way to connect. Also starts a mutex.
--  This prevents multiple threads from making queries at the same time (which breaks
--  SMB). 
--
-- @param host The host object
-- @return (status, socket) if the status is true, result is the newly crated socket. 
--         otherwise, socket is the error message. 
function start(host)
	local port = get_port(host)
	local status, result

	if(port == nil) then
		return false, "Couldn't find a valid port to check"
	end

	stdnse.print_debug(3, "SMB: Attempting to lock SMB mutex")
	mutex "lock"
	stdnse.print_debug(3, "SMB: Mutex lock obtained")

	if(port == 445) then
		status, result = start_raw(host, port)
		if(status == false) then
			stdnse.print_debug(3, "SMB: Attempting to release SMB mutex (1)")
			mutex "done"
			stdnse.print_debug(3, "SMB: SMB mutex released (1)")
		end
	
		return status, result
	elseif(port == 139) then
		status, result = start_netbios(host, port)
		if(status == false) then
			stdnse.print_debug(3, "SMB: Attempting to release SMB mutex (2)")
			mutex "done"
			stdnse.print_debug(3, "SMB: SMB mutex released (2)")
		end

		return status, result
	end

	stdnse.print_debug(3, "SMB: Attempting to release SMB mutex (3)")
	mutex "done"
	stdnse.print_debug(3, "SMB: SMB mutex released (3)")

	return false, "Couldn't find a valid port to check"
end

--- Kills the SMB connection, closes the socket, and releases the mutex. Because of the mutex 
--  being released, a script HAS to call <code>stop()</code> before it exits, no matter why it's exiting! 
--
--  In addition to killing the connection, this function can log off the user and disconnect
--  a tree. To do so, the appropriate parameters are passed. For a logoff, the uid is required. 
--  For a tree disconnect, both tid and uid are required. 
--
--@param socket The socket associated with the connection. 
--@param uid    [optional] If given, will do a logoff before disconnecting. 
--@param tid    [optional] If given, will do a tree disconnect before disconnecting. 
--@return (status, result) If status is false, result is an error message. Otherwise, result
--        is undefined. 
function stop(socket, uid, tid) 

	if(tid ~= nil and uid ~= nil) then
		tree_disconnect(socket, uid, tid)
	end

	if(uid ~= nil) then
		logoff(socket, uid)
	end

	stdnse.print_debug(3, "SMB: Attempting to release SMB mutex (4)")
	mutex "done"
	stdnse.print_debug(3, "SMB: SMB mutex released (4)")

	stdnse.print_debug(2, "Closing SMB socket")
	if(socket ~= nil) then
		local status, err = socket:close()

		if(status == false) then
			return false, "Failed to close socket: " .. err
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

	status, err = socket:connect(host.ip, port, "tcp")

	if(status == false) then
		return false, "Failed to connect to host: " .. err
	end

	return true, socket
end

--- This function will take a string like "a.b.c.d" and return "a", "a.b", "a.b.c", and "a.b.c.d". 
--  This is used for discovering NetBIOS names. 
--@param name The name to take apart
--@param list [optional] If list is set, names will be added to it then returned
--@return An array of the sub names
local function get_subnames(name, list)
	local i = -1
	local list = list or {}

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

--- Begins a SMB session over NetBIOS. This requires a NetBIOS Session Start message to 
--  be sent first, which in turn requires the NetBIOS name. The name can be provided as
--  a parameter, or it can be automatically determined. \n
--\n
-- Automatically determining the name is interesting, to say the least. Here are the names
-- it tries, and the order it tries them in:\n
-- 1) The name the user provided, if present\n
-- 2) The name pulled from NetBIOS (udp/137), if possible\n
-- 3) The generic name "*SMBSERVER"\n
-- 4) Each subset of the domain name (for example, scanme.insecure.org would attempt "scanme",
--    "scanme.insecure", and "scanme.insecure.org")\n
--\n
-- This whole sequence is a little hackish, but it's the standard way of doing it. 
--
--@param host The host object to check. 
--@param port The port to use (most likely 139).
--@param name [optional] The NetBIOS name of the host. Will attempt to automatically determine
--            if it isn't given. 
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
		new_names = get_subnames(host.name)
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
		stdnse.print_debug(1, "Trying to start NetBIOS session with name = '%s'", name)
		-- Request a NetBIOS session
		session_request = bin.pack(">CCSzz", 
					0x81,                        -- session request
					0x00,                        -- flags
					0x44,                        -- length
					netbios.name_encode(name),   -- server name
					netbios.name_encode("NMAP")  -- client name
				);

		stdnse.print_debug(3, "Connecting to %s", host.ip)
		status, err = socket:connect(host.ip, port, "tcp")
		if(status == false) then
			socket:close()
			return false, "Failed to connect: " .. err
		end

		-- Send the session request
		stdnse.print_debug(3, "Sending NetBIOS session request with name %s", name)
		status, err = socket:send(session_request)
		if(status == false) then
			socket:close()
			return false, "Failed to send: " .. err
		end
		socket:set_timeout(1000)
	
		-- Receive the session response
		stdnse.print_debug(3, "Receiving NetBIOS session response")
		status, result = socket:receive_bytes(4);
		if(status == false) then
			socket:close()
			return false, "Failed to close socket: " .. result
		end
		pos, result, flags, length = bin.unpack(">CCS", result)
	
		-- Check for a position session response (0x82)
		if result == 0x82 then
			stdnse.print_debug(3, "Successfully established NetBIOS session with server name %s", name)
			return true, socket
		end

		-- If the session failed, close the socket and try the next name
		stdnse.print_debug(3, "Session request failed, trying next name")
		socket:close()
	
		-- Try the next name
		i = i + 1

	until i > #names

	-- We reached the end of our names list
	stdnse.print_debug(3, "None of the NetBIOS names worked!")
	return false, "Couldn't find a NetBIOS name that works for the server. Sorry!"
end



--- Creates a string containing a SMB packet header. The header looks like this:\n
-- <code>
-- --------------------------------------------------------------------------------------------------\n
-- | 31 30 29 28 27 26 25 24 23 22 21 20 19 18 17 16 15 14 13 12 11 10 9  8  7  6  5  4  3  2  1  0 |\n
-- --------------------------------------------------------------------------------------------------\n
-- |         0xFF           |          'S'          |        'M'            |         'B'           |\n
-- --------------------------------------------------------------------------------------------------\n
-- |        Command         |                             Status...                                 |\n
-- --------------------------------------------------------------------------------------------------\n
-- |    ...Status           |        Flags          |                    Flags2                     |\n
-- --------------------------------------------------------------------------------------------------\n
-- |                    PID_high                    |                  Signature.....               |\n
-- --------------------------------------------------------------------------------------------------\n
-- |                                        ....Signature....                                       |\n
-- --------------------------------------------------------------------------------------------------\n
-- |              ....Signature                     |                    Unused                     |\n
-- --------------------------------------------------------------------------------------------------\n
-- |                      TID                       |                     PID                       |\n
-- --------------------------------------------------------------------------------------------------\n
-- |                      UID                       |                     MID                       |\n
-- ------------------------------------------------------------------------------------------------- \n
-- </code>
--
-- All fields are, incidentally, encoded in little endian byte order. \n
--\n
-- For the purposes here, the program doesn't care about most of the fields so they're given default \n
-- values. The fields of interest are:\n
-- * Command -- The command of the packet (<code>SMB_COM_NEGOTIATE</code>, <code>SMB_COM_SESSION_SETUP_ANDX</code>, etc)\n
-- * UID/TID -- Sent by the server, and just have to be echoed back\n
--@param command The command to use.
--@param uid     The UserID, which is returned by <code>SMB_COM_SESSION_SETUP_ANDX</code> (0 otherwise)
--@param tid     The TreeID, which is returned by <code>SMB_COM_TREE_CONNECT_ANDX</code> (0 otherwise)
--@return A binary string containing the packed packet header. 
local function smb_encode_header(command, uid, tid)

	-- Used for the header
	local smb = string.char(0xFF) .. "SMB"

	-- Pretty much every flags is deprecated. We set these two because they're required to be on. 
	local flags  = bit.bor(0x10, 0x08) -- SMB_FLAGS_CANONICAL_PATHNAMES | SMB_FLAGS_CASELESS_PATHNAMES
	-- These flags are less deprecated. We negotiate 32-bit status codes and long names. We also don't include Unicode, which tells
	-- the server that we deal in ASCII. 
	local flags2 = bit.bor(0x4000, 0x0040, 0x0001) -- SMB_FLAGS2_32BIT_STATUS | SMB_FLAGS2_IS_LONG_NAME | SMB_FLAGS2_KNOWS_LONG_NAMES

	local header = bin.pack("<CCCCCICSSLSSSSS",
				smb:byte(1),  -- Header
				smb:byte(2),  -- Header
				smb:byte(3),  -- Header
				smb:byte(4),  -- Header
				command,      -- Command
				0,            -- status
				flags,        -- flags
				flags2,       -- flags2
				0,            -- extra (pid_high)
				0,            -- extra (signature)
				0,            -- extra (unused)
				tid,          -- tid
				0,            -- pid
				uid,          -- uid
				0             -- mid
			)

	return header
end

--- Converts a string containing the parameters section into the encoded parameters string. 
-- The encoding is simple:\n
-- (1 byte)   The number of 2-byte values in the parameters section\n
-- (variable) The parameter section\n
-- This is automatically done by <code>smb_send()</code>. 
-- 
-- @param parameters The parameters section. 
-- @return The encoded parameters. 
local function smb_encode_parameters(parameters)
	return bin.pack("<CA", string.len(parameters) / 2, parameters)
end

--- Converts a string containing the data section into the encoded data string. 
-- The encoding is simple:\n
-- (2 bytes)  The number of bytes in the data section\n
-- (variable) The data section\n
-- This is automatically done by <code>smb_send()</code>. 
--
-- @param data The data section. 
-- @return The encoded data.
local function smb_encode_data(data)
	return bin.pack("<SA", string.len(data), data)
end

--- Prepends the NetBIOS header to the packet, which is essentially the length, encoded
--  in 4 bytes of big endian, and sends it out. The length field is actually 17 or 24 bits 
--  wide, depending on whether or not we're using raw, but that shouldn't matter. 
--
--@param socket The socket to send the packet on.
--@param header The header, encoded with <code>smb_get_header()</code>.
--@param parameters The parameters
--@param data The data
--@return (result, err) If result is false, err is the error message. Otherwise, err is
--        undefined
function smb_send(socket, header, parameters, data)
    local encoded_parameters = smb_encode_parameters(parameters)
    local encoded_data       = smb_encode_data(data)
    local len = string.len(header) + string.len(encoded_parameters) + string.len(encoded_data)
    local out = bin.pack(">I<AAA", len, header, encoded_parameters, encoded_data)

	stdnse.print_debug(2, "Sending SMB packet (len: %d)", string.len(out))
    return socket:send(out)
end

--- Reads the next packet from the socket, and parses it into the header, parameters, 
--  and data. 
-- [TODO] This assumes that exactly one packet arrives, which may not be the case. 
--        Some buffering should happen here. Currently, we're waiting on 32 bytes, which
--        is the length of the header, but there's no guarantee that we get the entire
--        body. 
--@param socket The socket to read the packet from
--@return (status, header, parameters, data) If status is true, the header, 
--        parameters, and data are all the raw arrays (with the lengths already
--        removed). If status is false, header contains an error message and parameters/
--        data are undefined. 
function smb_read(socket)
	local status, result
	local pos, length, header, parameter_length, parameters, data_length, data

	-- Receive the response
	-- [TODO] set the timeout length per jah's strategy:
	--   http://seclists.org/nmap-dev/2008/q3/0702.html
	socket:set_timeout(1000)
	status, result = socket:receive_bytes(32);

	-- Make sure the connection is still alive
	if(status ~= true) then
		return false, "Failed to receive bytes: " .. result
	end

	-- The length of the packet is 4 bytes of big endian (for our purposes).
	-- The header is 32 bytes.
	pos, length, header   = bin.unpack(">I<A32", result)
	-- The parameters length is a 1-byte value.
	pos, parameter_length = bin.unpack("<C",     result, pos)
	-- Double the length parameter, since parameters are two-byte values. 
	pos, parameters       = bin.unpack(string.format("<A%d", parameter_length*2), result, pos)
	-- The data length is a 2-byte value. 
	pos, data_length      = bin.unpack("<S",     result, pos)
	-- Read that many bytes of data.
	pos, data             = bin.unpack(string.format("<A%d", data_length),        result, pos)

	stdnse.print_debug(2, "Received %d bytes from SMB", string.len(result))
	return true, header, parameters, data
end

--- Sends out <code>SMB_COM_NEGOTIATE</code>, which is typically the first SMB packet sent out. 
-- Sends the following:\n
-- * List of known protocols\n
--\n
-- Receives:\n
-- * The prefered dialect\n
-- * The security mode\n
-- * Max number of multiplexed connectiosn, virtual circuits, and buffer sizes\n
-- * The server's system time and timezone\n
-- * The "encryption key" (aka, the server challenge)\n
-- * The capabilities\n
-- * The server and domain names\n
--@param socket The socket, in the proper state (ie, newly connected). 
--@return (status, result) If status is false, result is an error message. Otherwise, result is a 
--        table with the following elements:\n
--      'security_mode'    Whether or not to use cleartext passwords, message signatures, etc.\n
--      'max_mpx'          Maximum number of multiplexed connections\n
--      'max_vc'           Maximum number of virtual circuits\n
--      'max_buffer'       Maximum buffer size\n
--      'max_raw_buffer'   Maximum buffer size for raw connections (considered obsolete)\n
--      'session_key'      A value that's basically just echoed back\n
--      'capabilities'     The server's capabilities\n
--      'time'             The server's time (in UNIX-style seconds since 1970)\n
--      'date'             The server's date in a user-readable format\n
--      'timezone'         The server's timezone, in hours from UTC\n
--      'timezone_str'     The server's timezone, as a string\n
--      'server_challenge' A random string used for challenge/response\n
--      'domain'           The server's primary domain\n
--      'server'           The server's name\n
function negotiate_protocol(socket)
	local header, parameters, data
	local pos
	local header1, header2, header3, ehader4, command, status, flags, flags2, pid_high, signature, unused, pid, mid
	local dialect, security_mode, max_mpx, max_vc, max_buffer, max_raw_buffer, session_key, capabilities, time, timezone, key_length
	local server_challenge, date, timezone_str
	local domain, server
	local response = {}

	header     = smb_encode_header(command_codes['SMB_COM_NEGOTIATE'], 0, 0)

	-- Parameters are blank
	parameters = ""

	-- Data is a list of strings, terminated by a blank one. 
	data       = bin.pack("<CzCz", 2, "NT LM 0.12", 2, "")

	-- Send the negotiate request
	stdnse.print_debug(2, "Sending SMB_COM_NEGOTIATE")
	result, err = smb_send(socket, header, parameters, data)
	if(status == false) then
		return err
	end

	-- Read the result
	status, header, parameters, data = smb_read(socket)
	if(status ~= true) then
		return false, header
	end

	-- Since this is our first response, parse out the header
	pos, header1, header2, header3, header4, command, status, flags, flags2, pid_high, signature, unused, tid, pid, uid, mid = bin.unpack("<CCCCCICSSlSSSSS", header)

	-- Parse the parameter section
	pos, dialect, security_mode, max_mpx, max_vc, max_buffer, max_raw_buffer, session_key, capabilities, time, timezone, key_length = bin.unpack("<SCSSIIIILsC", parameters)

	-- Convert the time and timezone to more useful values
	time = (time / 10000000) - 11644473600
	date = os.date("%Y-%m-%d %H:%M:%S", time)
	timezone = -(timezone / 60)
	if(timezone == 0) then
		timezone_str = "UTC+0"
	elseif(timezone < 0) then
		timezone_str = "UTC-" .. math.abs(timezone)
	else
		timezone_str = "UTC+" .. timezone
	end

	-- Data section
	-- This one's a little messier, because I don't appear to have unicode support
	pos, server_challenge = bin.unpack(string.format("<A%d", key_length), data)

	-- Get the domain as a Unicode string
	local ch, dummy
	domain = ""
	pos, ch, dummy = bin.unpack("<CC", data, pos)
	while ch ~= 0 do
		domain = domain .. string.char(ch)
		pos, ch, dummy = bin.unpack("<CC", data, pos)
	end

	-- Get the server name as a Unicode string
	server = ""
	pos, ch, dummy = bin.unpack("<CC", data, pos)
	while ch do
		server = server .. string.char(ch)
		pos, ch, dummy = bin.unpack("<CC", data, pos)
	end

	-- Fill out response variables
	response['security_mode']    = security_mode
	response['max_mpx']          = max_mpx
	response['max_vc']           = max_vc
	response['max_buffer']       = max_buffer
	response['max_raw_buffer']   = max_raw_buffer
	response['session_key']      = session_key
	response['capabilities']     = capabilities
	response['time']             = time
	response['date']             = date
	response['timezone']         = timezone
	response['timezone_str']     = timezone_str
	response['server_challenge'] = server_challenge
	response['domain']           = domain
	response['server']           = server

	return true, response
end

--- Sends out <code>SMB_COM_SESSION_SETUP_ANDX</code>, which attempts to log a user in. 
-- Sends the following:\n
-- * Negotiated parameters (multiplexed connections, virtual circuit, capabilities)\n
-- * Passwords (plaintext, unicode, lanman, ntlm, lmv2, ntlmv2, etc)\n
-- * Account name\n
-- * OS (I just send "Nmap")\n
-- * Native LAN Manager (no clue what that is, but it seems to be ignored)\n
--\n
-- Receives the following:\n
-- * User ID\n
-- * Server OS\n
--\n
--@param socket       The socket, in the proper state (ie, after protocol has been negotiated).
--@param username     The account name to use. For Null sessions, leave it blank (''). 
--@param session_key  The session_key value, returned by <code>SMB_COM_NEGOTIATE</code>.  
--@param capabilities The server's capabilities, returned by <code>SMB_COM_NEGOTIATE</code>. 
--@return (status, result) If status is false, result is an error message. Otherwise, result is a 
--        table with the following elements:\n
--      'uid'         The UserID for the session
--      'is_guest'    If set, the username wasn't found so the user was automatically logged in
--                    as the guest account
--      'os'          The operating system
--      'lanmanager'  The servers's LAN Manager
function start_session(socket, username, session_key, capabilities)
	local status, result
	local header, parameters, data
	local pos
	local header1, header2, header3, header4, command, status, flags, flags2, pid_high, signature, unused, tid, pid, uid, mid 
	local andx_command, andx_reserved, andx_offset, action
	local os, lanmanager, domain
	local response = {}

	header     = smb_encode_header(command_codes['SMB_COM_SESSION_SETUP_ANDX'], 0, 0)

	-- Parameters
	parameters = bin.pack("<CCSSSSISSII", 
				0xFF,        -- ANDX -- no further commands
				0x00,        -- ANDX -- Reserved (0)
				0x0000,      -- ANDX -- next offset
				0x1000,      -- Max buffer size
				0x0001,      -- Max multiplexes
				0x0000,      -- Virtual circuit num
				session_key, -- The session key
				0,           -- ANSI/Lanman password length
				0,           -- Unicode/NTLM password length
				0,           -- Reserved
                capabilities -- Capabilities
			)

	-- Data is a list of strings, terminated by a blank one. 
	data       = bin.pack("<zzzz", 
				                -- ANSI/Lanman password
				                -- Unicode/NTLM password
				username,       -- Account
				"",             -- Domain
				"Nmap",         -- OS
				"Native Lanman" -- Native LAN Manager
			)
	-- Send the session setup request
	stdnse.print_debug(2, "Sending SMB_COM_SESSION_SETUP_ANDX")
	result, err = smb_send(socket, header, parameters, data)
	if(result == false) then
		return false, err
	end

	-- Read the result
	status, header, parameters, data = smb_read(socket)
	if(status ~= true) then
		return false, header
	end

	-- Check if we were allowed in
	pos, header1, header2, header3, header4, command, status, flags, flags2, pid_high, signature, unused, tid, pid, uid, mid = bin.unpack("<CCCCCICSSlSSSSS", header)
	if(status ~= 0) then
		return false, get_status_name(status)
	end

	-- Parse the parameters
	pos, andx_command, andx_reserved, andx_offset, action = bin.unpack("<CCSS", parameters)

	-- Parse the data
	pos, os, lanmanager, domain = bin.unpack("<zzz", data)

	-- Fill in the response string
	response['uid']        = uid
	response['is_guest']   = bit.band(action, 1)
	response['os']         = os
	response['lanmanager'] = lanmanager

	return true, response

end
 
--- Sends out <code>SMB_COM_SESSION_TREE_CONNECT_ANDX</code>, which attempts to connect to a share. 
-- Sends the following:\n
-- * Password (for share-level security, which we don't support)\n
-- * Share name\n
-- * Share type (or "?????" if it's unknown, that's what we do)\n
--\n
-- Receives the following:\n
-- * Tree ID\n
--\n
--@param socket The socket, in the proper state. 
--@param path   The path to connect (eg, "\\servername\C$")
--@param uid    The UserID, returned by <code>SMB_COM_SESSION_SETUP_ANDX</code>
--@return (status, result) If status is false, result is an error message. Otherwise, result is a 
--        table with the following elements:\n
--      'tid'         The TreeID for the session
function tree_connect(socket, path, uid)
	local header, parameters, data
	local pos
	local header1, header2, header3, header4, command, status, flags, flags2, pid_high, signature, unused, pid, mid 
	local andx_command, andx_reserved, andx_offset, action
	local response = {}

	header = smb_encode_header(command_codes['SMB_COM_TREE_CONNECT_ANDX'], uid, 0)
	parameters = bin.pack("<CCSSS", 
					0xFF,   -- ANDX no further commands
					0x00,   -- ANDX reserved
					0x0000, -- ANDX offset
					0x0000, -- flags
					0x0000 -- password length (for share-level security)
				)
	data = bin.pack("zz", 
					        -- Share-level password
					path,   -- Path
					"?????" -- Type of tree ("?????" = any)
				)

	-- Send the tree connect request
	stdnse.print_debug(2, "Sending SMB_COM_TREE_CONNECT_ANDX")
	result, err = smb_send(socket, header, parameters, data)
	if(result == false) then
		return false, err
	end

	-- Read the result
	status, header, parameters, data = smb_read(socket)
	if(status ~= true) then
		return false, header
	end

	-- Check if we were allowed in
	pos, header1, header2, header3, header4, command, status, flags, flags2, pid_high, signature, unused, tid, pid, uid, mid = bin.unpack("<CCCCCICSSlSSSSS", header)
	if(status ~= 0) then
		return false, get_status_name(status)
	end

	response['tid'] = tid

	return true, response
	
end

--- Disconnects a tree session. Should be called before logging off and disconnecting. 
--@param socket The socket
--@param uid    The UserID, returned by <code>SMB_COM_SESSION_SETUP_ANDX</code>
--@param tid    The TreeID, returned by <code>SMB_COM_TREE_CONNECT_ANDX</code>
--@return (status, result) If statis is false, result is an error message. If status is true, 
--              the disconnect was successful. 
function tree_disconnect(socket, uid, tid)
	local response = ""
	local header
	local header1, header2, header3, header4, command, status, flags, flags2, pid_high, signature, unused, pid, mid 
	local response = {}

	header = smb_encode_header(command_codes['SMB_COM_TREE_DISCONNECT'], uid, tid)

	-- Send the tree disconnect request
	stdnse.print_debug(2, "Sending SMB_COM_TREE_DISCONNECT")
	result, err = smb_send(socket, header, "", "")
	if(result == false) then
		return false, err
	end

	-- Read the result
	status, header, parameters, data = smb_read(socket)
	if(status ~= true) then
		return false, header
	end

	-- Check if there was an error
	pos, header1, header2, header3, header4, command, status, flags, flags2, pid_high, signature, unused, tid, pid, uid, mid = bin.unpack("<CCCCCICSSlSSSSS", header)
	if(status ~= 0) then
		return false, get_status_name(status)
	end

	return true
	
end

---Logs off the current user. Strictly speaking this isn't necessary, but it's the polite thing to do. 
--@param socket The socket. 
--@param uid    The user ID. 
--@return (status, result) If statis is false, result is an error message. If status is true, 
--              the logoff was successful. 
function logoff(socket, uid)
	local header, parameters
	local header1, header2, header3, header4, command, status, flags, flags2, pid_high, signature, unused, pid, mid 

	header = smb_encode_header(command_codes['SMB_COM_LOGOFF_ANDX'], uid, 0)

	-- Parameters are a blank ANDX block
	parameters = bin.pack("<CCS", 
					0xFF,   -- ANDX no further commands
					0x00,   -- ANDX reserved
					0x0000  -- ANDX offset
	             )

	-- Send the tree disconnect request
	stdnse.print_debug(2, "Sending SMB_COM_LOGOFF_ANDX")
	result, err = smb_send(socket, header, parameters, "")
	if(result == false) then
		return false, err
	end

	-- Read the result
	status, header, parameters, data = smb_read(socket)
	if(status ~= true) then
		return false, header
	end

	-- Check if there was an error
	pos, header1, header2, header3, header4, command, status, flags, flags2, pid_high, signature, unused, tid, pid, uid, mid = bin.unpack("<CCCCCICSSlSSSSS", header)
	if(status ~= 0) then
		return false, get_status_name(status)
	end

	return true
	
end

--- This sends a SMB request to open or create a file. 
--  Most of the parameters I pass here are used directly from a packetlog, especially the various permissions fields and flags. 
--  I might make this more adjustable in the future, but this has been working for me. 
--
--@param socket The socket, in the correct state
--@param path   The path of the file or pipe to open
--@param uid    The UserID
--@param tid    The TreeID
--@return (status, result) If status is false, result is an error message. Otherwise, result is a table
--        containing a lot of different elements, the most important one being 'fid', the handle to the opened file. 
function create_file(socket, path, uid, tid)
	local header, parameters, data
	local pos
	local header1, header2, header3, header4, command, status, flags, flags2, pid_high, signature, unused, pid, mid 
	local andx_command, andx_reserved, andx_offset
	local oplock_level, fid, create_action, created, last_access, last_write, last_change, attributes, allocation_size, end_of_file, filetype, ipc_state, is_directory
	local response = {}

	header = smb_encode_header(command_codes['SMB_COM_NT_CREATE_ANDX'], uid, tid)
	parameters = bin.pack("<CCSCSIIILIIIIIC", 
					0xFF,   -- ANDX no further commands
					0x00,   -- ANDX reserved
					0x0000, -- ANDX offset
					0x00,   -- Reserved
					string.len(path), -- Path length
					0x00000016,       -- Create flags
					0x00000000,       -- Root FID
					0x0002019F,       -- Access mask
					0x0000000000000000, -- Allocation size
					0x00000000,         -- File attributes
					0x00000003,         -- Share attributes
					0x00000001,         -- Disposition
					0x00400040,         -- Create options
					0x00000002,         -- Impersonation
					0x01                -- Security flags
				)

	data = bin.pack("z", path)

	-- Send the create file
	stdnse.print_debug(2, "Sending SMB_COM_NT_CREATE_ANDX")
	result, err = smb_send(socket, header, parameters, data)
	if(result == false) then
		return false, err
	end

	-- Read the result
	status, header, parameters, data = smb_read(socket)
	if(status ~= true) then
		return false, header
	end

	-- Check if we were allowed in
	pos, header1, header2, header3, header4, command, status, flags, flags2, pid_high, signature, unused, tid, pid, uid, mid = bin.unpack("<CCCCCICSSlSSSSS", header)
	if(status ~= 0) then
		return false, get_status_name(status)
	end

	-- Parse the parameters
	pos, andx_command, andx_reserved, andx_offset, oplock_level, fid, create_action, created, last_access, last_write, last_change, attributes, allocation_size, end_of_file, filetype, ipc_state, is_directory = bin.unpack("<CCSCSILLLLILLSSC", parameters)

	-- Fill in the response string
	response['oplock_level']    = oplock_level
	response['fid']             = fid
	response['create_action']   = create_action
	response['created']         = created
	response['last_access']     = last_access
	response['last_write']      = last_write
	response['last_change']     = last_change
	response['attributes']      = attributes
	response['allocation_size'] = allocation_size
	response['end_of_file']     = end_of_file
	response['filetype']        = filetype
	response['ipc_state']       = ipc_state
	response['is_directory']    = is_directory
	
	return true, response
	
end

---This is the core of making MSRPC calls. It sends out a MSRPC function with the given parameters and data. 
-- Don't confuse these parameters and data with SMB's concepts of parameters and data -- they are completely
-- different. In fact, these parameters and data are both sent in the SMB packet's 'data' section. \n
--\n
-- It is probably best to think of this as another protocol layer. This function will wrap SMB stuff around a 
-- MSRPC call, make the call, then unwrap the SMB stuff from it before returning. 
--
--@param socket The socket to send the packet on, in the proper state. 
--@param func   The function to call. The only one I've tested is 0x26, named pipes. 
--@param function_parameters The parameter data to pass to the function. This is untested, since none of the
--       transactions I've done have required parameters. 
--@param function_data The data to send with the packet. This is basically the next protocol layer
--@param uid    The UserID
--@param tid    The TreeID (handle to <code>$IPC</code>)
--@param fid    The FileID (opened by <code>create_file</code>)
--@return (status, result) If status is false, result is an error message. Otherwise, result is a table 
--        containing 'parameters' and 'data', representing the parameters and data returned by the server. 
function send_transaction(socket, func, function_parameters, function_data, uid, tid, fid)
	local header1, header2, header3, header4, command, status, flags, flags2, pid_high, signature, unused, pid, mid 
	local header, parameters, data
	local parameters_offset, data_offset
	local total_word_count, total_data_count, reserved1, parameter_count, parameter_offset, parameter_displacement, data_count, data_offset, data_displacement, setup_count, reserved2
	local response = {}

	-- Header is 0x20 bytes long (not counting NetBIOS header).
	header = smb_encode_header(command_codes['SMB_COM_TRANSACTION'], uid, tid) -- 0x25 = SMB_COM_TRANSACTION

	-- 0x20 for SMB header, 0x01 for parameters header, 0x20 for parameters length, 0x02 for data header, 0x07 for "\PIPE\"
	parameters_offset = 0x20 + 0x01 + 0x20 + 0x02 + 0x07
	data_offset       = 0x20 + 0x01 + 0x20 + 0x02 + 0x07 + string.len(function_parameters)

	-- Parameters are 0x20 bytes long. 
	parameters = bin.pack("<SSSSCCSISSSSSCCSS",
					string.len(function_parameters), -- Total parameter count. 
					string.len(function_data),       -- Total data count. 
					0x000,                           -- Max parameter count.
					0x400,                           -- Max data count.
					0x00,                            -- Max setup count.
					0x00,                            -- Reserved.
					0x0000,                          -- Flags (0x0000 = 2-way transaction, don't disconnect TIDs).
					0x00000000,                      -- Timeout (0x00000000 = return immediately).
					0x0000,                          -- Reserved.
					string.len(function_parameters), -- Parameter bytes.
					parameters_offset,               -- Parameter offset.
					string.len(function_data),       -- Data bytes.
					data_offset,                     -- Data offset.
					0x02,                            -- Number of 'setup' words (only ever seen '2').
					0x00,                            -- Reserved.
					func,                            -- Function to call.
					fid                              -- Handle to open file
				)

	-- \PIPE\ is 0x07 bytes long. 
	data = bin.pack("<z", "\\PIPE\\");
	data = data .. function_parameters;
	data = data .. function_data

	-- Send the transaction request
	stdnse.print_debug(2, "Sending SMB_COM_TRANSACTION")
	result, err = smb_send(socket, header, parameters, data)
	if(result == false) then
		return false, err
	end

	-- Read the result
	status, header, parameters, data = smb_read(socket)
	if(status ~= true) then
		return false, header
	end

	-- Check if it worked
	pos, header1, header2, header3, header4, command, status, flags, flags2, pid_high, signature, unused, tid, pid, uid, mid = bin.unpack("<CCCCCICSSlSSSSS", header)
	if(status ~= 0) then
		return false, status_codes[status]
	end

	-- Parse the parameters
	pos, total_word_count, total_data_count, reserved1, parameter_count, parameter_offset, parameter_displacement, data_count, data_offset, data_displacement, setup_count, reserved2 = bin.unpack("<SSSSSSSSSCC", parameters)

	-- Convert the parameter/data offsets into something more useful (the offset into the data section)
	-- - 0x20 for the header, - 0x01 for the length. 
	parameter_offset = parameter_offset - 0x20 - 0x01 - string.len(parameters) - 0x02;
	-- - 0x20 for the header, - 0x01 for parameter length, the parameter length, and - 0x02 for the data length. 
	data_offset = data_offset - 0x20 - 0x01 - string.len(parameters) - 0x02;

	-- I'm not sure I entirely understand why the '+1' is here, but I think it has to do with the string starting at '1' and not '0'.
	function_parameters = string.sub(data, parameter_offset + 1, parameter_offset + parameter_count)
	function_data       = string.sub(data, data_offset      + 1, data_offset      + data_count)

	response['parameters'] = function_parameters
	response['data']       = function_data

	return true, response
end

