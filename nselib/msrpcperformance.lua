---
-- This module is designed to parse the <code>PERF_DATA_BLOCK</code> structure, which is
-- stored in the registry under HKEY_PERFORMANCE_DATA. By querying this structure, you can
-- get a whole lot of information about what's going on. 
--
-- To use this from a script, see <code>get_performance_data</code>, it is the only 
-- "public" function in this module. 
--
-- My primary sources of information were:
-- * This 1996 journal by Matt Pietrek: <http://www.microsoft.com/msj/archive/S271.aspx>
-- * The followup article: <http://www.microsoft.com/msj/archive/S2A9.aspx>
-- * The WinPerf.h header file
--
-- And my primary inspiration was PsTools, specifically, <code>pstasklist.exe</code>. 
--
--@author Ron Bowes <ron@skullsecurity.net>
--@copyright Same as Nmap--See http://nmap.org/book/man-legal.html
-----------------------------------------------------------------------

local bin = require "bin"
local bit = require "bit"
local msrpc = require "msrpc"
local msrpctypes = require "msrpctypes"
local stdnse = require "stdnse"
_ENV = stdnse.module("msrpcperformance", stdnse.seeall)

---Parses the title database, which is a series of null-terminated string pairs. 
--
--@param data     The data being processed. 
--@param pos      The position within <code>data</code>. 
--@return (status, pos, result) The status (true if successful), the new position in <code>data</code> (or an error
--                              message), and a table representing the datatype, if any.
local function parse_perf_title_database(data, pos)
	local result = {}
	local i = 1

	repeat
		local number, name
		pos, number, name = bin.unpack("<zz", data, pos)

		if(number == nil) then
			return false, "Couldn't parse the title database: end of string encountered early"
		elseif(tonumber(number) == nil) then -- Not sure if this actually happens, but it doesn't hurt to check
			stdnse.print_debug(1, "MSRPC: ERROR: Couldn't parse the title database: string found where number expected (%d: '%s')", i, number)
			return false, "Couldn't parse the title database"
		end

		result[tonumber(number)] = name
		i = i + 1
	until pos >= #data

	return true, pos, result
end

---Parses a PERF_DATA_BLOCK, which has the following definition (from "WinPerf.h" on Visual Studio 8):
--
--<code>
--	typedef struct _PERF_DATA_BLOCK {
--		WCHAR           Signature[4];       // Signature: Unicode "PERF"
--		DWORD           LittleEndian;       // 0 = Big Endian, 1 = Little Endian
--		DWORD           Version;            // Version of these data structures
--		                                    // starting at 1
--		DWORD           Revision;           // Revision of these data structures
--		                                    // starting at 0 for each Version
--		DWORD           TotalByteLength;    // Total length of data block
--		DWORD           HeaderLength;       // Length of this structure
--		DWORD           NumObjectTypes;     // Number of types of objects
--		                                    // being reported
--		LONG            DefaultObject;      // Object Title Index of default
--		                                    // object to display when data from
--		                                    // this system is retrieved (-1 =
--		                                    // none, but this is not expected to
--		                                    // be used)
--		SYSTEMTIME      SystemTime;         // Time at the system under
--		                                    // measurement
--		LARGE_INTEGER   PerfTime;           // Performance counter value
--		                                    // at the system under measurement
--		LARGE_INTEGER   PerfFreq;           // Performance counter frequency
--		                                    // at the system under measurement
--		LARGE_INTEGER   PerfTime100nSec;    // Performance counter time in 100 nsec
--		                                    // units at the system under measurement
--		DWORD           SystemNameLength;   // Length of the system name
--		DWORD           SystemNameOffset;   // Offset, from beginning of this
--		                                    // structure, to name of system
--		                                    // being measured
--	} PERF_DATA_BLOCK, *PPERF_DATA_BLOCK;
--</code>
--
--@param data     The data being processed. 
--@param pos      The position within <code>data</code>. 
--@return (status, pos, result) The status (true if successful), the new position in <code>data</code> (or an error
--                              message), and a table representing the datatype, if any.
local function parse_perf_data_block(data, pos)
	local result = {}

	pos, result['Signature'] = msrpctypes.unicode_to_string(data, pos, 4, false)
	if(result['Signature'] ~= "PERF") then
		return false, "MSRPC: PERF_DATA_BLOCK signature is missing or incorrect"
	end

	pos, result['LittleEndian'] = msrpctypes.unmarshall_int32(data, pos)
	if(result['LittleEndian'] ~= 1) then
		return false, "MSRPC: PERF_DATA_BLOCK returned a non-understood endianness"
	end

	-- Parse the header
	pos, result['Version']          = msrpctypes.unmarshall_int32(data, pos)
	pos, result['Revision']         = msrpctypes.unmarshall_int32(data, pos)
	pos, result['TotalByteLength']  = msrpctypes.unmarshall_int32(data, pos)
	pos, result['HeaderLength']     = msrpctypes.unmarshall_int32(data, pos)
	pos, result['NumObjectTypes']   = msrpctypes.unmarshall_int32(data, pos)
	pos, result['DefaultObject']    = msrpctypes.unmarshall_int32(data, pos)
	pos, result['SystemTime']       = msrpctypes.unmarshall_SYSTEMTIME(data, pos)
	pos, result['PerfTime']         = msrpctypes.unmarshall_int64(data, pos)
	pos, result['PerfFreq']         = msrpctypes.unmarshall_int64(data, pos)
	pos, result['PerfTime100nSec']  = msrpctypes.unmarshall_int64(data, pos)
	pos = pos + 4 -- This value doesn't seem to line up, so add 4

	pos, result['SystemNameLength'] = msrpctypes.unmarshall_int32(data, pos)
	pos, result['SystemNameOffset'] = msrpctypes.unmarshall_int32(data, pos)

	-- Ensure that the system name is directly after the header. This technically shouldn't matter, but Microsoft's documentation
	-- (in WinPref.h) says that the actual object comes "after the PERF_DATA_BLOCK", so it doesn't make sense that the SystemName
	-- could be anywhere else. 
	if(pos ~= result['SystemNameOffset'] + 1) then
		return false, "MSRPC: PERF_DATA_BLOCK has SystemName in the wrong location"
	end

	-- Read the system name from the next location (which happens to be identical to SystemNameOffset, on a proper system)
	pos, result['SystemName'] = msrpctypes.unicode_to_string(data, pos, result['SystemNameLength'] / 2, true)

	pos = pos + 4 -- Again, we end up not lined up so here we fix it

	return true, pos, result
end


---Parse a PERF_OBJECT_TYPE structure. From Microsoft's documentation:
--
--<code>
-- //
-- //  The _PERF_DATA_BLOCK structure is followed by NumObjectTypes of
-- //  data sections, one for each type of object measured.  Each object
-- //  type section begins with a _PERF_OBJECT_TYPE structure.
-- //
-- typedef struct _PERF_OBJECT_TYPE {
-- 		DWORD           TotalByteLength;    // Length of this object definition
-- 		                                    // including this structure, the
-- 		                                    // counter definitions, and the
-- 		                                    // instance definitions and the
-- 		                                    // counter blocks for each instance:
-- 		                                    // This is the offset from this
-- 		                                    // structure to the next object, if
-- 		                                    // any
-- 		DWORD           DefinitionLength;   // Length of object definition,
-- 		                                    // which includes this structure
-- 		                                    // and the counter definition
-- 		                                    // structures for this object: this
-- 		                                    // is the offset of the first
-- 		                                    // instance or of the counters
-- 		                                    // for this object if there is
-- 		                                    // no instance
-- 		DWORD           HeaderLength;       // Length of this structure: this
-- 		                                    // is the offset to the first
-- 		                                    // counter definition for this
-- 		                                    // object
-- 		DWORD           ObjectNameTitleIndex;
-- 		                                    // Index to name in Title Database
-- #ifdef _WIN64
-- 		DWORD           ObjectNameTitle;    // Should use this as an offset
-- #else
-- 		LPWSTR          ObjectNameTitle;    // Initially NULL, for use by
-- 		                                    // analysis program to point to
-- 		                                    // retrieved title string
-- #endif
-- 		DWORD           ObjectHelpTitleIndex;
-- 		                                    // Index to Help in Title Database
-- #ifdef _WIN64
-- 		DWORD           ObjectHelpTitle;    // Should use this as an offset
-- #else
-- 		LPWSTR          ObjectHelpTitle;    // Initially NULL, for use by
-- 		                                    // analysis program to point to
-- 		                                    // retrieved title string
-- #endif
-- 		DWORD           DetailLevel;        // Object level of detail (for
-- 		                                    // controlling display complexity);
-- 		                                    // will be min of detail levels
-- 		                                    // for all this object's counters
-- 		DWORD           NumCounters;        // Number of counters in each
-- 		                                    // counter block (one counter
-- 		                                    // block per instance)
-- 		LONG            DefaultCounter;     // Default counter to display when
-- 		                                    // this object is selected, index
-- 		                                    // starting at 0 (-1 = none, but
-- 		                                    // this is not expected to be used)
-- 		LONG            NumInstances;       // Number of object instances
-- 		                                    // for which counters are being
-- 		                                    // returned from the system under
-- 		                                    // measurement. If the object defined
-- 		                                    // will never have any instance data
-- 		                                    // structures (PERF_INSTANCE_DEFINITION)
-- 		                                    // then this value should be -1, if the
-- 		                                    // object can have 0 or more instances,
-- 		                                    // but has none present, then this
-- 		                                    // should be 0, otherwise this field
-- 		                                    // contains the number of instances of
-- 		                                    // this counter.
-- 		DWORD           CodePage;           // 0 if instance strings are in
-- 		                                    // UNICODE, else the Code Page of
-- 		                                    // the instance names
-- 		LARGE_INTEGER   PerfTime;           // Sample Time in "Object" units
-- 		                                    //
-- 		LARGE_INTEGER   PerfFreq;           // Frequency of "Object" units in
-- 		                                    // counts per second.
-- } PERF_OBJECT_TYPE, *PPERF_OBJECT_TYPE;
--</code>
--
--@param data           The data being processed. 
--@param pos            The position within <code>data</code>. 
--@return (status, pos, result) The status (true if successful), the new position in <code>data</code> (or an error
--                              message), and a table representing the datatype, if any.
local function parse_perf_object_type(data, pos)
	local result = {}

	pos, result['TotalByteLength']      = msrpctypes.unmarshall_int32(data, pos) -- Offset to the next object
	pos, result['DefinitionLength']     = msrpctypes.unmarshall_int32(data, pos) -- Offset to the first instance (or counter, if no instances)
	pos, result['HeaderLength']         = msrpctypes.unmarshall_int32(data, pos) -- Offset to the first counter definition
	pos, result['ObjectNameTitleIndex'] = msrpctypes.unmarshall_int32(data, pos) -- Index in the Title Database
	pos, result['ObjectNameTitle']      = msrpctypes.unmarshall_int32(data, pos) -- TODO: will this work with 64-bit?
	pos, result['ObjectHelpTitleIndex'] = msrpctypes.unmarshall_int32(data, pos) -- Index in the Help Database
	pos, result['ObjectHelpTitle']      = msrpctypes.unmarshall_int32(data, pos) -- TODO: will this workw ith 64-bit?
	pos, result['DetailLevel']          = msrpctypes.unmarshall_int32(data, pos)
	pos, result['NumCounters']          = msrpctypes.unmarshall_int32(data, pos) -- The number of counters in each counter block
	pos, result['DefaultCounter']       = msrpctypes.unmarshall_int32(data, pos)
	pos, result['NumInstances']         = msrpctypes.unmarshall_int32(data, pos) -- Numer of object instances for which counters are being returned
	pos, result['CodePage']             = msrpctypes.unmarshall_int32(data, pos) -- 0 if strings are in UNICODE, otherwise the Code Page
--	if(result['CodePage'] ~= 0) then
--		return false, string.format("Unknown Code Page for data: %d\n", result['CodePage'])
--	end
	pos, result['PerfTime']             = msrpctypes.unmarshall_int64(data, pos) -- Sample time in "Object" units
	pos, result['PerfFreq']             = msrpctypes.unmarshall_int64(data, pos) -- Frequency of "Object" units in counts/second

	return true, pos, result
end


---Parse a PERF_COUNTER_DEFINITION structure. From Microsoft's documentation:
--
--<code>
--	//  There is one of the following for each of the
--	//  PERF_OBJECT_TYPE.NumCounters.  The Unicode names in this structure MUST
--	//  come from a message file.
--	typedef struct _PERF_COUNTER_DEFINITION {
--		DWORD           ByteLength;         // Length in bytes of this structure
--		DWORD           CounterNameTitleIndex;
--		                                    // Index of Counter name into
--		                                    // Title Database
--	#ifdef _WIN64
--		DWORD           CounterNameTitle;
--	#else
--		LPWSTR          CounterNameTitle;   // Initially NULL, for use by
--		                                    // analysis program to point to
--		                                    // retrieved title string
--	#endif
--		DWORD           CounterHelpTitleIndex;
--		                                    // Index of Counter Help into
--		                                    // Title Database
--	#ifdef _WIN64
--		DWORD           CounterHelpTitle;
--	#else
--		LPWSTR          CounterHelpTitle;   // Initially NULL, for use by
--		                                    // analysis program to point to
--		                                    // retrieved title string
--	#endif
--		LONG            DefaultScale;       // Power of 10 by which to scale
--		                                    // chart line if vertical axis is 100
--		                                    // 0 ==> 1, 1 ==> 10, -1 ==>1/10, etc.
--		DWORD           DetailLevel;        // Counter level of detail (for
--		                                    // controlling display complexity)
--		DWORD           CounterType;        // Type of counter
--		DWORD           CounterSize;        // Size of counter in bytes
--		DWORD           CounterOffset;      // Offset from the start of the
--		                                    // PERF_COUNTER_BLOCK to the first
--		                                    // byte of this counter
--	} PERF_COUNTER_DEFINITION, *PPERF_COUNTER_DEFINITION;
--</code>
--
--@param data           The data being processed. 
--@param pos            The position within <code>data</code>. 
--@return (status, pos, result) The status (true if successful), the new position in <code>data</code> (or an error
--                              message), and a table representing the datatype, if any.
local function parse_perf_counter_definition(data, pos)
	local result = {}
	local initial_pos = pos

	pos, result['ByteLength']            = msrpctypes.unmarshall_int32(data, pos)
	pos, result['CounterNameTitleIndex'] = msrpctypes.unmarshall_int32(data, pos)
	pos, result['CounterNameTitle']      = msrpctypes.unmarshall_int32(data, pos)
	pos, result['CounterHelpTitleIndex'] = msrpctypes.unmarshall_int32(data, pos)
	pos, result['CounterHelpTitle']      = msrpctypes.unmarshall_int32(data, pos)
	pos, result['DefaultScale']          = msrpctypes.unmarshall_int32(data, pos)
	pos, result['DetailLevel']           = msrpctypes.unmarshall_int32(data, pos)
	pos, result['CounterType']           = msrpctypes.unmarshall_int32(data, pos)
	pos, result['CounterSize']           = msrpctypes.unmarshall_int32(data, pos)
	pos, result['CounterOffset']         = msrpctypes.unmarshall_int32(data, pos)

	pos = initial_pos + result['ByteLength']

	return true, pos, result
end

---Parse the actual counter value. This is a fairly simple function, it takes a counter
-- definition and pulls out data based on it. 
--
-- Note: I don't think this is doing the 8-byte values right, I suspect that they're supposed
-- to be doubles. 
--
--@param data           The data being processed. 
--@param pos            The position within <code>data</code>. 
--@param counter_definition The matching counter_definition. 
--@return (status, pos, result) The status (true if successful), the new position in <code>data</code> (or an error
--                              message), and a table representing the datatype, if any.
local function parse_perf_counter(data, pos, counter_definition)
	local result

	if(counter_definition['CounterSize'] == 4) then
		pos, result = msrpctypes.unmarshall_int32(data, pos)
	elseif(counter_definition['CounterSize'] == 8) then
		pos, result = msrpctypes.unmarshall_int64(data, pos)
--		pos, result = bin.unpack("<d", data, pos)
	else
		pos, result = msrpctypes.unmarshall_raw(data, pos, counter_definition['CounterSize'])
	end

	return true, pos, result
end

---Parse a PERF_INSTANCE_DEFINITION structure. From Microsoft's documentation:
--
--<code>
--	//  If (PERF_DATA_BLOCK.NumInstances >= 0) then there will be
--	//  PERF_DATA_BLOCK.NumInstances of a (PERF_INSTANCE_DEFINITION
--	//  followed by a PERF_COUNTER_BLOCK followed by the counter data fields)
--	//  for each instance.
--	//
--	//  If (PERF_DATA_BLOCK.NumInstances < 0) then the counter definition
--	//  strucutre above will be followed by only a PERF_COUNTER_BLOCK and the
--	//  counter data for that COUNTER.
--	typedef struct _PERF_INSTANCE_DEFINITION {
--		DWORD           ByteLength;         // Length in bytes of this structure,
--		                                    // including the subsequent name
--		DWORD           ParentObjectTitleIndex;
--		                                    // Title Index to name of "parent"
--		                                    // object (e.g., if thread, then
--		                                    // process is parent object type);
--		                                    // if logical drive, the physical
--		                                    // drive is parent object type
--		DWORD           ParentObjectInstance;
--		                                    // Index to instance of parent object
--		                                    // type which is the parent of this
--		                                    // instance.
--		LONG            UniqueID;           // A unique ID used instead of
--		                                    // matching the name to identify
--		                                    // this instance, -1 = none
--		DWORD           NameOffset;         // Offset from beginning of
--		                                    // this struct to the Unicode name
--		                                    // of this instance
--		DWORD           NameLength;         // Length in bytes of name; 0 = none
--		                                    // this length includes the characters
--		                                    // in the string plus the size of the
--		                                    // terminating NULL char. It does not
--		                                    // include any additional pad bytes to
--		                                    // correct structure alignment
--	} PERF_INSTANCE_DEFINITION, *PPERF_INSTANCE_DEFINITION;
--</code>
--
--@param data           The data being processed. 
--@param pos            The position within <code>data</code>. 
--@return (status, pos, result) The status (true if successful), the new position in <code>data</code> (or an error
--                              message), and a table representing the datatype, if any.
local function parse_perf_instance_definition(data, pos)
	local result = {}

	-- Remember where we started. I noticed that where the counter part starts can move around, so we have to
	-- determine it by adding ByteLength to the initial position
	local initial_pos = pos

	pos, result['ByteLength']             = msrpctypes.unmarshall_int32(data, pos)
	pos, result['ParentObjectTitleIndex'] = msrpctypes.unmarshall_int32(data, pos)
	pos, result['ParentObjectInstance']   = msrpctypes.unmarshall_int32(data, pos)
	pos, result['UniqueID']               = msrpctypes.unmarshall_int32(data, pos)
	pos, result['NameOffset']             = msrpctypes.unmarshall_int32(data, pos)
	pos, result['NameLength']             = msrpctypes.unmarshall_int32(data, pos)

	pos, result['InstanceName']           = msrpctypes.unicode_to_string(data, pos, result['NameLength'] / 2, true)

	pos = initial_pos + result['ByteLength']

	return true, pos, result
end

---Parse a PERF_COUNTER_BLOCK structure. From Microsoft's documentation:
--
--<code>
--	typedef struct _PERF_COUNTER_BLOCK {
--		DWORD           ByteLength;         // Length in bytes of this structure,
--		                                    // including the following counters
--	} PERF_COUNTER_BLOCK, *PPERF_COUNTER_BLOCK;
--	
--</code>
--
--@param data           The data being processed. 
--@param pos            The position within <code>data</code>. 
--@return (status, pos, result) The status (true if successful), the new position in <code>data</code> (or an error
--                              message), and a table representing the datatype, if any.
local function parse_perf_counter_block(data, pos)
	local result = {}

	pos, result['ByteLength'] = msrpctypes.unmarshall_int32(data, pos)

	return true, pos, result
end

---Retrieve the parsed performance data from the given host for the requested object values. To get a list of possible
-- object values, leave 'objects' blank and look at <code>result['title_database']</code> -- it'll contain a list of 
-- indexes that can be looked up. These indexes are passed as a string or as a series of space-separated strings (eg, 
-- "230" for "Process" and "238" for "Process" and "Processor"). 
--
--@param host The host object
--@param objects [optional] The space-separated list of object numbers to retrieve. Default: only retrieve the database. 
function get_performance_data(host, objects)

	-- Create the SMB session
	local status, smbstate = msrpc.start_smb(host, msrpc.WINREG_PATH)
	if(status == false) then
		return false, smbstate
	end

	-- Bind to WINREG service
	local status, bind_result = msrpc.bind(smbstate, msrpc.WINREG_UUID, msrpc.WINREG_VERSION, nil)
	if(status == false) then
		msrpc.stop_smb(smbstate)
		return false, bind_result
	end

	-- Open HKEY_PERFORMANCE_DATA
	local status, openhkpd_result = msrpc.winreg_openhkpd(smbstate)
	if(status == false) then
		msrpc.stop_smb(smbstate)
		return false, openhkpd_result
	end

	local status, queryvalue_result = msrpc.winreg_queryvalue(smbstate, openhkpd_result['handle'], "Counter 009")
	if(status == false) then
		msrpc.stop_smb(smbstate)
		return false, queryvalue_result
	end

	-- Parse the title database
	local pos = 1
	local status
	local result = {}
	status, pos, result['title_database'] = parse_perf_title_database(queryvalue_result['value'], pos)
	if(status == false) then
		msrpc.stop_smb(smbstate)
		return false, pos
	end
	result['title_database'][0] = "<null>"


	if(objects ~= nil and #objects > 0) then
		-- Query for the objects
		local status, queryvalue_result = msrpc.winreg_queryvalue(smbstate, openhkpd_result['handle'], objects)
		if(status == false) then
			msrpc.stop_smb(smbstate)
			return false, queryvalue_result
		end

		-- Parse the header
		pos = 1
		local status, data_block
		status, pos, data_block = parse_perf_data_block(queryvalue_result['value'], pos)
		if(status == false) then
			msrpc.stop_smb(smbstate)
			return false, pos
		end

		-- Move past the header
		pos = 1 + data_block['HeaderLength']

		-- Parse the data sections
		for i = 1, data_block['NumObjectTypes'], 1 do
			local object_start = pos

			local counter_definitions = {}
			local object_instances    = {}
			local counter_definitions = {}

			-- Get the type of the object (this is basically the class definition -- info about the object instances)
			local status, object_type
			status, pos, object_type = parse_perf_object_type(queryvalue_result['value'], pos)
			if(status == false) then
				msrpc.stop_smb(smbstate)
				return false, pos
			end

			-- Start setting up the result object
--stdnse.print_debug("Index = %d\n", object_type['ObjectNameTitleIndex'])
			local object_name = result['title_database'][object_type['ObjectNameTitleIndex']]
			result[object_name] = {}
			
--stdnse.print_debug("\n\nOBJECT: %s\n", object_name)
--stdnse.print_debug(" Counters: %d\n", object_type['NumCounters'])
--stdnse.print_debug(" Instances: %d\n", object_type['NumInstances'])
--stdnse.print_debug("-----------------\n")

			-- Bring the position to the beginning of the counter definitions
			pos = object_start + object_type['HeaderLength']

			-- Parse the counter definitions
			for j = 1, object_type['NumCounters'], 1 do
				status, pos, counter_definitions[j] = parse_perf_counter_definition(queryvalue_result['value'], pos)
				if(status == false) then
					msrpc.stop_smb(smbstate)
					return false, pos
				end
--stdnse.print_debug(" Counter definition #%2d: [%d bytes] %s\n", j, counter_definitions[j]['CounterSize'], result['title_database'][counter_definitions[j]['CounterNameTitleIndex']])
			end

			-- Bring the position to the beginning of the instances (or counters)
			pos = object_start + object_type['DefinitionLength']

			-- Check if we have any instances (sometimes we don't -- if we don't, the value returned is a negative)
			if(bit.band(object_type['NumInstances'], 0x80000000) == 0) then
				-- Parse the object instances and counters
				for j = 1, object_type['NumInstances'], 1 do
					local instance_start = pos

					-- Instance definition
					local status
					status, pos, object_instances[j] = parse_perf_instance_definition(queryvalue_result['value'], pos)
					if(status == false) then
						msrpc.stop_smb(smbstate)
						return false, pos
					end

					-- Set up the instance array
					local instance_name = object_instances[j]['InstanceName']
					result[object_name][instance_name] = {}
		
					-- Bring the pos to the start of the counter block
					pos = instance_start + object_instances[j]['ByteLength']

--stdnse.print_debug("\n  INSTANCE: %s\n", instance_name)
--stdnse.print_debug("  Length: %d\n",     object_instances[j]['ByteLength'])
--stdnse.print_debug("  NameOffset: %d\n", object_instances[j]['NameOffset'])
--stdnse.print_debug("  NameLength: %d\n", object_instances[j]['NameLength'])
--stdnse.print_debug("  --------------\n")
		
					-- The counter block
					local status, counter_block
					status, pos, counter_block = parse_perf_counter_block(queryvalue_result['value'], pos)
					if(status == false) then
						msrpc.stop_smb(smbstate)
						return false, pos
					end
		
					for k = 1, object_type['NumCounters'], 1 do
						-- Each individual counter
						local status, counter_result
						status, pos, counter_result = parse_perf_counter(queryvalue_result['value'], pos, counter_definitions[k])
						if(status == false) then
							msrpc.stop_smb(smbstate)
							return false, pos
						end

						local counter_name = result['title_database'][counter_definitions[k]['CounterNameTitleIndex']]
--stdnse.print_debug("    %s: %s\n", counter_name, counter_result)

						-- Save it in the result
						result[object_name][instance_name][counter_name] = counter_result
					end
		
					-- Bring the pos to the end of the next section
					pos = instance_start + object_instances[j]['ByteLength'] + counter_block['ByteLength']
				end
			else
				for k = 1, object_type['NumCounters'], 1 do
					-- Each individual counter
					local status, counter_result
					status, pos, counter_result = parse_perf_counter(queryvalue_result['value'], pos, counter_definitions[k])
					if(status == false) then
						msrpc.stop_smb(smbstate)
						return false, pos
					end

					local counter_name = result['title_database'][counter_definitions[k]['CounterNameTitleIndex']]
--stdnse.print_debug("    %s: %s\n", counter_name, counter_result)

					-- Save it in the result
					result[object_name][counter_name] = counter_result
				end
			end
		end

		-- Blank out the database
		result['title_database'] = nil
	end

	msrpc.stop_smb(smbstate)
	
	return true, result
end



return _ENV;
