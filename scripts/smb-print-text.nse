local bin = require "bin"
local io = require "io"
local msrpc = require "msrpc"
local smb = require "smb"
local string = require "string"
local stdnse = require "stdnse"

description = [[
Attempts to print text on a shared printer by calling Print Spooler Service RPC functions.

In order to use the script, at least one printer needs to be shared
over SMB. If no printer is specified, script tries to enumerate existing
ones by calling LANMAN API which might not be always available.
LANMAN is available by default on Windows XP, but not on Vista or Windows 7
for example. In that case, you need to specify printer share name manually
using <code>printer</code> script argument. You can find out available shares
by using smb-enum-shares script.

Later versions of Windows require valid credentials by default
which you can specify trough smb library arguments <code>smbuser</code> and
<code>smbpassword</code> or other options.

]]
---
-- @usage nmap  -p 445 <target> --script=smb-print-text  --script-args="text=0wn3d"
--
-- @output
-- |_smb-print-text: Printer job started using MyPrinter printer share.
--
-- @args printer  Printer share name. Optional, by default script tries to enumerate available printer shares.
-- @args text     Text to print. Either text or filename need to be specified.
-- @args filename File to read text from (ASCII only).
--

author = "Aleksandar Nikolic"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"intrusive"}

hostrule = function(host)
  return smb.get_port(host) ~= nil
end

action = function(host,port)
  local status, smbstate
  local text = stdnse.get_script_args(SCRIPT_NAME .. '.text')
  local filename = stdnse.get_script_args(SCRIPT_NAME .. '.filename')
  if (not text) and (not filename) then
    stdnse.debug1("Script requires either text or filename script argument.")
    return false
  end
  local text_to_print
  if text then
    text_to_print = text
  else
    -- read text from file
    local file = io.open(filename, "rb")
    text_to_print = file:read("a")
    file:close()
  end
  status, smbstate = msrpc.start_smb(host, msrpc.SPOOLSS_PATH,true)
  if(status == false) then
    stdnse.debug1("SMB: " .. smbstate)
    return false, smbstate
  end

  local bind_result
  status, bind_result = msrpc.bind(smbstate,msrpc.SPOOLSS_UUID, msrpc.SPOOLSS_VERSION, nil)
  if(status == false) then
    msrpc.stop_smb(smbstate)
    stdnse.debug1("SMB: " .. bind_result)
    return false, bind_result
  end
  local printer = stdnse.get_script_args(SCRIPT_NAME .. '.printer')
  -- if printer not set find available printers
  if not printer then
    stdnse.debug1("No printer specified, trying to find one...")
    local lanman_result
    local REMSmb_NetShareEnum_P  = "WrLeh"
    local REMSmb_share_info_1 = "B13BWz"
    status, lanman_result = msrpc.call_lanmanapi(smbstate,0,REMSmb_NetShareEnum_P,REMSmb_share_info_1,bin.pack("ss",0x01,65406))
    if status == false then
      stdnse.debug1("SMB: " .. lanman_result)
      stdnse.debug1("SMB: Looks like LANMAN API is not available. Try setting printer script arg.")
      return false
    end

    local parameters = lanman_result.parameters
    local data = lanman_result.data
    local pos, status, convert, entry_count, available_entries = bin.unpack("<SSSS", parameters)
    pos = 0
    local share_type, name, _
    for i = 1, entry_count, 1 do
      _,share_type = bin.unpack(">s",data,pos+14)
      pos, name = bin.unpack("<z", data, pos)

      -- pos needs to be rounded to the next even multiple of 20
      pos = pos + ( 20 - (#name % 20) ) - 1
      if share_type == 1 then -- share is printer
        stdnse.debug1("Found printer share %s.", name)
        printer = name
      end
    end
  end
  if not printer then
    stdnse.debug1("No printer found, system may be unpatched but it needs at least one printer shared to be vulnerable.")
    return false
  end
  stdnse.debug1("Using %s as printer.",printer)
  -- call RpcOpenPrinterEx - opnum 69
  local status, result = msrpc.spoolss_open_printer(smbstate,"\\\\"..host.ip.."\\"..printer)
  if not status then
    return false
  end
  local printer_handle = string.sub(result.data,25,#result.data-4)
  stdnse.debug1("Printer handle %s",stdnse.tohex(printer_handle))
  -- call RpcStartDocPrinter - opnum 17
  status,result = msrpc.spoolss_start_doc_printer(smbstate,printer_handle,"nmap_print_test.txt") -- patched version will allow this
  if not status then
    return false
  end
  local print_job_id = string.sub(result.data,25,#result.data-4)
  stdnse.debug1("Start doc printer job id %s",stdnse.tohex(print_job_id))

  -- call RpcWritePrinter - 19
  status, result = msrpc.spoolss_write_printer(smbstate,printer_handle,text_to_print)
  if not status then
    return false
  end
  local write_result = string.sub(result.data,25,#result.data-4)
  stdnse.debug1("Written %s bytes to a file.",stdnse.tohex(write_result))

  status,result = msrpc.spoolss_end_doc_printer(smbstate,printer_handle)

  return string.format("Printer job started using <%s> printer share.", printer)
end
