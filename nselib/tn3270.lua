---
-- TN3270 Emulator Library
--
-- Summary
-- * This library implements an RFC 1576 and 2355 (somewhat) compliant TN3270 emulator.
--
-- The library consists of one class <code>Telnet</code> consisting of multiple
-- functions required for initiating a TN3270 connection.
--
-- The following sample code illustrates how scripts can use this class
-- to interface with a mainframe:
--
-- <code>
-- mainframe = Telnet:new()
-- status, err = mainframe:initiate(host, port)
-- status, err = mainframe:send_cursor("LOGON APPLID(TSO)")
-- mainframe:get_data()
-- curr_screen = mainframe:get_screen()
-- status, err = mainframe:disconnect()
-- </code>
--
-- The implementation is based on packet dumps, x3270, the excellent decoding
-- provided by Wireshark and the Data Stream Programmers Reference (Dec 88)

local stdnse    = require "stdnse"
local drda      = require "drda" -- We only need this to decode EBCDIC
local comm      = require "comm"
local math = require "math"
local nmap = require "nmap"
local string = require "string"
local table = require "table"

_ENV = stdnse.module("tn3270", stdnse.seeall)

Telnet = {
  --__index = Telnet,

  commands = {
    SE   = "\240", -- End of subnegotiation parameters
    SB   = "\250", -- Sub-option to follow
    WILL = "\251", -- Will; request or confirm option begin
    WONT = "\252", -- Wont; deny option request
    DO   = "\253", -- Do = Request or confirm remote option
    DONT = "\254", -- Don't = Demand or confirm option halt
    IAC  = "\255", -- Interpret as Command
    SEND = "\001", -- Sub-process negotiation SEND command
    IS   = "\000", -- Sub-process negotiation IS command
    EOR  = "\239"
  },
  tncommands = {
    ASSOCIATE  = "\000",
    CONNECT    = "\001",
    DEVICETYPE = "\002",
    FUNCTIONS  = "\003",
    IS         = "\004",
    REASON     = "\005",
    REJECT     = "\006",
    REQUEST    = "\007",
    RESPONSES  = "\002",
    SEND       = "\008",
    EOR        = "\239"
  },

    -- Thesse are the options we accept for telnet
  options = {
    BINARY   = "\000",
    EOR      = "\025",
    TTYPE    = "\024",
    TN3270   = "\028",
    TN3270E  = "\040" 
  },

  command = {
    EAU   = "\015",
    EW    = "\005",
    EWA   = "\013",
    RB    = "\002",
    RM    = "\006",
    RMA   = "",
    W     = "\001",
    WSF   = "\017",
    NOP   = "\003",
    SNS   = "\004",
    SNSID = "\228"
  },
  sna_command ={
    RMA   = "\110",
    EAU   = "\111",
    EWA   = "\126",
    W     = "\241",
    RB    = "\242",
    WSF   = "\243",
    EW    = "\245",
    NOP   = "\003",
    RM    = "\246"
  },

  orders = {
    SF  = "\029",
    SFE = "\041",
    SBA = "\017",
    SA  = "\040",
    MF  = "\044",
    IC  = "\019",
    PT  = "\005",
    RA  = "\060",
    EUA = "\018",
    GE  = "\008"
  },

  fcorders = {
    NUL = "\000",
    SUB = "\063",
    DUP = "\028",
    FM  = "\030",
    FF  = "\012",
    CR  = "\013",
    NL  = "\021",
    EM  = "\025",
    EO  = "\255"
  },

  aids = {
    NO      = 0x60, -- no aid
    QREPLY  = 0x61, -- reply
    ENTER   = 0x7d, -- enter
    PF1     = 0xf1,
    PF2     = 0xf2,
    PF3     = 0xf3,
    PF4     = 0xf4,
    PF5     = 0xf5,
    PF6     = 0xf6,
    PF7     = 0xf7,
    PF8     = 0xf8,
    PF9     = 0xf9,
    PF10    = 0x7a,
    PF11    = 0x7b,
    PF12    = 0x7c,
    PF13    = 0xc1,
    PF14    = 0xc2,
    PF15    = 0xc3,
    PF16    = 0xc4,
    PF17    = 0xc5,
    PF18    = 0xc6,
    PF19    = 0xc7,
    PF20    = 0xc8,
    PF21    = 0xc9,
    PF22    = 0x4a,
    PF23    = 0x4b,
    PF24    = 0x4c,
    OICR    = 0xe6,
    MSR_MHS = 0xe7,
    SELECT  = 0x7e,
    PA1     = 0x6c,
    PA2     = 0x6e,
    PA3     = 0x6b,
    CLEAR   = 0x6d,
    SYSREQ  = 0xf0
  },

  -- used to translate buffer addresses
  code_table = {
    0x40, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7,
    0xC8, 0xC9, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F,
    0x50, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7,
    0xD8, 0xD9, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F,
    0x60, 0x61, 0xE2, 0xE3, 0xE4, 0xE5, 0xE6, 0xE7,
    0xE8, 0xE9, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F,
    0xF0, 0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xF7,
    0xF8, 0xF9, 0x7A, 0x7B, 0x7C, 0x7D, 0x7E, 0x7F
  },

  -- Variables used for Telnet Negotiation and data buffers
  word_state = { "Negotiating", "Connected", "TN3270 mode", "TN3270E mode"},
  NEGOTIATING    = 1,
  CONNECTED      = 2,
  TN3270_DATA    = 3,
  TN3270E_DATA   = 4,
  device_type    = "IBM-3278-2",

  -- TN3270E Header variables
  tn3270_header = {
    data_type     = '',
    request_flag  = '',
    response_flag = '',
    seq_number    = ''
  },

  -- TN3270 Datatream Processing flags
  NO_OUTPUT      = 0,
  OUTPUT         = 1,
  BAD_COMMAND    = 2,
  BAD_ADDRESS    = 3,
  NO_AID         = 0x60,
  aid            = 0x60,  -- initial Attention Identifier is No AID

  -- Header response flags.
  NO_RESPONSE       = 0x00,
  ERROR_RESPONSE    = 0x01,
  ALWAYS_RESPONSE   = 0x02,
  POSITIVE_RESPONSE = 0x00,
  NEGATIVE_RESPONSE = 0x01,

  -- Header data type names.
  DT_3270_DATA    = 0x00,
  DT_SCS_DATA     = 0x01,
  DT_RESPONSE     = 0x02,
  DT_BIND_IMAGE   = 0x03,
  DT_UNBIND       = 0x04,
  DT_NVT_DATA     = 0x05,
  DT_REQUEST      = 0x06,
  DT_SSCP_LU_DATA = 0x07,
  DT_PRINT_EOJ    = 0x08,

  -- Header response data.
  POS_DEVICE_END             = 0x00,
  NEG_COMMAND_REJECT         = 0x00,
  NEG_INTERVENTION_REQUIRED  = 0x01,
  NEG_OPERATION_CHECK        = 0x02,
  NEG_COMPONENT_DISCONNECTED = 0x03,

  -- TN3270E Negotiation Options
  TN3270E_ASSOCIATE   = 0x00,
  TN3270E_CONNECT     = 0x01,
  TN3270E_DEVICE_TYPE = 0x02,
  TN3270E_FUNCTIONS   = 0x03,
  TN3270E_IS          = 0x04,
  TN3270E_REASON      = 0x05,
  TN3270E_REJECT      = 0x06,
  TN3270E_REQUEST     = 0x07,
  TN3270E_SEND        = 0x08,

  -- SFE Attributes
  SFE_3270 = "192",
  order_max = "\063", -- tn3270 orders can't be greater than 0x3F
  COLS = 80, -- hardcoded width.
  ROWS = 24, -- hardcoded rows. We only support 3270 model 2 which was 24x80.
  buffer_addr = 1,
  cursor_addr = 1,
  isSSL = true,

  --- Creates a new TN3270 Client object

  new = function(self, socket)
    local o = {
      socket = socket or nmap.new_socket(),
      -- TN3270 Buffers
      buffer         = {},
      fa_buffer      = {},
      output_buffer  = {},
      overwrite_buf  = {},
      telnet_state   = 0, -- same as TNS_DATA to begin with
      server_options = {},
      client_options = {},
      unsupported_opts = {},
      sb_options     = '',
      connected_lu   = '',
      connected_dtype= '',
      telnet_data    = '',
      tn_buffer      = '',
      negotiated     = false,
      first_screen   = false,
      state          = 0,
      buffer_address = 1,
      formatted      = false,
    }
    setmetatable(o, self)
    self.__index = self
    return o
  end,

  --- Connects to a tn3270 servers
  connect = function ( self, host, port )

    local TN_PROTOCOLS = { "ssl", "tcp" }
    local status, err
    if not self.isSSL then
      status, err = self.socket:connect(host, port, 'tcp')
      local proto = 'tcp'
      if status then
        TN_PROTOCOLS = {proto}
        return true
      end
    else

      for _, proto in pairs(TN_PROTOCOLS) do
        status, err = self.socket:connect(host, port, proto)
        if status then
          TN_PROTOCOLS = {proto}
          return true
        end
        stdnse.debug(3,"Can't connect using %s: %s", proto, err)
      end
    end
    self.socket:close()
    return false, err
  end,

  disconnect = function ( self )
    stdnse.debug(2,"Disconnecting")
    return self.socket:close()
  end,

  recv_data = function ( self )
    return self.socket:receive()
  end,

  close = function ( self )
    return self.socket:close()
  end,

  send_data = function ( self, data )
    stdnse.debug(2, "Sending data: 0x%s", stdnse.tohex(data))
    return self.socket:send( data )
  end,

  ------------- End networking functions


  -- TN3270 Helper functions
  -----------
  --- Decode Buffer Address
  --
  -- Buffer addresses can come in 14 or 12 (this terminal doesn't support 16 bit)
  -- this function takes two bytes (buffer addresses are two bytes long) and returns
  -- the decoded buffer address.
  -- @param1 unsigned char, first byte of buffer address.
  -- @param2 unsigned char, second byte of buffer address.
  -- @return integer of buffer address
  DECODE_BADDR = function ( byte1, byte2 )
    if (byte1 & 0xC0) == 0 then
      -- (byte1 & 0x3F) << 8 | byte2
      return (((byte1 & 0x3F) << 8) | byte2) 
    else
      -- (byte1 & 0x3F) << 6 | (byte2 & 0x3F)
      return (((byte1 & 0x3F) << 6) | (byte2 & 0x3F)) 
    end
  end,

  --- Encode Buffer Address
  --
  -- @param integer buffer address
  -- @return TN3270 encoded buffer address (12 bit) as string
  ENCODE_BADDR = function ( self, address )
    stdnse.debug(3, "Encoding Address: " .. address)
    return string.pack("BB",
      -- (address >> 8) & 0x3F
      -- we need the +1 because LUA tables start at 1 (yay!)
      self.code_table[((address >> 6) & 0x3F)+1],
      -- address & 0x3F
      self.code_table[(address & 0x3F)+1]
      )
  end,

  BA_TO_ROW = function ( self, addr )
    return math.ceil((addr / self.COLS) + 0.5)
  end,

  BA_TO_COL = function ( self, addr )
    return addr % self.COLS
  end,

  INC_BUF_ADDR = function ( self, addr )
    return ((addr + 1) % (self.COLS * self.ROWS))
  end,

  DEC_BUF_ADDR = function ( self, addr )
    return ((addr + 1) % (self.COLS * self.ROWS))
  end,

  --- Initiates tn3270 connection
  initiate = function ( self, host, port )
    local status = true
    --local status, err = self:connect(host , port)
    local opts = {recv_before = true}
    self.socket, self.telnet_data = comm.tryssl(host, port, '', opts)

    if ( not(self.socket) ) then
      return false, self.telnet_data
    end
    -- clear out options buffers
    self.client_options = {}
    self.server_options = {}
    self.state = self.NEGOTIATING
    self.first_screen = false

    self:process_packets() -- process the first batch of information
    -- then loop through until we're done negotiating telnet/tn3270 options
    while not self.first_screen and status do
      status, self.telnet_data = self:recv_data()
      self:process_packets()
    end
    return status
  end,

  --- rebuilds tn3270 screen based on information sent
  -- Closes the socket if the mainframe has closed the socket on us
  -- Is done reading when it encounters EOR
  get_data = function ( self )
    local status = true
    self.first_screen = false
    while not self.first_screen and status do
      status, self.telnet_data = self:recv_data()
      self:process_packets()
    end
    if not status then
      self:disconnect()
    end
    return status
  end,

  get_all_data = function ( self, timeout )
    if timeout == nil then
      timeout = 200
    end
    local status = true
    self.first_screen = false
    self.socket:set_timeout(timeout)
    while status do
      status, self.telnet_data = self:recv_data()
      if self.telnet_data ~= "TIMEOUT" then
        self:process_packets()
      end
    end
    self.socket:set_timeout(3000)
    return status
  end,

  process_packets = function ( self )
    for i = 1,#self.telnet_data,1 do
      self:ts_processor(self.telnet_data:sub(i,i))
    end
    -- once all the data has been processed we clear out the buffer
    self.telnet_data = ''
  end,

  --- Disable SSL
  -- by default the tn3270 object uses SSL first. This disables SSL
  disableSSL = function (self)
    stdnse.debug(2,"Disabling SSL connections")
    self.isSSL = false
  end,

  --- Telnet State processor
  --
  -- @return true if success false if encoutered any issues

  ts_processor = function ( self, data )
    local TNS_DATA   = 0
    local TNS_IAC    = 1
    local TNS_WILL   = 2
    local TNS_WONT   = 3
    local TNS_DO     = 4
    local TNS_DONT   = 5
    local TNS_SB     = 6
    local TNS_SB_IAC = 7
    local supported  = false
    local DO_reply   = self.commands.IAC .. self.commands.DO
    local DONT_reply = self.commands.IAC .. self.commands.DONT
    local WILL_reply = self.commands.IAC .. self.commands.WILL
    local WONT_reply = self.commands.IAC .. self.commands.WONT

    --nsedebug.print_hex(data)
    --stdnse.debug(3,"current state:" .. self.telnet_state)

    if self.telnet_state == TNS_DATA then
      if data == self.commands.IAC then
        -- got an IAC
        self.telnet_state = TNS_IAC
        return true
      end
      -- stdnse.debug("Adding 0x%s to Data Buffer", stdnse.tohex(data))
      self:store3270(data)
    elseif self.telnet_state == TNS_IAC then
      if data == self.commands.IAC then
        -- insert this 0xFF in to the buffer
        self:store3270(data)
        self.telnet_state = TNS_DATA
      elseif data == self.commands.EOR then
        -- we're at the end of the TN3270 data
        -- let's process it and see what we've got
        -- but only if we're in 3270 mode
        if self.state == self.TN3270_DATA or self.state == self.TN3270E_DATA then
          self:process_data()
        end
        self.telnet_state = TNS_DATA
      elseif data == self.commands.WILL then self.telnet_state = TNS_WILL
      elseif data == self.commands.WONT then self.telnet_state = TNS_WONT
      elseif data == self.commands.DO   then self.telnet_state = TNS_DO
      elseif data == self.commands.DONT then self.telnet_state = TNS_DONT
      elseif data == self.commands.SB   then self.telnet_state = TNS_SB
      end
    elseif self.telnet_state == TNS_WILL then
      stdnse.debug(3, "[TELNET] IAC WILL 0x%s?", stdnse.tohex(data))
      for _,v in pairs(self.options) do -- check to see if we support this sub option (SB)
        if v == data then
          stdnse.debug(3, "[TELNET] IAC DO 0x%s", stdnse.tohex(data))
          supported = true
          break
        end
      end -- end of checking options
      for _,v in pairs(self.unsupported_opts) do
        if v == data then
          stdnse.debug(3, "[TELNET] IAC DONT 0x%s (disabled)", stdnse.tohex(data))
          supported = false
        end
      end 
      if supported then
        if not self.server_options[data] then -- if we haven't already replied to this, let's reply
          self.server_options[data] = true
          self:send_data(DO_reply..data)
          stdnse.debug(3, "[TELNET] Sent Will Reply: 0x%s", stdnse.tohex(data))
          self:in3270()
        end
      else
        self:send_data(DONT_reply..data)
        stdnse.debug(3, "[TELNET] Sent Don't Reply: 0x%s", stdnse.tohex(data))
      end
      self.telnet_state = TNS_DATA
    elseif self.telnet_state == TNS_WONT then
      if self.server_options[data] then
        self.server_options[data] = false
        self:send_data(DONT_reply..data)
        stdnse.debug(3, "[TELNET] Sent Don't Reply: 0x%s", stdnse.tohex(data))
        self:in3270()
      end
      self.telnet_state = TNS_DATA
    elseif self.telnet_state == TNS_DO then
      stdnse.debug(3, "[TELNET] IAC DO 0x%s?", stdnse.tohex(data))
      for _,v in pairs(self.options) do -- check to see if we support this sub option (SB)
        if v == data then
          stdnse.debug(3, "[TELNET] IAC WILL 0x%s", stdnse.tohex(data))
          supported = true
          break
        end
      end -- end of checking options
      for _,v in pairs(self.unsupported_opts) do
        if v == data then
          stdnse.debug(3, "[TELNET] IAC WONT 0x%s (disabled)", stdnse.tohex(data))
          supported = false
        end
      end 
      if supported then
        if not self.client_options[data] then
          self.client_options[data] = true
          self:send_data(WILL_reply..data)
          stdnse.debug(3, "[TELNET] Sent Do Reply: 0x%s" , stdnse.tohex(data))
          self:in3270()
        end
      else
        self:send_data(WONT_reply..data)
        stdnse.debug(3, "[TELNET] Got unsupported Do. Sent Won't Reply: " .. data .. " " .. self.telnet_data)
      end
      self.telnet_state = TNS_DATA
    elseif self.telnet_state == TNS_DONT then
      if self.client_options[data] then
        self.client_options[data] = false
        self:send_data(WONT_reply .. data)
        stdnse.debug(3, "[TELNET] Sent Wont Reply: 0x%s", stdnse.tohex(data))
        self:in3270()
      end
      self.telnet_state = TNS_DATA
    elseif self.telnet_state == TNS_SB then
      if data == self.commands.IAC then
        self.telnet_state = TNS_SB_IAC
      else
        self.sb_options = self.sb_options .. data
      end
    elseif self.telnet_state == TNS_SB_IAC then
      stdnse.debug(3, "[TELNET] Processing SB options")
--      self.sb_options = self.sb_options .. data -- looks like this is a bug? Why append F0 to the end?
      if data == self.commands.SE then
        self.telnet_state = TNS_DATA
        if self.sb_options:sub(1,1) == self.options.TTYPE and
          self.sb_options:sub(2,2) == self.commands.SEND then
          self:send_data(self.commands.IAC  ..
            self.commands.SB   ..
            self.options.TTYPE ..
            self.commands.IS   ..
            self.device_type   ..
            self.commands.IAC  ..
            self.commands.SE   )
        elseif (self.client_options[self.options.TN3270] or self.client_options[self.options.TN3270E]) and
               (self.sb_options:sub(1,1) == self.options.TN3270 or 
                self.sb_options:sub(1,1) == self.options.TN3270E) then
          if not self:negotiate_tn3270() then
            return false
          end
          stdnse.debug(3, "[TELNET] Done Negotiating Options")
        else
          self.telnet_state = TNS_DATA
        end
        self.sb_options = ''
      end
      --self.sb_options = ''
    end -- end of makeshift switch/case
    return true
  end,

  --- Stores a character on a buffer to be processed
  --
  store3270 = function ( self, char )
    self.tn_buffer = self.tn_buffer .. char
  end,

  --- Function to negotiate TN3270 sub options

  negotiate_tn3270 = function ( self )
    stdnse.debug(3, "[TN3270] Processing tn data subnegotiation options ")
    local option = self.sb_options:sub(2,2)
   -- stdnse.debug("[TN3270E] We got this: 0x%s", stdnse.tohex(option))
    
    if option == self.tncommands.SEND then
      if self.sb_options:sub(3,3) == self.tncommands.DEVICETYPE then
        if self.connected_lu == '' then
          self:send_data(self.commands.IAC          ..
          self.commands.SB           ..
          self.options.TN3270E        ..
          self.tncommands.DEVICETYPE ..
          self.tncommands.REQUEST    ..
          self.device_type           ..
          self.commands.IAC          ..
          self.commands.SE           )
        else
          stdnse.debug(3,"[TN3270] Sending LU: %s", self.connected_lu)
          self:send_data(self.commands.IAC          ..
          self.commands.SB           ..
          self.options.TN3270E       ..
          self.tncommands.DEVICETYPE ..
          self.tncommands.REQUEST    ..
          self.device_type           ..
          self.tncommands.CONNECT    ..
          self.connected_lu          ..
          self.commands.IAC          ..
          self.commands.SE           )
        end
      else
        stdnse.debug(3,"[TN3270] Received TN3270 Send but not device type. Weird.")
        return false
      end
    elseif option == self.tncommands.DEVICETYPE then -- Mainframe is confirming device type. Good!
      if self.sb_options:sub(3,3) == self.tncommands.REJECT then
        -- Welp our LU request failed, shut it down
        stdnse.debug(3,"[TN3270] Received TN3270 REJECT.")
        return false
      elseif self.sb_options:sub(3,3) == self.tncommands.IS then
        local tn_loc = 1
        while self.sb_options:sub(4+tn_loc,4+tn_loc) ~= self.commands.SE and
        self.sb_options:sub(4+tn_loc,4+tn_loc) ~= self.tncommands.CONNECT do
          tn_loc = tn_loc + 1
        end
        --XXX Unused variable??? Should this be tn_loc?
        -- local sn_loc = 1
        if self.sb_options:sub(4+tn_loc,4+tn_loc) == self.tncommands.CONNECT then
          self.connected_lu = self.sb_options:sub(5+tn_loc, #self.sb_options)
          self.connected_dtype = self.sb_options:sub(4,3+tn_loc)
          stdnse.debug(3,"[TN3270] Current LU: %s", self.connected_lu)
        end
        -- since We've connected lets send our options
        self:send_data(self.commands.IAC          ..
          self.commands.SB           ..
          self.options.TN3270E       ..
          self.tncommands.FUNCTIONS  ..
          self.tncommands.REQUEST    ..
          --self.tncommands.RESPONSES  .. -- we'll only support basic 3270E mode
          self.commands.IAC          ..
          self.commands.SE           )
      end
    elseif option == self.tncommands.FUNCTIONS then
      if self.sb_options:sub(3,3) == self.tncommands.IS then
        -- they accepted the function request, lets move on
        self.negotiated = true
        stdnse.debug(3,"[TN3270] Option Negotiation Done!")
        self:in3270()
      elseif self.sb_options:sub(3,3) == self.tncommands.REQUEST then
        -- dummy functions for now. Our client doesn't have any
        -- functions really but we'll agree to whatever they want
        self:send_data(self.commands.IAC         ..
          self.commands.SB          ..
          self.options.TN3270E      ..
          self.tncommands.FUNCTIONS ..
          self.tncommands.IS        ..
          self.sb_options:sub(4,4)  ..
          self.commands.IAC         ..
          self.commands.SE          )
        self.negotiated = true
        self:in3270()
      end
    end
    return true
  end,

  --- Check to see if we're in TN3270
  in3270 = function ( self )
    if self.client_options[self.options.TN3270E] then
    stdnse.debug(3,"[in3270] In TN3270E mode")
      if self.negotiated then
        stdnse.debug(3,"[in3270] TN3270E negotiated")
        self.state = self.TN3270E_DATA
      end
    elseif self.client_options[self.options.EOR] and
      self.client_options[self.options.BINARY] and
      self.client_options[self.options.EOR] and
      self.client_options[self.options.BINARY] and
      self.client_options[self.options.TTYPE] then
      stdnse.debug(3,"[in3270] In TN3270 mode")
      self.state = self.TN3270_DATA
    end

    if self.state == self.TN3270_DATA or self.state == self.TN3270E_DATA then
      -- since we're in TN3270 mode, let's create an empty buffer
      stdnse.debug(3, "[in3270] Creating Empty IBM-3278-2 Buffer")
      for i=0, 1920 do
        self.buffer[i] = "\0"
        self.fa_buffer[i] = "\0"
        self.overwrite_buf[i] = "\0"
      end
      stdnse.debug(3, "[in3270] Empty Buffer Created. Length: " .. #self.buffer)
    end
    stdnse.debug(3,"[in3270] Current State: "..self.word_state[self.state])
  end,

  --- Also known as process_eor
  process_data = function ( self )
    local reply = 0
    stdnse.debug(3,"Processing TN3270 Data")
    if self.state == self.TN3270E_DATA then
      stdnse.debug(3,"[TN3270E] Processing TN3270 Data header: %s", stdnse.tohex(self.tn_buffer:sub(1,5)))
      self.tn3270_header.data_type     = self.tn_buffer:sub(1,1)
      self.tn3270_header.request_flag  = self.tn_buffer:sub(2,2)
      self.tn3270_header.response_flag = self.tn_buffer:sub(3,3)
      self.tn3270_header.seq_number    = self.tn_buffer:sub(4,5)
      if self.tn3270_header.data_type == "\000" then
        reply = self:process_3270(self.tn_buffer:sub(6))
        stdnse.debug(3,"[TN3270E] Reply: %s", reply)
      end
      if reply < 0  and self.tn3270_header.request_flag ~= self.TN3270E_RSF_NO_RESPONSE then
        self:tn3270e_nak(reply)
      elseif reply == self.NO_OUTPUT and
        self.tn3270_header.request_flag == self.ALWAYS_RESPONSE then
        self:tn3270e_ack()
      end
    else
      self:process_3270(self.tn_buffer)
    end
    -- nsedebug.print_hex(self.tn_buffer)

    self.tn_buffer = ''
    return  true
  end,

  tn3270e_nak = function ( self, reply )
    local neg = ""
    if reply == self.BAD_COMMAND then
      neg = self.NEG_COMMAND_REJECT
    elseif reply == self.BAD_ADDRESS then
      neg = self.NEG_OPERATION_CHECK
    end

    -- build the TN3270E nak reply header
    local reply_buf = string.pack("BBB c2",
      self.DT_RESPONSE, -- type
      0, -- request
      self.NEGATIVE_RESPONSE, -- response
      -- because this is telnet we gotta double up 0xFF chars
      self.tn3270_header.seq_number:sub(1,2):gsub(self.commands.IAC, self.commands.IAC:rep(2))
      ) .. neg .. self.commands.IAC .. self.commands.EOR

    -- now send the whole thing
    self:send_data(reply_buf)
  end,

  tn3270e_ack = function ( self )
    -- build the TN3270E ack reply header
    local reply_buf = string.pack("BBB c2",
      self.DT_RESPONSE, -- type
      0, -- request
      self.POSITIVE_RESPONSE, -- response
      -- because this is telnet we gotta double up 0xFF chars
      self.tn3270_header.seq_number:sub(1,2):gsub(self.commands.IAC, self.commands.IAC:rep(2))
      ) .. self.POS_DEVICE_END .. self.commands.IAC .. self.commands.EOR
    -- now send the whole package
    self:send_data(reply_buf)
  end,

  clear_screen = function ( self )
    self.buffer_address = 1
    for i=1,1920,1 do
      self.buffer[i] = "\0"
      self.fa_buffer[i] = "\0"
    end
  end,

  clear_unprotected = function ( self )
    -- we don't support protect vs unprotected (yet)
    -- this function is a stub for now
  end,

  process_3270 = function ( self, data )
    -- the first byte will be the command we have to follow
    local com = data:sub(1,1)
    stdnse.debug(3, "[PROCESS 3270] Value Received: 0x%s", stdnse.tohex(com))
    if com == self.command.EAU then
      stdnse.debug(3,"TN3270 Command: Erase All Unprotected")
      self:clear_unprotected()
      return self.NO_OUTPUT
    elseif com == self.command.EWA or com == self.sna_command.EWA or
      com == self.command.EW  or com == self.sna_command.EW  then
      stdnse.debug(3,"TN3270 Command: Erase Write (Alternate)")
      self:clear_screen()
      self:process_write(data) -- so far should only return No Output
      return self.NO_OUTPUT
    elseif com == self.command.W   or com == self.sna_command.W then
      stdnse.debug(3,"TN3270 Command: Write")
      self:process_write(data)
    elseif com == self.command.RB  or com == self.sna_command.RB then
      stdnse.debug(3,"TN3270 Command: Read Buffer")
      self:process_read()
      return self.OUTPUT
    elseif com == self.command.RM  or com == self.sna_command.RM or
      com == self.command.RMA or com == self.sna_command.RMA then
      stdnse.debug(3,"TN3270 Command: Read Modified (All)")
      --XXX What is read_modified? What is aid?
      --self:read_modified(aid)
      --return self.OUTPUT
      stdnse.debug1("UNIMPLEMENTED TN3270 Command: Read Modified (All)")
      return self.BAD_COMMAND
    elseif com == self.command.WSF or com == self.sna_command.WSF then
      stdnse.debug(3,"TN3270 Command: Write Structured Field")
      return self:w_structured_field(data)
    elseif com == self.command.NOP or com == self.sna_command.NOP then
      stdnse.debug(3,"TN3270 Command: No OP (NOP)")
      return self.NO_OUTPUT
    else
      stdnse.debug(3,"Unknown 3270 Data Stream command: 0x"..stdnse.tohex(com))
      return self.BAD_COMMAND

    end
    return 1 -- we may sometimes enter a state where we have nothing which is fine

  end,

  --- WCC / tn3270 data stream processor
  --
  -- @param tn3270 data stream
  -- @return status true on success, false on failure
  -- @return changes self.buffer to match requested changes
  process_write = function ( self, data )
    stdnse.debug(3, "Processing TN3270 Write Command")
    local prev = ''
    local cp = ''
    local num_attr = 0
    local last_cmd = false
    local i = 2 -- skip SF to get WCC

    if (data:byte(i) & 0x40) == 0x40 then
      stdnse.debug(3,"[WCC] Reset")
    end

    if (data:byte(i) & 0x02) == 0x02 then
      stdnse.debug(3,"[WCC] Restore")
    end

    i = 3 -- skip the SF and the WCC.
    while i <= #data do
      cp = data:sub(i,i)
      stdnse.debug(4,"Current Position: ".. i .. " of " .. #data)
      stdnse.debug(4,"Current Item: ".. stdnse.tohex(cp))
      -- yay! lua has no switch statement
      if cp == self.orders.SF then
        stdnse.debug(4,"Start Field")
        prev = 'ORDER'

        last_cmd = true
        i = i + 1 -- skip SF
        stdnse.debug(4,"Writting Zero to buffer at address: " .. self.buffer_address)
        stdnse.debug(4,"Attribute Type: 0x".. stdnse.tohex(data:sub(i,i)))
        self:write_field_attribute(data:sub(i,i))
        self:write_char("\00")
        self.buffer_address = self:INC_BUF_ADDR(self.buffer_address)
        -- set the current position one ahead (after SF)
        i = i + 1

      elseif cp == self.orders.SFE then
        stdnse.debug(4,"Start Field Extended")
        i = i + 1 -- skip SFE
        num_attr = data:byte(i)
        stdnse.debug(4,"Number of Attributes: ".. num_attr)
        for j = 1,num_attr do
          i = i + 1
          if data:byte(i) == 0xc0 then
            stdnse.debug(4,"Writting Zero to buffer at address: " .. self.buffer_address)
            stdnse.debug(4,"Attribute Type: 0x".. stdnse.tohex(data:sub(i,i)))
            self:write_char("\00")
            self:write_field_attribute(data:sub(i,i))
          end

          i = i + 1
        end
        i = i + 1
        self.buffer_address = self:INC_BUF_ADDR(self.buffer_address)
      elseif cp == self.orders.SBA then
        stdnse.debug(4,"Set Buffer Address (SBA) 0x11")
        self.buffer_address = self.DECODE_BADDR(data:byte(i+1), data:byte(i+2))
        stdnse.debug(4,"Buffer Address: " .. self.buffer_address)
        stdnse.debug(4,"Row: " .. self:BA_TO_ROW(self.buffer_address))
        stdnse.debug(4,"Col: " .. self:BA_TO_COL(self.buffer_address))
        last_cmd = true
        prev = 'SBA'
        -- the current position is SBA, the next two bytes are the lengths
        i = i + 3
        stdnse.debug(4,"Next Command: ".. stdnse.tohex(data:sub(i,i)))
      elseif cp == self.orders.IC then -- Insert Cursor
        stdnse.debug(4,"Insert Cursor (IC) 0x13")
        stdnse.debug(4,"Current Cursor Address: " .. self.cursor_addr)
        stdnse.debug(4,"Buffer Address: " .. self.buffer_address)
        stdnse.debug(4,"Row: " .. self:BA_TO_ROW(self.buffer_address))
        stdnse.debug(4,"Col: " .. self:BA_TO_COL(self.buffer_address))
        prev = 'ORDER'
        self.cursor_addr = self.buffer_address
        last_cmd = true
        i = i + 1
      elseif cp == self.orders.RA then
        -- Repeat address repeats whatever the next char is after the two byte buffer address
        -- There's all kinds of weird GE stuff we could do, but not now. Maybe in future vers
        stdnse.debug(4,"Repeat to Address (RA) 0x3C")
        local ra_baddr = self.DECODE_BADDR(data:byte(i+1), data:byte(i+2))
        stdnse.debug(4,"Repeat Character: " .. stdnse.tohex(data:sub(i+1,i+2)))

        stdnse.debug(4,"Repeat to this Address: " .. ra_baddr)
        stdnse.debug(4,"Currrent Address: " .. self.buffer_address)
        prev = 'ORDER'
        --char_code = data:sub(i+3,i+3)
        i = i + 3
        local char_to_repeat = data:sub(i,i)
        stdnse.debug(4,"Repeat Character: " .. stdnse.tohex(char_to_repeat))
        while (self.buffer_address ~= ra_baddr) do
          self:write_char(char_to_repeat)
          self.buffer_address = self:INC_BUF_ADDR(self.buffer_address)
        end
      elseif cp == self.orders.EUA then
        stdnse.debug(4,"Erase Unprotected All (EAU) 0x12")
        local eua_baddr = self.DECODE_BADDR(data:byte(i+1), data:byte(i+2))
        i = i + 3
        stdnse.debug(4,"EAU to this Address: " .. eua_baddr)
        stdnse.debug(4,"Currrent Address: " .. self.buffer_address)
        while (self.buffer_address ~= eua_baddr) do
          -- do nothing for now. this feature isn't supported/required at the moment
          self.buffer_address = self:INC_BUF_ADDR(self.buffer_address)
          --stdnse.debug(3,"Currrent Address: " .. self.buffer_address)
          --stdnse.debug(3,"EAU to this Address: " .. eua_baddr)
        end
      elseif cp == self.orders.GE then
        stdnse.debug(4,"Graphical Escape (GE) 0x08")
        prev = 'ORDER'
        i = i + 1 -- move to next byte
        local ge_char = data:sub(i,i)
        self:write_char(self, ge_char)
        self.buffer_address = self:INC_BUF_ADDR(self.buffer_address)
      elseif cp == self.orders.MF then
        -- MotherFucker, lol!
        -- or mainframe maybe
        -- we don't actually have 'fields' at this point
        -- so there's nothing to be modified
        stdnse.debug(4,"Modify Field (MF) 0x2C")
        prev = 'ORDER'
        i = i + 1
        local num_attr = tonumber(data:sub(i,i))
        for j = 1, num_attr, 1 do
          -- placeholder in case we need to do something here
          stdnse.debug(4,"Set Attribute (MF) 0x2C")
          i = i + 1
        end
        self.buffer_address = self:INC_BUF_ADDR(self.buffer_address)
      elseif cp == self.orders.SA then
        -- We'll add alerting here to identify hidden field
        -- but for now we're doing NOTHING
        i = i + 1

      elseif cp == self.fcorders.NUL or
        cp == self.fcorders.SUB or
        cp == self.fcorders.DUP or
        cp == self.fcorders.FM or
        cp == self.fcorders.FF or
        cp == self.fcorders.CR or
        cp == self.fcorders.NL or
        cp == self.fcorders.EM or
        cp == self.fcorders.EO then
        stdnse.debug(4,"Format Control Order received")
        prev = 'ORDER'
        self:write_char("\064")
        self.buffer_address = self:INC_BUF_ADDR(self.buffer_address)
        i = i + 1
      else -- whoa we made it.
        local ascii_char = drda.StringUtil.toASCII(cp)
        stdnse.debug(4,"Inserting 0x"..stdnse.tohex(cp).." (".. ascii_char ..") at the following location:")
        stdnse.debug(4,"Row: " .. self:BA_TO_ROW(self.buffer_address))
        stdnse.debug(4,"Col: " .. self:BA_TO_COL(self.buffer_address))
        stdnse.debug(4,"Buffer Address: " .. self.buffer_address)
        self:write_char(data:sub(i,i))
        self.buffer_address = self:INC_BUF_ADDR(self.buffer_address)
        self.first_screen = true
        i = i + 1
      end -- end of massive if/else
    end -- end of while loop
    self.formatted = true
  end,

  write_char = function ( self, char )
    if self.buffer[self.buffer_address] == "\0" then
      self.buffer[self.buffer_address] = char
    else
      self.overwrite_buf[self.buffer_address] = self.buffer[self.buffer_address]
      self.buffer[self.buffer_address] = char
    end
  end,

  write_field_attribute = function ( self, attr )
    self.fa_buffer[self.buffer_address] = attr
  end,

  process_read = function ( self )
    local output_addr = 0
    self.output_buffer = {}
    stdnse.debug(3,"Generating Read Buffer")
    self.output_buffer[output_addr] = string.pack("B",self.aid)
    output_addr = output_addr + 1
    stdnse.debug(3,"Output Address: ".. output_addr)
    self.output_buffer[output_addr] = self:ENCODE_BADDR(self.cursor_addr)
    return self:send_tn3270(self.output_buffer)

    -- need to add while loop

  end,

  w_structured_field = function ( self, wsf_data )
    -- this is the ugliest hack ever
    -- but it works and it doesn't matter what we support anyway
    stdnse.debug(3, "Processing TN3270 Write Structured Field Command")
    -- all our options, one liner style
    local query_options =
    "\x88\x00\x16\x81\x86\x00\x08\x00\xf4\xf1\x00\xf2\x00\xf3\x00\xf4\z
     \x00\xf5\x00\xf6\x00\xf7\x00\x00\x0d\x81\x87\x04\x00\xf0\xf1\xf1\z
     \xf2\xf2\xf4\xf4\x00\x22\x81\x85\x82\x00\x07\x10\x00\x00\x00\x00\z
     \x07\x00\x00\x00\x00\x65\x00\x25\x00\x00\x00\x02\xb9\x00\x25\x01\z
     \x00\xf1\x03\xc3\x01\x36\x00\x2e\x81\x81\x03\x00\x00\x50\x00\x18\z
     \x00\x00\x01\x00\x48\x00\x01\x00\x48\x07\x10\x00\x00\x00\x00\x00\z
     \x00\x13\x02\x00\x01\x00\x50\x00\x18\x00\x00\x01\x00\x48\x00\x01\z
     \x00\x48\x07\x10\x00\x1c\x81\xa6\x00\x00\x0b\x01\x00\x00\x50\x00\z
     \x18\x00\x50\x00\x18\x0b\x02\x00\x00\x07\x00\x10\x00\x07\x00\x10\z
     \x00\x07\x81\x88\x00\x01\x02\x00\x16\x81\x80\x80\x81\x84\x85\x86\z
     \x87\x88\xa1\xa6\xa8\x96\x99\xb0\xb1\xb2\xb3\xb4\xb6\x00\x08\x81\z
     \x84\x00\x0a\x00\x04\x00\x06\x81\x99\x00\x00\xff\xef"
    stdnse.debug(3, "Current WSF : %s", stdnse.tohex(wsf_data:sub(4,4)) )

    if self.state == self.TN3270E_DATA then 
      -- We need to add the header here since we're in TN3270E mode
      query_options = "\x00\x00\x00\x00\x00" .. query_options
    end
    self:send_data(query_options)
    return 1
  end,


  --- Sends TN3270 Packet
  --
  -- Expands IAC to IAC IAC and finally appends IAC EOR
  -- @param data: table containing buffer array
  send_tn3270 = function ( self, data )
    local packet = ''
    if self.state == self.TN3270E_DATA then
      packet = "\x00\x00\x00\x00\x00"
      -- we need to create the tn3270E (the E is important) header
      -- which, in basic 3270E is 5 bytes of 0x00
      --packet = string.pack("BBB >I2",
      --  self.DT_3270_DATA, -- type
      --  0, -- request
      --  0, -- response
      --  0
       -- )
      --self.tn3270_header.seq_number
    end
    -- create send buffer and double up IACs

    for i=0,#data do
      stdnse.debug(3,"Adding 0x" .. stdnse.tohex(data[i]) .. " to the read buffer")
      packet = packet .. data[i]
      if data[i] == self.commands.IAC then
        packet = packet .. self.commands.IAC
      end
    end
    packet = packet .. self.commands.IAC .. self.commands.EOR
    return self:send_data(packet) -- send the output buffer
  end,

  get_screen = function ( self )
    stdnse.debug(3,"Returning the current TN3270 buffer")
    local buff = '\n'
    for i = 0,#self.buffer do
      if self.buffer[i] == "\00" then
        buff = buff .. " "
      else
        buff = buff .. drda.StringUtil.toASCII(self.buffer[i])
      end
      if (i+1) % 80 == 0 then
        buff = buff .. "\n"
      end
    end
    return buff
  end,

  get_screen_debug = function ( self, lvl )
    lvl = lvl or 1
    stdnse.debug(lvl,"---------------------- Printing the current TN3270 buffer ----------------------")
    local buff = ''
    for i = 0,#self.buffer do
      if self.buffer[i] == "\00" then
        buff = buff .. " "
      else
        buff = buff .. drda.StringUtil.toASCII(self.buffer[i])
      end
      if (i+1) % 80 == 0 then
        stdnse.debug(lvl, buff)
        buff = ''
      end
    end
    stdnse.debug(lvl,"----------------------- End of the current TN3270 buffer ---------------------")

    return buff
  end,

  get_screen_raw = function ( self )
    local buff = ''
    for i = 0,#self.buffer do
      buff = buff .. drda.StringUtil.toASCII(self.buffer[i])
    end
    return buff
  end,


  --- Sends data at the current cursor location. Ignores field attributes.
  --
  -- It only uses enter key (AID = 0x7d) to send this data
  -- for more complicated items use send_location
  -- @param string you wish to send.
  send_cursor = function ( self, data )
    local ebcdic_letter = ''
    self.output_buffer = {} -- empty the output buffer
    self.output_buffer[0] = string.pack("B",self.aids.ENTER) -- what follows is an ENTER
    stdnse.debug(3,"Cursor Location ("..self.cursor_addr.."): Row: %s, Column: %s ",
      self:BA_TO_ROW(self.cursor_addr),
      self:BA_TO_COL(self.cursor_addr) )
    table.insert(self.output_buffer, self:ENCODE_BADDR(self.cursor_addr + #data)) -- location of cursor
    table.insert(self.output_buffer, self.orders.SBA) -- set the buffer address to the following location
    table.insert(self.output_buffer, self:ENCODE_BADDR(self.cursor_addr)) -- location of buffer address
    for i = 1, #data do
      stdnse.debug(3,"Inserting %s to the send buffer", data:sub(i,i))
      ebcdic_letter = drda.StringUtil.toEBCDIC( data:sub(i,i) )
      table.insert(self.output_buffer, ebcdic_letter ) -- insert the ebcdic character on the array
    end
    return self:send_tn3270(self.output_buffer)
  end,

  --- Sends the data to the location specified
  --
  -- Using a location on the screen sends the data
  -- @param location: a location on the screen (between 0 and 1920)
  -- @param data: ascii data to send to that location
  send_location = function( self, location, data )
    local cursor_location = location + #data
    local ebcdic_letter = ''
    self.output_buffer = {}
    self.output_buffer[0] = string.pack("B",self.aids.ENTER)
    table.insert(self.output_buffer, self:ENCODE_BADDR(cursor_location))
    stdnse.debug(3,"Cursor Location ("..cursor_location.."): Row: %s, Column: %s ",
      self:BA_TO_ROW(cursor_location),
      self:BA_TO_COL(cursor_location) )
    stdnse.debug(3,"Inserting %s at location %d", data, location )
    table.insert(self.output_buffer, self.orders.SBA)
    cursor_location = location
    table.insert(self.output_buffer, self:ENCODE_BADDR(cursor_location))
    for j = 1, #data do
      ebcdic_letter = drda.StringUtil.toEBCDIC( data:sub(j,j) )
      table.insert(self.output_buffer, ebcdic_letter )
    end

    return self:send_tn3270(self.output_buffer)
  end,

  --- Sends the data to multiple locations on the screen
  --
  -- Using a supplied tuple of location and data generates tn3270 data to
  -- fill out the screen
  -- @param location_tuple: and array of tuples with location and data. For
  --                        example: send_locations([{579:"dade"},{630:"secret"}])
  send_locations = function( self, location_tuple )
    local cursor_location = location_tuple[#location_tuple][1] + #location_tuple[#location_tuple][2]
    local ebcdic_letter = ''
    self.output_buffer = {}
    self.output_buffer[0] = string.pack("B",self.aids.ENTER)
    table.insert(self.output_buffer, self:ENCODE_BADDR(cursor_location))
    stdnse.debug(3,"Cursor Location ("..cursor_location.."): Row: %s, Column: %s ",
      self:BA_TO_ROW(cursor_location),
      self:BA_TO_COL(cursor_location) )
    for i = 1, #location_tuple do
      stdnse.debug(3,"Inserting %s at location %d", location_tuple[i][2], location_tuple[i][1] )
      table.insert(self.output_buffer, self.orders.SBA)
      cursor_location = location_tuple[i][1]
      table.insert(self.output_buffer, self:ENCODE_BADDR(cursor_location))
      for j = 1, #location_tuple[i][2] do
        ebcdic_letter = drda.StringUtil.toEBCDIC( location_tuple[i][2]:sub(j,j) )
        table.insert(self.output_buffer, ebcdic_letter )
      end
    end
    return self:send_tn3270(self.output_buffer)
  end,

  send_enter = function ( self )
    local ebcdic_letter = ''
    self.output_buffer = {}
    self.output_buffer[0] = string.pack("B",self.aids.ENTER)
    table.insert(self.output_buffer, self:ENCODE_BADDR(self.cursor_addr))
    table.insert(self.output_buffer, self.orders.SBA)
    table.insert(self.output_buffer, self:ENCODE_BADDR(self.cursor_addr))
    return self:send_tn3270(self.output_buffer)
  end,

  send_clear = function ( self )
    return self:send_data( string.pack("B",self.aids.CLEAR) .. self.commands.IAC .. self.commands.EOR )
  end,

  send_pf = function ( self, pf )
    if pf > 24 or pf < 0 then
      return false, "PF Value must be between 1 and 24"
    end
    self.output_buffer = {}
    self.output_buffer[0] = string.pack("B", self.aids["PF"..pf] )
    stdnse.debug(3,"Cursor Location ("..self.cursor_addr.."): Row: %s, Column: %s ",
      self:BA_TO_ROW(self.cursor_addr),
      self:BA_TO_COL(self.cursor_addr) )
    self.output_buffer[1] = self:ENCODE_BADDR(self.cursor_addr)
    return self:send_tn3270(self.output_buffer)
  end,

  writeable = function (self)
    -- Returns a list with all writeable fields as {location, length} tuples
    local writeable_list = {}
    for i = 0,#self.fa_buffer do
      if ( self.fa_buffer[i] ~= "\00" ) and (self.fa_buffer[i]:byte(1) & 0x20) ~= 0x20 then
        -- found writeable flag
        for j = i,#self.fa_buffer do
          -- find end of field
          if (self.fa_buffer[j]:byte(1) & 0x20) == 0x20 then
            stdnse.debug(3,"[WRITEABLE] Area: %d Row: %d Col: %d Length: %d", i + 1, self:BA_TO_ROW(i + 1), self:BA_TO_COL(i + 2), j-i-1)
            table.insert(writeable_list, {i + 1, j-i-1})
            break
          end
        end
      end
    end
    return writeable_list
  end,

  find = function ( self, str )
    local buff = ''
    for i = 0,#self.buffer do
      if self.buffer[i] == "\00" then
        buff = buff .. " "
      else
        buff = buff .. drda.StringUtil.toASCII(self.buffer[i])
      end
    end
    --local buff = self:get_screen()
    stdnse.debug(3, "[FIND] Looking for: %s", tostring(str))
    local i, j = string.find(buff, str)
    if i == nil then
      stdnse.debug(3, "[FIND] Couldn't find: %s", tostring(str))
      return false
    else
      stdnse.debug(3, "[FIND] Found String: %s", tostring(str))
      return i , j
    end
  end,

  isClear = function ( self )
    local buff = ''
    for i = 0,#self.buffer do
      if self.buffer[i] == "\00" then
        buff = buff .. " "
      else
        buff = buff .. drda.StringUtil.toASCII(self.buffer[i])
      end
    end
    local i, j = string.find(buff, '%w')
    if i ~= nil then
      stdnse.debug(3, "[CLEAR] Screen has text")
      return false
    else
      stdnse.debug(3, "[CLEAR] Screen is Empty")
      return true
    end
  end,

  --- Any Hidden Fields
  --
  -- @returns true if there are any hidden fields in the buffer
  any_hidden = function ( self )
    local hidden_attrib = 0x0c -- 00001100 is hidden
    for i = 0,#self.fa_buffer do
      if (self.fa_buffer[i]:byte(1) & hidden_attrib) == hidden_attrib then
        return true
      end
    end
  end,

  --- Hidden Fields
  --
  -- @returns the locations of hidden fields in a table with each pair being the start and stop of the hidden field
  hidden_fields_location = function ( self )
    local hidden_attrib = 0x0c -- 00001100 is hidden
    local hidden_location = {}
    local i = 1
    if not self:any_hidden() then
      return hidden_location
    end
    while i <= #self.fa_buffer do
      if (self.fa_buffer[i]:byte(1) & hidden_attrib) == hidden_attrib then
        stdnse.debug(3, "Found hidden field at buffer location: " .. i)
        table.insert(hidden_location, i)
        i = i + 1
        while self.fa_buffer[i] == "\0" do
          i = i + 1
        end
        table.insert(hidden_location, i)
      end
      i = i + 1
    end
    return hidden_location
  end,

  hidden_fields = function ( self )
    local locations = self:hidden_fields_location()
    local fields = {}
    local i, j = 1,1
    local start, stop = 0
    while i <= #locations do
      start = locations[i] + 1
      stop  = locations[i+1] - 1
      stdnse.debug(3, "Start Location: %i Stop Location %i", start, stop)
      fields[j] = ''
      for k = start,stop do
        -- stdnse.debug(3, "k = %i Inserting 0x%s", k, stdnse.tohex(self.buffer[k]))
        fields[j] = fields[j] .. drda.StringUtil.toASCII(self.buffer[k])
      end
      j = j + 1
      i = i + 2
    end
    return fields
  end,

  any_overwritten = function ( self )
    for i = 1, #self.overwrite_buf do
      if self.overwrite_buf[i] ~= "\0" then
        return true
      end
    end
    return false
  end,

  set_lu = function (self, LU)
    -- Sets an LU
    self.connected_lu = LU
  end,

  get_lu = function ( self )
     return self.connected_lu
  end,
  disable_tn3270e = function ( self )
    stdnse.debug(3,"Disabling TN3270E")
    table.insert(self.unsupported_opts,self.options.TN3270E)
  end, 
  overwrite_data = function ( self )
    if not self:any_overwritten() then
      return false
    end
    stdnse.debug(3,"Printing the overwritten TN3270 buffer")
    local buff = '\n'
    for i = 0,#self.overwrite_buf do
      if self.overwrite_buf[i] == "\0" then
        buff = buff .. " "
      else
        buff = buff .. drda.StringUtil.toASCII(self.buffer[i])
      end
      if i % 80 == 0 then
        buff = buff .. "\n"
      end
    end
    return buff
  end
}

return _ENV
