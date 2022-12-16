local datetime = require "datetime"
local http = require "http"
local nmap = require "nmap"
local stdnse = require "stdnse"
local string = require "string"
local tab = require "tab"
local table = require "table"
_ENV = stdnse.module("ipp", stdnse.seeall)

---
--
-- A small CUPS ipp (Internet Printing Protocol) library implementation
--
-- @author Patrik Karlsson
--

-- The IPP layer
IPP = {

  StatusCode = {
    OK        = 0,
  },

  State = {
    IPP_JOB_PENDING     = 3,
    IPP_JOB_HELD        = 4,
    IPP_JOB_PROCESSING  = 5,
    IPP_JOB_STOPPED     = 6,
    IPP_JOB_CANCELED    = 7,
    IPP_JOB_ABORTED     = 8,
    IPP_JOB_COMPLETED   = 9,
  },

  StateName = {
    [3] = "Pending",
    [4] = "Held",
    [5] = "Processing",
    [6] = "Stopped",
    [7] = "Canceled",
    [8] = "Aborted",
    [9] = "Completed",
  },

  OperationID = {
    IPP_CANCEL_JOB           = 0x0008,
    IPP_GET_JOB_ATTRIBUTES   = 0x0009,
    IPP_GET_JOBS             = 0x000a,
    CUPS_GET_PRINTERS        = 0x4002,
    CUPS_GET_DOCUMENT        = 0x4027
  },

  PrinterState = {
    IPP_PRINTER_IDLE         = 3,
    IPP_PRINTER_PROCESSING   = 4,
    IPP_PRINTER_STOPPED      = 5,
  },

  Attribute = {

    IPP_TAG_OPERATION = 0x01,
    IPP_TAG_JOB = 0x02,
    IPP_TAG_END = 0x03,
    IPP_TAG_PRINTER = 0x04,
    IPP_TAG_INTEGER = 0x21,
    IPP_TAG_ENUM = 0x23,
    IPP_TAG_NAME = 0x42,
    IPP_TAG_KEYWORD = 0x44,
    IPP_TAG_URI = 0x45,
    IPP_TAG_CHARSET = 0x47,
    IPP_TAG_LANGUAGE = 0x48,

    new = function(self, tag, name, value)
      local o = { tag = tag, name = name, value = value }
      setmetatable(o, self)
      self.__index = self
      return o
    end,

    parse = function(data, pos)
      local attrib = IPP.Attribute:new()
      local val
      attrib.tag, attrib.name, val, pos = string.unpack(">Bs2s2", data, pos)
      attrib.value = {}
      table.insert(attrib.value, { tag = attrib.tag, val = val })

      repeat
        local tag, name_len, val

        if ( #data < pos + 3 ) then
          break
        end

        tag, name_len, pos = string.unpack(">BI2", data, pos)
        if ( name_len == 0 ) then
          val, pos = string.unpack(">s2", data, pos)
          table.insert(attrib.value, { tag = tag, val = val })
        else
          pos = pos - 3
        end
      until( name_len ~= 0 )

      -- do minimal decoding
      for i=1, #attrib.value do
        if ( attrib.value[i].tag == IPP.Attribute.IPP_TAG_INTEGER ) then
          attrib.value[i].val = string.unpack(">I4", attrib.value[i].val)
        elseif ( attrib.value[i].tag == IPP.Attribute.IPP_TAG_ENUM ) then
          attrib.value[i].val = string.unpack(">I4", attrib.value[i].val)
        end
      end

      if ( 1 == #attrib.value ) then
        attrib.value = attrib.value[1].val
      end
      --print(attrib.name, attrib.value, stdnse.tohex(val))

      return pos, attrib
    end,

    __tostring = function(self)
      if ( "string" == type(self.value) ) then
        return string.pack(">Bs2s2", self.tag, self.name, self.value)
      else
        local data = {string.pack(">Bs2s2", self.tag, self.name, self.value[1].val)}
        for i=2, #self.value do
          data[#data+1] = string.pack(">BI2s2", self.value[i].tag, 0, self.value[i].val)
        end
        return table.concat(data)
      end
    end

  },

  -- An attribute group, groups several attributes
  AttributeGroup = {

    new = function(self, tag, attribs)
      local o = { tag = tag, attribs = attribs or {} }
      setmetatable(o, self)
      self.__index = self
      return o
    end,

    addAttribute = function(self, attrib)
      table.insert(self.attribs, attrib)
    end,

    --
    -- Gets the first attribute matching name and optionally tag from the
    -- attribute group.
    --
    -- @param name string containing the attribute name
    -- @param tag number containing the attribute tag
    getAttribute = function(self, name, tag)
      for _, attrib in ipairs(self.attribs) do
        if ( attrib.name == name ) then
          if ( not(tag) ) then
            return attrib
          elseif ( tag and attrib.tag == tag ) then
            return attrib
          end
        end
      end
    end,

    getAttributeValue = function(self, name, tag)
      for _, attrib in ipairs(self.attribs) do
        if ( attrib.name == name ) then
          if ( not(tag) ) then
            return attrib.value
          elseif ( tag and attrib.tag == tag ) then
            return attrib.value
          end
        end
      end
    end,

    __tostring = function(self)
      local data = {string.pack("B", self.tag)}

      for _, attrib in ipairs(self.attribs) do
        data[#data+1] = tostring(attrib)
      end
      return table.concat(data)
    end

  },

  -- The IPP request
  Request = {

    new = function(self, opid, reqid)
      local o = {
        version        = 0x0101,
        opid           = opid,
        reqid          = reqid,
        attrib_groups  = {},
      }
      setmetatable(o, self)
      self.__index = self
      return o
    end,

    addAttributeGroup = function(self, group)
      table.insert( self.attrib_groups, group )
    end,

    __tostring = function(self)
      local data = {string.pack(">I2I2I4", self.version, self.opid, self.reqid )}

      for _, group in ipairs(self.attrib_groups) do
        data[#data+1] = tostring(group)
      end
      data[#data+1] = string.pack("B", IPP.Attribute.IPP_TAG_END)
      return table.concat(data)
    end,

  },

  -- A class to handle responses from the server
  Response = {

    -- Creates a new instance of response
    new = function(self)
      local o = {}
      setmetatable(o, self)
      self.__index = self
      return o
    end,

    getAttributeGroups = function(self, tag)
      local groups = {}
      for _, v in ipairs(self.attrib_groups or {}) do
        if ( v.tag == tag ) then
          table.insert(groups, v)
        end
      end
      return groups
    end,

    parse = function(data)
      local resp = IPP.Response:new()
      local pos

      resp.version, resp.status, resp.reqid, pos = string.unpack(">I2I2I4", data)

      resp.attrib_groups = {}
      local group = nil
      repeat
        local tag = data:byte(pos, pos)

        if ( tag == IPP.Attribute.IPP_TAG_OPERATION or
          tag == IPP.Attribute.IPP_TAG_JOB or
          tag == IPP.Attribute.IPP_TAG_PRINTER or
          tag == IPP.Attribute.IPP_TAG_END ) then

          if group then
            table.insert(resp.attrib_groups, group)
          end
          if tag ~= IPP.Attribute.IPP_TAG_END then
            group = IPP.AttributeGroup:new(tag)
          else
            group = nil
          end
          pos = pos + 1
        else
          if not group then
            stdnse.debug2("Unexpected tag: %d", tag)
            return
          end
          local attrib
          pos, attrib = IPP.Attribute.parse(data, pos)
          group:addAttribute(attrib)
        end
      until pos > #data

      return resp
    end,

  },


}

HTTP = {

  Request = function(host, port, request)
    local headers = {
      ['Content-Type'] = 'application/ipp',
      ['User-Agent'] = 'CUPS/1.5.1',
    }
    port.version.service_tunnel = "ssl"
    local http_resp = http.post(host, port, '/', { header = headers }, nil, tostring(request))
    if ( http_resp.status ~= 200 ) then
      return false, "Unexpected response from server"
    end

    local response = IPP.Response.parse(http_resp.body)
    if ( not(response) ) then
      return false, "Failed to parse response"
    end

    return true, response
  end,

}


Helper = {

  new = function(self, host, port, options)
    local o = { host = host, port = port, options = options or {} }
    setmetatable(o, self)
    self.__index = self
    return o
  end,

  connect = function(self)
    self.socket = nmap.new_socket()
    self.socket:set_timeout(self.options.timeout or 10000)
    return self.socket:connect(self.host, self.port)
  end,

  getPrinters = function(self)

    local attribs = {
      IPP.Attribute:new(IPP.Attribute.IPP_TAG_CHARSET, "attributes-charset", "utf-8" ),
      IPP.Attribute:new(IPP.Attribute.IPP_TAG_LANGUAGE, "attributes-natural-language", "en"),
    }

    local ag = IPP.AttributeGroup:new(IPP.Attribute.IPP_TAG_OPERATION, attribs)
    local request = IPP.Request:new(IPP.OperationID.CUPS_GET_PRINTERS, 1)
    request:addAttributeGroup(ag)

    local status, response = HTTP.Request( self.host, self.port, tostring(request) )
    if ( not(response) ) then
      return status, response
    end

    local printers = {}

    for _, ag in ipairs(response:getAttributeGroups(IPP.Attribute.IPP_TAG_PRINTER)) do
      local attrib = {
        ["printer-name"] = "name",
        ["printer-location"] = "location",
        ["printer-make-and-model"] = "model",
        ["printer-state"] = "state",
        ["queued-job-count"] = "queue_count",
        ["printer-dns-sd-name"] = "dns_sd_name",
      }

      local printer = {}
      for k, v in pairs(attrib) do
        if ( ag:getAttributeValue(k) ) then
          printer[v] = ag:getAttributeValue(k)
        end
      end
      table.insert(printers, printer)
    end
    return true, printers
  end,

  getQueueInfo = function(self, uri)
    local uri = uri or ("ipp://%s/"):format(self.host.ip)

    local attribs = {
      IPP.Attribute:new(IPP.Attribute.IPP_TAG_CHARSET, "attributes-charset", "utf-8" ),
      IPP.Attribute:new(IPP.Attribute.IPP_TAG_LANGUAGE, "attributes-natural-language", "en-us"),
      IPP.Attribute:new(IPP.Attribute.IPP_TAG_URI, "printer-uri", uri),
      IPP.Attribute:new(IPP.Attribute.IPP_TAG_KEYWORD, "requested-attributes", {
        -- { tag = IPP.Attribute.IPP_TAG_KEYWORD, val = "job-originating-host-name"},
        { tag = IPP.Attribute.IPP_TAG_KEYWORD, val = "com.apple.print.JobInfo.PMJobName"},
        { tag = IPP.Attribute.IPP_TAG_KEYWORD, val = "com.apple.print.JobInfo.PMJobOwner"},
        { tag = IPP.Attribute.IPP_TAG_KEYWORD, val = "job-id" },
        { tag = IPP.Attribute.IPP_TAG_KEYWORD, val = "job-k-octets" },
        { tag = IPP.Attribute.IPP_TAG_KEYWORD, val = "job-name" },
        { tag = IPP.Attribute.IPP_TAG_KEYWORD, val = "job-state" },
        { tag = IPP.Attribute.IPP_TAG_KEYWORD, val = "printer-uri" },
        -- { tag = IPP.Attribute.IPP_TAG_KEYWORD, val = "job-originating-user-name" },
        -- { tag = IPP.Attribute.IPP_TAG_KEYWORD, val = "job-printer-state-message" },
        -- { tag = IPP.Attribute.IPP_TAG_KEYWORD, val = "job-printer-uri" },
        { tag = IPP.Attribute.IPP_TAG_KEYWORD, val = "time-at-creation" } } ),
        IPP.Attribute:new(IPP.Attribute.IPP_TAG_KEYWORD, "which-jobs", "not-completed" )
    }

    local ag = IPP.AttributeGroup:new(IPP.Attribute.IPP_TAG_OPERATION, attribs)
    local request = IPP.Request:new(IPP.OperationID.IPP_GET_JOBS, 1)
    request:addAttributeGroup(ag)

    local status, response = HTTP.Request( self.host, self.port, tostring(request) )
    if ( not(response) ) then
      return status, response
    end

    local results = {}
    for _, ag in ipairs(response:getAttributeGroups(IPP.Attribute.IPP_TAG_JOB)) do
      local uri = ag:getAttributeValue("printer-uri")
      local printer = uri:match(".*/(.*)$") or "Unknown"
      -- some jobs have multiple state attributes, so far the ENUM ones have been correct
      local state = ag:getAttributeValue("job-state", IPP.Attribute.IPP_TAG_ENUM) or ag:getAttributeValue("job-state")
      -- some jobs have multiple id tag, so far the INTEGER type have shown the correct ID
      local id = ag:getAttributeValue("job-id", IPP.Attribute.IPP_TAG_INTEGER) or ag:getAttributeValue("job-id")
      local attr = ag:getAttribute("time-at-creation")
      local tm = ag:getAttributeValue("time-at-creation")
      local size = ag:getAttributeValue("job-k-octets") .. "k"
      local jobname = ag:getAttributeValue("com.apple.print.JobInfo.PMJobName") or "Unknown"
      local owner = ag:getAttributeValue("com.apple.print.JobInfo.PMJobOwner") or "Unknown"

      results[printer] = results[printer] or {}
      table.insert(results[printer], {
        id = id,
        time = datetime.format_timestamp(tm),
        state = ( IPP.StateName[tonumber(state)] or "Unknown" ),
        size = size,
        owner = owner,
        jobname = jobname })
    end

    local output = {}
    for name, entries in pairs(results) do
      local t = tab.new(5)
      tab.addrow(t, "id", "time", "state", "size (kb)", "owner", "jobname")
      for _, entry in ipairs(entries) do
        tab.addrow(t, entry.id, entry.time, entry.state, entry.size, entry.owner, entry.jobname)
      end
      if ( 1<#t ) then
        table.insert(output, { name = name, tab.dump(t) })
      end
    end

    return output
  end,

  close = function(self)
    return self.socket:close()
  end,
}

return _ENV;
