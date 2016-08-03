---
-- This is the NSE implementation of SLAXML.
-- SLAXML is a pure-Lua SAX-like streaming XML parser. It is more robust
-- than many (simpler) pattern-based parsers that exist, properly supporting
-- code like <code><expr test="5 > 7" /></code>, CDATA nodes, comments,
-- namespaces, and processing instructions.
-- It is currently not a truly valid XML parser, however, as it allows certain XML that is
-- syntactically-invalid (not well-formed) to be parsed without reporting an error.
-- The streaming parser does a simple pass through the input and reports what it sees along the way.
-- You can optionally ignore white-space only text nodes using the <code>stripWhitespace</code> option.
-- The library contains the parser class and the parseDOM function.
--
-- Basic Usage of the library:
-- <code>
-- local parser = parser:new()
-- parser:parseSAX(xmlbody, {stripWhitespace=true})
-- </code>
-- To specify custom call backs use :
-- <code>
-- local call_backs = {
--   startElement = function(name,nsURI,nsPrefix)       end, -- When "<foo" or <x:foo is seen
--   attribute    = function(name,value,nsURI,nsPrefix) end, -- attribute found on current element
--   closeElement = function(name,nsURI)                end, -- When "</foo>" or </x:foo> or "/>" is seen
--   text         = function(text)                      end, -- text and CDATA nodes
--   comment      = function(content)                   end, -- comments
--   pi           = function(target,content)            end, -- processing instructions e.g. "<?yes mon?>"
-- }
-- local parser = parser:new(call_backs)
-- parser:parseSAX(xmlbody)
-- </code>
-- The code also contains the <code>parseDOM</code> function.
-- To get the dom table use the <code>parseDOM</code> method as follows.
-- <code>
-- parseDOM(xmlbody, options)
-- </code>
--
-- DOM Table Features
--
-- Document - the root table returned from the parseDOM() method.
--
-- * <code>doc.type</code> : the string "document"
-- * <code>doc.name</code> : the string "#doc"
-- * <code>doc.kids</code> : an array table of child processing instructions, the root element, and comment nodes.
-- * <code>doc.root</code> : the root element for the document
--
-- Element
--
-- * <code>someEl.type</code> : the string "element"
-- * <code>someEl.name</code> : the string name of the element (without any namespace prefix)
-- * <code>someEl.nsURI</code> : the namespace URI for this element; nil if no namespace is applied
-- * <code>someEl.attr</code> : a table of attributes, indexed by name and index
--
-- <code>local value = someEl.attr['attribute-name']</code> : any namespace prefix of the attribute is not part of the name
--
-- <code>local someAttr = someEl.attr[1]</code> : an single attribute table (see below); useful for iterating all
-- attributes of an element, or for disambiguating attributes with the same name in different namespaces
--
-- * <code>someEl.kids</code> : an array table of child elements, text nodes, comment nodes, and processing instructions
-- * <code>someEl.el</code> : an array table of child elements only
-- * <code>someEl.parent</code> : reference to the parent element or document table
--
-- Attribute
--
-- * <code>someAttr.type</code> : the string "attribute"
-- * <code>someAttr.name</code> : the name of the attribute (without any namespace prefix)
-- * <code>someAttr.value</code> : the string value of the attribute (with XML and numeric entities unescaped)
-- * <code>someAttr.nsURI</code> : the namespace URI for the attribute; nil if no namespace is applied
-- * <code>someAttr.parent</code> : reference to the owning element table
--
-- Text - for both CDATA and normal text nodes
--
-- * <code>someText.type</code> : the string "text"
-- * <code>someText.name</code> : the string "#text"
-- * <code>someText.value</code> : the string content of the text node (with XML and numeric entities unescaped for non-CDATA elements)
-- * <code>someText.parent</code> : reference to the parent element table
--
-- Comment
--
-- * <code>someComment.type</code> : the string "comment"
-- * <code>someComment.name</code> : the string "#comment"
-- * <code>someComment.value</code> : the string content of the attribute
-- * <code>someComment.parent</code> : reference to the parent element or document table
--
-- Processing Instruction
--
-- * <code>someComment.type</code> : the string "pi"
-- * <code>someComment.name</code> : the string name of the PI, e.g. <?foo …?> has a name of "foo"
-- * <code>someComment.value</code> : the string content of the PI, i.e. everything but the name
-- * <code>someComment.parent</code> : reference to the parent element or document table
--
-- @args slaxml.debug Debug level at which default callbacks will print detailed
--                    parsing info. Default: 3
--
-- @author Gavin Kistner <original pure lua implemetation>
-- @author Gyanendra Mishra <NSE specific implementation>

--[=====================================================================[
v0.7 Copyright © 2013-2014 Gavin Kistner <!@phrogz.net>; MIT Licensed
See http://github.com/Phrogz/SLAXML for details.
--]=====================================================================]

local string = require "string"
local stdnse = require "stdnse"
local table = require "table"
local unicode = require "unicode"
_ENV = stdnse.module("slaxml", stdnse.seeall)




-- A table containing the default call backs to be used
-- This really floods the script output, you will mostly be
-- using custom call backs.
-- Set the debugging level required for the default call backs. Defaults to 3.
local debugging_level = tonumber(stdnse.get_script_args('slaxml.debug')) or 3
local DEFAULT_CALLBACKS = {
    --- A call back for processing instructions.
    -- To use define pi = function(<target>, <content>) <function body> end in parser._call table.
    -- Executes whenever a processing instruction is found.
    -- @param target the PI target
    -- @param content any value not containing the sequence  '?>'
    pi = function(target,content)
      stdnse.debug(debugging_level, string.format("<?%s %s?>",target,content))
    end,
    --- A call back for comments.
    -- To use define comment = function(<content>) <function body> end in parser._call table.
    -- Executes whenever a comment is encountered.
    -- @param content The comment body itself.
    comment = function(content)
      stdnse.debug(debugging_level, debugging_level, string.format("<!-- %s -->",content))
    end,
    --- A call back for the start of elements.
    -- To use define startElement = function(<name>, <nsURI>, <nsPrefix>) <function body> end in parser._call table.
    -- Executes whenever an element starts.
    -- @param name The name of the element.
    -- @param nsURI The name space URI.
    -- @param nsPrefix The name space prefix.
    startElement = function(name,nsURI,nsPrefix)
      local output = "<"
      if nsPrefix then output = output .. nsPrefix .. ":" end
      output = output .. name
      if nsURI    then output = output .. " (ns='" .. nsURI .. "')" end
      output = output .. ">"
      stdnse.debug(debugging_level, output)
    end,
    --- A call back for attributes.
    -- To use define attribute = function(<name>, <attribtute>, <nsURI>, <nsPrefix>) <function body> end in parser._call table.
    -- Executes whenever an attribute is found.
    -- @param name The name of the attribute.
    -- @param value The value of the attribute.
    -- @param nsURI The name space URI.
    -- @param nsPrefix The name space prefix.
    attribute = function(name,value,nsURI,nsPrefix)
      local output = '  '
      if nsPrefix then output = output .. nsPrefix .. ":"  end
      output = output .. name .. '=' .. string.format('%q',value)
      if nsURI then output = output .. (" (ns='" .. nsURI .. "')") end
      stdnse.debug(debugging_level, output)
    end,
    --- A call back for text content.
    -- To use define text = function(<text>) <function body> end in parser._call table.
    -- Executes whenever pure text is found.
    -- @param text The actual text.
    text = function(text)
      stdnse.debug(debugging_level, string.format("  text: %q",text))
    end,
    --- A call back for the end of elements.
    -- To use define closeElement = function(<name>, <nsURI>, <nsPrefix>) <function body> end in parser._call table.
    -- Executes whenever an element closes.
    -- @param name The name of the element.
    -- @param nsURI The name space URI.
    -- @param nsPrefix The name space prefix.
    closeElement = function(name,nsURI,nsPrefix)
      stdnse.debug(debugging_level, string.format("</%s>",name))
    end,
  }

local entityMap  = { ["lt"]="<", ["gt"]=">", ["amp"]="&", ["quot"]='"', ["apos"]="'" }
local entitySwap = function(orig,n,s) return entityMap[s] or n=="#" and unicode.utf8_enc(tonumber('0'..s)) or orig end

parser = {

  new = function(self, callbacks)
    local o = {
    _call = callbacks or DEFAULT_CALLBACKS
    }
    setmetatable(o, self)
    self.__index = self
    return o
  end,

  unescape = function(str) return string.gsub( str, '(&(#?)([%d%a]+);)', entitySwap ) end,

  --- Parses the xml in sax like manner.
  -- @self The parser object.
  -- @param xml The xml body to be parsed.
  -- @param options Options if any specified.
  parseSAX = function(self, xml, options)
    if not options then options = { stripWhitespace=false } end

    -- Cache references for maximum speed
    local find, sub, gsub, char, push, pop, concat = string.find, string.sub, string.gsub, string.char, table.insert, table.remove, table.concat
    local first, last, match1, match2, match3, pos2, nsURI
    local unpack = table.unpack
    local pos = 1
    local state = "text"
    local textStart = 1
    local currentElement={}
    local currentAttributes={}
    local currentAttributeCt -- manually track length since the table is re-used
    local nsStack = {}
    local anyElement = false

    local function finishText()
      if first>textStart and self._call.text then
        local text = sub(xml,textStart,first-1)
        if options.stripWhitespace then
          text = gsub(text,'^%s+','')
          text = gsub(text,'%s+$','')
          if #text==0 then text=nil end
        end
        if text then self._call.text(parser.unescape(text)) end
      end
    end

    local function findPI()
      first, last, match1, match2 = find( xml, '^<%?([:%a_][:%w_.-]*) ?(.-)%?>', pos )
      if first then
        finishText()
        if self._call.pi then self._call.pi(match1,match2) end
        pos = last+1
        textStart = pos
        return true
      end
    end

    local function findComment()
      first, last, match1 = find( xml, '^<!%-%-(.-)%-%->', pos )
      if first then
        finishText()
        if self._call.comment then self._call.comment(match1) end
        pos = last+1
        textStart = pos
        return true
      end
    end

    local function nsForPrefix(prefix)
      if prefix=='xml' then return 'http://www.w3.org/XML/1998/namespace' end -- http://www.w3.org/TR/xml-names/#ns-decl
      for i=#nsStack,1,-1 do if nsStack[i][prefix] then return nsStack[i][prefix] end end
      stdnse.debug1(("Cannot find namespace for prefix %s"):format(prefix))
      return
    end

    local function startElement()
      anyElement = true
      first, last, match1 = find( xml, '^<([%a_][%w_.-]*)', pos )
      if first then
        currentElement[2] = nil -- reset the nsURI, since this table is re-used
        currentElement[3] = nil -- reset the nsPrefix, since this table is re-used
        finishText()
        pos = last+1
        first,last,match2 = find(xml, '^:([%a_][%w_.-]*)', pos )
        if first then
          currentElement[1] = match2
          currentElement[3] = match1 -- Save the prefix for later resolution
          match1 = match2
          pos = last+1
        else
          currentElement[1] = match1
          for i=#nsStack,1,-1 do if nsStack[i]['!'] then currentElement[2] = nsStack[i]['!']; break end end
        end
        currentAttributeCt = 0
        push(nsStack,{})
        return true
      end
    end

    local function findAttribute()
      first, last, match1 = find( xml, '^%s+([:%a_][:%w_.-]*)%s*=%s*', pos )
      if first then
        pos2 = last+1
        first, last, match2 = find( xml, '^"([^<"]*)"', pos2 ) -- FIXME: disallow non-entity ampersands
        if first then
          pos = last+1
          match2 = parser.unescape(match2)
        else
          first, last, match2 = find( xml, "^'([^<']*)'", pos2 ) -- FIXME: disallow non-entity ampersands
          if first then
            pos = last+1
            match2 = parser.unescape(match2)
          end
        end
      end
      if match1 and match2 then
        local currentAttribute = {match1,match2}
        local prefix,name = string.match(match1,'^([^:]+):([^:]+)$')
        if prefix then
          if prefix=='xmlns' then
            nsStack[#nsStack][name] = match2
          else
            currentAttribute[1] = name
            currentAttribute[4] = prefix
          end
        else
          if match1=='xmlns' then
            nsStack[#nsStack]['!'] = match2
            currentElement[2]      = match2
          end
        end
        currentAttributeCt = currentAttributeCt + 1
        currentAttributes[currentAttributeCt] = currentAttribute
        return true
      end
    end

    local function findCDATA()
      first, last, match1 = find( xml, '^<!%[CDATA%[(.-)%]%]>', pos )
      if first then
        finishText()
        if self._call.text then self._call.text(match1) end
        pos = last+1
        textStart = pos
        return true
      end
    end

    local function closeElement()
      first, last, match1 = find( xml, '^%s*(/?)>', pos )
      if first then
        state = "text"
        pos = last+1
        textStart = pos

        -- Resolve namespace prefixes AFTER all new/redefined prefixes have been parsed
        if currentElement[3] then currentElement[2] = nsForPrefix(currentElement[3])    end
        if self._call.startElement then self._call.startElement(unpack(currentElement)) end
        if self._call.attribute then
          for i=1,currentAttributeCt do
            if currentAttributes[i][4] then currentAttributes[i][3] = nsForPrefix(currentAttributes[i][4]) end
            self._call.attribute(unpack(currentAttributes[i]))
          end
        end

        if match1=="/" then
          pop(nsStack)
          if self._call.closeElement then self._call.closeElement(unpack(currentElement)) end
        end
        return true
      end
    end

    local function findElementClose()
      first, last, match1, match2 = find( xml, '^</([%a_][%w_.-]*)%s*>', pos )
      if first then
        nsURI = nil
        for i=#nsStack,1,-1 do if nsStack[i]['!'] then nsURI = nsStack[i]['!']; break end end
      else
        first, last, match2, match1 = find( xml, '^</([%a_][%w_.-]*):([%a_][%w_.-]*)%s*>', pos )
        if first then nsURI = nsForPrefix(match2) end
      end
      if first then
        finishText()
        if self._call.closeElement then self._call.closeElement(match1,nsURI) end
        pos = last+1
        textStart = pos
        pop(nsStack)
        return true
      end
    end

    while pos<#xml do
      if state=="text" then
        if not (findPI() or findComment() or findCDATA() or findElementClose()) then
          if startElement() then
            state = "attributes"
          else
            first, last = find( xml, '^[^<]+', pos )
            pos = (first and last or pos) + 1
          end
        end
      elseif state=="attributes" then
        if not findAttribute() then
          if not closeElement() then
            stdnse.debug1("Was in an element and couldn't find attributes or the close.")
            return
          end
        end
      end
    end

    if not anyElement then stdnse.debug1("Parsing did not discover any elements") end
    if #nsStack > 0 then stdnse.debug1("Parsing ended with unclosed elements") end
  end,

}

--- Parses xml and outputs a  dom table.
-- @param xml the xml body to be parsed.
-- @param options if any to use. Supports <code>stripWhitespaces</code> currently.
function parseDOM (xml, options)
  if not options then options={} end
  local rich = not options.simple
  local push, pop = table.insert, table.remove
  local stack = {}
  local doc = { type="document", name="#doc", kids={} }
  local current = doc
  local builder = parser:new{
    startElement = function(name,nsURI)
      local el = { type="element", name=name, kids={}, el=rich and {} or nil, attr={}, nsURI=nsURI, parent=rich and current or nil }
      if current==doc then
        if doc.root then stdnse.debug2(("Encountered element '%s' when the document already has a root '%s' element"):format(name,doc.root.name)) return end
        doc.root = el
      end
      push(current.kids,el)
      if current.el then push(current.el,el) end
      current = el
      push(stack,el)
    end,
    attribute = function(name,value,nsURI)
      if not current or current.type~="element" then stdnse.debug2(("Encountered an attribute %s=%s but I wasn't inside an element"):format(name,value)) return end
      local attr = {type='attribute',name=name,nsURI=nsURI,value=value,parent=rich and current or nil}
      if rich then current.attr[name] = value end
      push(current.attr,attr)
    end,
    closeElement = function(name)
      if current.name~=name or current.type~="element" then stdnse.debug2(("Received a close element notification for '%s' but was inside a '%s' %s"):format(name,current.name,current.type)) return end
      pop(stack)
      current = stack[#stack]
    end,
    text = function(value)
      if current.type~='document' then
        if current.type~="element" then stdnse.debug2(("Received a text notification '%s' but was inside a %s"):format(value,current.type)) return end
        push(current.kids,{type='text',name='#text',value=value,parent=rich and current or nil})
      end
    end,
    comment = function(value)
      push(current.kids,{type='comment',name='#comment',value=value,parent=rich and current or nil})
    end,
    pi = function(name,value)
      push(current.kids,{type='pi',name=name,value=value,parent=rich and current or nil})
    end
  }
  builder:parseSAX  (xml,options)
  return doc
end

return _ENV;

