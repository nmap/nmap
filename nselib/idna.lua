---
-- Library methods for handling IDNA domains.
--
-- Internationalized Domain Names (IDNs) follow a mechanism to process
-- Internationalizing Domain Names in Applications (IDNA) for handling
-- characters outside the ASCII repertoire in a standard fashion. IDNs use
-- characters drawn from a large repertoire (Unicode), but IDNA allows the
-- non-ASCII characters to be represented using only the ASCII characters
-- already allowed in so-called host names today.  This backward-compatible
-- representation is required in existing protocols like DNS, so that IDNs can be
-- introduced with no changes to the existing infrastructure.  IDNA is
-- only meant for processing domain names, not free text.
--
-- Client software, such as browsers and emailers, faces a difficult transition
-- from the version of international domain names approved in 2003 (IDNA2003),
-- to the revision approved in 2010 (IDNA2008). The following functions allows
-- the developer and end user to access domains that are valid under either
-- system but the default conversion is set to IDNA2008.
--
-- IDNA specification solves the problem of extending the repertoire
-- of characters that can be used in domain names to include the Unicode
-- repertoire (with some restrictions).
--
-- Applications can use IDNA to support internationalized domain names
-- anywhere that ASCII domain names are already supported, including DNS
-- master files and resolver interfaces. The IDNA protocol is contained
-- completely within applications.  It is not a client-server or peer-to-peer
-- protocol: everything is done inside the application itself.  When used with
-- a DNS resolver library, IDNA is inserted as a "shim" between the application
-- and the resolver library.  When used for writing names into a DNS zone, IDNA
-- is used just before the name is committed to the zone.
--
-- References:
-- * http://ietf.org/rfc/rfc3490.txt
-- * http://tools.ietf.org/html/rfc5890
-- * https://tools.ietf.org/html/rfc5891
-- * http://tools.ietf.org/html/rfc5892
-- * http://www.unicode.org/reports/tr46/
--
-- TODO:
-- Add support for mapping right to left scripts for IDNA library.
-- References:
-- * http://tools.ietf.org/html/rfc5893
-- * http://www.unicode.org/reports/tr9/
-- * http://www.unicode.org/reports/tr46/#Right_to_Left_Scripts
--
-- @author Rewanth Cool
-- @copyright Same as Nmap--See https://nmap.org/book/man-legal.html

local stdnse = require "stdnse"
local string = require "string"
local math = require "math"
local table = require "table"
local unicode = require "unicode"
local unittest = require "unittest"
local punycode = require "punycode"
local idnaMappings = require "data.idnaMappings".tbl

_ENV = stdnse.module("idna", stdnse.seeall)

-- Localize few functions for a tiny speed boost, since these will be
-- used frequently.
local floor = math.floor
local byte = string.byte
local char = string.char
local find = string.find
local match = string.match
local reverse = string.reverse
local sub = string.sub

-- Concatenates the strings and tables (depth = 1) in a given table.
--
-- @param tbl A table is given as an input which contains values as string
-- or table (depth = 1).
-- @return Returns table after concatinating all the values.
local function concat_table_in_tables(tbl)

  local t = {}
  for _, v in ipairs(tbl) do
    if type(v) == "table" then
      for _, q in ipairs(v) do
        table.insert(t, q)
      end
    else
      table.insert(t, v)
    end
  end

  return t

end


--- Maps the codepoints of the input to their respective
-- codepoints based on the latest IDNA version mapping.
--
-- @param decoded_tbl Table of Unicode decoded codepoints.
-- @param useSTD3ASCIIRules Boolean value to set the mapping according to IDNA2003 rules.
--        useSTD3ASCIIRules=true refers to IDNA2008.
--        useSTD3ASCIIRules=false refers to IDNA2003.
-- @param transitionalProcessing Processing option to handle deviation codepoints.
--        transitionalProcessing=true maps deviation codepoints to the input.
--        transitionalProcessing=false maintains original input.
-- @param viewDisallowedCodePoints Boolean value to see the list of disallowed codepoints.
-- @return Returns table with the list of mapped codepoints.
function map(decoded_tbl, useSTD3ASCIIRules, transitionalProcessing, viewDisallowedCodePoints)

  -- Assigns default values if not specified.

  -- According to IDNA2008, transitionalProcessing=true (default).
  if transitionalProcessing == nil then
    transitionalProcessing = true
  end

  if useSTD3ASCIIRules == nil then
    useSTD3ASCIIRules = true
  end
  if viewDisallowedCodePoints == nil then
    viewDisallowedCodePoints = false
  end

  local disallowedCodePoints = {}

  -- Mapping codepoints based on latest IDNA mapping list.
  for index, cp in ipairs(decoded_tbl) do
    local lookup = idnaMappings[cp]
    if type(lookup) == "number" then
      decoded_tbl[index] = lookup
    -- Handles the IDNA deviated set of codepoints.
    elseif transitionalProcessing and lookup.status == "deviation" then
      decoded_tbl[index] = lookup[1]
    -- Removes the IDNA ignored set of codepoints.
    elseif lookup.status == "ignored" then
      decoded_tbl[index] = {}
    end
  end

  decoded_tbl = concat_table_in_tables(decoded_tbl)

  --TODO:
  -- Map bidi characters.
  -- Right-to-left domain names.
  -- References:
  -- http://unicode.org/reports/tr9/
  -- http://www.unicode.org/reports/tr46/#Right_to_Left_Scripts
  -- http://tools.ietf.org/html/rfc5893

  -- Saves the list of disallowed codepoints.
  if viewDisallowedCodePoints then
    for index, cp in ipairs(decoded_tbl) do
      local lookup = idnaMappings[cp]
      if type(lookup) == "table" then
        if lookup.status == "disallowed" then
          table.insert(disallowedCodePoints, cp)
        end
      end

      -- If useSTD3ASCIIRules=true, both the disallowed_STD3_valid and
      -- disallowed_STD3_mapped are considered as disallowed codepoints.
      -- To use this part of code, add disallowed_STD3_mapped and disallowed_STD3_valid
      -- codepoints to idnaMappings.lua. For now, we ignore these because idnaMappings.lua
      -- is set to support only for the latest version of IDNA.
      if useSTD3ASCIIRules then
        if type(lookup) == "table" then
          if lookup.status == "disallowed_STD3_valid" or lookup.status == "disallowed_STD3_mapped" then
            table.insert(disallowedCodePoints, cp)
          end
        end
      end
    end
  end

  decoded_tbl = concat_table_in_tables(decoded_tbl)

  -- If useSTD3ASCIIRules=false, then disallowed_STD3_mapped values are considered
  -- as mapped codepoints and are mapped with the input.
  -- To use this part of code, add disallowed_STD3_mapped and disallowed_STD3_valid
  -- codepoints to idnaMappings.lua. For now, we ignore these because idnaMappings.lua
  -- is set to support only for the latest version of IDNA.
  if not useSTD3ASCIIRules then
    for index, cp in ipairs(decoded_tbl) do
      local lookup = idnaMappings[cp]
      if type(lookup) == "table" then
        if lookup.status == "disallowed_STD3_mapped" then
          decoded_tbl[index] = lookup[1]
        end
      end
    end
  end

  decoded_tbl = concat_table_in_tables(decoded_tbl)

  return decoded_tbl, disallowedCodePoints
end


--- Validate the input based on IDNA codepoints validation rules.
--
-- @param tableOfTables Table of codepoints of the splitted input.
-- @param checkHyphens Boolean flag checks for 0x002D in unusual places.
function validate(tableOfTables, checkHyphens)

  if checkHyphens == nil then
    checkHyphens = true
  end

  -- Validates the list of input codepoints.
  for _, tbl in ipairs(tableOfTables) do

    if checkHyphens then

      -- Checks the 3rd and 4th position of input.
      if (tbl[3] and tbl[3] == 0x002D) or (tbl[4] and tbl[4] == 0x002D) then
        return false
      end

      -- Checks for starting and ending of input.
      if tbl[1] == 0x002D or tbl[#tbl] == 0x002D then
        return false
      end

    end

    for _, v in ipairs(tbl) do
      if v == 0x002E then
        return false
      end
    end

    -- TODO:
    -- 1. Add validation for checkBidi, checkJoiners (if required).
    -- 2. The label must not begin with a combining mark, that is: General_Category=Mark.
  end

  return true

end

--- Breaks the tables of codepoints using a delimiter.
--
-- @param A table is given as an input which contains codepoints.
-- @param ASCII value of delimiter is provided.
-- @return Returns table of tables after breaking the give table using delimiter.
local function breakInput(codepoints, delimiter)

  local tbl = {}
  local output = {}

  local delimiter = delimiter or 0x002E

  for _, v in ipairs(codepoints) do
    if v == delimiter then
      table.insert(output, tbl)
      tbl = {}
    else
      table.insert(tbl, v)
    end
  end

  table.insert(output, tbl)

  return output

end

--- Converts the input codepoints into ASCII text based on IDNA rules.
--
-- @param codepoints Table of codepoints of decoded input.
-- @param tbl Table of optional params.
-- @param transitionalProcessing Boolean value. Default: true.
-- @param checkHyphens Boolean flag for checking hyphens presence in input.
--        Default: true.
-- @param checkBidi Boolean flag to represent if the input is of Bidi type.
--        Default: false.
-- @param checkJoiners Boolean flag to check for ContextJ rules in input.
--        Default: false.
-- @param useSTD3ASCIIRules Boolean value to represent ASCII rules. Default: true.
-- @return Returns the IDNA ASCII format of the input.
-- @return Throws nil, if there is any error in conversion.
function toASCII(codepoints, transitionalProcessing, checkHyphens, checkBidi, checkJoiners, useSTD3ASCIIRules)

  -- Assigns default values if not specified.
  if transitionalProcessing == nil then
    transitionalProcessing = true
  end
  if checkHyphens == nil then
    checkHyphens = true
  end

  -- Bidi refers to right-to-left scripts.
  -- Labels must satisfy all six of the numbered conditions in RFC 5893, Section 2.
  -- to use checkBidi functionality.
  if checkBidi == nil then
    checkBidi = false
  end

  -- Labels must satisify the ContextJ rules to use checkJoiners functionality.
  if checkJoiners == nil then
    checkJoiners = false
  end

  if useSTD3ASCIIRules == nil then
    useSTD3ASCIIRules = true
  end

  local decoded_tbl, disallowedCodePoints = map(codepoints, useSTD3ASCIIRules, transitionalProcessing)

  if decoded_tbl == nil then
    return nil
  end

  -- Prints the list of disallowed values in the given input.
  if #disallowedCodePoints > 0 then
    stdnse.debug(table.concat(disallowedCodePoints, ", "))
  end

  -- Breaks the codepoints into multiple tables using delimiter.
  decoded_tbl = breakInput(decoded_tbl, 0x2E)

  if decoded_tbl == nil then
    return nil
  end

  -- Validates the codepoints and if any invalid codepoint found, returns nil.
  if not validate(decoded_tbl, checkHyphens) then
    return nil
  end

  for i, label in ipairs(decoded_tbl) do
    decoded_tbl[i] = punycode.encode_label(label)
  end
  return table.concat(decoded_tbl, ".")

end

--- Converts the input into Unicode codepoints based on IDNA rules.
--
-- Note that the input should already be a table of Unicode code points. If
-- your input is an ASCII string, convert it by using
-- <code>unicode.decode</code> with the <code>unicode.utf8_dec</code> decoder.
-- @param codepoints A domain name as a list of code points.
-- @param transitionalProcessing Boolean value. Default: true.
-- @param checkHyphens Boolean flag for checking hyphens presence in input.
--        Default: true.
-- @param checkBidi Boolean flag to represent if the input is of Bidi type.
--        Default: false.
-- @param checkJoiners Boolean flag to check for ContextJ rules in input.
--        Default: false.
-- @param useSTD3ASCIIRules Boolean value to represent ASCII rules. Default: true.
-- @return Returns the Unicode format of the input based on IDNA rules.
-- @return Throws nil, if there is any error in conversion.
function toUnicode(codepoints, transitionalProcessing, checkHyphens, checkBidi, checkJoiners, useSTD3ASCIIRules)

  -- Assigns default values if not specified.
  if transitionalProcessing == nil then
    transitionalProcessing = true
  end
  if checkHyphens == nil then
    checkHyphens = true
  end
  if checkBidi == nil then
    checkBidi = false
  end
  if checkJoiners == nil then
    checkJoiners = false
  end
  if useSTD3ASCIIRules == nil then
    useSTD3ASCIIRules = true
  end

  -- Breaks the codepoints into multiple tables using delimiter.
  local decoded_tbl, disallowedCodePoints = map(codepoints, useSTD3ASCIIRules, transitionalProcessing)
  decoded_tbl = breakInput(decoded_tbl, 0x2E)
  if decoded_tbl == nil then
    return nil
  end

  -- Validates the codepoints and if any invalid codepoint found, returns nil.
  --if not validate(decoded_tbl, checkHyphens) then
  --  return nil
  --end

  local output = {}
  for i, label in ipairs(decoded_tbl) do
    if label[1] == string.byte("x") and
      label[2] == string.byte("n") and
      label[3] == string.byte("-") and
      label[4] == string.byte("-") then
      local decoded = punycode.decode_label(unicode.encode(label, unicode.utf8_enc))
      label = decoded or label
    end
    for j = 1, #label do
      output[#output+1] = label[j]
    end
    if i < #decoded_tbl then
      output[#output+1] = 0x2E
    end
  end

  return output

end

if not unittest.testing() then
  return _ENV
end

-- These are the used for two way testing (both encoding and decoding).
local encodingAndDecodingTestCases = {
  {
    "\xce\xb1\xcf\x80\xcf\x80\xce\xbb\xce\xb5.\xce\xba\xce\xbf\xce\xbc",
    "xn--mxairta.xn--vxaei"
  },
  {
    "a\xe0\xa5\x8db",
    "xn--ab-fsf"
  },
  {
    "\xd9\x86\xd8\xa7\xd9\x85\xd9\x87\xd8\xa7\xdb\x8c.com",
    "xn--mgba3gch31f.com"
  },
  {
    "\xe0\xb7\x81\xe0\xb7\x8a\xe0\xb6\xbb\xe0\xb7\x93.com",
    "xn--10cl1a0b.com"
  },
  {
    "\xd0\xbf\xd1\x80\xd0\xb0\xd0\xb2\xd0\xb8\xd1\x82\xd0\xb5\xd0\xbb\xd1\x8c\xd1\x81\xd1\x82\xd0\xb2\xd0\xbe.\xd1\x80\xd1\x84",
    "xn--80aealotwbjpid2k.xn--p1ai"
  },
  {
    "\xe0\xa4\x95\xe0\xa4\xbe\xe0\xa4\xb6\xe0\xa5\x80\xe0\xa4\xaa\xe0\xa5\x81\xe0\xa4\xb0.\xe0\xa4\xad\xe0\xa4\xbe\xe0\xa4\xb0\xe0\xa4\xa4",
    "xn--11b6bsw3bni.xn--h2brj9c"
  },
  {
    "rewanthcool.com",
    "rewanthcool.com"
  },
  {
    "\xe3\xaf\x99\xe3\xaf\x9c\xe3\xaf\x99\xe3\xaf\x9f.com",
    "xn--domain.com"
  }
}

-- These test cases are used for only converting them into ASCII text.
local toASCIITestCases = {
  {
    "ma\xc3\xb1ana.com",
    "xn--maana-pta.com"
  },
  {
    "RewanthCool.com",
    "rewanthcool.com"
  },
  {
    "\xc3\xb6bb.at",
    "xn--bb-eka.at"
  },
  {
    "\xe3\x83\x89\xe3\x83\xa1\xe3\x82\xa4\xe3\x83\xb3.\xe3\x83\x86\xe3\x82\xb9\xe3\x83\x88",
    "xn--eckwd4c7c.xn--zckzah"
  },
  {
    "\xd0\xb4\xd0\xbe\xd0\xbc\xd0\xb5\xd0\xbd\xd0\xb0.\xd0\xb8\xd1\x81\xd0\xbf\xd1\x8b\xd1\x82\xd0\xb0\xd0\xbd\xd0\xb8\xd0\xb5",
    "xn--80ahd1agd.xn--80akhbyknj4f"
  },
  {
    "\xe6\xb5\x8b\xe8\xaf\x95",
    "xn--0zwm56d"
  },
  {
    "k\xc3\xb6nigsg\xc3\xa4\xc3\x9fchen",
    "xn--knigsgsschen-lcb0w"
  },
  {
    "fa\xc3\x9f.de",
    "fass.de"
  },
  {
    "\xce\xb2\xcf\x8c\xce\xbb\xce\xbf\xcf\x82.com",
    "xn--nxasmq6b.com"
  },
  {
    "mycharity\xe3\x80\x82org",
    "mycharity.org"
  },
  {
    "K\xc3\xb6nigsg\xc3\xa4\xc3\x9fchen",
    "xn--knigsgsschen-lcb0w"
  },
  {
    "B\xc3\xbccher.de",
    "xn--bcher-kva.de"
  },
  {
    "xn--ma\xc3\xb1ana.com",
    nil
  }
}

-- These test cases are used for only converting them into ASCII text.
-- The last two values in a table are outputs for different cases.
--
-- Format:
-- {
--  input unicode string,
--  transitional processed output, --transitional=true
--  non-transitional processed output --transitional=false
-- }
local multipleProcessingTestCases = {
  {
    "a\xe0\xa5\x8d\xe2\x80\x8cb",
    "xn--ab-fsf",
    "xn--ab-fsf604u"
  },
  {
    "A\xe0\xa5\x8d\xe2\x80\x8cb",
    "xn--ab-fsf",
    "xn--ab-fsf604u"
  },
  {
    "A\xe0\xa5\x8d\xe2\x80\x8Cb",
    "xn--ab-fsf",
    "xn--ab-fsf604u"
  },
  {
    "\xd9\x86\xd8\xa7\xd9\x85\xd9\x87\xe2\x80\x8c\xd8\xa7\xdb\x8c",
    "xn--mgba3gch31f",
    "xn--mgba3gch31f060k"
  },
  {
    "\xd9\x86\xd8\xa7\xd9\x85\xd9\x87\xe2\x80\x8c\xd8\xa7\xdb\x8c.com",
    "xn--mgba3gch31f.com",
    "xn--mgba3gch31f060k.com"
  },
  {
    "\xc3\x9f\xe0\xa7\x81\xe1\xb7\xad\xe3\x80\x82\xd8\xa085",
    "xn--ss-e2f077r.xn--85-psd",
    "xn--zca266bwrr.xn--85-psd"
  },
  {
    "\xc3\x9f\xe0\xa7\x81\xe1\xb7\xad\xe3\x80\x82\xd8\xa08\xe2\x82\x85",
    "xn--ss-e2f077r.xn--85-psd",
    "xn--zca266bwrr.xn--85-psd"
  }
}

test_suite = unittest.TestSuite:new()

for _, v in ipairs(toASCIITestCases) do
  test_suite:add_test(unittest.equal(toASCII(unicode.decode(v[1], unicode.utf8_dec)), v[2]))
end

for _, v in ipairs(encodingAndDecodingTestCases) do
  test_suite:add_test(unittest.equal(toASCII(unicode.decode(v[1], unicode.utf8_dec)), v[2]))
  test_suite:add_test(unittest.equal(unicode.encode(toUnicode(unicode.decode(v[2], unicode.utf8_dec)), unicode.utf8_enc), v[1]))
end

for _, v in ipairs(multipleProcessingTestCases) do
  -- Performs transitional conversion.
  test_suite:add_test(unittest.equal(toASCII(unicode.decode(v[1], unicode.utf8_dec)), v[2]))
  -- Performs non-transitional conversion.
  test_suite:add_test(unittest.equal(toASCII(unicode.decode(v[1], unicode.utf8_dec), false), v[3]))
end

return _ENV
