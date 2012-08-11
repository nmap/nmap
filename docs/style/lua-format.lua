-- Copyright (c) 2011 Patrick Joseph Donnelly
--
-- Permission is hereby granted, free of charge, to any person obtaining a copy
-- of this software and associated documentation files (the "Software"), to deal
-- in the Software without restriction, including without limitation the rights
-- to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
-- copies of the Software, and to permit persons to whom the Software is
-- furnished to do so, subject to the following conditions:
--
-- The above copyright notice and this permission notice shall be included in
-- all copies or substantial portions of the Software.
--
-- THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
-- IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
-- FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
-- AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
-- LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
-- OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
-- SOFTWARE.

local DEBUG = false;

local assert = assert;
local pairs = pairs;
local require = require;
local tostring = tostring;

local io = require "io";
local read = io.read;
local write = io.write;
local stderr = io.stderr;

local table = require "table";
local concat = table.concat;

local lpeg = require "lpeg";

lpeg.setmaxstack(8000);

local P = lpeg.P;
local S = lpeg.S;
local V = lpeg.V;

local C = lpeg.C;
local Cb = lpeg.Cb;
local Cc = lpeg.Cc;
local Cf = lpeg.Cf;
local Cg = lpeg.Cg;
local Cp = lpeg.Cp;
local Cs = lpeg.Cs;
local Cmt = lpeg.Cmt;
local Ct = lpeg.Ct;

local NEWLINE = Cb "newline" * ((V "space" - P "\n")^0 * P "\n")^-1;
local SPACE = Cb "space";
local INDENT_SPACE = Cb "indent_space";
local function INDENT_INCREASE (p, nonewline)
  if nonewline then
    return Cg(Cg(Cb "indent" * INDENT_SPACE, "indent") * p);
  else
    return Cg(Cg(Cb "indent" * INDENT_SPACE, "indent") * NEWLINE * p);
  end
end
local INDENT = Cb "indent";

local shebang = P "#" * (P(1) - P "\n")^0 * P "\n";

local function K (k) -- keyword
  return C(k) * -(V "alnum" + P "_");
end

-- The formatter uses captures to indent code. We necessarily use thousands and
-- thousands of them. At various strategic points, we concatenate these captures
-- so we don't overflow the Lua stack.
local function FLATTEN (pattern)
  return Ct(pattern) / concat;
end

local lua = lpeg.locale {
  V "_init" * FLATTEN(V "_script");

  _init = Cg(Cc "\n", "newline") * Cg(Cc "", "indent") * Cg(Cc "  ", "indent_space") * Cg(Cc " ", "space");

  _script = C(shebang)^-1 * V "filler" * V "chunk" * V "filler" * -P(1);

  -- keywords

  keywords = K "and" + K "break" + K "do" + K "else" + K "elseif" +
             K "end" + K "false" + K "for" + K "function" + K "if" +
             K "in" + K "local" + K "nil" + K "not" + K "or" + K "repeat" +
             K "return" + K "then" + K "true" + K "until" + K "while";

  -- longstrings

  longstring = P { -- from Roberto Ierusalimschy's lpeg examples
    (V "open" * (P(1) - V "closeeq")^0 * V "close") / "%0";

    open = "[" * Cg((P "=")^0, "init") * P "[" * (P "\n")^-1;
    close = "]" * C((P "=")^0) * "]";
    closeeq = Cmt(V "close" * Cb "init", function (s, i, a, b) return a == b end)
  };

  -- comments & whitespace

  -- read a comment but do not capture any whitespace at the end
  chomp_comment = C((P(1) - (V "space" - P "\n")^0 * (P "\n" + -P(1)))^0) * (V "space" - P "\n")^0 * (P "\n" + -P(1)) * Cc "\n";
  one_line_comment = -V "multi_line_comment" * C "--" * V "chomp_comment";
  multi_line_comment = C "--" * V "longstring";
  comment = V "multi_line_comment" + V "one_line_comment" * INDENT;

  whitespace = (V "space" + (SPACE * V "comment" * SPACE))^0;
  space_after_stat = ((V "space" - P "\n")^0 * (P ";")^-1 * (V "space" - P "\n")^0 * SPACE * V "one_line_comment") +
                     (V "whitespace" * P ";")^-1 * NEWLINE;

  -- match "filler" comments
  line_of_space = (V "space" - P "\n")^0 * P "\n";
  collapse_whitespace = V "line_of_space"^2 * Cc "\n\n" + V "line_of_space"^1 * Cc "\n";
  filler_comment = (V "space" - P "\n")^0 * INDENT * V "one_line_comment"; -- * C "\n"^-1;
  --filler_comment = (V "space" - P "\n")^0 * INDENT * (V "one_line_comment" - V "multi_line_comment"); -- * C "\n"^-1; -- FIXME highlighted after INDENT
  filler = (V "collapse_whitespace" + V "filler_comment")^0 * V "whitespace" + V "whitespace";

  -- Types and Comments

  Name = C((V "alpha" + P "_") * (V "alnum" + P "_")^0) - V "keywords";
  BinaryExponent = S "pP" * (P "-")^-1 * V "digit"^1;
  DecimalExponent = S "eE" * (P "-")^-1 * V "digit"^1;
  Number = C((P "-")^-1 * V "whitespace" * P "0" * S "xX" * V "xdigit"^1 * (P "." * V "xdigit"^0)^-1 * V "BinaryExponent"^-1 * -(V "alnum" + P "_")) +
           C((P "-")^-1 * V "whitespace" * V "digit"^1 * (P "." * V "digit"^0)^-1 * V "DecimalExponent"^-1 * -(V "alnum" + P "_")) +
           C((P "-")^-1 * V "whitespace" * P "." * V "digit"^1 * V "DecimalExponent"^-1 * -(V "alnum" + P "_"));
  String = C(P "\"" * (P "\\" * P(1) + (1 - P "\""))^0 * P "\"") +
           C(P "'" * (P "\\" * P(1) + (1 - P "'"))^0 * P "'") +
           V "longstring";

  -- Lua Complete Syntax

  chunk = FLATTEN((V "filler" * INDENT * FLATTEN(V "stat") * V "space_after_stat")^0 * (V "filler" * INDENT * V "retstat" * V "space_after_stat")^-1);

  block = V "chunk";

  stat = P ";" +
         V "label" +
         K "break" +
         K "goto" * SPACE * V "whitespace" * V "Name" +
         K "do" * INDENT_INCREASE(V "filler" * V "block" * V "filler") * INDENT * K "end" +
         K "while" * SPACE * V "whitespace" * V "_oneline_exp" * V "whitespace" * SPACE * K "do" * INDENT_INCREASE(V "filler" * V "block" * V "filler") * INDENT * K "end" +
         K "repeat" * INDENT_INCREASE(V "filler" * V "block" * V "filler") * INDENT * K "until" * SPACE * V "whitespace" * V "_oneline_exp" +
         K "if" * SPACE * V "whitespace" * V "_oneline_exp" * V "whitespace" * SPACE * K "then" * INDENT_INCREASE(V "filler" * V "block" * V "filler") * (INDENT * K "elseif" * SPACE * V "whitespace" * V "_oneline_exp" * V "whitespace" * SPACE * K "then" * INDENT_INCREASE(V "filler" * V "block" * V "filler"))^0 * (INDENT * K "else" * INDENT_INCREASE(V "filler" * V "block" * V "filler"))^-1 * INDENT * K "end" +
         K "for" * SPACE * V "whitespace" * V "Name" * V "whitespace" * SPACE * C "=" * SPACE * V "whitespace" * V "_oneline_exp" * V "whitespace" * C "," * SPACE * V "whitespace" * V "_oneline_exp" * (V "whitespace" * C "," * SPACE * V "whitespace" * V "_oneline_exp")^-1 * V "whitespace" * SPACE * K "do" * INDENT_INCREASE(V "filler" * V "block" * V "filler") * INDENT * K "end" +
         K "for" * SPACE * V "whitespace" * V "namelist" * V "whitespace" * SPACE * K "in" * SPACE * V "whitespace" * V "explist" * V "whitespace" * SPACE * K "do" * INDENT_INCREASE(V "filler" * V "block" * V "filler") * INDENT * K "end" +
         K "function" * SPACE * V "whitespace" * V "funcname" * SPACE * V "whitespace" * V "funcbody" +
         K "local" * SPACE * V "whitespace" * K "function" * SPACE * V "whitespace" * V "Name" * V "whitespace" * SPACE * V "funcbody" +
         K "local" * SPACE * V "whitespace" * V "namelist" * (SPACE * V "whitespace" * C "=" * SPACE * V "whitespace" * V "explist")^-1 * V "_check_ambiguous" +
         V "_function_declaration" +
         V "varlist" * V "whitespace" * SPACE * C "=" * SPACE * V "whitespace" * V "explist" * V "_check_ambiguous" +
         V "functioncall" * V "_check_ambiguous";

  -- If the script uses a semicolon to avoid an ambiguous syntax situation, we keep it.
  -- Example:
  --  a = f()
  --  ("foo"):method()
  --
  -- Can be parsed as:
  --  a = f()("foo"):method();
  -- or
  --  a = f();
  --  ("foo"):method();
  _check_ambiguous = #(V "whitespace" * P ";" * V "whitespace" * P "(") * Cc ";" + P(true);

  _function_declaration = Cmt(V "Name" * V "space"^0 * P "=" * V "space"^0 * FLATTEN(V "function") * -(V "whitespace" * (V "binop" + P ",")), function (s, p, name, f) local new = f:gsub("^function", "function "..name) return true, new end);

  label = C "::" * V "whitespace" *  V "Name" * V "whitespace" * C "::";

  retstat = K "return" * (SPACE * V "whitespace" * V "explist")^-1;

  funcname = V "Name" * (V "whitespace" * C "." * V "whitespace" * V "Name")^0 * (V "whitespace" * C ":" * V "whitespace" * V "Name")^-1;

  namelist = V "Name" * (V "whitespace" * C "," * SPACE * V "whitespace" * V "Name")^0;

  varlist = V "var" * (V "whitespace" * C "," * SPACE * V "whitespace" * V "var")^0;

  -- Let's come up with a syntax that does not use left recursion (only listing changes to Lua 5.1 extended BNF syntax)
  -- value ::= nil | false | true | Number | String | '...' | function | tableconstructor | functioncall | var | '(' exp ')'
  -- exp ::= unop exp | value [binop exp]
  -- prefix ::= '(' exp ')' | Name
  -- index ::= '[' exp ']' | '.' Name
  -- call ::= args | ':' Name args
  -- suffix ::= call | index
  -- var ::= prefix {suffix} index | Name
  -- functioncall ::= prefix {suffix} call

  _deparenthesis_value = P "(" * V "whitespace" * (V "_deparenthesis_value" + V "_value_simple") * V "whitespace" * P ")";

  _value_simple = K "nil" +
                 K "false" +
                 K "true" +
                 V "Number" +
                 V "String" +
                 V "function" +
                 V "tableconstructor" +
                 V "var";

  -- Something that represents a value (or many values)
  value = K "nil" +
          K "false" +
          K "true" +
          V "Number" +
          V "String" +
          K "..." +
          V "function" +
          V "tableconstructor" +
          V "functioncall" +
          V "var" +
          V "_deparenthesis_value" + -- remove redundant parenthesis
          C "(" * V "whitespace" * V "exp" * V "whitespace" * C ")";

  -- An expression operates on values to produce a new value or is a value
  exp = V "unop" * V "whitespace" * V "exp" +
        V "value" * (V "whitespace" * V "binop" * V "whitespace" * V "exp")^-1;

  -- This is an expression which is always truncated to 1 result, and so we can remove
  -- redundant parenthesis.
  _single_exp = P "(" * V "whitespace" * V "_single_exp" * V "whitespace" * P ")" * -(V "whitespace" * (V "suffix" + V "binop")) + 
               V "exp";

  _oneline_exp = Cg(Cg(Cc " ", "newline") * Cg(Cc "", "indent") * Cg(Cc "", "indent_space") * V "_single_exp");

  -- Index and Call
  index = C "[" * V "whitespace" * V "_single_exp" * V "whitespace" * C "]" +
          C "." * V "whitespace" * V "Name";
  call = V "args" +
         C ":" * V "whitespace" * V "Name" * V "whitespace" * V "args";

  -- A Prefix is a the leftmost side of a var(iable) or functioncall
  prefix = C "(" * V "whitespace" * V "exp" * V "whitespace" * C ")" +
           V "Name";
  -- A Suffix is a Call or Index
  suffix = V "call" +
           V "index";

  var = V "prefix" * (V "whitespace" * V "suffix" * #(V "whitespace" * V "suffix"))^0 * V "whitespace" * V "index" +
        V "Name";
  functioncall = V "prefix" * (V "whitespace" * V "suffix" * #(V "whitespace" * V "suffix"))^0 * V "whitespace" * V "call";

  explist = V "exp" * (V "whitespace" * C "," * SPACE * V "whitespace" * V "exp")^0;

  -- Change func({}) to func {}
  -- Change func("...") to func "..."
  args = P "(" * SPACE * V "whitespace" * V "tableconstructor" * V "whitespace" * P ")" +
         P "(" * SPACE * V "whitespace" * V "String" * V "whitespace" * P ")" +
         C "(" * INDENT_INCREASE(V "whitespace" * (V "explist" * V "whitespace")^-1, true) * C ")" +
         SPACE * V "tableconstructor" +
         SPACE * V "String";

  ["function"] = FLATTEN(K "function" * SPACE * V "whitespace" * V "funcbody");

  funcbody = C "(" * V "whitespace" * (V "parlist" * V "whitespace")^-1 * C ")" * INDENT_INCREASE(V "block" * V "whitespace") * INDENT * K "end";

  parlist = V "namelist" * (V "whitespace" * C "," * SPACE * V "whitespace" * K "...")^-1 +
            K "...";

  tableconstructor = FLATTEN(C "{" * (INDENT_INCREASE(V "filler" * V "fieldlist" * V "filler") * INDENT + V "filler") * C "}");

  field_space_after = (V "space" - P "\n")^0 * SPACE * V "one_line_comment";
  fieldlist = INDENT * FLATTEN(V "field") * (V "whitespace" * V "fieldsep" * (V "field_space_after" + NEWLINE) * V "filler" * INDENT * FLATTEN(V "field"))^0 * (V "whitespace" * V "fieldsep" + Cc ",")^-1 * (V "field_space_after" + NEWLINE);

  field = C "[" * V "whitespace" * V "_oneline_exp" * V "whitespace" * C "]" * SPACE * V "whitespace" * C "=" * SPACE * V "whitespace" * V "_single_exp" +
          V "Name" * SPACE * V "whitespace" * C "=" * SPACE * V "whitespace" * V "_single_exp" +
          V "exp";

  fieldsep = C "," +
             P ";" * Cc ","; -- use only commas

  binop = SPACE * K "and" * SPACE + -- match longest token sequences first
          SPACE * K "or" * SPACE +
          SPACE * C ".." * SPACE +
          SPACE * C "<=" * SPACE +
          SPACE * C ">=" * SPACE +
          SPACE * C "==" * SPACE +
          SPACE * C "~=" * SPACE +
          SPACE * C "+" * SPACE +
          SPACE * (C "-" - P "--") * SPACE +
          SPACE * C "*" * SPACE +
          SPACE * C "/" * SPACE +
          C "^" + -- no space for power
          SPACE * C "%" * SPACE +
          SPACE * C "<" * SPACE +
          SPACE * C ">" * SPACE;

  unop = (C "-" - P "--") +
         C "#" +
         K "not" * SPACE;
};

if DEBUG then
  local level = 0;
  for k, p in pairs(lua) do
    local enter = lpeg.Cmt(lpeg.P(true), function (s, p)
      stderr:write((" "):rep(level*2), "ENTER ", k, ": ", s:sub(p, p), "\n");
      level = level+1;
      return true;
    end);
    local match = lpeg.Cmt(lpeg.P(true), function (s, p)
      level = level-1;
      if k == "space" or k == "comment" then
        return true;
      else
        stderr:write((" "):rep(level*2), "MATCH ", k, "\n", s:sub(p - 200 < 0 and 1 or p-200, p-1), "\n");
        return true;
      end
    end);
    local leave = lpeg.Cmt(lpeg.P(true), function (s, p)
      level = level-1;
      stderr:write((" "):rep(level*2), "LEAVE ", k, "\n");
      return false;
    end);
    lua[k] = enter * p * match + leave;
  end
end

lua = P(lua);

write(assert(lua:match(assert(read "*a"))));
