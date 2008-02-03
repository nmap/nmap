
--{{{  history

--15/03/06 DCN Created based on RemDebug
--28/04/06 DCN Update for Lua 5.1
--01/06/06 DCN Fix command argument parsing
--             Add step/over N facility
--             Add trace lines facility
--05/06/06 DCN Add trace call/return facility
--06/06/06 DCN Make it behave when stepping through the creation of a coroutine
--06/06/06 DCN Integrate the simple debugger into the main one
--07/06/06 DCN Provide facility to step into coroutines
--13/06/06 DCN Fix bug that caused the function environment to get corrupted with the global one
--14/06/06 DCN Allow 'sloppy' file names when setting breakpoints
--04/08/06 DCN Allow for no space after command name
--11/08/06 DCN Use io.write not print
--30/08/06 DCN Allow access to array elements in 'dump'
--10/10/06 DCN Default to breakfile for all commands that require a filename and give '-'
--06/12/06 DCN Allow for punctuation characters in DUMP variable names
--03/01/07 DCN Add pause on/off facility
--19/06/07 DCN Allow for duff commands being typed in the debugger (thanks to Michael.Bringmann@lsi.com)
--             Allow for case sensitive file systems               (thanks to Michael.Bringmann@lsi.com)

--}}}
--{{{  description

--A simple command line debug system for Lua written by Dave Nichols of
--Match-IT Limited. Its public domain software. Do with it as you wish.

--This debugger was inspired by:
-- RemDebug 1.0 Beta
-- Copyright Kepler Project 2005 (http://www.keplerproject.org/remdebug)

--Usage:
--  require('debugger')        --load the debug library
--  pause(message)             --start/resume a debug session

--An assert() failure will also invoke the debugger.

--}}}

local IsWindows = string.find(string.lower(os.getenv('OS') or ''),'^windows')

local coro_debugger
local events = { BREAK = 1, WATCH = 2, STEP = 3, SET = 4 }
local breakpoints = {}
local watches = {}
local step_into   = false
local step_over   = false
local step_lines  = 0
local step_level  = {main=0}
local stack_level = {main=0}
local trace_level = {main=0}
local trace_calls = false
local trace_returns = false
local trace_lines = false
local ret_file, ret_line, ret_name
local current_thread = 'main'
local started = false
local pause_off = false
local _g      = _G
local cocreate, cowrap = coroutine.create, coroutine.wrap
local pausemsg = 'pause'

--{{{  local hints -- command help
--The format in here is name=summary|description
local hints = {

pause =   [[
pause(msg)          -- start/resume a debugger session|

This can only be used in your code or from the console as a means to
start/resume a debug session.
If msg is given that is shown when the session starts/resumes. Useful to
give a context if you've instrumented your code with pause() statements.
]],

poff =    [[
poff                -- turn off pause() command|

This causes all pause() commands to be ignored. This is useful if you have
instrumented your code in a busy loop and want to continue normal execution
with no further interruption.
]],

pon =     [[
pon                 -- turn on pause() command|

This re-instates honouring the pause() commands you may have instrumented
your code with.
]],

setb =    [[
setb [line file]    -- set a breakpoint to line/file|

If file is omitted or is "-" the breakpoint is set at the file for the
currently set level (see "set"). Execution pauses when this line is about
to be executed and the debugger session is re-activated.

The file can be given as the fully qualified name, partially qualified or
just the file name. E.g. if file is set as "myfile.lua", then whenever
execution reaches any file that ends with "myfile.lua" it will pause.
]],

delb =    [[
delb [line file]    -- removes a breakpoint|

If file is omitted or is "-" the breakpoint is removed for the file of the
currently set level (see "set").
]],

delallb = [[
delallb             -- removes all breakpoints|
]],

setw =    [[
setw <exp>          -- adds a new watch expression|

The expression is evaluated before each line is executed. If the expression
yields true then execution is paused and the debugger session re-activated.
The expression is executed in the context of the line about to be executed.
]],

delw =    [[
delw <index>        -- removes the watch expression at index|

The index is that returned when the watch expression was set by setw.
]],

delallw = [[
delallw             -- removes all watch expressions|
]],

run     = [[
run                 -- run until next breakpoint or watch expression|
]],

step    = [[
step [N]            -- run next N lines, stepping into function calls|

If N is omitted, use 1.
]],

over    = [[
over [N]            -- run next N lines, stepping over function calls|

If N is omitted, use 1.
]],

out     = [[
out [N]             -- run lines until stepped out of N functions|

If N is omitted, use 1.
If you are inside a function, using "out 1" will run until you return
from that function to the caller.
]],

goto    = [[
goto <line>         -- step to line number <line> in the current file|

The line and current file are those in the currently set context level.
]],

listb   = [[
listb               -- lists breakpoints|
]],

listw   = [[
listw               -- lists watch expressions|
]],

set     = [[
set [level]         -- set context to stack level, omitted=show|

If level is omitted it just prints the current level set.
This sets the current context to the level given. This affects the
context used for several other functions (e.g. vars). The possible
levels are those shown by trace.
]],

vars    = [[
vars [depth]        -- list context locals to depth, omitted=1|

If depth is omitted then uses 1.
Use a depth of 0 for the maximum.
Lists all non-nil local variables and all non-nil upvalues in the
currently set context. For variables that are tables, lists all fields
to the given depth.
]],

fenv    = [[
fenv [depth]        -- list context function env to depth, omitted=1|

If depth is omitted then uses 1.
Use a depth of 0 for the maximum.
Lists all function environment variables in the currently set context.
For variables that are tables, lists all fields to the given depth.
]],

glob    = [[
glob [depth]        -- list globals to depth, omitted=1|

If depth is omitted then uses 1.
Use a depth of 0 for the maximum.
Lists all global variables.
For variables that are tables, lists all fields to the given depth.
]],

ups     = [[
ups                 -- list all the upvalue names|

These names will also be in the "vars" list unless their value is nil.
This provides a means to identify which vars are upvalues and which are
locals. If a name is both an upvalue and a local, the local value takes
precedance.
]],

locs    = [[
locs                -- list all the locals names|

These names will also be in the "vars" list unless their value is nil.
This provides a means to identify which vars are upvalues and which are
locals. If a name is both an upvalue and a local, the local value takes
precedance.
]],

dump    = [[
dump <var> [depth]  -- dump all fields of variable to depth|

If depth is omitted then uses 1.
Use a depth of 0 for the maximum.
Prints the value of <var> in the currently set context level. If <var>
is a table, lists all fields to the given depth. <var> can be just a
name, or name.field or name.# to any depth, e.g. t.1.f accesses field
'f' in array element 1 in table 't'.

Can also be called from a script as dump(var,depth).
]],

tron    = [[
tron [crl]          -- turn trace on for (c)alls, (r)etuns, (l)lines|

If no parameter is given then tracing is turned off.
When tracing is turned on a line is printed to the console for each
debug 'event' selected. c=function calls, r=function returns, l=lines.
]],

trace   = [[
trace               -- dumps a stack trace|

Format is [level] = file,line,name
The level is a candidate for use by the 'set' command.
]],

info    = [[
info                -- dumps the complete debug info captured|

Only useful as a diagnostic aid for the debugger itself. This information
can be HUGE as it dumps all variables to the maximum depth, so be careful.
]],

show    = [[
show line file X Y  -- show X lines before and Y after line in file|

If line is omitted or is '-' then the current set context line is used.
If file is omitted or is '-' then the current set context file is used.
If file is not fully qualified and cannot be opened as specified, then
a search for the file in the package[path] is performed using the usual
"require" searching rules. If no file extension is given, .lua is used.
Prints the lines from the source file around the given line.
]],

exit    = [[
exit                -- exits debugger, re-start it using pause()|
]],

help    = [[
help [command]      -- show this list or help for command|
]],

["<statement>"] = [[
<statement>         -- execute a statement in the current context|

The statement can be anything that is legal in the context, including
assignments. Such assignments affect the context and will be in force
immediately. Any results returned are printed. Use '=' as a short-hand
for 'return', e.g. "=func(arg)" will call 'func' with 'arg' and print
the results, and "=var" will just print the value of 'var'.
]],

what    = [[
what <func>         -- show where <func> is defined (if known)|
]],

}
--}}}

--{{{  local function getinfo(level,field)

--like debug.getinfo but copes with no activation record at the given level
--and knows how to get 'field'. 'field' can be the name of any of the
--activation record fields or any of the 'what' names or nil for everything.
--only valid when using the stack level to get info, not a function name.

local function getinfo(level,field)
  level = level + 1  --to get to the same relative level as the caller
  if not field then return debug.getinfo(level) end
  local what
  if field == 'name' or field == 'namewhat' then
    what = 'n'
  elseif field == 'what' or field == 'source' or field == 'linedefined' or field == 'lastlinedefined' or field == 'short_src' then
    what = 'S'
  elseif field == 'currentline' then
    what = 'l'
  elseif field == 'nups' then
    what = 'u'
  elseif field == 'func' then
    what = 'f'
  else
    return debug.getinfo(level,field)
  end
  local ar = debug.getinfo(level,what)
  if ar then return ar[field] else return nil end
end

--}}}
--{{{  local function indented( level, ... )

local function indented( level, ... )
  io.write( string.rep('  ',level), table.concat({...}), '\n' )
end

--}}}
--{{{  local function dumpval( level, name, value, limit )

local dumpvisited

local function dumpval( level, name, value, limit )
  local index
  if type(name) == 'number' then
    index = string.format('[%d] = ',name)
  elseif type(name) == 'string'
     and (name == '__VARSLEVEL__' or name == '__ENVIRONMENT__' or name == '__GLOBALS__' or name == '__UPVALUES__' or name == '__LOCALS__') then
    --ignore these, they are debugger generated
    return
  elseif type(name) == 'string' and string.find(name,'^[_%a][_.%w]*$') then
    index = name ..' = '
  else
    index = string.format('[%q] = ',tostring(name))
  end
  if type(value) == 'table' then
    if dumpvisited[value] then
      indented( level, index, string.format('ref%q;',dumpvisited[value]) )
    else
      dumpvisited[value] = tostring(value)
      if (limit or 0) > 0 and level+1 >= limit then
        indented( level, index, dumpvisited[value] )
      else
        indented( level, index, '{  -- ', dumpvisited[value] )
        for n,v in pairs(value) do
          dumpval( level+1, n, v, limit )
        end
        indented( level, '};' )
      end
    end
  else
    if type(value) == 'string' then
      if string.len(value) > 40 then
        indented( level, index, '[[', value, ']];' )
      else
        indented( level, index, string.format('%q',value), ';' )
      end
    else
      indented( level, index, tostring(value), ';' )
    end
  end
end

--}}}
--{{{  local function dumpvar( value, limit, name )

local function dumpvar( value, limit, name )
  dumpvisited = {}
  dumpval( 0, name or tostring(value), value, limit )
end

--}}}
--{{{  local function show(file,line,before,after)

--show +/-N lines of a file around line M

local function show(file,line,before,after)

  line   = tonumber(line   or 1)
  before = tonumber(before or 10)
  after  = tonumber(after  or before)

  if not string.find(file,'%.') then file = file..'.lua' end

  local f = io.open(file,'r')
  if not f then
    --{{{  try to find the file in the path
    
    --
    -- looks for a file in the package path
    --
    local path = package.path or LUA_PATH or ''
    for c in string.gmatch (path, "[^;]+") do
      local c = string.gsub (c, "%?%.lua", file)
      f = io.open (c,'r')
      if f then
        break
      end
    end
    
    --}}}
    if not f then
      io.write('Cannot find '..file..'\n')
      return
    end
  end

  local i = 0
  for l in f:lines() do
    i = i + 1
    if i >= (line-before) then
      if i > (line+after) then break end
      if i == line then
        io.write(i..'***\t'..l..'\n')
      else
        io.write(i..'\t'..l..'\n')
      end
    end
  end

  f:close()

end

--}}}
--{{{  local function tracestack(l)

local function gi( i )
  return function() i=i+1 return debug.getinfo(i),i end
end

local function gl( level, j )
  return function() j=j+1 return debug.getlocal( level, j ) end
end

local function gu( func, k )
  return function() k=k+1 return debug.getupvalue( func, k ) end
end

local  traceinfo

local function tracestack(l)
  local l = l + 1                        --NB: +1 to get level relative to caller
  traceinfo = {}
  traceinfo.pausemsg = pausemsg
  for ar,i in gi(l) do
    table.insert( traceinfo, ar )
    local names  = {}
    local values = {}
    for n,v in gl(i,0) do
      if string.sub(n,1,1) ~= '(' then   --ignore internal control variables
        table.insert( names, n )
        table.insert( values, v )
      end
    end
    if #names > 0 then
      ar.lnames  = names
      ar.lvalues = values
    end
    if ar.func then
      local names  = {}
      local values = {}
      for n,v in gu(ar.func,0) do
        if string.sub(n,1,1) ~= '(' then   --ignore internal control variables
          table.insert( names, n )
          table.insert( values, v )
        end
      end
      if #names > 0 then
        ar.unames  = names
        ar.uvalues = values
      end
    end
  end
end

--}}}
--{{{  local function trace()

local function trace(set)
  local mark
  for level,ar in ipairs(traceinfo) do
    if level == set then
      mark = '***'
    else
      mark = ''
    end
    io.write('['..level..']'..mark..'\t'..(ar.name or ar.what)..' in '..ar.short_src..':'..ar.currentline..'\n')
  end
end

--}}}
--{{{  local function info()

local function info() dumpvar( traceinfo, 0, 'traceinfo' ) end

--}}}

--{{{  local function set_breakpoint(file, line)

local function set_breakpoint(file, line)
  if not breakpoints[line] then
    breakpoints[line] = {}
  end
  breakpoints[line][file] = true
end

--}}}
--{{{  local function remove_breakpoint(file, line)

local function remove_breakpoint(file, line)
  if breakpoints[line] then
    breakpoints[line][file] = nil
  end
end

--}}}
--{{{  local function has_breakpoint(file, line)

--allow for 'sloppy' file names
--search for file and all variations walking up its directory hierachy
--ditto for the file with no extension

local function has_breakpoint(file, line)
  if not breakpoints[line] then return false end
  local noext = string.gsub(file,"(%..-)$",'',1)
  if noext == file then noext = nil end
  while file do
    if breakpoints[line][file] then return true end
    file = string.match(file,"[:/\](.+)$")
  end
  while noext do
    if breakpoints[line][noext] then return true end
    noext = string.match(noext,"[:/\](.+)$")
  end
  return false
end

--}}}
--{{{  local function capture_vars(ref,level,line)

local function capture_vars(ref,level,line)
  --get vars, file and line for the given level relative to debug_hook offset by ref

  local lvl = ref + level                --NB: This includes an offset of +1 for the call to here

  --{{{  capture variables
  
  local ar = debug.getinfo(lvl, "f")
  if not ar then return {},'?',0 end
  
  local vars = {__UPVALUES__={}, __LOCALS__={}}
  local i
  
  local func = ar.func
  if func then
    i = 1
    while true do
      local name, value = debug.getupvalue(func, i)
      if not name then break end
      if string.sub(name,1,1) ~= '(' then  --NB: ignoring internal control variables
        vars[name] = value
        vars.__UPVALUES__[i] = name
      end
      i = i + 1
    end
    vars.__ENVIRONMENT__ = getfenv(func)
  end
  
  vars.__GLOBALS__ = getfenv(0)
  
  i = 1
  while true do
    local name, value = debug.getlocal(lvl, i)
    if not name then break end
    if string.sub(name,1,1) ~= '(' then    --NB: ignoring internal control variables
      vars[name] = value
      vars.__LOCALS__[i] = name
    end
    i = i + 1
  end
  
  vars.__VARSLEVEL__ = level
  
  if func then
    --NB: Do not do this until finished filling the vars table
    setmetatable(vars, { __index = getfenv(func), __newindex = getfenv(func) })
  end
  
  --NB: Do not read or write the vars table anymore else the metatable functions will get invoked!
  
  --}}}

  local file = getinfo(lvl, "source")
  if string.find(file, "@") == 1 then
    file = string.sub(file, 2)
  end
  if IsWindows then file = string.lower(file) end

  if not line then
    line = getinfo(lvl, "currentline")
  end

  return vars,file,line

end

--}}}
--{{{  local function restore_vars(ref,vars)

local function restore_vars(ref,vars)

  if type(vars) ~= 'table' then return end

  local level = vars.__VARSLEVEL__       --NB: This level is relative to debug_hook offset by ref
  if not level then return end

  level = level + ref                    --NB: This includes an offset of +1 for the call to here

  local i
  local written_vars = {}

  i = 1
  while true do
    local name, value = debug.getlocal(level, i)
    if not name then break end
    if vars[name] and string.sub(name,1,1) ~= '(' then     --NB: ignoring internal control variables
      debug.setlocal(level, i, vars[name])
      written_vars[name] = true
    end
    i = i + 1
  end

  local ar = debug.getinfo(level, "f")
  if not ar then return end

  local func = ar.func
  if func then

    i = 1
    while true do
      local name, value = debug.getupvalue(func, i)
      if not name then break end
      if vars[name] and string.sub(name,1,1) ~= '(' then   --NB: ignoring internal control variables
        if not written_vars[name] then
          debug.setupvalue(func, i, vars[name])
        end
        written_vars[name] = true
      end
      i = i + 1
    end

  end

end

--}}}
--{{{  local function trace_event(event, line, level)

local function print_trace(level,depth,event,file,line,name)

  --NB: level here is relative to the caller of trace_event, so offset by 2 to get to there
  level = level + 2

  local file = file or getinfo(level,'short_src')
  local line = line or getinfo(level,'currentline')
  local name = name or getinfo(level,'name')

  local prefix = ''
  if current_thread ~= 'main' then prefix = '['..tostring(current_thread)..'] ' end

  io.write(prefix..
           string.format('%08.2f:%02i.',os.clock(),depth)..
           string.rep('.',depth%32)..
           (file or '')..' ('..(line or '')..') '..
           (name or '')..
           ' ('..event..')\n')

end

local function trace_event(event, line, level)

  if event == 'return' and trace_returns then
    --note the line info for later
    ret_file = getinfo(level+1,'short_src')
    ret_line = getinfo(level+1,'currentline')
    ret_name = getinfo(level+1,'name')
  end

  if event ~= 'line' then return end

  local slevel = stack_level[current_thread]
  local tlevel = trace_level[current_thread]

  if trace_calls and slevel > tlevel then
    --we are now in the function called, so look back 1 level further to find the calling file and line
    print_trace(level+1,slevel-1,'c',nil,nil,getinfo(level+1,'name'))
  end

  if trace_returns and slevel < tlevel then
    print_trace(level,slevel,'r',ret_file,ret_line,ret_name)
  end

  if trace_lines then
    print_trace(level,slevel,'l')
  end

  trace_level[current_thread] = stack_level[current_thread]

end

--}}}
--{{{  local function debug_hook(event, line, level, thread)

local function debug_hook(event, line, level, thread)
  if not started then debug.sethook() return end
  current_thread = thread or 'main'
  local level = level or 2
  trace_event(event,line,level)
  if event == "call" then
    stack_level[current_thread] = stack_level[current_thread] + 1
  elseif event == "return" then
    stack_level[current_thread] = stack_level[current_thread] - 1
    if stack_level[current_thread] < 0 then stack_level[current_thread] = 0 end
  else
    local vars,file,line = capture_vars(level,1,line)
    local stop, ev, idx = false, events.STEP, 0
    while true do
      for index, value in pairs(watches) do
        setfenv(value.func, vars)
        local status, res = pcall(value.func)
        if status and res then
          ev, idx = events.WATCH, index
          stop = true
          break
        end
      end
      if stop then break end
      if (step_into)
      or (step_over and (stack_level[current_thread] <= step_level[current_thread] or stack_level[current_thread] == 0)) then
        step_lines = step_lines - 1
        if step_lines < 1 then
          ev, idx = events.STEP, 0
          break
        end
      end
      if has_breakpoint(file, line) then
        ev, idx = events.BREAK, 0
        break
      end
      return
    end
    tracestack(level)
    local last_next = 1
    local err, next = assert(coroutine.resume(coro_debugger, ev, vars, file, line, idx))
    while true do
      if next == 'cont' then
        return
      elseif next == 'stop' then
        started = false
        debug.sethook()
        return
      elseif tonumber(next) then --get vars for given level or last level
        next = tonumber(next)
        if next == 0 then next = last_next end
        last_next = next
        restore_vars(level,vars)
        vars, file, line = capture_vars(level,next)
        err, next = assert(coroutine.resume(coro_debugger, events.SET, vars, file, line, idx))
      else
        io.write('Unknown command from debugger_loop: '..tostring(next)..'\n')
        io.write('Stopping debugger\n')
        next = 'stop'
      end
    end
  end
end

--}}}
--{{{  local function report(ev, vars, file, line, idx_watch)

local function report(ev, vars, file, line, idx_watch)
  local vars = vars or {}
  local file = file or '?'
  local line = line or 0
  local prefix = ''
  if current_thread ~= 'main' then prefix = '['..tostring(current_thread)..'] ' end
  if ev == events.STEP then
    io.write(prefix.."Paused at file "..file.." line "..line..' ('..stack_level[current_thread]..')\n')
  elseif ev == events.BREAK then
    io.write(prefix.."Paused at file "..file.." line "..line..' ('..stack_level[current_thread]..') (breakpoint)\n')
  elseif ev == events.WATCH then
    io.write(prefix.."Paused at file "..file.." line "..line..' ('..stack_level[current_thread]..')'.." (watch expression "..idx_watch.. ": ["..watches[idx_watch].exp.."])\n")
  elseif ev == events.SET then
    --do nothing
  else
    io.write(prefix.."Error in application: "..file.." line "..line.."\n")
  end
  if ev ~= events.SET then
    if pausemsg and pausemsg ~= '' then io.write('Message: '..pausemsg..'\n') end
    pausemsg = ''
  end
  return vars, file, line
end

--}}}

--{{{  local function debugger_loop(server)

local function debugger_loop(ev, vars, file, line, idx_watch)

  io.write("Lua Debugger\n")
  local eval_env, breakfile, breakline = report(ev, vars, file, line, idx_watch)
  io.write("Type 'help' for commands\n")

  local command, args

  --{{{  local function getargs(spec)
  
  --get command arguments according to the given spec from the args string
  --the spec has a single character for each argument, arguments are separated
  --by white space, the spec characters can be one of:
  -- F for a filename    (defaults to breakfile if - given in args)
  -- L for a line number (defaults to breakline if - given in args)
  -- N for a number
  -- V for a variable name
  -- S for a string
  
  local function getargs(spec)
    local res={}
    local char,arg
    local ptr=1
    for i=1,string.len(spec) do
      char = string.sub(spec,i,i)
      if     char == 'F' then
        _,ptr,arg = string.find(args..' ',"%s*([%w%p]*)%s*",ptr)
        if not arg or arg == '' then arg = '-' end
        if arg == '-' then arg = breakfile end
      elseif char == 'L' then
        _,ptr,arg = string.find(args..' ',"%s*([%w%p]*)%s*",ptr)
        if not arg or arg == '' then arg = '-' end
        if arg == '-' then arg = breakline end
        arg = tonumber(arg) or 0
      elseif char == 'N' then
        _,ptr,arg = string.find(args..' ',"%s*([%w%p]*)%s*",ptr)
        if not arg or arg == '' then arg = '0' end
        arg = tonumber(arg) or 0
      elseif char == 'V' then
        _,ptr,arg = string.find(args..' ',"%s*([%w%p]*)%s*",ptr)
        if not arg or arg == '' then arg = '' end
      elseif char == 'S' then
        _,ptr,arg = string.find(args..' ',"%s*([%w%p]*)%s*",ptr)
        if not arg or arg == '' then arg = '' end
      else
        arg = ''
      end
      table.insert(res,arg or '')
    end
    return unpack(res)
  end
  
  --}}}

  while true do
    io.write("[DEBUG]> ")
    local line = io.read("*line")
    if line == nil then io.write('\n'); line = 'exit' end

    if string.find(line, "^[a-z]+") then
      command = string.sub(line, string.find(line, "^[a-z]+"))
      args    = string.gsub(line,"^[a-z]+%s*",'',1)            --strip command off line
    else
      command = ''
    end

    if command == "setb" then
      --{{{  set breakpoint
      
      local line, filename  = getargs('LF')
      if filename ~= '' and line ~= '' then
        set_breakpoint(filename,line)
        io.write("Breakpoint set in file "..filename..' line '..line..'\n')
      else
        io.write("Bad request\n")
      end
      
      --}}}

    elseif command == "delb" then
      --{{{  delete breakpoint
      
      local line, filename = getargs('LF')
      if filename ~= '' and line ~= '' then
        remove_breakpoint(filename, line)
        io.write("Breakpoint deleted from file "..filename..' line '..line.."\n")
      else
        io.write("Bad request\n")
      end
      
      --}}}

    elseif command == "delallb" then
      --{{{  delete all breakpoints
      breakpoints = {}
      io.write('All breakpoints deleted\n')
      --}}}

    elseif command == "listb" then
      --{{{  list breakpoints
      for i, v in pairs(breakpoints) do
        for ii, vv in pairs(v) do
          io.write("Break at: "..i..' in '..ii..'\n')
        end
      end
      --}}}

    elseif command == "setw" then
      --{{{  set watch expression
      
      if args and args ~= '' then
        local func = loadstring("return(" .. args .. ")")
        local newidx = #watches + 1
        watches[newidx] = {func = func, exp = args}
        io.write("Set watch exp no. " .. newidx..'\n')
      else
        io.write("Bad request\n")
      end
      
      --}}}

    elseif command == "delw" then
      --{{{  delete watch expression
      
      local index = tonumber(args)
      if index then
        watches[index] = nil
        io.write("Watch expression deleted\n")
      else
        io.write("Bad request\n")
      end
      
      --}}}

    elseif command == "delallw" then
      --{{{  delete all watch expressions
      watches = {}
      io.write('All watch expressions deleted\n')
      --}}}

    elseif command == "listw" then
      --{{{  list watch expressions
      for i, v in pairs(watches) do
        io.write("Watch exp. " .. i .. ": " .. v.exp..'\n')
      end
      --}}}

    elseif command == "run" then
      --{{{  run until breakpoint
      step_into = false
      step_over = false
      eval_env, breakfile, breakline = report(coroutine.yield('cont'))
      --}}}

    elseif command == "step" then
      --{{{  step N lines (into functions)
      local N = tonumber(args) or 1
      step_over  = false
      step_into  = true
      step_lines = tonumber(N or 1)
      eval_env, breakfile, breakline = report(coroutine.yield('cont'))
      --}}}

    elseif command == "over" then
      --{{{  step N lines (over functions)
      local N = tonumber(args) or 1
      step_into  = false
      step_over  = true
      step_lines = tonumber(N or 1)
      step_level[current_thread] = stack_level[current_thread]
      eval_env, breakfile, breakline = report(coroutine.yield('cont'))
      --}}}

    elseif command == "out" then
      --{{{  step N lines (out of functions)
      local N = tonumber(args) or 1
      step_into  = false
      step_over  = true
      step_lines = 1
      step_level[current_thread] = stack_level[current_thread] - tonumber(N or 1)
      eval_env, breakfile, breakline = report(coroutine.yield('cont'))
      --}}}

    elseif command == "goto" then
      --{{{  step until reach line
      local N = tonumber(args)
      if N then
        step_over  = false
        step_into  = false
        if has_breakpoint(breakfile,N) then
          eval_env, breakfile, breakline = report(coroutine.yield('cont'))
        else
          local bf = breakfile
          set_breakpoint(breakfile,N)
          eval_env, breakfile, breakline = report(coroutine.yield('cont'))
          if breakfile == bf and breakline == N then remove_breakpoint(breakfile,N) end
        end
      else
        io.write("Bad request\n")
      end
      --}}}

    elseif command == "set" then
      --{{{  set/show context level
      local level = args
      if level and level == '' then level = nil end
      if level then
        eval_env, breakfile, breakline = report(coroutine.yield(level))
      end
      if eval_env.__VARSLEVEL__ then
        io.write('Level: '..eval_env.__VARSLEVEL__..'\n')
      else
        io.write('No level set\n')
      end
      --}}}

    elseif command == "vars" then
      --{{{  list context variables
      local depth = args
      if depth and depth == '' then depth = nil end
      depth = tonumber(depth) or 1
      dumpvar(eval_env, depth+1, 'variables')
      --}}}

    elseif command == "glob" then
      --{{{  list global variables
      local depth = args
      if depth and depth == '' then depth = nil end
      depth = tonumber(depth) or 1
      dumpvar(eval_env.__GLOBALS__,depth+1,'globals')
      --}}}

    elseif command == "fenv" then
      --{{{  list function environment variables
      local depth = args
      if depth and depth == '' then depth = nil end
      depth = tonumber(depth) or 1
      dumpvar(eval_env.__ENVIRONMENT__,depth+1,'environment')
      --}}}

    elseif command == "ups" then
      --{{{  list upvalue names
      dumpvar(eval_env.__UPVALUES__,2,'upvalues')
      --}}}

    elseif command == "locs" then
      --{{{  list locals names
      dumpvar(eval_env.__LOCALS__,2,'upvalues')
      --}}}

    elseif command == "what" then
      --{{{  show where a function is defined
      if args and args ~= '' then
        local v = eval_env
        local n = nil
        for w in string.gmatch(args,"[%w_]+") do
          v = v[w]
          if n then n = n..'.'..w else n = w end
          if not v then break end
        end
        if type(v) == 'function' then
          local def = debug.getinfo(v,'S')
          if def then
            io.write(def.what..' in '..def.short_src..' '..def.linedefined..'..'..def.lastlinedefined..'\n')
          else
            io.write('Cannot get info for '..v..'\n')
          end
        else
          io.write(v..' is not a function\n')
        end
      else
        io.write("Bad request\n")
      end
      --}}}

    elseif command == "dump" then
      --{{{  dump a variable
      local name, depth = getargs('VN')
      if name ~= '' then
        if depth == '' or depth == 0 then depth = nil end
        depth = tonumber(depth or 1)
        local v = eval_env
        local n = nil
        for w in string.gmatch(name,"[^%.]+") do     --get everything between dots
          if tonumber(w) then
            v = v[tonumber(w)]
          else
            v = v[w]
          end
          if n then n = n..'.'..w else n = w end
          if not v then break end
        end
        dumpvar(v,depth+1,n)
      else
        io.write("Bad request\n")
      end
      --}}}

    elseif command == "show" then
      --{{{  show file around a line or the current breakpoint
      
      local line, file, before, after = getargs('LFNN')
      if before == 0 then before = 10     end
      if after  == 0 then after  = before end
      
      if file ~= '' and file ~= "=stdin" then
        show(file,line,before,after)
      else
        io.write('Nothing to show\n')
      end
      
      --}}}

    elseif command == "poff" then
      --{{{  turn pause command off
      pause_off = true
      --}}}

    elseif command == "pon" then
      --{{{  turn pause command on
      pause_off = false
      --}}}

    elseif command == "tron" then
      --{{{  turn tracing on/off
      local option = getargs('S')
      trace_calls   = false
      trace_returns = false
      trace_lines   = false
      if string.find(option,'c') then trace_calls   = true end
      if string.find(option,'r') then trace_returns = true end
      if string.find(option,'l') then trace_lines   = true end
      --}}}

    elseif command == "trace" then
      --{{{  dump a stack trace
      trace(eval_env.__VARSLEVEL__)
      --}}}

    elseif command == "info" then
      --{{{  dump all debug info captured
      info()
      --}}}

    elseif command == "pause" then
      --{{{  not allowed in here
      io.write('pause() should only be used in the script you are debugging\n')
      --}}}

    elseif command == "help" then
      --{{{  help
      local command = getargs('S')
      if command ~= '' and hints[command] then
        io.write(hints[command]..'\n')
      else
        for _,v in pairs(hints) do
          local _,_,h = string.find(v,"(.+)|")
          io.write(h..'\n')
        end
      end
      --}}}

    elseif command == "exit" then
      --{{{  exit debugger
      return 'stop'
      --}}}

    elseif line ~= '' then
      --{{{  just execute whatever it is in the current context
      
      --map line starting with "=..." to "return ..."
      if string.sub(line,1,1) == '=' then line = string.gsub(line,'=','return ',1) end
      
      local ok, func = pcall(loadstring,line)
      if func == nil then                             --Michael.Bringmann@lsi.com
        io.write("Compile error: "..line..'\n')
      elseif not ok then
        io.write("Compile error: "..func..'\n')
      else
        setfenv(func, eval_env)
        local res = {pcall(func)}
        if res[1] then
          if res[2] then
            table.remove(res,1)
            for _,v in ipairs(res) do
              io.write(tostring(v))
              io.write('\t')
            end
            io.write('\n')
          end
          --update in the context
          eval_env, breakfile, breakline = report(coroutine.yield(0))
        else
          io.write("Run error: "..res[2]..'\n')
        end
      end
      
      --}}}
    end
  end

end

--}}}

--{{{  coroutine.create

--This function overrides the built-in for the purposes of propagating
--the debug hook settings from the creator into the created coroutine.

_G.coroutine.create = function(f)
  local thread
  local hook, mask, count = debug.gethook()
  if hook then
    local function thread_hook(event,line)
      hook(event,line,3,thread)
    end
    thread = cocreate(function(...)
                        stack_level[thread] = 0
                        trace_level[thread] = 0
                        step_level [thread] = 0
                        debug.sethook(thread_hook,mask,count)
                        return f(...)
                      end)
    return thread
  else
    return cocreate(f)
  end
end

--}}}
--{{{  coroutine.wrap

--This function overrides the built-in for the purposes of propagating
--the debug hook settings from the creator into the created coroutine.

_G.coroutine.wrap = function(f)
  local thread
  local hook, mask, count = debug.gethook()
  if hook then
    local function thread_hook(event,line)
      hook(event,line,3,thread)
    end
    thread = cowrap(function(...)
                      stack_level[thread] = 0
                      trace_level[thread] = 0
                      step_level [thread] = 0
                      debug.sethook(thread_hook,mask,count)
                      return f(...)
                    end)
    return thread
  else
    return cowrap(f)
  end
end

--}}}

--{{{  function pause()

--
-- Starts/resumes a debug session
--

function pause(x)
  if pause_off then return end               --being told to ignore pauses
  pausemsg = x or 'pause'
  local lines
  local src = getinfo(2,'short_src')
  if src == "stdin" then
    lines = 1   --if in a console session, stop now
  else
    lines = 2   --if in a script, stop when get out of pause()
  end
  if started then
    --we'll stop now 'cos the existing debug hook will grab us
    step_lines = lines
    step_into  = true
  else
    coro_debugger = cocreate(debugger_loop)  --NB: Use original coroutune.create
    --set to stop when get out of pause()
    trace_level[current_thread] = 0
    step_level [current_thread] = 0
    stack_level[current_thread] = 1
    step_lines = lines
    step_into  = true
    started    = true
    debug.sethook(debug_hook, "crl")         --NB: this will cause an immediate entry to the debugger_loop
  end
end

--}}}
--{{{  function dump()

--shows the value of the given variable, only really useful
--when the variable is a table
--see dump debug command hints for full semantics

function dump(v,depth)
  dumpvar(v,(depth or 1)+1,tostring(v))
end

--}}}
--{{{  function debug.traceback(x)

local _traceback = debug.traceback       --note original function

--override standard function
debug.traceback = function(x)
  local assertmsg = _traceback(x)        --do original function
  pause(x)                               --let user have a look at stuff
  return assertmsg                       --carry on
end

_TRACEBACK = debug.traceback             --Lua 5.0 function

--}}}

