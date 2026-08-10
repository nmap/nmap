--httpd.lua - a dead simple HTTP server. Expects GET requests and serves files
--matching these requests. Can guess mime based on an extension too. Currently
--disallows any filenames that start or end with "..".

------------------------------------------------------------------------------
--                          Configuration section                           --
------------------------------------------------------------------------------

server_headers = {
    ["Server"] = "Ncat --lua-exec httpd.lua",
    ["Connection"] = "close",
}

function guess_mime(resource)
    if string.sub(resource, -5) == ".html" then return "text/html" end
    if string.sub(resource, -4) == ".htm" then return "text/html" end
    return "application/octet-stream"
end

------------------------------------------------------------------------------
--                       End of configuration section                       --
------------------------------------------------------------------------------

function print_rn(str)
    io.stdout:write(str .. "\r\n")
    io.stdout:flush()
end

function debug(str)
    io.stderr:write("[" .. os.date() .. "] ")
    io.stderr:write(str .. "\n")
    io.stderr:flush()
end

function url_decode(str)
    --taken from here: http://lua-users.org/wiki/StringRecipes
    return str:gsub("%%(%x%x)",
        function(h) return string.char(tonumber(h,16)) end)
end

--Read a line of at most 8096 bytes (or whatever the first parameter says)
--from standard input. Returns the string and a boolean value that is true if
--we hit the newline (defined as "\n") or false if the line had to be
--truncated. This is here because io.stdin:read("*line") could lead to memory
--exhaustion if we received gigabytes of characters with no newline.
function read_line(max_len)
    local ret = ""
    for i = 1, (max_len or 8096) do
        local chr = io.read(1)
        if chr == "\n" then
            return ret, true
        end
        ret = ret .. chr
    end

    return ret, false
end

--The following function and variables was translated from Go to Lua. The
--original code can be found here:
--
--http://golang.org/src/pkg/unicode/utf8/utf8.go#L45
local surrogate_min = 0xD800
local surrogate_max = 0xDFFF

local t1 = 0x00 -- 0000 0000
local tx = 0x80 -- 1000 0000
local t2 = 0xC0 -- 1100 0000
local t3 = 0xE0 -- 1110 0000
local t4 = 0xF0 -- 1111 0000
local t5 = 0xF8 -- 1111 1000

local maskx = 0x3F -- 0011 1111
local mask2 = 0x1F -- 0001 1111
local mask3 = 0x0F -- 0000 1111
local mask4 = 0x07 -- 0000 0111

local char1_max = 0x7F    -- (1<<7)  - 1
local char2_max = 0x07FF  -- (1<<11) - 1
local char3_max = 0xFFFF  -- (1<<16) - 1

local max_char = 0x10FFFF -- \U0010FFFF

function get_next_char_len(p)
    local n = p:len()
    local c0 = p:byte(1)

    --1-byte, 7-bit sequence?
    if c0 < tx then
        return 1
    end

    --unexpected continuation byte?
    if c0 < t2 then
        return nil
    end

    --need first continuation byte
    if n < 2 then
        return nil
    end
    local c1 = p:byte(2)
    if c1 < tx or t2 <= c1 then
        return nil
    end

    --2-byte, 11-bit sequence?
    if c0 < t3 then
        local l1 = (c0 & mask2) << 6
        local l2 = c1 & maskx
        local r = l1 | l2
        if r <= char1_max then
            return nil
        end
        return 2
    end

    --need second continuation byte
    if n < 3 then
        return nil
    end
    local c2 = p:byte(3)
    if c2 < tx or t2 <= c2 then
        return nil
    end

    --3-byte, 16-bit sequence?
    if c0 < t4 then
        local l1 = (c0 & mask3) << 12
        local l2 = (c1 & maskx) << 6
        local l3 = c2 & maskx
        local r = l1 | l2 | l3
        if r <= char2_max then
            return nil
        end
        if surrogate_min <= r and r <= surrogate_max then
            return nil
        end
        return 3
    end

    --need third continuation byte
    if n < 4 then
        return nil
    end
    local c3 = p:byte(4)
    if c3 < tx or t2 <= c3 then
        return nil
    end

    --4-byte, 21-bit sequence?
    if c0 < t5 then
        local l1 = (c0 & mask4) << 18
        local l2 = (c1 & maskx) << 12
        local l3 = (c2 & maskx) << 6
        local l4 = c3 & maskx
        local r = l1 | l2 | l3 | l4
        if r <= char3_max or max_char < r then
            return nil
        end
        return 4
    end

    --error
    return nil
end

function validate_utf8(s)
    local i = 1
    local len = s:len()
    while i <= len do
        local size = get_next_char_len(s:sub(i))
        if size == nil then
            return false
        end
        i = i + size
    end
    return true
end

--Returns a table containing the list of directories resulting from splitting
--the argument by '/'.
function split_path(path)
    --[[
    for _, v in pairs({"/a/b/c", "a/b/c", "//a/b/c", "a/b/c/", "a/b/c//"}) do
        print(v,table.concat(split_path(v), ','))
    end

    -- /a/b/c  ,a,b,c
    -- a/b/c   a,b,c
    -- //a/b/c ,,a,b,c
    -- a/b/c/  a,b,c
    -- a/b/c// a,b,c,
    ]]
    local ret  = {}
    local j = 0
    for i=1, path:len() do
        if path:sub(i,i) == '/' then
            if j == 0 then
                ret[#ret+1] = path:sub(1, i-1)
            else
                ret[#ret+1] = path:sub(j+1, i-1)
            end
            j = i
        end
    end
    if j ~= path:len() then
        ret[#ret+1] = path:sub(j+1, path:len())
    end
    return ret
end


function is_path_valid(resource)
     --remove the beginning slash
    resource = string.sub(resource, 2, string.len(resource))

    --Windows drive names are not welcome.
    if resource:match("^([a-zA-Z]):") then
        return false
    end

    --if it starts with a dot or a slash or a backslash, forbid any acccess to it.
    local first_char = resource:sub(1, 1)

    if first_char == "." then
        return false
    end

    if first_char == "/" then
        return false
    end

    if resource:find("\\") then
        return false
    end

    for _, directory in pairs(split_path(resource)) do
        if directory == '' then
            return false
        end

        if directory == '..' then
            return false
        end
    end

    return true
end

--Make a response, output it and stop execution.
--
--It takes an associative array with three optional keys: status (status line)
--and headers, which lists all additional headers to be sent. You can also
--specify "data" - either a function that is expected to return nil at some
--point or a plain string.
function make_response(params)

    --Print the status line. If we got none, assume it's all okay.
    if not params["status"] then
        params["status"] = "HTTP/1.1 200 OK"
    end
    print_rn(params["status"])

    --Send the date.
    print_rn("Date: " .. os.date("!%a, %d %b %Y %H:%M:%S GMT"))

    --Send the server headers as described in the configuration.
    for key, value in pairs(server_headers) do
        print_rn(("%s: %s"):format(key, value))
    end

    --Now send the headers from the parameter, if any.
    if params["headers"] then
        for key, value in pairs(params["headers"]) do
            print_rn(("%s: %s"):format(key, value))
        end
    end

    --If there's any data, check if it's a function.
    if params["data"] then

        if type(params["data"]) == "function" then

            print_rn("")
            debug("Starting buffered output...")

            --run the function and print its contents, until we hit nil.
            local f = params["data"]
            while true do
                local ret = f()
                if ret == nil then
                    debug("Buffered output finished.")
                    break
                end
                io.stdout:write(ret)
                io.stdout:flush()
            end

        else

            --It's a plain string. Send its length and output it.
            debug("Just printing the data. Status='" .. params["status"] .. "'")
            print_rn("Content-length: " .. params["data"]:len())
            print_rn("")
            io.stdout:write(params["data"])
            io.stdout:flush()

        end
    else
        print_rn("")
    end

    os.exit(0)
end

function make_error(error_str)
    make_response({
        ["status"] = "HTTP/1.1 "..error_str,
        ["headers"] = {["Content-type"] = "text/html"},
        ["data"] = "<h1>"..error_str.."</h1>",
    })
end

do_400 = function() make_error("400 Bad Request") end
do_403 = function() make_error("403 Forbidden") end
do_404 = function() make_error("404 Not Found") end
do_405 = function() make_error("405 Method Not Allowed") end
do_414 = function() make_error("414 Request-URI Too Long") end

------------------------------------------------------------------------------
--                         End of library section                           --
------------------------------------------------------------------------------

input, success = read_line()

if not success then
    do_414()
end

if input:sub(-1) == "\r" then
    input = input:sub(1,-2)
end

--We assume that:
-- * a method is alphanumeric uppercase,
-- * resource may contain anything that's not a space,
-- * protocol version is followed by a single space.
method, resource, protocol = input:match("([A-Z]+) ([^ ]+) ?(.*)")

if resource:find(string.char(0)) ~= nil then
    do_400()
end

if not validate_utf8(resource) then
    do_400()
end

if method ~= "GET" then
    do_405()
end

while true do

    input = read_line()
    if input == "" or input == "\r" then
        break
    end
end

debug("Got a request for '" .. resource
    .. "' (urldecoded: '" .. url_decode(resource) .. "').")
resource = url_decode(resource)

--make sure that the resource starts with a slash.
if resource:sub(1, 1) ~= '/' then
    do_400() --could probably use a fancier error here.
end

if not is_path_valid(resource) then
    do_403()
end

--try to make all file openings from now on relative to the working directory.
resource = "./" .. resource

--If it's a directory, try to load index.html from it.
if resource:sub(-1) == "/" then
    resource = resource .. '/index.html'
end

--try to open the file...
f = io.open(resource, "rb")
if f == nil then
    do_404() --opening file failed, throw a 404.
end

--and output it all.
make_response({
    ["data"] = function() return f:read(1024) end,
    ["headers"] = {["Content-type"] = guess_mime(resource)},
})
