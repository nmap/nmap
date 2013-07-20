input = io.stdin:read("*line")

server_headers = {
    ["Server"] = "Ncat --lua-exec httpd.lua",
    ["Connection"] = "close",
}

function make_reply(params)

    if params["status"] then
        print(params["status"].."\r")
    else
        print("HTTP/1.1 200 OK")
    end

    --Not sure if it's exactly RFC RFC 1123 - no idea how Lua handles locales
    --and what happens if the day is one-digit. TODO: check it.
    print("Date: "..os.date("!%a, %d %b %Y %H:%M:%S GMT").."\r")

    for key, value in pairs(server_headers) do
        print(string.format("%s: %s\r", key, value))
    end

    if params["headers"] then
        for key, value in pairs(params["headers"]) do
            print(string.format("%s: %s\r", key, value))
        end
    end

    if params["data"] then
        print("Content-length: "..string.len(params["data"].."\r"))
        print("\r")
        print(params["data"])
    else
        print("\r")
    end
    os.exit(1)
end

function do_400()
    make_reply({
        ["status"] = "HTTP/1.1 400 Bad Request\r",
        ["headers"] = {["Content-type"] = "text/html"},
        ["data"] = "<h1>Bad request.</h1>",
    })
end

function do_403()
    make_reply({
        ["status"] = "HTTP/1.1 403 Forbidden\r",
        ["headers"] = {["Content-type"] = "text/html"},
        ["data"] = "<h1>Forbidden.</h1>",
    })
end

function do_404()
    make_reply({
        ["status"] = "HTTP/1.1 404 Not Found\r",
        ["headers"] = {["Content-type"] = "text/html"},
        ["data"] = "<h1>Not Found.</h1>",
    })
end



--We assume that:
-- * a method is alphanumeric uppercase,
-- * resource may contain anything that's not a space,
-- * protocol version is followed by a single space.
pattern = "([A-Z]+ )([^ ]+) ?(.*)"
method, resource, protocol = string.match(input, pattern)

headers = {}
while true do

    input = io.stdin:read("*line")
    if not input or input ~= "\r" then
        break
    end

    --header line is anything before the colon (at least one character),
    --then there's space, and the value is anything that is left,
    --again - at least one character.
    key, value = string.match(input, "(.+): (.+)")

    if key == nil then
        do_400()
    end

    headers[key] = value
end

--make sure that the resource starts with a slash.
if string.sub(resource, 0, 1) ~= '/' then
        do_400() --could probably use a fancier error here.
end

--now, remove the beginning slash
resource = string.sub(resource, 2, string.len(resource))

--if the resource was made of a slash only, let's make it index.html.
if resource == "" then
    resource = "index.html"
end

--if it starts with a dot, forbid any acccess to it.
if string.sub(resource, 0, 1) == "." then
    do_403() --no hidden Unix files or simple directory traversal, sorry!
end

--try to open the file...
f = io.open(resource, "r")
if not f then
    do_404() --opening file failed, throw a 404.
end

--and output it all.
print(f:read("*all"))
