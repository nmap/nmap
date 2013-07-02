--Emulates the RFC 862 echo service, behaving like Unix's "cat" tool.

while true do

    data = io.stdin:read(512)

    if data == nil then
        break
    end

    io.stdout:write(data)
    io.stdout:flush()

end
