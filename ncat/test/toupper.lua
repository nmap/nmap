--Emulates the RFC 862 echo service, behaving like Unix's "cat" tool.

while true do

    data = io.stdin:read(1)

    if data == nil then
        break
    end

    io.write(data:upper())
    io.flush()

end
