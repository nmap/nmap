--This script reads data from the standard input and discards them.

while true do

    data = io.stdin:read(512)

    if data == nil then
        break
    end

end
