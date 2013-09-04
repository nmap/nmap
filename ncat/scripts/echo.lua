--Emulates the RFC 862 echo service, behaving like Unix's "cat" tool.

while true do

  --We're reading in 1-byte chunks because calls like io.stdin:read(512) would
  --wait for full 512 bytes of data before continuing.
  data = io.stdin:read(1)

  if data == nil then
    break
  end

  io.stdout:write(data)
  io.stdout:flush()

end
