print("I'm in hello.lua.")

function on_connect()
sock_write("Hello")
end

--connect("localhost", 2233)
--connect("localhost", 2234)
