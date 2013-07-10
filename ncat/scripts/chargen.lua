--chargen.lua - implements the RFC 864 CHARGEN service which basically spams
--the remote user until he decides to close the connection.
--
--CAVEAT: at the moment you need --lua-extensions to make sure this script will
--die once the connection gets closed. Otherwise, you will get a nasty infinite
--loop that will waste your CPU power until you kill the process.

while true do
    print("chargen")
end

