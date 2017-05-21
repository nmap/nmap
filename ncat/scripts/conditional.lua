--This is another --lua-exec demo. It displays a menu to a user, waits for her
--input and makes a decision according to what the user entered. All happens
--in an infinite loop.

--This function reads a line of at most 8096 bytes (or whatever the first
--parameter says) from standard input. Returns the string and a boolean value
--that is true if we hit the newline (defined as "\n") or false if the line had
--to be truncated. This is here because io.stdin:read("*line") could lead to
--memory exhaustion if we received gigabytes of characters with no newline.
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

while true do

  print "Here's a menu for you: "
  print "1. Repeat the menu."
  print "0. Exit."

  io.write "Please enter your choice: "
  io.flush(io.stdout)
  i = read_line()

  --WARNING! Without this line, the script will go into an infinite loop
  --that keeps consuming system resources when the connection gets broken.
  --Ncat's subprocesses are NOT killed in this case!
  if i == nil then
    break
  end

  print("You wrote: ", i, ".")

  if i == "0" then
    break
  elseif i == "1" then
    print "As you wish."
  else
    print "No idea what you meant. Please try again."
  end

  print() --print a newline
end
