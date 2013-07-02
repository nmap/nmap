--This is another --lua-exec demo. It displays a menu to a user, waits for her
--input and makes a decision according to what the user entered. All happens
--in an infinite loop.

while true do

    print("Here's a menu for you: ")
    print("1. Repeat the menu.")
    print("0. Exit.")

    io.write("Please enter your choice: ")
    io.flush(io.stdout)
    i = io.read()

    --WARNING! Without this line, the script will go into an infinite loop
    --that keeps consuming system resources when the connection gets broken.
    --Ncat's subprocesses are NOT killed in this case!
    if i == nil then
        break
    end

    print("You wrote: ",i,".")

    if i == "0" then
        break
    elseif i == "1" then
        print("As you wish.")
    else
        print("No idea what you meant. Please try again.")
    end

    print() --print a newline
end
