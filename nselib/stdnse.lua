module(..., package.seeall)

print_debug = function(...)
	local verbosity = 1;
	if ((#arg > 1) and (tonumber(arg[1]))) then
		verbosity = table.remove(arg, 1);
	end
	
	nmap.print_debug_unformatted(verbosity, string.format(unpack(arg, start)));
end

