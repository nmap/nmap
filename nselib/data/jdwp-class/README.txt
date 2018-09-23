This directory contains sources and compiled classes
used by jdwp-* scripts.

All classes must have run() method defined which is
expected to return a string.
Method run() can have arguments, but then the scripts
would need to be modified to add those arguments when
class is injected. As JDWPExecCmd has a run() method
which accepts a string as its argument, see
jdwp-exec script for details of passing the
arguments to a method via JDWP.
Arguments need to be tagged with their respective type.
For other tags see http://docs.oracle.com/javase/6/docs/technotes/guides/jni/spec/types.html#wp9502 .
Example from jdwp-exec:

	local cmdID
	status,cmdID = jdwp.createString(socket,0,cmd)
	local runArgs = string.pack(">B I8", 0x4c, cmdID) -- 0x4c is object type tag
	-- invoke run method
	local result
	status, result = jdwp.invokeObjectMethod(socket,0,injectedClass.instance,injectedClass.thread,injectedClass.id,runMethodID,1,runArgs)

To compile these sources:
# javac *.java


