This is directory for OpenVMS support,
provided shared and static library,
pcre2grep  utility also.

Requires:
bzip2 library : http://vaxvms.org/clamav/
zlib library  : http://vaxvms.org/libsdl/required.html


To build the library please:

@[.VMS]CONFIGURE.COM
@BUILD

After build, PCRE2$STARTUP.COM has been created
it should be started before use (good place from LOGIN.COM)

Feel free to contact:
alexey@vaxman.de
Alexey Chupahin
