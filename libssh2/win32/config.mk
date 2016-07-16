
# Tweak these for your system
!if "$(OPENSSLINC)" == ""
OPENSSLINC=..\openssl-0.9.8zc\inc32
!endif

!if "$(OPENSSLLIB)" == ""
OPENSSLLIB=..\openssl-0.9.8zc\out32dll
!endif

!if "$(ZLIBINC)" == ""
ZLIBINC=..\zlib-1.2.8
!endif

!if "$(ZLIBLIB)" == ""
ZLIBLIB=..\zlib-1.2.8
!endif

!if "$(TARGET)" == ""
TARGET=Release
!endif

!if "$(TARGET)" == "Debug"
SUFFIX=_debug
CPPFLAGS=/Od /MDd
DLLFLAGS=/DEBUG /LDd
!else
CPPFLAGS=/Oi /O2 /Oy /GF /Y- /MD /DNDEBUG
DLLFLAGS=/DEBUG /LD
!endif

CPPFLAGS=/nologo /GL /Zi /EHsc $(CPPFLAGS) /Iwin32 /Iinclude

!if "$(WITH_WINCNG)" == "1"
CPPFLAGS=$(CPPFLAGS) /DLIBSSH2_WINCNG
# LIBS=bcrypt.lib crypt32.lib
!else
CPPFLAGS=$(CPPFLAGS) /DLIBSSH2_OPENSSL /I$(OPENSSLINC)
LIBS=$(LIBS) $(OPENSSLLIB)\libeay32.lib $(OPENSSLLIB)\ssleay32.lib
!endif

!if "$(WITH_ZLIB)" == "1"
CPPFLAGS=$(CPPFLAGS) /DLIBSSH2_HAVE_ZLIB /I$(ZLIBINC)
LIBS=$(LIBS) $(ZLIBLIB)\zlib.lib
!endif

CFLAGS=$(CPPFLAGS)
RCFLAGS=/Iinclude
DLLFLAGS=$(CFLAGS) $(DLLFLAGS)
LIBS=$(LIBS) ws2_32.lib user32.lib advapi32.lib gdi32.lib

INTDIR=$(TARGET)\$(SUBDIR)


