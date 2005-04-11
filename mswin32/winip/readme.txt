WinIP -- a set of functions to allow raw IP on Windows

There is no documentation (yet).

The winip library consists of all files in this directory.  It is
a set of functions designed to implement something resembling BSD
raw sockets on Windows using either winpcap or Win2K SOCK_RAW.
It determines as runtime which one should be used.

This library was inspired by nmapNT by ryan@eeye.com.  It doesn't
contain any of his original code any more (I think).  His code
has been moved to wintcpip.c.

Note:  functions in this library with the same name as the
corresponding nmap function are still LGPL since they are
not based (except for semantics) on nmap.

Proposed changes should be discussed on nmap-dev if nmap-related
or you could e-mail me and maybe I'll set up a list for general
development or use.

Note: snmpapi.cpp and MibAccess.* are based on sources from
codeguru.com.  They are for win95 support, and are not needed
if snmp95.cpp is modified to do nothing.

You still need WinSock2 to run on Win95.  Get it at: (one line)
http://www.microsoft.com/Windows95/downloads/contents
/WUAdminTools/S_WUNetworkingTools/W95Sockets2/Default.asp

Get winpcap from http://netgroup-serv.polito.it/winpcap


My PGP key is:

-----BEGIN PGP PUBLIC KEY BLOCK-----
Version: PGPfreeware 6.5.8 for non-commercial use <http://www.pgp.com>

mQGiBDnOgrERBADxtQfwz3gj76DTXGPvie4ZkD3OVuQw4CP0etMsiqPtipGVuetu
A3+4XLG2CljxN3c3/KRuG1AF5M0T81IB96wGHJYP/LLQ9sp6TguQgFsTXdIRVXGF
57+Uw2Bz1twsYWsb3vVcn5K+W7XhyEq5gVzvBbRA4tieUvwXdntYDhEP+wCg/9sR
clVmF3kx4DfrJpsWIyv4bJsEALup/as6kW1X7I0wS0fPM1zHBaTg6/bP8mI90asX
5xEDgsmHvc6SsQbAk4YAKMggLBtkXNA6AdBLnnh2ef5vOnrHAUbrcejR5YXxihQ9
YKTxQ9oEnlL0sdVokEQJ9KGJofl2BmDTzPtUhxdKtGfeNz9AbrXawwxOsfOGPIB0
cgkxA/9hdMU80ktpoKBw8o1xgX5DDaD6XjfqvmV2NwJQRXmyC596woMHUaG3WNHI
/famgszy0SG9i9oQH0XFYEmqF7MuAfwK61i5Yzb5lKq2XHIiXbpz4pWso9sbZyDU
9YQXRQxFMaEiQs5o2Ky61U64Fy6/n7DdeJDx4PFiNafYVE/Q9LQmQW5keSBMdXRv
bWlyc2tpIDxMdXRvQG1haWxhbmRuZXdzLmNvbT6JAE4EEBECAA4FAjnOgrEECwMC
AQIZAQAKCRAxdZqcg8510+X7AKCXnBYDFqwZ4r2OqgcEzTFtpjK66QCg2tEgIyg8
cFgFJhNC6h+k0fjgisK5Aw0EOc6CsRAMAMwdd1ckOErixPDojhNnl06SE2H22+sl
Dhf99pj3yHx5sHIdOHX79sFzxIMRJitDYMPj6NYK/aEoJguuqa6zZQ+iAFMBoHzW
q6MSHvoPKs4fdIRPyvMX86RA6dfSd7ZCLQI2wSbLaF6dfJgJCo1+Le3kXXn11JJP
mxiO/CqnS3wy9kJXtwh/CBdyorrWqULzBej5UxE5T7bxbrlLOCDaAadWoxTpj0BV
89AHxstDqZSt90xkhkn4DIO9ZekX1KHTUPj1WV/cdlJPPT2N286Z4VeSWc39uK50
T8X8dryDxUcwYc58yWb/Ffm7/ZFexwGq01uejaClcjrUGvC/RgBYK+X0iP1YTknb
zSC0neSRBzZrM2w4DUUdD3yIsxx8Wy2O9vPJI8BD8KVbGI2Ou1WMuF040zT9fBdX
Q6MdGGzeMyEstSr/POGxKUAYEY18hKcKctaGxAMZyAcpesqVDNmWn6vQClCbAkbT
CD1mpF1Bn5x8vYlLIhkmuquiXsNV6UwybwACAgwAsKr5rKpGFEK+3ZR/xnoPgo+Z
x/P19nQyBkA9ZYNelG3y+3UMKakQ0HLp08NmBOBvUFBUBbsQdqEn1RYnkEVVb/Zm
7I2olottdoPxjSpHXoQqa0W0DYe7iFVKKUbePYyrwMSkqTm5+3WOIhPVj1pnhkhq
MwrYUAu0yUIQ463QKuxIh/nxzShMEbx1HGdCmeT3j5ic865fQESRBYw3npxkvKGv
K4huVO/ZC8SiXglHd9uac8N/Hv+zhnEV1rTN/sXQsIlPKPEdgfWXLPmu1aKdtWs6
68xSdO5zeexvWoj7hcwwT1fb86U8GVRTvJb2+hD4TdNg8Id7pWGOCU9aeEjksNYX
Q3dNjNjSUGe+SIhTDVqPcUPR2RqQ3gYZsqVSzQO/YECqaFj2Jr/SD4GHfbQwy3j/
BrSTim1aBJi0yeF04Eh/0mbujg0ujBSSlcEn5MBm+dhRKDpiAjxwj95lJGn//W0j
vH/52MyAJLZKak50G20FsE9MuF0p14d5B5Ybv7zliQBGBBgRAgAGBQI5zoKxAAoJ
EDF1mpyDznXTL1QAn1Ykin2yyKCu82Je54fB97sSMhwiAKD5s4mwOmPqcfwqGe2q
yOZTzqpgXw==
=TKs6
-----END PGP PUBLIC KEY BLOCK-----



Version history:
0.1:  first public release (in nmap)
0.2:  adds windows 95 support


Known issues:

If there is a lot of traffic over any given interface unrelated
to the client, and if the interface is using Win2K raw sockets,
then there may be data loss.  I will fix it if this becomes
a problem.

It needs testing to make sure it works somewhat normally if
iphlpapi is not present.

Support for forcing a given source address is somewhat sketchy.
Support for IP over an interface that isn't bound to MS's stack
is nonexistant, although it could feasably be added

Need to implement PPP over winpcap on win98 (and FDDI,
ATM, and TokenRing on all platforms).


Files contained in this library:
winip.c
winip.h
rawrecv.c
pcapsend.c
genmod.h
iphlpapi.txt
iphlpapi.lib
iphlpapi.c
iphlpapi.def
iphlpapi.bat
iphlpapi.h
snmp95.cpp
snmpapi.cpp
MibAccess.cpp
MibAccess.h