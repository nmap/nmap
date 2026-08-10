CSOURCES = channel.c comp.c crypt.c hostkey.c kex.c mac.c misc.c \
 packet.c publickey.c scp.c session.c sftp.c userauth.c transport.c \
 version.c knownhost.c agent.c $(CRYPTO_CSOURCES) pem.c keepalive.c global.c \
 blowfish.c bcrypt_pbkdf.c agent_win.c

HHEADERS = libssh2_priv.h $(CRYPTO_HHEADERS) transport.h channel.h comp.h \
 mac.h misc.h packet.h userauth.h session.h sftp.h crypto.h blf.h agent.h
