CSOURCES =              \
  agent.c               \
  bcrypt_pbkdf.c        \
  channel.c             \
  comp.c                \
  crypt.c               \
  crypto.c              \
  global.c              \
  hostkey.c             \
  keepalive.c           \
  kex.c                 \
  knownhost.c           \
  mac.c                 \
  misc.c                \
  packet.c              \
  pem.c                 \
  publickey.c           \
  scp.c                 \
  session.c             \
  sftp.c                \
  transport.c           \
  userauth.c            \
  userauth_kbd_packet.c \
  version.c

HHEADERS =              \
  channel.h             \
  comp.h                \
  crypto.h              \
  libgcrypt.h           \
  libssh2_priv.h        \
  libssh2_setup.h       \
  mac.h                 \
  mbedtls.h             \
  misc.h                \
  openssl.h             \
  os400qc3.h            \
  packet.h              \
  session.h             \
  sftp.h                \
  transport.h           \
  userauth.h            \
  userauth_kbd_packet.h \
  wincng.h

EXTRA_DIST =            \
  agent_win.c           \
  blowfish.c            \
  libgcrypt.c           \
  mbedtls.c             \
  openssl.c             \
  os400qc3.c            \
  wincng.c
