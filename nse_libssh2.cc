/* Binding for the libssh2 library. Note that there is not a one-to-one correspondance
 * between functions in libssh2 and the binding. 
 * Currently, during the ssh2 handshake, a call to nsock.recieve may result in an EOF
 * error. This appears to only occur when stressing the ssh server (ie during a brute
 * force attempt) or while behind a restrictive firewall/IDS.
 * by Devin Bjelland
 */

extern "C" {
  #include "lua.h"
  #include "lauxlib.h"
}

#include "nse_debug.h"
#include "nse_nsock.h"
#include "nse_utility.h"

#include <libssh2.h>

#include <fcntl.h>
#include <netdb.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>

enum {
  SSH2_UDATA = lua_upvalueindex(1)
};

struct ssh_userdata {
  int sp[2];
  LIBSSH2_SESSION *session;
};

static int ssh_error (lua_State *L, LIBSSH2_SESSION *session, const char *msg)
{
  char *errmsg;
  libssh2_session_last_error(session, &errmsg, NULL, 0);
  return nseU_safeerror(L, "%s: %s", msg, errmsg);
}

static int finish_send (lua_State *L)
{
  if (lua_toboolean(L, -2)) {
    return 0;
  } else {
    return lua_error(L); /* uses idx 6 */
  }
}

static int finish_read (lua_State *L)
{
  struct ssh_userdata *sshu = (struct ssh_userdata *) nseU_checkudata(L, 1, SSH2_UDATA, "ssh2");

  if (lua_toboolean(L, -2)) {
    size_t n = 0;
    size_t l;
    lua_getuservalue(L, 1);
    lua_getfield(L, -1, "sp_buff");
    lua_pushvalue(L, 3);
    lua_concat(L, 2);
    const char *data = lua_tolstring(L, -1, &l);
    lua_pushliteral(L, "");
    lua_setfield(L, 4, "sp_buff");
    while (n < l) {
      int rc = write(sshu->sp[1], data+n, l-n);
      if(rc == -1 && errno != EAGAIN) {
        luaL_error(L, "Writing to socket pair: %s", strerror(errno));
      } else if(rc == -1 && errno == EAGAIN) {
        lua_pushlstring(L, data+n, l-n);
        lua_setfield(L, 4, "sp_buff");
        break;
      } else {
        n += rc;
      }
    }
    return 0;
  } else {
    return lua_error(L); /* uses idx 6 */
  }
}

static int filter (lua_State *L)
{
  int rc;
  char data[4096];
  struct ssh_userdata *sshu = (struct ssh_userdata *) nseU_checkudata(L, 1, SSH2_UDATA, "ssh2");

  lua_getuservalue(L, 1);
  lua_getfield(L, -1, "sock");
  lua_replace(L, -2);

  rc = read(sshu->sp[1], data, sizeof(data));
  if (rc > 0) {
    //write data to nsock socket
    lua_getfield(L, -1, "send");
    lua_insert(L, -2); /* swap */
    lua_pushlstring(L, data, rc);
    lua_callk(L, 2, 2, 0, finish_send);
    return finish_send(L);
  } else if (rc == -1 && errno != EAGAIN) {
    luaL_error(L, "%s", strerror(errno));
  }

  lua_getfield(L, -1, "receive");
  lua_insert(L, -2); /* swap */
  lua_callk(L, 1, 2, 0, finish_read);
  return finish_read(L);
}

static int do_session_handshake (lua_State *L)
{
  int rc;
  struct ssh_userdata *sshu;

  assert(lua_gettop(L) == 4);

  sshu = (struct ssh_userdata *) nseU_checkudata(L, 3, SSH2_UDATA, "ssh2");
  while((rc = libssh2_session_handshake(sshu->session, sshu->sp[0])) == LIBSSH2_ERROR_EAGAIN) {
    luaL_getmetafield(L, 3, "filter");
    lua_pushvalue(L, 3);
    lua_callk(L, 1, 0, 0, do_session_handshake);
  }

  if (rc)
    luaL_error(L, "Unable to complete libssh2 handshake.");

  lua_pushvalue(L, 3);
  return 1;
}

static int finish_session_open (lua_State *L) {
  assert(lua_gettop(L) == 6);
  if (lua_toboolean(L, -2)) {
    lua_pop(L, 2);
    return do_session_handshake(L);
  } else {
    return lua_error(L);
  }
}

/* Creates libssh2 session, connects to hostname:port and tries to perform a 
 * ssh handshake on socket. Returns ssh_state on success
 *
 * session_open(hostname, port)
 */
static int l_session_open(lua_State *L) {
  int rc;

  luaL_checkint(L, 2);

  lua_settop(L, 2);

  ssh_userdata *state = (ssh_userdata *)lua_newuserdata(L, sizeof(ssh_userdata)); /* index 3 */
  assert(lua_gettop(L) == 3);
  state->session = NULL;
  state->sp[0] = -1;
  state->sp[1] = -1;
  lua_pushvalue(L, lua_upvalueindex(1)); /* metatable */
  lua_setmetatable(L, 3);
  lua_newtable(L);
  lua_setuservalue(L, 3);
  lua_getuservalue(L, 3); /* index 4 */
  assert(lua_gettop(L) == 4);

  state->session = libssh2_session_init();
  libssh2_session_set_blocking(state->session, 0);
  
  if (socketpair(AF_UNIX, SOCK_STREAM, 0, state->sp) == -1) {
    return nseU_safeerror(L, "trying to create socketpair");
  }
  rc = fcntl(state->sp[1], F_GETFD);
  if (rc == -1)
    return nseU_safeerror(L, "%s", strerror(errno));
  rc |= O_NONBLOCK;
  rc = fcntl(state->sp[1], F_SETFL, rc);
  if (rc == -1)
    return nseU_safeerror(L, "%s", strerror(errno));

  lua_getglobal(L, "nmap");
  lua_getfield(L, -1, "new_socket");
  lua_replace(L, -2);
  lua_call(L, 0, 1);
  lua_setfield(L, 4, "sock");
  
  lua_pushliteral(L, "");
  lua_setfield(L, 4, "sp_buff");

  assert(lua_gettop(L) == 4);
 
  lua_getfield(L, 4, "sock");
  lua_getfield(L, -1, "connect");
  lua_insert(L, -2); /* swap */
  lua_pushvalue(L, 1);
  lua_pushvalue(L, 2);
  lua_callk(L, 3, 2, 3, finish_session_open);
  return finish_session_open(L);
}

/* Returns the SHA1 or MD5 hostkey hash of provided session or nil if it is not available
 *
 */
static int l_hostkey_hash(lua_State *L) {
  static int hash_option[] = {LIBSSH2_HOSTKEY_HASH_MD5, LIBSSH2_HOSTKEY_HASH_SHA1};
  static int hash_length[] = {16, 20};
  static const char *hashes[] = {"md5", "sha1", NULL};  

  luaL_Buffer B;
  struct ssh_userdata *state = (struct ssh_userdata *) nseU_checkudata(L, 1, SSH2_UDATA, "ssh2");
  int type = luaL_checkoption(L, 2, "sha1", hashes); 
  const unsigned char *hash = (const unsigned char *) libssh2_hostkey_hash(state->session, hash_option[type]);

  if (hash == NULL)
    return nseU_safeerror(L, "could not get hostkey hash");

  luaL_buffinit(L, &B);
  for (int i = 0; i < hash_length[type]; i++) {
    char byte[3]; /* with space for NUL */
    snprintf(byte, sizeof(byte), "%02X", (unsigned int) hash[i]);
    if (i)
        luaL_addchar(&B, ':');
    luaL_addlstring(&B, byte, 2);
  }
  luaL_pushresult(&B);

  return 1;
}

static int l_set_timeout(lua_State *L) {
  struct ssh_userdata *state = (struct ssh_userdata *) nseU_checkudata(L, 1, SSH2_UDATA, "ssh2");
  long timeout = luaL_checklong(L, 2);
  libssh2_session_set_timeout(state->session, timeout);  

  return 0;
}

/* Return list of supported authenication methods
 *
 */
static int l_userauth_list(lua_State *L) {
  struct ssh_userdata *state = (struct ssh_userdata *) nseU_checkudata(L, 1, SSH2_UDATA, "ssh2");
  const char *username = luaL_checkstring(L, 2);
  char *auth_list;

  while((auth_list = libssh2_userauth_list(state->session, username, lua_rawlen(L, 2))) == NULL && libssh2_session_last_errno(state->session) == LIBSSH2_ERROR_EAGAIN) {
    luaL_getmetafield(L, 1, "filter");
    lua_pushvalue(L, 1);
    lua_callk(L, 1, 0, 0, l_userauth_list);
  }

  if(auth_list) {
    const char *auth = strtok(auth_list, ",");
    lua_newtable(L);
    do {
      lua_pushstring(L, auth);
      lua_rawseti(L, -2, lua_rawlen(L, -2)+1);
    } while((auth = strtok(NULL, ",")));
    libssh2_free(state->session, (void *)auth_list);
  } else if (libssh2_userauth_authenticated(state->session)) {
    lua_pushliteral(L, "none_auth");
  } else {
    return ssh_error(L, state->session, "userauth_list");
  }
  return 1;
}

static int l_userauth_publickey(lua_State *L) {
  int rc;
  const char *username, *private_key_file, *passphrase, *public_key_file;
  struct ssh_userdata *state = (struct ssh_userdata *) nseU_checkudata(L, 1, SSH2_UDATA, "ssh2");
  username = luaL_checkstring(L, 2);
  private_key_file = luaL_checkstring(L, 3);
  if (lua_isstring(L, 4)) {
    passphrase = lua_tostring(L, 4);
  }
  else {
    passphrase = NULL;
  }
  if (lua_isstring(L, 5)) {
    public_key_file = lua_tostring(L, 5);
  }
  else {
    public_key_file = NULL;
  }
  
  while ((rc = libssh2_userauth_publickey_fromfile(state->session, username, public_key_file, private_key_file, passphrase)) == LIBSSH2_ERROR_EAGAIN) {
    luaL_getmetafield(L, 1, "filter");
    lua_pushvalue(L, 1);
    lua_callk(L, 1, 0, 0, l_userauth_publickey);
  }
  
  if(rc == 0) {
    lua_pushboolean(L, 1);
  } else {
    lua_pushboolean(L, 0);
  }
  return 1;
  

}

static int l_read_publickey(lua_State *L) {
  FILE *fd;
  char c;
  const char* publickeyfile = luaL_checkstring(L, 1);
  luaL_Buffer publickey_data;
  fd = fopen(publickeyfile, "r");
  if (!fd) {
    luaL_error(L, "Error reading file");
  }

  luaL_buffinit(L, &publickey_data);
  while(fread(&c, 1, 1, fd) && '\r' && c != '\n' && c != ' ') continue;
  
  while(fread(&c, 1, 1, fd) && '\r' && c != '\n' && c != ' ') {
    luaL_addchar (&publickey_data, c);
  }
  fclose(fd);
 
  lua_getglobal(L, "require");
  lua_pushstring(L, "base64");
  lua_call(L, 1, 1);
  lua_getfield(L, -1, "dec");
  
  luaL_pushresult(&publickey_data);
  lua_call(L, 1, 1);
  
  return 1;
}

static int publickey_canauth_cb(LIBSSH2_SESSION *session, unsigned char **sig, size_t *sig_len, const unsigned char *data, size_t data_len, void **abstract) {
  return 0;
}

static int l_publickey_canauth(lua_State *L) {
  char *errmsg;
  int errlen;
  int rc;
  const char *username;
  unsigned const char *publickey_data;
  size_t len;
  struct ssh_userdata *state = (struct ssh_userdata *) nseU_checkudata(L, 1, SSH2_UDATA, "ssh2");
  username = luaL_checkstring(L, 2);
  if (lua_isstring(L, 3)) {
    publickey_data = (unsigned const char*) lua_tolstring(L, 3, &len);
  } else {
    luaL_error(L, "Invalid public key");
  } 
  
  while ((rc = libssh2_userauth_publickey(state->session, username, publickey_data, len, &publickey_canauth_cb, NULL)) == LIBSSH2_ERROR_EAGAIN) {
    luaL_getmetafield(L, 1, "filter");
    lua_pushvalue(L, 1);
    lua_callk(L, 1, 0, 0, l_publickey_canauth);
  }
  libssh2_session_last_error(state->session, &errmsg, &errlen, 0);
  if(rc == LIBSSH2_ERROR_ALLOC || rc == LIBSSH2_ERROR_PUBLICKEY_UNVERIFIED) {
    lua_pushboolean(L, 1);
  //Username/PublicKey combination invalid
  } else if(rc == LIBSSH2_ERROR_AUTHENTICATION_FAILED) {
    lua_pushboolean(L, 0);
  } else {
    luaL_error(L, "Invalid Publickey");
  }
  return 1;
}

/* Attempts to authenticate session with provided username and password
 * returns true on success and false otherwise 
 *
 * userauth_password(state, username, password) 
 */
static int l_userauth_password(lua_State *L) {
  int rc;
  const char *username, *password;
  struct ssh_userdata *state = (struct ssh_userdata *) nseU_checkudata(L, 1, SSH2_UDATA, "ssh2");
  username = luaL_checkstring(L, 2);
  password = luaL_checkstring(L, 3);

  while((rc = libssh2_userauth_password(state->session, username, password)) == LIBSSH2_ERROR_EAGAIN) {
    luaL_getmetafield(L, 1, "filter");
    lua_pushvalue(L, 1);
    lua_callk(L, 1, 0, 0, l_userauth_password);
  }
  if(rc == 0) {
    lua_pushboolean(L, 1);
  } else {
    lua_pushboolean(L, 0);
  }
  return 1;
}

static int l_session_close(lua_State *L) {
  struct ssh_userdata *state = (struct ssh_userdata *) nseU_checkudata(L, 1, SSH2_UDATA, "ssh2");
  int rc;
  while ((rc = libssh2_session_disconnect(state->session, "Normal Shutdown")) == LIBSSH2_ERROR_EAGAIN) {
    luaL_getmetafield(L, 1, "filter");
    lua_pushvalue(L, 1);
    lua_callk(L, 1, 0, 0, l_session_close);
  }
 
  if (rc < 0)
    luaL_error(L, "unable to disconnect session");
  
  if (libssh2_session_free(state->session) < 0) {
    luaL_error(L, "unable to free session");
  }
  return 0;
}

static const struct luaL_Reg libssh2 [] = {
  {"session_open", l_session_open},
  {"hostkey_hash", l_hostkey_hash},
  {"set_timeout",  l_set_timeout},
  {"userauth_list", l_userauth_list},
  {"userauth_publickey", l_userauth_publickey},
  {"read_publickey", l_read_publickey},
  {"publickey_canauth", l_publickey_canauth},
  {"userauth_password", l_userauth_password},
  {"session_close", l_session_close},
  {NULL, NULL}
};

static int gc (lua_State *L)
{
  struct ssh_userdata *sshu = (struct ssh_userdata *) nseU_checkudata(L, 1, SSH2_UDATA, "ssh2");
  if (sshu) {
    lua_pushvalue(L, lua_upvalueindex(1));
    lua_getfield(L, -1, "session_close");
    lua_insert(L, -2); /* swap */
    lua_pcall(L, 1, 0, 0); /* if an error occurs, don't do anything */
  }
  close(sshu->sp[0]);
  close(sshu->sp[1]);
  return 0;
}

int luaopen_libssh2 (lua_State *L) {
  lua_settop(L, 0); /* clear the stack */

  luaL_newlibtable(L, libssh2);

  lua_newtable(L); /* ssh2 session metatable */
  lua_pushvalue(L, -1);
  lua_pushcclosure(L, gc, 1);
  lua_setfield(L, -2, "__gc");
  lua_pushvalue(L, -1);
  lua_pushcclosure(L, filter, 1);
  lua_setfield(L, -2, "filter");

  luaL_setfuncs(L, libssh2, 1);

  if(libssh2_init(0) != 0) {
    luaL_error(L, "unable to open libssh2");
  }
  return 1;
}
