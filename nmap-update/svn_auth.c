/* The functions in this file have been copied from
     subversion-1.5.x/subversion/libsvn_subr/cmdline.c
     subversion-1.5.x/subversion/libsvn_subr/simple_providers.c
   The point of copying these functions is to disable automatic username
   guessing based on UID, and always prompt for a username unless it is already
   defined in the auth cache or in a configuration file. libsvn_cmdline doesn't
   support disabling this while still calling svn_cmdline_create_auth_baton,
   which otherwise does a lot of useful things. This is an attempt to copy the
   minimum amount of code to disable username guessing.

   These changes have been made (set off with #if 0):
   * Disabled username guessing in prompt_for_simple_creds.
   * Made svn_auth_get_simple_prompt_provider have static scope.
   * Put an "nmap_update_" prefix on svn_auth_get_simple_prompt_provider and
     svn_cmdline_setup_auth_baton. */

/*
 * ====================================================================
 * Copyright (c) 2003-2006, 2008 CollabNet.  All rights reserved.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution.  The terms
 * are also available at http://subversion.tigris.org/license-1.html.
 * If newer versions of this license are posted there, you may use a
 * newer version instead, at your option.
 *
 * This software consists of voluntary contributions made by many
 * individuals.  For exact contribution history, see the revision
 * history and logs, available at http://subversion.tigris.org/.
 * ====================================================================
 */

#ifndef WIN32
#include "config.h"
#else
#include "win_config.h"
#endif

#if HAVE_SUBVERSION_1_SVN_CLIENT_H
#include <subversion-1/svn_client.h>
#include <subversion-1/svn_cmdline.h>
#include <subversion-1/svn_opt.h>
#include <subversion-1/svn_pools.h>
#include <subversion-1/svn_types.h>
#else
#include <svn_client.h>
#include <svn_cmdline.h>
#include <svn_opt.h>
#include <svn_pools.h>
#include <svn_types.h>
#endif


/*-----------------------------------------------------------------------*/
/* File provider                                                         */
/*-----------------------------------------------------------------------*/

/* The keys that will be stored on disk */
#define SVN_AUTH__AUTHFILE_USERNAME_KEY            "username"
#define SVN_AUTH__AUTHFILE_PASSWORD_KEY            "password"
#define SVN_AUTH__AUTHFILE_PASSTYPE_KEY            "passtype"

#define SVN_AUTH__SIMPLE_PASSWORD_TYPE             "simple"
#define SVN_AUTH__WINCRYPT_PASSWORD_TYPE           "wincrypt"
#define SVN_AUTH__KEYCHAIN_PASSWORD_TYPE           "keychain"


/*-----------------------------------------------------------------------*/
/* Prompt provider                                                       */
/*-----------------------------------------------------------------------*/

/* Baton type for username/password prompting. */
typedef struct
{
  svn_auth_simple_prompt_func_t prompt_func;
  void *prompt_baton;

  /* how many times to re-prompt after the first one fails */
  int retry_limit;
} simple_prompt_provider_baton_t;


/* Iteration baton type for username/password prompting. */
typedef struct
{
  /* how many times we've reprompted */
  int retries;
} simple_prompt_iter_baton_t;


/*** Helper Functions ***/
static svn_error_t *
prompt_for_simple_creds(svn_auth_cred_simple_t **cred_p,
                        simple_prompt_provider_baton_t *pb,
                        apr_hash_t *parameters,
                        const char *realmstring,
                        svn_boolean_t first_time,
                        svn_boolean_t may_save,
                        apr_pool_t *pool)
{
  const char *def_username = NULL, *def_password = NULL;

  *cred_p = NULL;

  /* If we're allowed to check for default usernames and passwords, do
     so. */
  if (first_time)
    {
      def_username = apr_hash_get(parameters,
                                  SVN_AUTH_PARAM_DEFAULT_USERNAME,
                                  APR_HASH_KEY_STRING);

      /* No default username?  Try the auth cache. */
      if (! def_username)
        {
          const char *config_dir = apr_hash_get(parameters,
                                                SVN_AUTH_PARAM_CONFIG_DIR,
                                                APR_HASH_KEY_STRING);
          apr_hash_t *creds_hash = NULL;
          svn_string_t *str;
          svn_error_t *err;

          err = svn_config_read_auth_data(&creds_hash, SVN_AUTH_CRED_SIMPLE,
                                          realmstring, config_dir, pool);
          svn_error_clear(err);
          if (! err && creds_hash)
            {
              str = apr_hash_get(creds_hash,
                                 SVN_AUTH__AUTHFILE_USERNAME_KEY,
                                 APR_HASH_KEY_STRING);
              if (str && str->data)
                def_username = str->data;
            }
        }

#if 0
      /* Still no default username?  Try the UID. */
      if (! def_username)
        def_username = svn_user_get_name(pool);
#endif

      def_password = apr_hash_get(parameters,
                                  SVN_AUTH_PARAM_DEFAULT_PASSWORD,
                                  APR_HASH_KEY_STRING);
    }

  /* If we have defaults, just build the cred here and return it.
   *
   * ### I do wonder why this is here instead of in a separate
   * ### 'defaults' provider that would run before the prompt
   * ### provider... Hmmm.
   */
  if (def_username && def_password)
    {
      *cred_p = apr_palloc(pool, sizeof(**cred_p));
      (*cred_p)->username = apr_pstrdup(pool, def_username);
      (*cred_p)->password = apr_pstrdup(pool, def_password);
      (*cred_p)->may_save = TRUE;
    }
  else
    {
      SVN_ERR(pb->prompt_func(cred_p, pb->prompt_baton, realmstring,
                              def_username, may_save, pool));
    }

  return SVN_NO_ERROR;
}


/* Our first attempt will use any default username/password passed
   in, and prompt for the remaining stuff. */
static svn_error_t *
simple_prompt_first_creds(void **credentials_p,
                          void **iter_baton,
                          void *provider_baton,
                          apr_hash_t *parameters,
                          const char *realmstring,
                          apr_pool_t *pool)
{
  simple_prompt_provider_baton_t *pb = provider_baton;
  simple_prompt_iter_baton_t *ibaton = apr_pcalloc(pool, sizeof(*ibaton));
  const char *no_auth_cache = apr_hash_get(parameters,
                                           SVN_AUTH_PARAM_NO_AUTH_CACHE,
                                           APR_HASH_KEY_STRING);

  SVN_ERR(prompt_for_simple_creds((svn_auth_cred_simple_t **) credentials_p,
                                  pb, parameters, realmstring, TRUE,
                                  ! no_auth_cache, pool));

  ibaton->retries = 0;
  *iter_baton = ibaton;

  return SVN_NO_ERROR;
}


/* Subsequent attempts to fetch will ignore the default values, and
   simply re-prompt for both, up to a maximum of ib->pb->retry_limit. */
static svn_error_t *
simple_prompt_next_creds(void **credentials_p,
                         void *iter_baton,
                         void *provider_baton,
                         apr_hash_t *parameters,
                         const char *realmstring,
                         apr_pool_t *pool)
{
  simple_prompt_iter_baton_t *ib = iter_baton;
  simple_prompt_provider_baton_t *pb = provider_baton;
  const char *no_auth_cache = apr_hash_get(parameters,
                                           SVN_AUTH_PARAM_NO_AUTH_CACHE,
                                           APR_HASH_KEY_STRING);

  if (ib->retries >= pb->retry_limit)
    {
      /* give up, go on to next provider. */
      *credentials_p = NULL;
      return SVN_NO_ERROR;
    }
  ib->retries++;

  SVN_ERR(prompt_for_simple_creds((svn_auth_cred_simple_t **) credentials_p,
                                  pb, parameters, realmstring, FALSE,
                                  ! no_auth_cache, pool));

  return SVN_NO_ERROR;
}


static const svn_auth_provider_t simple_prompt_provider = {
  SVN_AUTH_CRED_SIMPLE,
  simple_prompt_first_creds,
  simple_prompt_next_creds,
  NULL,
};


/* Public API */
static void
nmap_update_svn_auth_get_simple_prompt_provider
  (svn_auth_provider_object_t **provider,
   svn_auth_simple_prompt_func_t prompt_func,
   void *prompt_baton,
   int retry_limit,
   apr_pool_t *pool)
{
  svn_auth_provider_object_t *po = apr_pcalloc(pool, sizeof(*po));
  simple_prompt_provider_baton_t *pb = apr_pcalloc(pool, sizeof(*pb));

  pb->prompt_func = prompt_func;
  pb->prompt_baton = prompt_baton;
  pb->retry_limit = retry_limit;

  po->vtable = &simple_prompt_provider;
  po->provider_baton = pb;
  *provider = po;
}

svn_error_t *
nmap_update_svn_cmdline_setup_auth_baton(svn_auth_baton_t **ab,
                             svn_boolean_t non_interactive,
                             const char *auth_username,
                             const char *auth_password,
                             const char *config_dir,
                             svn_boolean_t no_auth_cache,
                             svn_config_t *cfg,
                             svn_cancel_func_t cancel_func,
                             void *cancel_baton,
                             apr_pool_t *pool)
{
  svn_boolean_t store_password_val = TRUE;
  svn_auth_provider_object_t *provider;

  /* The whole list of registered providers */
  apr_array_header_t *providers
    = apr_array_make(pool, 12, sizeof(svn_auth_provider_object_t *));

  /* The main disk-caching auth providers, for both
     'username/password' creds and 'username' creds.  */
#if defined(WIN32) && !defined(__MINGW32__)
  svn_auth_get_windows_simple_provider(&provider, pool);
  APR_ARRAY_PUSH(providers, svn_auth_provider_object_t *) = provider;
#endif
#ifdef SVN_HAVE_KEYCHAIN_SERVICES
  svn_auth_get_keychain_simple_provider(&provider, pool);
  APR_ARRAY_PUSH(providers, svn_auth_provider_object_t *) = provider;
#endif
  svn_auth_get_simple_provider(&provider, pool);
  APR_ARRAY_PUSH(providers, svn_auth_provider_object_t *) = provider;
  svn_auth_get_username_provider(&provider, pool);
  APR_ARRAY_PUSH(providers, svn_auth_provider_object_t *) = provider;

  /* The server-cert, client-cert, and client-cert-password providers. */
#if defined(WIN32) && !defined(__MINGW32__)
  svn_auth_get_windows_ssl_server_trust_provider(&provider, pool);
  APR_ARRAY_PUSH(providers, svn_auth_provider_object_t *) = provider;
#endif
  svn_auth_get_ssl_server_trust_file_provider(&provider, pool);
  APR_ARRAY_PUSH(providers, svn_auth_provider_object_t *) = provider;
  svn_auth_get_ssl_client_cert_file_provider(&provider, pool);
  APR_ARRAY_PUSH(providers, svn_auth_provider_object_t *) = provider;
  svn_auth_get_ssl_client_cert_pw_file_provider(&provider, pool);
  APR_ARRAY_PUSH(providers, svn_auth_provider_object_t *) = provider;

  if (non_interactive == FALSE)
    {
      svn_cmdline_prompt_baton_t *pb = NULL;

      if (cancel_func)
        {
          pb = apr_palloc(pool, sizeof(*pb));

          pb->cancel_func = cancel_func;
          pb->cancel_baton = cancel_baton;
        }

      /* Two basic prompt providers: username/password, and just username. */
      nmap_update_svn_auth_get_simple_prompt_provider(&provider,
                                          svn_cmdline_auth_simple_prompt,
                                          pb,
                                          2, /* retry limit */
                                          pool);
      APR_ARRAY_PUSH(providers, svn_auth_provider_object_t *) = provider;

      svn_auth_get_username_prompt_provider
        (&provider, svn_cmdline_auth_username_prompt, pb,
         2, /* retry limit */ pool);
      APR_ARRAY_PUSH(providers, svn_auth_provider_object_t *) = provider;

      /* Three ssl prompt providers, for server-certs, client-certs,
         and client-cert-passphrases.  */
      svn_auth_get_ssl_server_trust_prompt_provider
        (&provider, svn_cmdline_auth_ssl_server_trust_prompt, pb, pool);
      APR_ARRAY_PUSH(providers, svn_auth_provider_object_t *) = provider;

      svn_auth_get_ssl_client_cert_prompt_provider
        (&provider, svn_cmdline_auth_ssl_client_cert_prompt, pb, 2, pool);
      APR_ARRAY_PUSH(providers, svn_auth_provider_object_t *) = provider;

      svn_auth_get_ssl_client_cert_pw_prompt_provider
        (&provider, svn_cmdline_auth_ssl_client_cert_pw_prompt, pb, 2, pool);
      APR_ARRAY_PUSH(providers, svn_auth_provider_object_t *) = provider;
    }

  /* Build an authentication baton to give to libsvn_client. */
  svn_auth_open(ab, providers, pool);

  /* Place any default --username or --password credentials into the
     auth_baton's run-time parameter hash. */
  if (auth_username)
    svn_auth_set_parameter(*ab, SVN_AUTH_PARAM_DEFAULT_USERNAME,
                           auth_username);
  if (auth_password)
    svn_auth_set_parameter(*ab, SVN_AUTH_PARAM_DEFAULT_PASSWORD,
                           auth_password);

  /* Same with the --non-interactive option. */
  if (non_interactive)
    svn_auth_set_parameter(*ab, SVN_AUTH_PARAM_NON_INTERACTIVE, "");

  if (config_dir)
    svn_auth_set_parameter(*ab, SVN_AUTH_PARAM_CONFIG_DIR,
                           config_dir);

  SVN_ERR(svn_config_get_bool(cfg, &store_password_val,
                              SVN_CONFIG_SECTION_AUTH,
                              SVN_CONFIG_OPTION_STORE_PASSWORDS,
                              TRUE));

  if (! store_password_val)
    svn_auth_set_parameter(*ab, SVN_AUTH_PARAM_DONT_STORE_PASSWORDS, "");

  /* There are two different ways the user can disable disk caching
     of credentials:  either via --no-auth-cache, or in the config
     file ('store-auth-creds = no'). */
  SVN_ERR(svn_config_get_bool(cfg, &store_password_val,
                              SVN_CONFIG_SECTION_AUTH,
                              SVN_CONFIG_OPTION_STORE_AUTH_CREDS,
                              TRUE));

  if (no_auth_cache || ! store_password_val)
    svn_auth_set_parameter(*ab, SVN_AUTH_PARAM_NO_AUTH_CACHE, "");

  return SVN_NO_ERROR;
}
