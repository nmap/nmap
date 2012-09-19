#include <ctype.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/stat.h>

#include "nbase.h"

#ifndef WIN32
#include <dirent.h>
#include <getopt.h>
#include <pwd.h>
#include <unistd.h>
#include "config.h"
#else
#include <shlobj.h>
#include "win_config.h"
#endif

/* See the file tools/examples/minimal_client.c in the Subversion source
   directory for an example of using the svn_client API. */

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

/* From svn_auth.c. */
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
                             apr_pool_t *pool);

#include "default_channel.h"

#ifdef WIN32
#define PATHSEP "\\"
#else
#define PATHSEP "/"
#endif

static const char *DEFAULT_SVN_REPO = "https://svn.nmap.org/updates";

static const char *DEFAULT_CHANNELS[] = { DEFAULT_CHANNEL };


/* Internal error handling. */

#define NELEMS(a) (sizeof(a) / sizeof(*a))

#define internal_error(msg) \
do {\
	fprintf(stderr, "%s:%d: internal error: %s.\n", __FILE__, __LINE__, msg); \
	abort(); \
} while (0)

#define internal_assert(expr) \
do { \
	if (!(expr)) \
		internal_error("assertion failed: " #expr); \
} while (0)

static char *safe_strdup(const char *s)
{
	char *t;
	size_t len;

	len = strlen(s);
	t = safe_malloc(len + 1);
	memcpy(t, s, len);
	t[len] = '\0';

	return t;
}

static int streq(const char *a, const char *b)
{
	return strcmp(a, b) == 0;
}

static char *string_make(const char *begin, const char *end)
{
	char *s;

	s = safe_malloc(end - begin + 1);
	memcpy(s, begin, end - begin);
	s[end - begin] = '\0';

	return s;
}

static char *strbuf_append(char **buf, size_t *size, size_t *offset, const char *s, size_t n)
{
	internal_assert(*offset <= *size);

	/* Double the buffer size if necessary. */
	if (n >= *size - *offset) {
		*size = (*size + n) * 2;
		*buf = safe_realloc(*buf, *size + 1);
	}
	memcpy(*buf + *offset, s, n);
	*offset += n;
	(*buf)[*offset] = '\0';

	return *buf;
}

/* Append a '\0'-terminated string as with strbuf_append. */
static char *strbuf_append_str(char **buf, size_t *size, size_t *offset, const char *s)
{
	return strbuf_append(buf, size, offset, s, strlen(s));
}

static char *strbuf_append_char(char **buf, size_t *size, size_t *offset, char c)
{
	return strbuf_append(buf, size, offset, &c, 1);
}

static char *strbuf_trim(char **buf, size_t *size, size_t *offset)
{
	if (*offset < *size) {
		*size = *offset;
		*buf = safe_realloc(*buf, *size + 1);
	}
	internal_assert((*buf)[*size] == '\0');

	return *buf;
}

static char *string_unescape(const char *escaped)
{
	char *buf;
	size_t size, offset;
	const char *p;

	buf = NULL;
	size = 0;
	offset = 0;

	p = escaped;
	while (*p != '\0') {
		char hex[3], *tail;
		unsigned long byte;

		/* We support backslash escapes for '\\' and '"', and \xXX
		   hexadecimal only. */
		if (*p == '\\') {
			p++;
			switch (*p) {
			case '\\':
			case '"':
				strbuf_append_char(&buf, &size, &offset, *p);
				p++;
				break;
			case 'x':
				p++;
				if (!(isxdigit(*p) && isxdigit(*(p + 1))))
					goto bail;
				memcpy(hex, p, 2);
				hex[2] = '\0';

				errno = 0;
				byte = strtoul(hex, &tail, 16);
				if (errno != 0 || byte > 255 || *tail != '\0')
					goto bail;
				strbuf_append_char(&buf, &size, &offset, (char) byte);

				p += 2;
				break;
			default:
				goto bail;
				break;
			}
		} else {
			strbuf_append_char(&buf, &size, &offset, *p);
			p++;
		}
	}

	return strbuf_trim(&buf, &size, &offset);

bail:
	if (buf != NULL)
		free(buf);

	return NULL;
}

/* Return a newly allocated string that is the concatenation of all the va_list
   args, separated by join:
     str1 JOIN str2 JOIN str3 ...
   The final argument must be NULL. */
static char *strs_vjoin(const char *join, const char *first, va_list ap)
{
	char *buf;
	size_t size, offset;
	const char *p;

	internal_assert(first != NULL);

	buf = NULL;
	size = 0;
	offset = 0;

	strbuf_append_str(&buf, &size, &offset, first);

	while ((p = va_arg(ap, const char *)) != NULL) {
		strbuf_append_str(&buf, &size, &offset, join);
		strbuf_append_str(&buf, &size, &offset, p);
	}

	strbuf_trim(&buf, &size, &offset);

	return buf;
}

static char *strs_cat(const char *first, ...)
{
	va_list ap;
	char *result;

	va_start(ap, first);
	result = strs_vjoin("", first, ap);
	va_end(ap);

	return result;
}

static char *path_join(const char *first, ...)
{
	va_list ap;
	char *result;

	va_start(ap, first);
	result = strs_vjoin(PATHSEP, first, ap);
	va_end(ap);

	return result;
}

#ifdef WIN32
static char *get_user_dir(const char *subdir) {
	char appdata[MAX_PATH];

	if (SHGetFolderPath(NULL, CSIDL_APPDATA, NULL, SHGFP_TYPE_CURRENT, appdata) != S_OK)
		return NULL;

	return path_join(appdata, "nmap", subdir, NULL);
}
#else
static char *get_user_dir(const char *subdir) {
	static struct passwd *pw;

	errno = 0;
	pw = getpwuid(getuid());
	if (pw == NULL)
		return NULL;

	return path_join(pw->pw_dir, ".nmap", subdir, NULL);
}
#endif

static char *get_install_dir(void) {
	return get_user_dir("updates");
}

static char *get_staging_dir(void) {
	return get_user_dir("updates-staging");
}

static char *get_conf_filename(void) {
	return get_user_dir("nmap-update.conf");
}


/* Configuration file parsing. */

enum token_type {
	TOKEN_ERROR,
	TOKEN_EOL,
	TOKEN_EOF,
	TOKEN_WORD,
	TOKEN_EQUALS,
	TOKEN_STRING,
};

struct config_parser {
	FILE *fp;
	unsigned long lineno;
};

struct config_entry {
	char *key;
	char *value;
};

static void config_entry_free(struct config_entry *entry)
{
	free(entry->key);
	free(entry->value);
}

static int config_parser_open(const char *filename, struct config_parser *cp)
{
	cp->fp = fopen(filename, "r");
	if (cp->fp == NULL)
		return -1;
	cp->lineno = 1;

	return 0;
}

static int config_parser_close(struct config_parser *cp)
{
	int ret;

	ret = fclose(cp->fp);
	if (ret == EOF)
		return -1;

	return 0;
}

static int is_word_char(int c)
{
	return c != EOF && !isspace(c) && c != '"' && c != '#';
}

static char *read_quoted_string(struct config_parser *cp)
{
	char *buf, *unescaped;
	size_t size, offset;
	int c;

	buf = NULL;
	size = 0;
	offset = 0;

	for (;;) {
		errno = 0;
		c = fgetc(cp->fp);
		if (c == EOF)
			/* EOF in the middle of a string is always an error. */
			return NULL;
		if (c == '\n')
			return NULL;
		if (c == '"')
			break;
		if (c == '\\') {
			strbuf_append_char(&buf, &size, &offset, c);
			errno = 0;
			c = fgetc(cp->fp);
			if (c == EOF)
				return NULL;
		}
		strbuf_append_char(&buf, &size, &offset, c);
	}

	unescaped = string_unescape(buf);
	free(buf);

	return unescaped;
}

static enum token_type config_parser_read_token(struct config_parser *cp,
	char **token)
{
	size_t size, offset;
	unsigned long prev_lineno;
	int c;

	*token = NULL;
	size = 0;
	offset = 0;

	/* Skip comments and blank space. */
	prev_lineno = cp->lineno;
	do {
		errno = 0;
		while (isspace(c = fgetc(cp->fp))) {
			if (c == '\n')
				cp->lineno++;
		}
		if (c == EOF) {
			if (errno != 0)
				goto bail;
			*token = NULL;
			return TOKEN_EOF;
		}
		if (c == '#') {
			while ((c = fgetc(cp->fp)) != EOF && c != '\n')
				;
			if (c == EOF) {
				if (errno != 0)
					goto bail;
				*token = NULL;
				return TOKEN_EOF;
			} else if (c == '\n') {
				cp->lineno++;
			}
		}
	} while (isspace(c) || c == '#');

	/* Collapse multiple consecutive line endings. */
	if (cp->lineno != prev_lineno) {
		ungetc(c, cp->fp);
		*token = NULL;
		return TOKEN_EOL;
	}

	if (c == '=') {
		strbuf_append_char(token, &size, &offset, c);
		return TOKEN_EQUALS;
	} else if (is_word_char(c)) {
		while (is_word_char(c)) {
			strbuf_append_char(token, &size, &offset, c);
			errno = 0;
			c = fgetc(cp->fp);
			if (c == EOF && errno != 0)
				goto bail;
		}
		return TOKEN_WORD;
	} else if (c == '"') {
		char *qs;

		qs = read_quoted_string(cp);
		if (qs == NULL)
			goto bail;
		*token = safe_strdup(qs);
		return TOKEN_STRING;
	} else {
		goto bail;
	}

bail:
	if (*token != NULL)
		free(*token);
	*token = NULL;

	return TOKEN_ERROR;
}

static int config_parser_next(struct config_parser *cp, struct config_entry *entry)
{
	char *token;
	enum token_type type;

	while ((type = config_parser_read_token(cp, &token)) == TOKEN_EOL)
		;
	if (type == TOKEN_EOF) {
		free(token);
		return 0;
	}
	if (type != TOKEN_WORD) {
		free(token);
		return -1;
	}
	entry->key = token;

	type = config_parser_read_token(cp, &token);
	if (type != TOKEN_EQUALS) {
		free(token);
		return -1;
	}
	free(token);

	type = config_parser_read_token(cp, &token);
	if (!(type == TOKEN_WORD || type == TOKEN_STRING)) {
		free(token);
		return -1;
	}
	entry->value = token;

	return 1;
}


/* Global state. */

static char *program_name;
static struct {
	int verbose;
	const char *install_dir;
	const char *staging_dir;
	const char *conf_filename;
	const char **channels;
	unsigned int num_channels;
	char *svn_repo;
	char *username;
	char *password;
} options;

struct metadata {
	int is_expired;
	time_t expiry_date;
};

static void metadata_init(struct metadata *metadata)
{
	metadata->is_expired = 0;
	metadata->expiry_date = 0;
}

static void init_options(void)
{
	options.verbose = 0;
	options.install_dir = get_install_dir();
	if (options.install_dir == NULL) {
		fprintf(stderr, "Could not find an install directory: %s.\n",
			strerror(errno));
		exit(1);
	}
	options.staging_dir = get_staging_dir();
	if (options.staging_dir == NULL) {
		fprintf(stderr, "Could not find a staging directory: %s.\n",
			strerror(errno));
		exit(1);
	}
	options.conf_filename = get_conf_filename();
	if (options.conf_filename == NULL) {
		fprintf(stderr, "Could not find the configuration file: %s.\n",
			strerror(errno));
		exit(1);
	}
	options.channels = DEFAULT_CHANNELS;
	options.num_channels = NELEMS(DEFAULT_CHANNELS);

	options.svn_repo = NULL;
	options.username = NULL;
	options.password = NULL;
}

static int read_config_file(const char *conf_filename)
{
	struct config_parser cp;
	struct config_entry entry;
	int ret;

	if (options.verbose)
		printf("Trying to open configuration file %s.\n", conf_filename);

	errno = 0;
	if (config_parser_open(conf_filename, &cp) == -1) {
		if (options.verbose)
			printf("Failed to open %s: %s.\n", conf_filename, strerror(errno));
		return -1;
	}

	while ((ret = config_parser_next(&cp, &entry)) > 0) {
		if (streq(entry.key, "username")) {
			if (options.username != NULL) {
				fprintf(stderr, "Warning: %s:%lu: duplicate \"%s\".\n",
					conf_filename, cp.lineno, entry.key);
				free(options.username);
			}
			options.username = safe_strdup(entry.value);
		} else if (streq(entry.key, "password")) {
			if (options.password != NULL) {
				fprintf(stderr, "Warning: %s:%lu: duplicate \"%s\".\n",
					conf_filename, cp.lineno, entry.key);
				free(options.password);
			}
			options.password = safe_strdup(entry.value);
		} else if (streq(entry.key, "repo")) {
			if (options.svn_repo != NULL) {
				fprintf(stderr, "Warning: %s:%lu: duplicate \"%s\".\n",
					conf_filename, cp.lineno, entry.key);
				free(options.svn_repo);
			}
			options.svn_repo = safe_strdup(entry.value);
		} else {
			fprintf(stderr, "Warning: %s:%lu: unknown key \"%s\".\n",
				conf_filename, cp.lineno, entry.key);
		}

		config_entry_free(&entry);
	}
	if (ret == -1) {
		fprintf(stderr, "Parse error on line %lu of %s.\n",
			cp.lineno, conf_filename);
		exit(1);
	}

	errno = 0;
	if (config_parser_close(&cp) == -1) {
		if (options.verbose)
			printf("Failed to close %s: %s.\n", conf_filename, strerror(errno));
		return -1;
	}

	return 0;
}

static int parse_date(const char *s, time_t *t)
{
	struct tm tm = {0};

	if (sscanf(s, "%d-%d-%d", &tm.tm_year, &tm.tm_mon, &tm.tm_mday) != 3)
		return -1;
	tm.tm_year -= 1900;
	tm.tm_mon -= 1;
	*t = mktime(&tm);
	if (*t == -1)
		return -1;

	return 0;
}

static int date_is_after(time_t t, time_t now)
{
	return difftime(t, now) > 0;
}

static int read_metadata_file(const char *metadata_filename, struct metadata *metadata)
{
	struct config_parser cp;
	struct config_entry entry;
	int ret;

	errno = 0;
	if (config_parser_open(metadata_filename, &cp) == -1) {
		/* A missing file is not an error for metadata. */
		return 0;
	}

	while ((ret = config_parser_next(&cp, &entry)) > 0) {
		if (streq(entry.key, "expired")) {
			if (parse_date(entry.value, &metadata->expiry_date) == -1) {
				fprintf(stderr, "Warning: %s:%lu: can't parse date \"%s\".\n",
					metadata_filename, cp.lineno, entry.value);
			} else {
				if (date_is_after(time(NULL), metadata->expiry_date))
					metadata->is_expired = 1;
			}
		} else {
			fprintf(stderr, "Warning: %s:%lu: unknown key \"%s\".\n",
				metadata_filename, cp.lineno, entry.key);
		}

		config_entry_free(&entry);
	}
	if (ret == -1) {
		fprintf(stderr, "Parse error on line %lu of %s.\n",
			cp.lineno, metadata_filename);
		config_parser_close(&cp);
		return -1;
	}

	errno = 0;
	if (config_parser_close(&cp) == -1) {
		if (options.verbose)
			printf("Failed to close %s: %s.\n", metadata_filename, strerror(errno));
		return -1;
	}

	return 0;
}


static void usage(FILE *fp)
{
	char *install_dir;

	internal_assert(program_name != NULL);
	install_dir = get_install_dir();
	fprintf(fp, "\
Usage: %s [-d INSTALL_DIR] [CHANNEL...]\n\
Updates system-independent Nmap files. By default the new files are installed to\n\
%s. Each CHANNEL is a version number like \"" DEFAULT_CHANNEL "\".\n\
\n\
  -d DIR               install files to DIR (default %s).\n\
  -h, --help           show this help.\n\
  -r, --repo REPO      use REPO as SVN repository and path (default %s).\n\
  -v, --verbose        be more verbose.\n\
  --username USERNAME  use this username.\n\
  --password PASSWORE  use this password.\n\
", program_name, install_dir, install_dir, DEFAULT_SVN_REPO);
	free(install_dir);
}

static void usage_error(void)
{
	usage(stderr);
	exit(1);
}


static const char *try_channels(const char *channels[], unsigned int num_channels);
static int stage_and_install(const char *channel);
static int stage_channel(const char *channel, const char *staging_dir);
static int install(const char *staging_dir, const char *install_dir);
static int channel_is_expired(const char *channel, time_t *expiry_date);

static void summarize_options(void)
{
	unsigned int i;

	printf("Installing to directory: %s.\n", options.install_dir);
	printf("Using staging directory: %s.\n", options.staging_dir);

	printf("Using channels:");
	for (i = 0; i < options.num_channels; i++)
		printf(" %s", options.channels[i]);
	printf(".\n");
}

const struct option LONG_OPTIONS[] = {
	{ "help", no_argument, NULL, 'h' },
	{ "repo", required_argument, NULL, 'r' },
	{ "verbose", required_argument, NULL, 'v' },
	{ "username", required_argument, NULL, '?' },
	{ "password", required_argument, NULL, '?' },
};

int main(int argc, char *argv[])
{
	int opt, longoptidx;
	const char *successful_channel;
	const char *username, *password, *svn_repo;
	time_t expiry_date;

	internal_assert(argc > 0);
	program_name = argv[0];

	init_options();

	if (svn_cmdline_init(program_name, stderr) != 0)
		internal_error("svn_cmdline_init");

	username = NULL;
	password = NULL;
	svn_repo = NULL;

	while ((opt = getopt_long(argc, argv, "d:hr:v", LONG_OPTIONS, &longoptidx)) != -1) {
		if (opt == 'd') {
			options.install_dir = optarg;
		} else if (opt == 'h') {
			usage(stdout);
			exit(0);
		} else if (opt == 'r') {
			svn_repo = optarg;
		} else if (opt == 'v') {
			options.verbose = 1;
		} else if (opt == '?' && streq(LONG_OPTIONS[longoptidx].name, "username")) {
			username = optarg;
		} else if (opt == '?' && streq(LONG_OPTIONS[longoptidx].name, "password")) {
			password = optarg;
		} else {
			usage_error();
		}
	}

	/* User-specified channels. */
	if (optind < argc) {
		options.channels = (const char **) argv + optind;
		options.num_channels = argc - optind;
	}
	internal_assert(options.channels != NULL);
	internal_assert(options.num_channels > 0);

	if (options.verbose)
		summarize_options();

	read_config_file(options.conf_filename);

	/* Default options. */
	if (options.svn_repo == NULL)
		options.svn_repo = safe_strdup(DEFAULT_SVN_REPO);

	/* Possibly override configuration file. */
	if (username != NULL) {
		free(options.username);
		options.username = safe_strdup(username);
	}
	if (password != NULL) {
		free(options.password);
		options.password = safe_strdup(password);
	}
	if (svn_repo != NULL) {
		free(options.svn_repo);
		options.svn_repo = safe_strdup(svn_repo);
	}

	successful_channel = try_channels(options.channels, options.num_channels);

	if (successful_channel != NULL && channel_is_expired(successful_channel, &expiry_date)) {
		fprintf(stderr, "\
\n\
UPDATE CHANNEL %s HAS EXPIRED:\n\
\n\
The channel %s has expired and won't receive any more\n\
updates.  Visit http://nmap.org for a newer Nmap release with \n\
supported updates.\n\
", successful_channel, successful_channel);
	}

	if (successful_channel == NULL && options.username == NULL) {
		fprintf(stderr, "\
\n\
Could not stage any channels and don't have authentication credentials.\n\
\n\
Edit the file %s and enter your username and password. For example:\n\
  username = user\n\
  password = secret\n\
", options.conf_filename);
	}

	if (successful_channel != NULL)
		return 0;
	else
		return 1;
}


static const char *try_channels(const char *channels[], unsigned int num_channels)
{
	unsigned int i;

	for (i = 0; i < num_channels; i++) {
		if (stage_and_install(channels[i]) == 0)
			return channels[i];
	}

	return NULL;
}


static void fatal_err_svn(svn_error_t *err)
{
	svn_handle_error2(err, stderr, TRUE, "nmap-update: ");
}

static svn_error_t *checkout_svn(const char *url, const char *path)
{
	svn_error_t *err;
	apr_pool_t *pool;
	svn_opt_revision_t peg_revision, revision;
	svn_client_ctx_t *ctx;
	svn_revnum_t revnum;
	svn_config_t *cfg;

	peg_revision.kind = svn_opt_revision_unspecified;
	revision.kind = svn_opt_revision_head;

	pool = svn_pool_create(NULL);

	err = svn_client_create_context(&ctx, pool);
	if (err != NULL)
		fatal_err_svn(err);

	/* The creation of this directory is needed to cache credentials. */
	err = svn_config_ensure(NULL, pool);
	if (err != NULL)
		fatal_err_svn(err);

	err = svn_config_get_config(&ctx->config, NULL, pool);
	if (err != NULL)
		fatal_err_svn(err);
	cfg = apr_hash_get(ctx->config, SVN_CONFIG_CATEGORY_CONFIG,
		APR_HASH_KEY_STRING);
	svn_config_set_bool(cfg, SVN_CONFIG_SECTION_GLOBAL,
		SVN_CONFIG_OPTION_SSL_TRUST_DEFAULT_CA, TRUE);
	nmap_update_svn_cmdline_setup_auth_baton(&ctx->auth_baton,
		FALSE, /* non_interactive */
		options.username, /* username */
		options.password, /* password */
		NULL, /* config_dir */
		FALSE, /* no_auth_cache */
		cfg, /* cfg */
		NULL, /* cancel_func */
		NULL, /* cancel_baton */
		pool);

	err = svn_client_checkout2(&revnum, url, path,
		&peg_revision, &revision,
		TRUE, /* recurse */
		TRUE, /* ignore_externals */
		ctx, pool);
	svn_pool_destroy(pool);
	if (err != NULL)
		return err;

	printf("Checked out r%lu\n", (unsigned long) revnum);

	return SVN_NO_ERROR;
}

static int stage_and_install(const char *channel)
{
	char *staging_dir, *install_dir;
	int rc;

	internal_assert(options.staging_dir != NULL);

	staging_dir = path_join(options.staging_dir, channel, NULL);
	rc = stage_channel(channel, staging_dir);
	if (rc == -1) {
		free(staging_dir);
		return -1;
	}

	install_dir = path_join(options.install_dir, channel, NULL);
	rc = install(staging_dir, install_dir);

	free(staging_dir);
	free(install_dir);

	return rc;
}

static int stage_channel(const char *channel, const char *staging_dir)
{
	char *svn_url;
	svn_error_t *err;
	int rc;

	rc = 0;

	svn_url = strs_cat(options.svn_repo, "/", channel, NULL);

	if (options.verbose)
		printf("Checking out %s to %s.\n", svn_url, staging_dir);

	printf("\
\n\
The Nmap Updater is currently only available to a small set of users\n\
for testing purposes. We hope to expand it in the future.\n\
\n\
");

	err = checkout_svn(svn_url, staging_dir);
	if (err != NULL) {
		svn_handle_error2(err, stderr, FALSE, "nmap-update: ");
		fprintf(stderr, "Error checking out %s.\n", svn_url);
		rc = -1;
	}

	free(svn_url);

	return rc;
}

static int channel_is_expired(const char *channel, time_t *expiry_date)
{
	char *metadata_filename;
	struct metadata metadata;
	int rc;

	metadata_init(&metadata);

	metadata_filename = path_join(options.staging_dir, channel, "metadata.conf", NULL);
	rc = read_metadata_file(metadata_filename, &metadata);
	if (rc == -1) {
		fprintf(stderr, "Can't read metadata file %s.\n", metadata_filename);
		free(metadata_filename);
		exit(1);
	}
	free(metadata_filename);

	*expiry_date = metadata.expiry_date;

	return metadata.is_expired;
}

static int copy_tree(const char *from_dirname, const char *to_dirname);
static int rename_file(const char *from_filename, const char *to_filename);

static int install(const char *staging_dir, const char *install_dir)
{
	if (options.verbose)
		printf("Installing from %s to %s.\n", staging_dir, install_dir);

	return copy_tree(staging_dir, install_dir);
}

static int copy_file(const char *from_filename, const char *to_filename)
{
	char buf[BUFSIZ];
	char *tmp_filename;
	FILE *from_fd, *tmp_fd;
	int rc, from_rc, tmp_rc;
	size_t nr, nw;

	tmp_filename = NULL;
	from_fd = NULL;
	tmp_fd = NULL;

	errno = 0;
	from_fd = fopen(from_filename, "rb");
	if (from_fd == NULL) {
		fprintf(stderr, "Can't open %s: %s.\n", from_filename, strerror(errno));
		goto bail;
	}

	tmp_filename = strs_cat(to_filename, "-tmp", NULL);
	errno = 0;
	tmp_fd = fopen(tmp_filename, "wb");
	if (tmp_fd == NULL) {
		fprintf(stderr, "Can't open %s: %s.\n", tmp_filename, strerror(errno));
		goto bail;
	}

	errno = 0;
	while ((nr = fread(buf, 1, sizeof(buf), from_fd)) != 0) {
		errno = 0;
		nw = fwrite(buf, 1, nr, tmp_fd);
		if (nw != nr || errno != 0) {
			printf("%lu %lu\n", nw, nr);
			fprintf(stderr, "Error writing to %s: %s.\n", tmp_filename, strerror(errno));
			goto bail;
		}
	}
	if (errno != 0) {
		fprintf(stderr, "Error reading from %s: %s.\n", from_filename, strerror(errno));
		goto bail;
	}

	from_rc = fclose(from_fd);
	from_fd = NULL;
	if (from_rc == -1) {
		fprintf(stderr, "Can't close %s: %s.\n", from_filename, strerror(errno));
		goto bail;
	}
	tmp_rc = fclose(tmp_fd);
	tmp_fd = NULL;
	if (tmp_rc == -1) {
		fprintf(stderr, "Can't close %s: %s.\n", to_filename, strerror(errno));
		goto bail;
	}

	rc = rename_file(tmp_filename, to_filename);
	if (rc == -1) {
		fprintf(stderr, "Can't rename %s to %s: %s.\n",
			tmp_filename, to_filename, strerror(errno));
		goto bail;
	}

	free(tmp_filename);
	tmp_filename = NULL;

	return 0;

bail:
	if (from_fd != NULL)
		fclose(from_fd);
	if (tmp_fd != NULL)
		fclose(tmp_fd);
	if (tmp_filename != NULL)
		free(tmp_filename);

	return -1;
}

static int is_pathsep(int c)
{
#ifdef WIN32
	return c == '/' || c == '\\';
#else
	return c == '/';
#endif
}

static char *parent_dir(const char *path)
{
	const char *p;

	p = path + strlen(path) - 1;
	while (p > path && is_pathsep(*p))
		p--;
	while (p > path && !is_pathsep(*p))
		p--;
	while (p > path && is_pathsep(*p))
		p--;

	if (p == path)
		return safe_strdup("/");

	return string_make(path, p + 1);
}

#ifdef WIN32
static int rename_file(const char *from_filename, const char *to_filename)
{
	int rc;

	/* Windows rename doesn't remove the destination if it exists. */
	errno = 0;
	rc = unlink(to_filename);
	if (rc == -1 && errno != ENOENT)
		return -1;

	return rename(from_filename, to_filename);
}

static int makedir(const char *dirname)
{
	return CreateDirectory(dirname, NULL) != 0 ? 0 : -1;
}

static int makedirs(const char *dirname)
{
	char *parent;
	int rc;

	rc = makedir(dirname);
	if (rc == 0 || GetLastError() == ERROR_ALREADY_EXISTS)
		return 0;

	if (GetLastError() != ERROR_PATH_NOT_FOUND)
		return -1;

	parent = parent_dir(dirname);
	rc = makedirs(parent);
	free(parent);
	if (rc == -1)
		return -1;

	rc = makedir(dirname);
	if (rc == -1)
		return -1;

	return rc;
}

static int copy_tree(const char *from_dirname, const char *to_dirname)
{
	WIN32_FIND_DATA ffd;
	HANDLE find_handle;
	DWORD dwError;
	char *from_pattern;
	int rc;

	rc = makedirs(to_dirname);
	if (rc == -1) {
		fprintf(stderr, "Can't create the directory %s: %s.\n",
			to_dirname, strerror(errno));
		return -1;
	}

	from_pattern = path_join(from_dirname, "*", NULL);
	find_handle = FindFirstFile(from_pattern, &ffd);
	free(from_pattern);
	if (find_handle == INVALID_HANDLE_VALUE) {
		fprintf(stderr, "Can't open the directory %s.\n", from_dirname);
		return -1;
	}

	do {
		char *from_path, *to_path;
		int error;

		from_path = path_join(from_dirname, ffd.cFileName, NULL);
		to_path = path_join(to_dirname, ffd.cFileName, NULL);

		error = 0;
		if (ffd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
			if (streq(ffd.cFileName, ".") || streq(ffd.cFileName, ".."))
				continue;
			if (streq(ffd.cFileName, ".svn"))
				continue;
			rc = makedirs(to_path);
			if (rc == 0) {
				rc = copy_tree(from_path, to_path);
				if (rc == -1)
					error = 1;
			} else {
				error = 1;
			}
		} else {
			rc = copy_file(from_path, to_path);
			if (rc == -1)
				error = 1;
		}

		free(from_path);
		free(to_path);

		if (error)
			goto bail;
	} while (FindNextFile(find_handle, &ffd) != 0);
	dwError = GetLastError();
	if (dwError != ERROR_NO_MORE_FILES) {
		fprintf(stderr, "Error in FindFirstFile/FindNextFile.\n");
		goto bail;
	}

	FindClose(find_handle);

	return 0;

bail:
	FindClose(find_handle);

	return -1;
}
#else
static int rename_file(const char *from_filename, const char *to_filename)
{
	return rename(from_filename, to_filename);
}

static int makedir(const char *dirname)
{
	return mkdir(dirname, S_IRUSR | S_IWUSR | S_IXUSR | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH);
}

static int makedirs(const char *dirname)
{
	char *parent;
	int rc;

	rc = makedir(dirname);
	if (rc == 0 || errno == EEXIST)
		return 0;

	if (errno != ENOENT)
		return -1;

	parent = parent_dir(dirname);
	rc = makedirs(parent);
	free(parent);
	if (rc == -1)
		return -1;

	rc = makedir(dirname);
	if (rc == -1)
		return -1;

	return rc;
}

static int copy_tree(const char *from_dirname, const char *to_dirname)
{
	DIR *dir;
	const struct dirent *ent;
	int rc;

	rc = makedirs(to_dirname);
	if (rc == -1) {
		fprintf(stderr, "Can't create the directory %s: %s.\n",
			to_dirname, strerror(errno));
		return -1;
	}

	dir = opendir(from_dirname);
	if (dir == NULL) {
		fprintf(stderr, "Can't open the directory %s: %s.\n",
			from_dirname, strerror(errno));
		return -1;
	}

	errno = 0;
	while ((ent = readdir(dir)) != NULL) {
		char *from_path, *to_path;
		int error;

		from_path = path_join(from_dirname, ent->d_name, NULL);
		to_path = path_join(to_dirname, ent->d_name, NULL);

		error = 0;
		if (ent->d_type == DT_DIR) {
			if (streq(ent->d_name, ".") || streq(ent->d_name, ".."))
				continue;
			if (streq(ent->d_name, ".svn"))
				continue;
			rc = makedirs(to_path);
			if (rc == 0) {
				rc = copy_tree(from_path, to_path);
				if (rc == -1)
					error = 1;
			} else {
				error = 1;
			}
		} else if (ent->d_type == DT_REG) {
			rc = copy_file(from_path, to_path);
			if (rc == -1)
				error = 1;
		} else {
			fprintf(stderr, "Warning: unknown file type %u of %s.\n",
				ent->d_type, ent->d_name);
		}

		free(from_path);
		free(to_path);

		if (error)
			goto bail;
	}
	if (errno != 0) {
		fprintf(stderr, "Error in readdir: %s.\n", strerror(errno));
		goto bail;
	}

	rc = closedir(dir);
	if (rc == -1) {
		fprintf(stderr, "Can't close the directory %s: %s.\n",
			from_dirname, strerror(errno));
		return -1;
	}

	return 0;

bail:
	closedir(dir);

	return -1;
}
#endif
