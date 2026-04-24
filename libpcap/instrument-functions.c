/*
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that: (1) source code
 * distributions retain the above copyright notice and this paragraph
 * in its entirety, and (2) distributions including binary code include
 * the above copyright notice and this paragraph in its entirety in
 * the documentation or other materials provided with the distribution.
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND
 * WITHOUT ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, WITHOUT
 * LIMITATION, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <bfd.h>

/*
 * Generate instrumentation calls for entry and exit to functions.
 * Just after function entry and just before function exit, the
 * following profiling functions are called with the address of the
 * current function and its call site (currently not use).
 *
 * The attribute 'no_instrument_function' causes this instrumentation is
 * not done.
 *
 * These profiling functions call print_debug(). This function prints the
 * current function name with indentation and call level.
 * If entering in a function it prints also the calling function name with
 * file name and line number.
 *
 * If the environment variable INSTRUMENT is
 * unset or set to an empty string, print nothing, like with no instrumentation
 * set to "all" or "a", print all the functions names
 * set to "global" or "g", print only the global functions names
 */

#define ND_NO_INSTRUMENT __attribute__((no_instrument_function))

/* Store the function call level, used also in pretty_print_packet() */
extern int profile_func_level;
int profile_func_level = -1;

typedef enum {
	ENTER,
	EXIT
} action_type;

void __cyg_profile_func_enter(void *this_fn, void *call_site) ND_NO_INSTRUMENT;

void __cyg_profile_func_exit(void *this_fn, void *call_site) ND_NO_INSTRUMENT;

static void print_debug(void *this_fn, void *call_site, action_type action)
	ND_NO_INSTRUMENT;

void
__cyg_profile_func_enter(void *this_fn, void *call_site)
{
	print_debug(this_fn, call_site, ENTER);
}

void
__cyg_profile_func_exit(void *this_fn, void *call_site)
{
	print_debug(this_fn, call_site, EXIT);
}

static void print_debug(void *this_fn, void *call_site, action_type action)
{
	static bfd* abfd;
	static asymbol **symtab;
	static long symcount;
	static asection *text;
	static bfd_vma vma;
	static int instrument_set;
	static int instrument_off;
	static int instrument_global;

	if (!instrument_set) {
		static char *instrument_type;

		/* Get the configuration environment variable INSTRUMENT value if any */
		instrument_type = getenv("INSTRUMENT");
		/* unset or set to an empty string ? */
		if (instrument_type == NULL ||
			!strncmp(instrument_type, "", sizeof(""))) {
			instrument_off = 1;
		} else {
			/* set to "global" or "g" ? */
			if (!strncmp(instrument_type, "global", sizeof("global")) ||
				!strncmp(instrument_type, "g", sizeof("g")))
				instrument_global = 1;
			else if (strncmp(instrument_type, "all", sizeof("all")) &&
					 strncmp(instrument_type, "a", sizeof("a"))) {
				fprintf(stderr, "INSTRUMENT can be only \"\", \"all\", \"a\", "
						"\"global\" or \"g\".\n");
				exit(1);
			}
		}
		instrument_set = 1;
	}

	if (instrument_off)
			return;

	/* If no errors, this block should be executed one time */
	if (!abfd) {
		char pgm_name[1024];
		long symsize;

		ssize_t ret = readlink("/proc/self/exe", pgm_name, sizeof(pgm_name));
		if (ret == -1) {
			perror("failed to find executable");
			return;
		}
		if (ret == sizeof(pgm_name)) {
			/* no space for the '\0' */
			printf("truncation may have occurred\n");
			return;
		}
		pgm_name[ret] = '\0';

		bfd_init();

		abfd = bfd_openr(pgm_name, NULL);
		if (!abfd) {
			bfd_perror("bfd_openr");
			return;
		}

		if (!bfd_check_format(abfd, bfd_object)) {
			bfd_perror("bfd_check_format");
			return;
		}

		if((symsize = bfd_get_symtab_upper_bound(abfd)) == -1) {
			bfd_perror("bfd_get_symtab_upper_bound");
			return;
		}

		symtab = (asymbol **)malloc((size_t)symsize);
		symcount = bfd_canonicalize_symtab(abfd, symtab);
		if (symcount < 0) {
			free(symtab);
			bfd_perror("bfd_canonicalize_symtab");
			return;
		}

		if ((text = bfd_get_section_by_name(abfd, ".text")) == NULL) {
			bfd_perror("bfd_get_section_by_name");
			return;
		}
		vma = text->vma;
	}

	if (instrument_global) {
		symbol_info syminfo;
		int found;
		long i;

		i = 0;
		found = 0;
		while (i < symcount && !found) {
			bfd_get_symbol_info(abfd, symtab[i], &syminfo);
			if ((void *)syminfo.value == this_fn) {
				found = 1;
			}
			i++;
		}
		/* type == 'T' for a global function */
		if (found == 1 && syminfo.type != 'T')
			return;
	}

	/* Current function */
	if ((bfd_vma)this_fn < vma) {
		printf("[ERROR address this_fn]");
	} else {
		const char *file;
		const char *func;
		unsigned int line;

		if (!bfd_find_nearest_line(abfd, text, symtab, (bfd_vma)this_fn - vma,
								   &file, &func, &line)) {
			printf("[ERROR bfd_find_nearest_line this_fn]");
		} else {
			int i;

			if (action == ENTER)
				profile_func_level += 1;
			/* Indentation */
			for (i = 0 ; i < profile_func_level ; i++)
				putchar(' ');
			if (action == ENTER)
				printf("[>> ");
			else
				printf("[<< ");
			/* Function name */
			if (func == NULL || *func == '\0')
				printf("???");
			else
				printf("%s", func);
			printf(" (%d)", profile_func_level);
			/* Print the "from" part except for the main function) */
			if (action == ENTER && func != NULL &&
				strncmp(func, "main", sizeof("main"))) {
				/* Calling function */
				if ((bfd_vma)call_site < vma) {
					printf("[ERROR address call_site]");
				} else {
					if (!bfd_find_nearest_line(abfd, text, symtab,
											   (bfd_vma)call_site - vma, &file,
											   &func, &line)) {
						printf("[ERROR bfd_find_nearest_line call_site]");
					} else {
						printf(" from ");
						/* Function name */
						if (func == NULL || *func == '\0')
							printf("???");
						else
							printf("%s", func);
						/* File name */
						if (file == NULL || *file == '\0')
							printf(" ??:");
						else {
							char *slashp = strrchr(file, '/');
							if (slashp != NULL)
								file = slashp + 1;
							printf(" %s:", file);
						}
						/* Line number */
						if (line == 0)
							printf("?");
						else
							printf("%u", line);
						printf("]");
					}
				}
			}
			putchar('\n');
			if (action == EXIT)
				profile_func_level -= 1;
		}
	}
	fflush(stdout);
}

/* vi: set tabstop=4 softtabstop=0 shiftwidth=4 smarttab autoindent : */
