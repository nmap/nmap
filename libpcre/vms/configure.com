$! Configure procedure 
$! (c) Alexey Chupahin  11-APR-2024
$! alexey@vaxman.de, alexey_chupahin@mail.ru
$!
$!
$ SET NOON
$SET NOVER
$WRITE SYS$OUTPUT " "
$WRITE SYS$OUTPUT "Configuring PCRE2 library for OpenVMS  "
$WRITE SYS$OUTPUT "(c) Alexey Chupahin   CHAPG"
$WRITE SYS$OUTPUT " "
$! Checking architecture
$DECC = F$SEARCH("SYS$SYSTEM:DECC$COMPILER.EXE") .NES. ""
$    IF F$GETSYI("ARCH_TYPE").EQ.1 THEN CPU = "VAX"
$    IF F$GETSYI("ARCH_TYPE").EQ.2 THEN CPU = "Alpha"
$    IF F$GETSYI("ARCH_TYPE").EQ.3 THEN CPU = "I64"
$    IF F$GETSYI("ARCH_TYPE").EQ.4 THEN CPU = "x86"
$WRITE SYS$OUTPUT "Checking architecture 	...  ", CPU
$IF ( (CPU.EQS."Alpha").OR.(CPU.EQS."I64").OR(CPU.EQS."x86") )
$  THEN
$       SHARED=64
$  ELSE
$       SHARED=32
$ENDIF
$!
$IF (DECC) THEN $WRITE SYS$OUTPUT  "Compiler		...  DEC C"
$IF (.NOT. DECC) THEN $WRITE SYS$OUTPUT  "BAD compiler" GOTO EXIT
$MMS = F$SEARCH("SYS$SYSTEM:MMS.EXE") .NES. ""
$MMK = F$TYPE(MMK) 
$IF (MMS .OR. MMK.NES."") THEN GOTO TEST_LIBRARIES
$! I cant find any make tool
$ WRITE SYS$OUTPUT "Install MMS or MMK"
$GOTO EXIT
$!PERL = F$TYPE(MMK) 
$!IF (PERL.NES."") THEN GOTO TEST_LIBRARIES
$!WRITE SYS$OUTPUT "Install PERL"
$!GOTO EXIT
$!
$!
$! Is it package root directory? If no, go to [-]
$ IF (F$SEARCH("[]VMS.DIR").EQS."") .AND. (F$SEARCH("[]vms.dir").EQS."")
$  THEN
$       SET DEF [-]
$ ENDIF
$!
$TEST_LIBRARIES:
$!   Setting as MAKE utility one of MMS or MMK. I prefer MMS.
$IF (MMK.NES."") THEN MAKE="MMK"
$IF (MMS) THEN MAKE="MMS"
$WRITE SYS$OUTPUT "Checking build utility	...  ''MAKE'"
$!WRITE SYS$OUTPUT "Checking PERL		...  found"
$WRITE SYS$OUTPUT " "
$!
$!
$! Check files and ODS-2. unzip makes files FILE.H.GENERIC like FILE_H.GENERIC.  Should rename to FILE.H_GENERIC
$IF F$SEARCH("[.SRC]PCRE2_H.GENERIC") .NES. ""
$ THEN
$	REN [.SRC]PCRE2_H.GENERIC [.SRC]PCRE2.H_GENERIC
$ ELSE
$	IF F$SEARCH("[.SRC]PCRE2.H_GENERIC") .EQS. ""
$	 THEN
$		WRITE SYS$OUTPUT "Not ODS-2 volume, or PCRE2_H.GENERIC not found"
$		EXIT
$	ENDIF
$ENDIF
$IF F$SEARCH("[.SRC]PCRE2_CHARTABLES_C.DIST") .NES. ""
$ THEN
$	REN [.SRC]PCRE2_CHARTABLES_C.DIST [.SRC]PCRE2_CHARTABLES.C_DIST
$ ELSE
$	IF F$SEARCH("[.SRC]PCRE2_CHARTABLES.C_DIST") .EQS. ""
$	 THEN
$		WRITE SYS$OUTPUT "Not ODS-2 volume, or PCRE2_CHARTABLES_C.DIST not found"
$		EXIT
$	ENDIF
$ENDIF
$WRITE SYS$OUTPUT "Source Files OK"
$!
$!
$I18 = F$SEARCH("SYS$I18N_ICONV:ISO8859-1_UTF-8.ICONV") .NES. ""
$IF (I18)
$  THEN
$	WRITE SYS$OUTPUT "Found I18 extension ICONV codes"
$!"Checking for iconv    "
$ DEFINE SYS$ERROR _NLA0:
$ DEFINE SYS$OUTPUT _NLA0:
$ CC/OBJECT=TEST.OBJ SYS$INPUT
#include <stdio.h>
#include <iconv.h>
#include <errno.h>
#include  <stdlib.h>

int main ()
{
    /*                                                                   */
    /* Declare variables to be used                                      */
    /*                                                                   */
    char fromcodeset[30];
    char tocodeset[30];
    int  iconv_opened;
    iconv_t iconv_struct;                   /* Iconv descriptor      */

    /*                                                                   */
    /* Initialize variables                                              */
    /*                                                                   */
    sprintf(fromcodeset,"UTF-8");
    sprintf(tocodeset,"ISO8859-1");
    iconv_opened = FALSE;

    /*                                                                   */
    /* Attempt to create a conversion descriptor for the codesets        */
    /* specified. If the return value from iconv_open is -1 then         */
    /* an error has occurred. Check value of errno.                      */
    /*                                                                   */
    if ((iconv_struct = iconv_open (tocodeset, fromcodeset)) == (iconv_t)-1)
    {
        /*                                                               */
        /* Check the value of errno                                      */
        /*                                                               */
        switch (errno)
        {
        case EMFILE:
        case ENFILE:
          printf("Too many iconv conversion files open\n");
          exit(2);
          break;

        case ENOMEM:
          printf("Not enough memory\n");
          printf("Checking iconv .....  no\n");
          exit(2);
	  break;

        case EINVAL:
          printf("Unsupported conversion\n");
	  exit(2);
          break;

        default:
          printf("Unexpected error from iconv_open\n");
	  exit(2);
          break;
        }
    }
    else
        /*                                                               */
 /* Successfully allocated a conversion descriptor   */
 /*         */
 iconv_opened = TRUE;

    /*                                                                   */
    /*  Was a conversion descriptor allocated                            */
    /*                                                                   */
    if (iconv_opened)
    {
        /*                                                               */
        /* Attempt to deallocate the conversion descriptor. If           */
        /* iconv_close returns -1 then an error has occurred.            */
        /*                                                               */
        if (iconv_close (iconv_struct) == -1)
        {
            /*                                                           */
            /* An error occurred. Check the value of errno               */
            /*                                                           */
            switch (errno)
            {
            case EBADF:
                printf("Conversion descriptor is invalid\n");
                exit(2);
		break;
            default:
                break;
            }
        }
        else
            printf("Checking iconv .....  yes\n");
    }
    return(1);
}
$!
$TMP = $STATUS
$DEASS SYS$ERROR
$DEAS  SYS$OUTPUT
$!WRITE SYS$OUTPUT TMP
$IF (TMP .NE. %X10B90001)
$  THEN
$       HAVE_ICONV=0
$       GOTO NEXT0
$ENDIF
$DEFINE SYS$ERROR _NLA0:
$DEFINE SYS$OUTPUT _NLA0:
$LINK/EXE=TEST TEST
$TMP = $STATUS
$DEAS  SYS$ERROR
$DEAS  SYS$OUTPUT
$!WRITE SYS$OUTPUT TMP
$IF (TMP .NE. %X10000001)
$  THEN
$       HAVE_ICONV=0
$       GOTO NEXT0
$  ELSE
$       HAVE_ICONV=1
$ENDIF
$NEXT0:
$IF (HAVE_ICONV.EQ.1)
$  THEN
$       WRITE SYS$OUTPUT "Checking for iconv ...   Yes"
$  ELSE
$       WRITE SYS$OUTPUT "Checking for iconv ...   No"
$ENDIF
$!
$!
$! Checking for BZIP2 library
$!
$ DEFINE SYS$ERROR _NLA0:
$ DEFINE SYS$OUTPUT _NLA0:
$ CC/OBJECT=TEST.OBJ/INCLUDE=(BZ2LIB) SYS$INPUT
      #include <stdlib.h>
      #include <stdio.h>
      #include <bzlib.h>
   int main()
     {
        printf("checking version bzip2 library:  %s\n",BZ2_bzlibVersion());
     }
$TMP = $STATUS
$DEASS SYS$ERROR
$DEAS  SYS$OUTPUT
$!WRITE SYS$OUTPUT TMP
$IF (TMP .NE. %X10B90001)
$  THEN
$       HAVE_BZIP2=0
$       GOTO ERR0
$ENDIF
$DEFINE SYS$ERROR _NLA0:
$DEFINE SYS$OUTPUT _NLA0:
$!Testing for CHAPG BZIP2
$!
$LINK/EXE=TEST TEST,BZ2LIB:BZIP2/OPT
$TMP = $STATUS
$DEAS SYS$ERROR
$DEAS SYS$OUTPUT
$IF (TMP .NE. %X10000001)
$  THEN
$       HAVE_BZIP2=0
$       GOTO ERR0
$  ELSE
$       HAVE_BZIP2=1
$ENDIF
$ERR0:
$IF (HAVE_BZIP2.EQ.1)
$  THEN
$       WRITE SYS$OUTPUT "Checking for CHAPG bzip2 library ...   Yes"
$       RUN TEST
$       GOTO NEXT4
$  ELSE
$       WRITE SYS$OUTPUT "Checking for correct bzip2 library ...   No"
$       WRITE SYS$OUTPUT "To get bzip2 archives support, please download"
$       WRITE SYS$OUTPUT "and install good library ported by Alexey Chupahin"
$       WRITE SYS$OUTPUT "from openvms clamav site http://vaxvms.org/clamav/"
$       WRITE SYS$OUTPUT ""
$	GOTO EXIT
$ENDIF
$NEXT4:
$!
$!
$!"Checking for CHAPG zlib library    "
$DEFINE SYS$ERROR _NLA0:
$DEFINE SYS$OUTPUT _NLA0:
$ CC/OBJECT=TEST.OBJ/INCLUDE=(ZLIB) SYS$INPUT
      #include <stdlib.h>
      #include <stdio.h>
      #include <string.h>
      #include <zlib.h>
   int main()
     {
        printf("checking version zlib:  %s\n",zlibVersion());
       // printf("checking zlib is correct ");
     }

$TMP = $STATUS
$DEASS SYS$ERROR
$DEAS  SYS$OUTPUT
$IF (TMP .NE. %X10B90001)
$  THEN
$       HAVE_ZLIB=0
$       GOTO ERR4
$ENDIF
$DEFINE SYS$ERROR _NLA0:
$DEFINE SYS$OUTPUT _NLA0:
$!
$LINK/EXE=TEST TEST,ZLIB:ZLIB.OPT/OPT
$TMP = $STATUS
$DEAS SYS$ERROR
$DEAS SYS$OUTPUT
$IF (TMP .NE. %X10000001)
$  THEN
$       HAVE_ZLIB=0
$       GOTO ERR4
$  ELSE
$       HAVE_ZLIB=1
$ENDIF
$ERR4:
$IF (HAVE_ZLIB.EQ.1)
$  THEN
$       WRITE SYS$OUTPUT "Checking for CHAPG zlib library ...   Yes"
$       RUN TEST
$       GOTO NEXT5
$  ELSE
$       WRITE SYS$OUTPUT "Checking for CHAPG zlib library ...   No"
$       WRITE SYS$OUTPUT "Please install ZLIB from"
$       WRITE SYS$OUTPUT "http://vaxvms.org/libsdl/required.html"
$       GOTO EXIT
$ENDIF
$!
$NEXT5:

$!
$!WRITING BUILD FILES
$OPEN/WRITE OUT BUILD.COM
$ WRITE OUT "$","SET DEF [.SRC]"
$ WRITE OUT "$",MAKE
$ WRITE OUT "$ CURRENT = F$ENVIRONMENT (""DEFAULT"") "
$ WRITE OUT "$","SET DEF [-]"
$ WRITE OUT "$CLAM=CURRENT"
$ WRITE OUT "$OPEN/WRITE OUTT PCRE2$STARTUP.COM"
$ WRITE OUT "$WRITE OUTT ""DEFINE PCRE2 ","'","'","CLAM'"" "
$ WRITE OUT "$WRITE OUTT ""DEFINE PCRE2$SHR ","'","'","CLAM'PCRE2$SHR.EXE"" "
$ WRITE OUT "$WRITE OUTT ""PCRE2GREP:==$", "'","'","CLAM'PCRE2GREP.EXE"""
$ WRITE OUT "$CLOSE OUTT"
$ WRITE OUT "$WRITE SYS$OUTPUT "" "" "
$ WRITE OUT "$WRITE SYS$OUTPUT ""***************************************************************************** "" "
$ WRITE OUT "$WRITE SYS$OUTPUT ""Compilation is completed."" "
$ WRITE OUT "$WRITE SYS$OUTPUT ""PCRE2$STARTUP.COM is created. "" "
$ WRITE OUT "$WRITE SYS$OUTPUT ""This file setups all logicals needed."" " 
$ WRITE OUT "$WRITE SYS$OUTPUT ""It should be executed before using PCRE2 Library. "" "
$ WRITE OUT "$WRITE SYS$OUTPUT ""Use PCRE2:PCRE2.OPT to link you program"" "
$ WRITE OUT "$WRITE SYS$OUTPUT ""PCRE2GREP grep utility is installed here for your needs "" "
$ WRITE OUT "$WRITE SYS$OUTPUT ""***************************************************************************** "" "
$CLOSE OUT 
$! BUILD.COM finished
$ WRITE SYS$OUTPUT "BUILD.COM has been created"
$!
$!Creating OPT.OPT file containig external libraries for linker
$OPEN/WRITE OUT [.SRC]PCRE2.OPT
$IF (SHARED.GT.0)  THEN  WRITE OUT "PCRE2:PCRE2$SHR/SHARE"
$IF (SHARED.EQ.0)
$  THEN  
$	WRITE OUT "PCRE2:PCRE2/LIB"
$ENDIF
$CLOSE OUT
$WRITE SYS$OUTPUT "PCRE2.OPT has been created"
$IF (SHARED.EQ.64)
$ THEN
$	COPY SYS$INPUT [.SRC]PCRE2$DEF.OPT
!
case_sensitive=NO
symbol_vector = (PCRE2_CONFIG_8	= PROCEDURE)
symbol_vector = (PCRE2_MAKETABLES_8	= PROCEDURE)
symbol_vector = (PCRE2_MAKETABLES_FREE_8	= PROCEDURE)
symbol_vector = (PCRE2_CODE_COPY_8	= PROCEDURE)
symbol_vector = (PCRE2_CODE_FREE_8	= PROCEDURE)
symbol_vector = (_PCRE2_CHECK_ESCAPE_8	= PROCEDURE)
symbol_vector = (PCRE2_COMPILE_8	= PROCEDURE)
symbol_vector = (PCRE2_CODE_COPY_WITH_TABLES_8	= PROCEDURE)
symbol_vector = (PCRE2_GET_ERROR_MESSAGE_8	= PROCEDURE)
symbol_vector = (PCRE2_MATCH_DATA_CREATE_8	= PROCEDURE)
symbol_vector = (VMS_PCRE2_GET_M_D_HPFRAM_S_8	= PROCEDURE)
symbol_vector = (PCRE2_GET_MATCH_DATA_SIZE_8	= PROCEDURE)
symbol_vector = (PCRE2_GET_STARTCHAR_8	= PROCEDURE)
symbol_vector = (PCRE2_GET_OVECTOR_COUNT_8	= PROCEDURE)
symbol_vector = (PCRE2_GET_OVECTOR_POINTER_8	= PROCEDURE)
symbol_vector = (PCRE2_GET_MARK_8	= PROCEDURE)
symbol_vector = (PCRE2_MATCH_DATA_FREE_8	= PROCEDURE)
symbol_vector = (VMS_PCRE2_M_D_CRT_FR_PATT_8	= PROCEDURE)
symbol_vector = (PCRE2_MATCH_8	= PROCEDURE)
symbol_vector = (PCRE2_PATTERN_INFO_8	= PROCEDURE)
symbol_vector = (PCRE2_CALLOUT_ENUMERATE_8	= PROCEDURE)
symbol_vector = (PCRE2_SET_GLOB_ESCAPE_8	= PROCEDURE)
symbol_vector = (PCRE2_SET_GLOB_SEPARATOR_8	= PROCEDURE)
symbol_vector = (VMS_PCRE2_SET_RCRS_MEM_MNG_8	= PROCEDURE)
symbol_vector = (PCRE2_SET_DEPTH_LIMIT_8	= PROCEDURE)
symbol_vector = (PCRE2_SET_RECURSION_LIMIT_8	= PROCEDURE)
symbol_vector = (PCRE2_SET_OFFSET_LIMIT_8	= PROCEDURE)
symbol_vector = (PCRE2_SET_MATCH_LIMIT_8	= PROCEDURE)
symbol_vector = (PCRE2_SET_HEAP_LIMIT_8	= PROCEDURE)
symbol_vector = (PCRE2_SET_SUBSTITUTE_CALLOUT_8	= PROCEDURE)
symbol_vector = (PCRE2_SET_CALLOUT_8	= PROCEDURE)
symbol_vector = (VMS_PCRE2_SET_CMPL_RCRS_GRD_8	= PROCEDURE)
symbol_vector = (VMS_PCRE2_SET_CMPL_EXT_OPT_8	= PROCEDURE)
symbol_vector = (PCRE2_SET_PARENS_NEST_LIMIT_8	= PROCEDURE)
symbol_vector = (PCRE2_SET_MAX_VARLOOKBEHIND_8	= PROCEDURE)
symbol_vector = (PCRE2_SET_NEWLINE_8	= PROCEDURE)
symbol_vector = (PCRE2_SET_MAX_PATTERN_LENGTH_8	= PROCEDURE)
symbol_vector = (PCRE2_SET_BSR_8	= PROCEDURE)
symbol_vector = (PCRE2_SET_CHARACTER_TABLES_8	= PROCEDURE)
symbol_vector = (PCRE2_CONVERT_CONTEXT_FREE_8	= PROCEDURE)
symbol_vector = (PCRE2_MATCH_CONTEXT_FREE_8	= PROCEDURE)
symbol_vector = (PCRE2_COMPILE_CONTEXT_FREE_8	= PROCEDURE)
symbol_vector = (PCRE2_GENERAL_CONTEXT_FREE_8	= PROCEDURE)
symbol_vector = (PCRE2_CONVERT_CONTEXT_COPY_8	= PROCEDURE)
symbol_vector = (PCRE2_MATCH_CONTEXT_COPY_8	= PROCEDURE)
symbol_vector = (PCRE2_COMPILE_CONTEXT_COPY_8	= PROCEDURE)
symbol_vector = (PCRE2_GENERAL_CONTEXT_COPY_8	= PROCEDURE)
symbol_vector = (_PCRE2_MEMCTL_MALLOC_8	= PROCEDURE)
symbol_vector = (PCRE2_CONVERT_CONTEXT_CREATE_8	= PROCEDURE)
symbol_vector = (PCRE2_MATCH_CONTEXT_CREATE_8	= PROCEDURE)
symbol_vector = (PCRE2_COMPILE_CONTEXT_CREATE_8	= PROCEDURE)
symbol_vector = (PCRE2_GENERAL_CONTEXT_CREATE_8	= PROCEDURE)
symbol_vector = (_PCRE2_AUTO_POSSESSIFY_8	= PROCEDURE)
symbol_vector = (_PCRE2_CKD_SMUL	= PROCEDURE)
symbol_vector = (_PCRE2_FIND_BRACKET_8	= PROCEDURE)
symbol_vector = (_PCRE2_IS_NEWLINE_8	= PROCEDURE)
symbol_vector = (_PCRE2_WAS_NEWLINE_8	= PROCEDURE)
symbol_vector = (_PCRE2_SCRIPT_RUN_8	= PROCEDURE)
symbol_vector = (_PCRE2_STRCMP_8	= PROCEDURE)
symbol_vector = (_PCRE2_STRCPY_C8_8	= PROCEDURE)
symbol_vector = (_PCRE2_STRLEN_8	= PROCEDURE)
symbol_vector = (_PCRE2_STRNCMP_C8_8	= PROCEDURE)
symbol_vector = (_PCRE2_STRNCMP_8	= PROCEDURE)
symbol_vector = (_PCRE2_STRCMP_C8_8	= PROCEDURE)
symbol_vector = (_PCRE2_STUDY_8	= PROCEDURE)
symbol_vector = (_PCRE2_VALID_UTF_8	= PROCEDURE)
symbol_vector = (VMS_PCRE2_DEF_CMPL_CNTXT_8	= DATA)
symbol_vector = (VMS_PCRE2_DEF_CNVRT_CNTXT_8	= DATA)
symbol_vector = (_PCRE2_CALLOUT_END_DELIMS_8	= DATA)
symbol_vector = (_PCRE2_CALLOUT_START_DELIMS_8	= DATA)
symbol_vector = (_PCRE2_DEFAULT_MATCH_CONTEXT_8	= DATA)
symbol_vector = (_PCRE2_DEFAULT_TABLES_8	= DATA)
symbol_vector = (_PCRE2_HSPACE_LIST_8	= DATA)
symbol_vector = (_PCRE2_OP_LENGTHS_8	= DATA)
symbol_vector = (_PCRE2_UCD_CASELESS_SETS_8	= DATA)
symbol_vector = (_PCRE2_UCD_RECORDS_8	= DATA)
symbol_vector = (_PCRE2_UCD_STAGE1_8	= DATA)
symbol_vector = (_PCRE2_UCD_STAGE2_8	= DATA)
symbol_vector = (_PCRE2_VSPACE_LIST_8	= DATA)
!
! ### PSECT list extracted from PCRE2.MAP;1
!
$ENDIF
$!
$!
COPY SYS$INPUT [.SRC]CONFIG.H
/* src/config.h.in.  Generated from configure.ac by autoheader.  */


/* PCRE2 is written in Standard C, but there are a few non-standard things it
can cope with, allowing it to run on SunOS4 and other "close to standard"
systems.

In environments that support the GNU autotools, config.h.in is converted into
config.h by the "configure" script. In environments that use CMake,
config-cmake.in is converted into config.h. If you are going to build PCRE2 "by
hand" without using "configure" or CMake, you should copy the distributed
config.h.generic to config.h, and edit the macro definitions to be the way you
need them. You must then add -DHAVE_CONFIG_H to all of your compile commands,
so that config.h is included at the start of every source.

Alternatively, you can avoid editing by using -D on the compiler command line
to set the macro values. In this case, you do not have to set -DHAVE_CONFIG_H,
but if you do, default values will be taken from config.h for non-boolean
macros that are not defined on the command line.

Boolean macros such as HAVE_STDLIB_H and SUPPORT_PCRE2_8 should either be
defined (conventionally to 1) for TRUE, and not defined at all for FALSE. All
such macros are listed as a commented #undef in config.h.generic. Macros such
as MATCH_LIMIT, whose actual value is relevant, have defaults defined, but are
surrounded by #ifndef/#endif lines so that the value can be overridden by -D.

PCRE2 uses memmove() if HAVE_MEMMOVE is defined; otherwise it uses bcopy() if
HAVE_BCOPY is defined. If your system has neither bcopy() nor memmove(), make
sure both macros are undefined; an emulation function will then be used. */

/* By default, the \R escape sequence matches any Unicode line ending
   character or sequence of characters. If BSR_ANYCRLF is defined (to any
   value), this is changed so that backslash-R matches only CR, LF, or CRLF.
   The build-time default can be overridden by the user of PCRE2 at runtime.
   */
#undef BSR_ANYCRLF

/* Define to any value to disable the use of the z and t modifiers in
   formatting settings such as %zu or %td (this is rarely needed). */
#undef DISABLE_PERCENT_ZT

/* If you are compiling for a system that uses EBCDIC instead of ASCII
   character codes, define this macro to any value. When EBCDIC is set, PCRE2
   assumes that all input strings are in EBCDIC. If you do not define this
   macro, PCRE2 will assume input strings are ASCII or UTF-8/16/32 Unicode. It
   is not possible to build a version of PCRE2 that supports both EBCDIC and
   UTF-8/16/32. */
#undef EBCDIC

/* In an EBCDIC environment, define this macro to any value to arrange for the
   NL character to be 0x25 instead of the default 0x15. NL plays the role that
   LF does in an ASCII/Unicode environment. */
#undef EBCDIC_NL25

/* Define this if your compiler supports __attribute__((uninitialized)) */
#undef HAVE_ATTRIBUTE_UNINITIALIZED

/* Define to 1 if you have the <assert.h> header file. */
#define HAVE_ASSERT_H 1

/* Define to 1 if you have the 'bcopy' function. */
#define HAVE_BCOPY 1

/* Define this if your compiler provides __builtin_mul_overflow() */
#undef HAVE_BUILTIN_MUL_OVERFLOW

/* Define this if your compiler provides __builtin_unreachable() */
#undef HAVE_BUILTIN_UNREACHABLE

/* Define to 1 if you have the <dirent.h> header file. */
#define HAVE_DIRENT_H 1

/* Define to 1 if you have the <dlfcn.h> header file. */
#define HAVE_DLFCN_H 1

/* Define to 1 if you have the <editline/readline.h> header file. */
#undef HAVE_EDITLINE_READLINE_H

/* Define to 1 if you have the <edit/readline/readline.h> header file. */
#undef HAVE_EDIT_READLINE_READLINE_H

/* Define to 1 if you have the <inttypes.h> header file. */
#define HAVE_INTTYPES_H 1

/* Define to 1 if you have the <limits.h> header file. */
#define HAVE_LIMITS_H 1

/* Define to 1 if you have the 'memfd_create' function. */
#undef HAVE_MEMFD_CREATE

/* Define to 1 if you have the 'memmove' function. */
#define HAVE_MEMMOVE 1

/* Define to 1 if you have the <minix/config.h> header file. */
#undef HAVE_MINIX_CONFIG_H

/* Define to 1 if you have the 'mkostemp' function. */
#undef HAVE_MKOSTEMP

/* Define if you have POSIX threads libraries and header files. */
#define HAVE_PTHREAD 1

/* Have PTHREAD_PRIO_INHERIT. */
#undef HAVE_PTHREAD_PRIO_INHERIT

/* Define to 1 if you have the <readline.h> header file. */
#undef HAVE_READLINE_H

/* Define to 1 if you have the <readline/history.h> header file. */
#undef HAVE_READLINE_HISTORY_H

/* Define to 1 if you have the <readline/readline.h> header file. */
#undef HAVE_READLINE_READLINE_H

/* Define to 1 if you have the `realpath' function. */
#define HAVE_REALPATH 1

/* Define to 1 if you have the 'secure_getenv' function. */
#undef HAVE_SECURE_GETENV

/* Define to 1 if you have the <stdint.h> header file. */
#define HAVE_STDINT_H 1

/* Define to 1 if you have the <stdio.h> header file. */
#define HAVE_STDIO_H 1

/* Define to 1 if you have the <stdlib.h> header file. */
#define HAVE_STDLIB_H 1

/* Define to 1 if you have the 'strerror' function. */
#define HAVE_STRERROR 1

/* Define to 1 if you have the <strings.h> header file. */
#define HAVE_STRINGS_H 1

/* Define to 1 if you have the <string.h> header file. */
#define HAVE_STRING_H 1

/* Define to 1 if you have the <sys/stat.h> header file. */
#define HAVE_SYS_STAT_H 1

/* Define to 1 if you have the <sys/types.h> header file. */
#define HAVE_SYS_TYPES_H 1

/* Define to 1 if you have the <sys/wait.h> header file. */
#define HAVE_SYS_WAIT_H 1

/* Define to 1 if you have the <unistd.h> header file. */
#define HAVE_UNISTD_H 1

/* Define to 1 if the compiler supports simple visibility declarations. */
#undef HAVE_VISIBILITY

/* Define to 1 if you have the <wchar.h> header file. */
#define HAVE_WCHAR_H 1

/* Define to 1 if you have the <windows.h> header file. */
#undef HAVE_WINDOWS_H

/* Define to 1 if you have the <zlib.h> header file. */

/* This limits the amount of memory that may be used while matching a pattern.
   It applies to both pcre2_match() and pcre2_dfa_match(). It does not apply
   to JIT matching. The value is in kibibytes (units of 1024 bytes). */
#undef HEAP_LIMIT

/* The value of LINK_SIZE determines the number of bytes used to store links
   as offsets within the compiled regex. The default is 2, which allows for
   compiled patterns up to 65535 code units long. This covers the vast
   majority of cases. However, PCRE2 can also be compiled to use 3 or 4 bytes
   instead. This allows for longer patterns in extreme cases. */
#undef LINK_SIZE

/* Define to the sub-directory where libtool stores uninstalled libraries. */
#undef LT_OBJDIR

/* The value of MATCH_LIMIT determines the default number of times the
   pcre2_match() function can record a backtrack position during a single
   matching attempt. The value is also used to limit a loop counter in
   pcre2_dfa_match(). There is a runtime interface for setting a different
   limit. The limit exists in order to catch runaway regular expressions that
   take forever to determine that they do not match. The default is set very
   large so that it does not accidentally catch legitimate cases. */
#undef MATCH_LIMIT

/* The above limit applies to all backtracks, whether or not they are nested.
   In some environments it is desirable to limit the nesting of backtracking
   (that is, the depth of tree that is searched) more strictly, in order to
   restrict the maximum amount of heap memory that is used. The value of
   MATCH_LIMIT_DEPTH provides this facility. To have any useful effect, it
   must be less than the value of MATCH_LIMIT. The default is to use the same
   value as MATCH_LIMIT. There is a runtime method for setting a different
   limit. In the case of pcre2_dfa_match(), this limit controls the depth of
   the internal nested function calls that are used for pattern recursions,
   lookarounds, and atomic groups. */
#undef MATCH_LIMIT_DEPTH

/* This limit is parameterized just in case anybody ever wants to change it.
   Care must be taken if it is increased, because it guards against integer
   overflow caused by enormously large patterns. */
#undef MAX_NAME_COUNT

/* This limit is parameterized just in case anybody ever wants to change it.
   Care must be taken if it is increased, because it guards against integer
   overflow caused by enormously large patterns. */
#undef MAX_NAME_SIZE

/* The value of MAX_VARLOOKBEHIND specifies the default maximum length, in
   characters, for a variable-length lookbehind assertion. */
#undef MAX_VARLOOKBEHIND

/* Defining NEVER_BACKSLASH_C locks out the use of \C in all patterns. */
#undef NEVER_BACKSLASH_C

/* The value of NEWLINE_DEFAULT determines the default newline character
   sequence. PCRE2 client programs can override this by selecting other values
   at run time. The valid values are 1 (CR), 2 (LF), 3 (CRLF), 4 (ANY), 5
   (ANYCRLF), and 6 (NUL). */
#undef NEWLINE_DEFAULT

/* Name of package */
#define PACKAGE "pcre2"

/* Define to the address where bug reports for this package should be sent. */
#define PACKAGE_BUGREPORT ""

/* Define to the full name of this package. */
#define PACKAGE_NAME "PCRE2"

/* Define to the full name and version of this package. */
#define PACKAGE_STRING "PCRE2 10.43 VMS"

/* Define to the one symbol short name of this package. */
#define PACKAGE_TARNAME "pcre2"

/* Define to the home page for this package. */
#define PACKAGE_URL ""

/* Define to the version of this package. */
#define PACKAGE_VERSION "10.43"

/* The value of PARENS_NEST_LIMIT specifies the maximum depth of nested
   parentheses (of any kind) in a pattern. This limits the amount of system
   stack that is used while compiling a pattern. */
#undef PARENS_NEST_LIMIT

/* The value of PCRE2GREP_BUFSIZE is the starting size of the buffer used by
   pcre2grep to hold parts of the file it is searching. The buffer will be
   expanded up to PCRE2GREP_MAX_BUFSIZE if necessary, for files containing
   very long lines. The actual amount of memory used by pcre2grep is three
   times this number, because it allows for the buffering of "before" and
   "after" lines. */
#define PCRE2GREP_BUFSIZE 20480

/* The value of PCRE2GREP_MAX_BUFSIZE specifies the maximum size of the buffer
   used by pcre2grep to hold parts of the file it is searching. The actual
   amount of memory used by pcre2grep is three times this number, because it
   allows for the buffering of "before" and "after" lines. */
#define PCRE2GREP_MAX_BUFSIZE 1048576

/* Define to any value to include debugging code. */
#undef PCRE2_DEBUG

/* to make a symbol visible */
#undef PCRE2_EXPORT


/* If you are compiling for a system other than a Unix-like system or
   Win32, and it needs some magic to be inserted before the definition
   of a function that is exported by the library, define this macro to
   contain the relevant magic. If you do not define this macro, a suitable
   __declspec value is used for Windows systems; in other environments
   a compiler relevant "extern" is used with any "visibility" related
   attributes from PCRE2_EXPORT included.
   This macro apears at the start of every exported function that is part
   of the external API. It does not appear on functions that are "external"
   in the C sense, but which are internal to the library. */
#undef PCRE2_EXP_DEFN

/* Define to any value if linking statically (TODO: make nice with Libtool) */
#undef PCRE2_STATIC

/* Define to necessary symbol if this constant uses a non-standard name on
   your system. */
#undef PTHREAD_CREATE_JOINABLE

/* Define to any non-zero number to enable support for SELinux compatible
   executable memory allocator in JIT. Note that this will have no effect
   unless SUPPORT_JIT is also defined. */
#undef SLJIT_PROT_EXECUTABLE_ALLOCATOR

/* Define to 1 if all of the C89 standard headers exist (not just the ones
   required in a freestanding environment). This macro is provided for
   backward compatibility; new code need not use it. */
#define STDC_HEADERS 1

/* Define to any value to enable differential fuzzing support. */
#undef SUPPORT_DIFF_FUZZ

/* Define to any value to enable support for Just-In-Time compiling. */
#undef SUPPORT_JIT

/* Define to any value to allow pcre2grep to be linked with libbz2, so that it
   is able to handle .bz2 files. */

/* Define to any value to allow pcre2test to be linked with libedit. */
#undef SUPPORT_LIBEDIT

/* Define to any value to allow pcre2test to be linked with libreadline. */
#undef SUPPORT_LIBREADLINE

/* Define to any value to allow pcre2grep to be linked with libz, so that it
   is able to handle .gz files. */

/* Define to any value to enable callout script support in pcre2grep. */
#undef SUPPORT_PCRE2GREP_CALLOUT

/* Define to any value to enable fork support in pcre2grep callout scripts.
   This will have no effect unless SUPPORT_PCRE2GREP_CALLOUT is also defined.
   */
#undef SUPPORT_PCRE2GREP_CALLOUT_FORK

/* Define to any value to enable JIT support in pcre2grep. Note that this will
   have no effect unless SUPPORT_JIT is also defined. */
#undef SUPPORT_PCRE2GREP_JIT

/* Define to any value to enable the 16 bit PCRE2 library. */
#undef SUPPORT_PCRE2_16

/* Define to any value to enable the 32 bit PCRE2 library. */
#undef SUPPORT_PCRE2_32

/* Define to any value to enable the 8 bit PCRE2 library. */
#define SUPPORT_PCRE2_8 1

/* Define to any value to enable support for Unicode and UTF encoding. This
   will work even in an EBCDIC environment, but it is incompatible with the
   EBCDIC macro. That is, PCRE2 can support *either* EBCDIC code *or*
   ASCII/Unicode, but not both at once. */
#undef SUPPORT_UNICODE

/* Define to any value for valgrind support to find invalid memory reads. */
#undef SUPPORT_VALGRIND

/* Enable extensions on AIX, Interix, z/OS.  */
#ifndef _ALL_SOURCE
# undef _ALL_SOURCE
#endif
/* Enable general extensions on macOS.  */
#ifndef _DARWIN_C_SOURCE
# undef _DARWIN_C_SOURCE
#endif
/* Enable general extensions on Solaris.  */
#ifndef __EXTENSIONS__
# undef __EXTENSIONS__
#endif
/* Enable GNU extensions on systems that have them.  */
#ifndef _GNU_SOURCE
# undef _GNU_SOURCE
#endif
/* Enable X/Open compliant socket functions that do not require linking
   with -lxnet on HP-UX 11.11.  */
#ifndef _HPUX_ALT_XOPEN_SOCKET_API
# undef _HPUX_ALT_XOPEN_SOCKET_API
#endif
/* Identify the host operating system as Minix.
   This macro does not affect the system headers' behavior.
   A future release of Autoconf may stop defining this macro.  */
#ifndef _MINIX
# undef _MINIX
#endif
/* Enable general extensions on NetBSD.
   Enable NetBSD compatibility extensions on Minix.  */
#ifndef _NETBSD_SOURCE
# undef _NETBSD_SOURCE
#endif
/* Enable OpenBSD compatibility extensions on NetBSD.
   Oddly enough, this does nothing on OpenBSD.  */
#ifndef _OPENBSD_SOURCE
# undef _OPENBSD_SOURCE
#endif
/* Define to 1 if needed for POSIX-compatible behavior.  */
#ifndef _POSIX_SOURCE
# undef _POSIX_SOURCE
#endif
/* Define to 2 if needed for POSIX-compatible behavior.  */
#ifndef _POSIX_1_SOURCE
# undef _POSIX_1_SOURCE
#endif
/* Enable POSIX-compatible threading on Solaris.  */
#ifndef _POSIX_PTHREAD_SEMANTICS
# undef _POSIX_PTHREAD_SEMANTICS
#endif
/* Enable extensions specified by ISO/IEC TS 18661-5:2014.  */
#ifndef __STDC_WANT_IEC_60559_ATTRIBS_EXT__
# undef __STDC_WANT_IEC_60559_ATTRIBS_EXT__
#endif
/* Enable extensions specified by ISO/IEC TS 18661-1:2014.  */
#ifndef __STDC_WANT_IEC_60559_BFP_EXT__
# undef __STDC_WANT_IEC_60559_BFP_EXT__
#endif
/* Enable extensions specified by ISO/IEC TS 18661-2:2015.  */
#ifndef __STDC_WANT_IEC_60559_DFP_EXT__
# undef __STDC_WANT_IEC_60559_DFP_EXT__
#endif
/* Enable extensions specified by C23 Annex F.  */
#ifndef __STDC_WANT_IEC_60559_EXT__
# undef __STDC_WANT_IEC_60559_EXT__
#endif
/* Enable extensions specified by ISO/IEC TS 18661-4:2015.  */
#ifndef __STDC_WANT_IEC_60559_FUNCS_EXT__
# undef __STDC_WANT_IEC_60559_FUNCS_EXT__
#endif
/* Enable extensions specified by C23 Annex H and ISO/IEC TS 18661-3:2015.  */
#ifndef __STDC_WANT_IEC_60559_TYPES_EXT__
# undef __STDC_WANT_IEC_60559_TYPES_EXT__
#endif
/* Enable extensions specified by ISO/IEC TR 24731-2:2010.  */
#ifndef __STDC_WANT_LIB_EXT2__
# undef __STDC_WANT_LIB_EXT2__
#endif
/* Enable extensions specified by ISO/IEC 24747:2009.  */
#ifndef __STDC_WANT_MATH_SPEC_FUNCS__
# undef __STDC_WANT_MATH_SPEC_FUNCS__
#endif
/* Enable extensions on HP NonStop.  */
#ifndef _TANDEM_SOURCE
# undef _TANDEM_SOURCE
#endif
/* Enable X/Open extensions.  Define to 500 only if necessary
   to make mbstate_t available.  */
#ifndef _XOPEN_SOURCE
# undef _XOPEN_SOURCE
#endif


/* Version number of package */
#undef VERSION

/* Number of bits in a file offset, on hosts where this is settable. */
#undef _FILE_OFFSET_BITS

/* Define to 1 on platforms where this makes off_t a 64-bit type. */
#undef _LARGE_FILES

/* Number of bits in time_t, on hosts where this is settable. */
#undef _TIME_BITS

/* Define to 1 on platforms where this makes time_t a 64-bit type. */
#undef __MINGW_USE_VC2005_COMPAT

/* Define to empty if 'const' does not conform to ANSI C. */
#undef const

/* Define to the type of a signed integer type of width exactly 64 bits if
   such a type exists and the standard includes do not define it. */
#undef int64_t

/* Define as 'unsigned int' if <stddef.h> doesn't define. */
#undef size_t

// VMS
#include <stdint.h>
#define PCRE2_EXPORT
#define LINK_SIZE 2
#define MAX_NAME_COUNT 10000
#define MAX_NAME_SIZE 32
#define MATCH_LIMIT 10000000
#define HEAP_LIMIT 20000000
#define NEWLINE_DEFAULT 2
#define PARENS_NEST_LIMIT 250
#define MATCH_LIMIT_DEPTH MATCH_LIMIT
#define MAX_VARLOOKBEHIND 255

/*
#define _pcre2_default_compile_context_ vms_pcre2_def_cmpl_cntxt_
#define _pcre2_default_convert_context_ vms_pcre2_def_cnvrt_cntxt_
#define pcre2_set_compile_extra_options_8 vms_pcre2_set_cmpl_ext_opt_8
#define pcre2_set_compile_recursion_guard_8 vms_pcre2_set_cmpl_rcrs_grd_8
#define pcre2_set_recursion_memory_management_8 vms_pcre2_set_rcrs_mem_mng_8
#define pcre2_match_data_create_from_pattern_8 vms_pcre2_m_d_crt_fr_patt_8
#define pcre2_get_match_data_heapframes_size_8 vms_pcre2_get_m_d_hpfram_s_8
#define pcre2_serialize_get_number_of_codes_8 vms_pcre2_ser_get_n_of_cod_8
#define pcre2_substring_nametable_scan_8    vms_pcre2_substr_nmtab_scan_8
#define pcre2_substring_length_bynumber_8   vms_pcre2_substr_len_bynum_8
#define pcre2_substring_number_from_name_8 vms_pcre2_substr_num_f_nam_8
*/

#define HAVE_BZLIB_H 1
#define SUPPORT_LIBBZ2 1

#define HAVE_ZLIB_H 1
#define SUPPORT_LIBZ 1
$!
$!
$WRITE SYS$OUTPUT "config.h created"
$!
$!Creating Descrip.mms in each directory needed
$!
$!
$COPY SYS$INPUT [.SRC]DESCRIP.MMS
# (c) Alexey Chupahin 09-APR-2024
# OpenVMS 7.3-2, DEC 2000 mod.300
# OpenVMS 8.3,   Digital PW 600au
# OpenVMS 8.4,   Compaq DS10L
# OpenVMS 8.3,   HP rx1620


.FIRST
        DEF PCRE2 []


CC=cc
CFLAGS =  /INCLUDE=([],[-],[-.VMS],ZLIB,BZ2LIB) \
          /DEFINE=(HAVE_CONFIG_H,PCRE2_CODE_UNIT_WIDTH=8)\
          /OPTIMIZE=(INLINE=SPEED) \
          /DEB

OBJ=\
PCRE2POSIX.OBJ,\
PCRE2_AUTO_POSSESS.OBJ,\
PCRE2_CHKDINT.OBJ,\
PCRE2_CHARTABLES.OBJ,\
PCRE2_COMPILE.OBJ,\
PCRE2_CONFIG.OBJ,\
PCRE2_CONTEXT.OBJ,\
PCRE2_CONVERT.OBJ,\
PCRE2_DFA_MATCH.OBJ,\
PCRE2_ERROR.OBJ,\
PCRE2_EXTUNI.OBJ,\
PCRE2_FIND_BRACKET.OBJ,\
PCRE2_JIT_COMPILE.OBJ,\
PCRE2_MAKETABLES.OBJ,\
PCRE2_MATCH.OBJ,\
PCRE2_MATCH_DATA.OBJ,\
PCRE2_NEWLINE.OBJ,\
PCRE2_ORD2UTF.OBJ,\
PCRE2_PATTERN_INFO.OBJ,\
PCRE2_SCRIPT_RUN.OBJ,\
PCRE2_SERIALIZE.OBJ,\
PCRE2_STRING_UTILS.OBJ,\
PCRE2_STUDY.OBJ,\
PCRE2_SUBSTITUTE.OBJ,\
PCRE2_SUBSTRING.OBJ,\
PCRE2_TABLES.OBJ,\
PCRE2_UCD.OBJ,\
PCRE2_VALID_UTF.OBJ,\
PCRE2_XCLASS.OBJ

ALL : PCRE2.H PCRE2.OLB PCRE2$SHR.EXE PCRE2DEMO.EXE PCRE2GREP.EXE
        $!

PCRE2$SHR.EXE : PCRE2.OLB
        LINK/SHARE=PCRE2$SHR.EXE PCRE2:PCRE2.OLB/LIB,PCRE2:PCRE2$DEF.OPT/OPT

PCRE2.OLB : $(OBJ)
        LIB/CREA PCRE2.OLB $(OBJ)

PCRE2DEMO.EXE : PCRE2DEMO.OBJ
        LINK/EXE=PCRE2DEMO PCRE2DEMO,PCRE2:PCRE2.OPT/OPT

PCRE2GREP.EXE : PCRE2GREP.OBJ
        LINK/EXE=PCRE2GREP PCRE2GREP,PCRE2:PCRE2.OPT/OPT,ZLIB:ZLIB.OPT/OPT,BZ2LIB:BZIP2.OPT/OPT

PCRE2.H : PCRE2.H_GENERIC
        WRITE SYS$OUTPUT "Patching PCRE2.H"
        COPY/CONCAT [-.VMS]PCRE2.H_PATCH,[]PCRE2.H_GENERIC PCRE2.H

PCRE2_CHARTABLES.OBJ : PCRE2_CHARTABLES.C
         $(CC) $(CFLAGS) $(MMS$SOURCE) /OBJ=$(MMS$TARGET)

PCRE2_CHARTABLES.C : PCRE2_CHARTABLES.C_DIST
         COPY PCRE2_CHARTABLES.C_DIST PCRE2_CHARTABLES.C

PCRE2DEMO.OBJ : PCRE2DEMO.C
         $(CC) $(CFLAGS) $(MMS$SOURCE) /OBJ=$(MMS$TARGET)

PCRE2GREP.OBJ : PCRE2GREP.C
         $(CC) $(CFLAGS) /WARN=DIS=ALL $(MMS$SOURCE) /OBJ=$(MMS$TARGET)

PCRE2POSIX.OBJ : PCRE2POSIX.C
         $(CC) $(CFLAGS) $(MMS$SOURCE) /OBJ=$(MMS$TARGET)

PCRE2POSIX_TEST.OBJ : PCRE2POSIX_TEST.C
         $(CC) $(CFLAGS) $(MMS$SOURCE) /OBJ=$(MMS$TARGET)

PCRE2TEST.OBJ : PCRE2TEST.C
         $(CC) $(CFLAGS) $(MMS$SOURCE) /OBJ=$(MMS$TARGET)

PCRE2_AUTO_POSSESS.OBJ : PCRE2_AUTO_POSSESS.C
         $(CC) $(CFLAGS) $(MMS$SOURCE) /OBJ=$(MMS$TARGET)

PCRE2_CHKDINT.OBJ : PCRE2_CHKDINT.C
         $(CC) $(CFLAGS) $(MMS$SOURCE) /OBJ=$(MMS$TARGET)

PCRE2_COMPILE.OBJ : PCRE2_COMPILE.C
         $(CC) $(CFLAGS) $(MMS$SOURCE) /OBJ=$(MMS$TARGET)

PCRE2_COMPILE.OBJ : PCRE2_COMPILE_CLASS.C
         $(CC) $(CFLAGS) $(MMS$SOURCE) /OBJ=$(MMS$TARGET)

PCRE2_CONFIG.OBJ : PCRE2_CONFIG.C
         $(CC) $(CFLAGS) $(MMS$SOURCE) /OBJ=$(MMS$TARGET)

PCRE2_CONTEXT.OBJ : PCRE2_CONTEXT.C
         $(CC) $(CFLAGS) $(MMS$SOURCE) /OBJ=$(MMS$TARGET)

PCRE2_CONVERT.OBJ : PCRE2_CONVERT.C
         $(CC) $(CFLAGS) $(MMS$SOURCE) /OBJ=$(MMS$TARGET)

PCRE2_DFA_MATCH.OBJ : PCRE2_DFA_MATCH.C
         $(CC) $(CFLAGS) $(MMS$SOURCE) /OBJ=$(MMS$TARGET)

PCRE2_DFTABLES.OBJ : PCRE2_DFTABLES.C
         $(CC) $(CFLAGS) $(MMS$SOURCE) /OBJ=$(MMS$TARGET)

PCRE2_ERROR.OBJ : PCRE2_ERROR.C
         $(CC) $(CFLAGS) $(MMS$SOURCE) /OBJ=$(MMS$TARGET)

PCRE2_EXTUNI.OBJ : PCRE2_EXTUNI.C
         $(CC) $(CFLAGS) $(MMS$SOURCE) /OBJ=$(MMS$TARGET)

PCRE2_FIND_BRACKET.OBJ : PCRE2_FIND_BRACKET.C
         $(CC) $(CFLAGS) $(MMS$SOURCE) /OBJ=$(MMS$TARGET)

PCRE2_FUZZSUPPORT.OBJ : PCRE2_FUZZSUPPORT.C
         $(CC) $(CFLAGS) $(MMS$SOURCE) /OBJ=$(MMS$TARGET)

PCRE2_JIT_COMPILE.OBJ : PCRE2_JIT_COMPILE.C
         $(CC) $(CFLAGS) $(MMS$SOURCE) /OBJ=$(MMS$TARGET)

PCRE2_JIT_MATCH.OBJ : PCRE2_JIT_MATCH.C
         $(CC) $(CFLAGS) $(MMS$SOURCE) /OBJ=$(MMS$TARGET)

PCRE2_JIT_MISC.OBJ : PCRE2_JIT_MISC.C
         $(CC) $(CFLAGS) $(MMS$SOURCE) /OBJ=$(MMS$TARGET)

PCRE2_JIT_TEST.OBJ : PCRE2_JIT_TEST.C
         $(CC) $(CFLAGS) $(MMS$SOURCE) /OBJ=$(MMS$TARGET)

PCRE2_MAKETABLES.OBJ : PCRE2_MAKETABLES.C
         $(CC) $(CFLAGS) $(MMS$SOURCE) /OBJ=$(MMS$TARGET)

PCRE2_MATCH.OBJ : PCRE2_MATCH.C
         $(CC) $(CFLAGS) $(MMS$SOURCE) /OBJ=$(MMS$TARGET)

PCRE2_MATCH_DATA.OBJ : PCRE2_MATCH_DATA.C
         $(CC) $(CFLAGS) $(MMS$SOURCE) /OBJ=$(MMS$TARGET)

PCRE2_NEWLINE.OBJ : PCRE2_NEWLINE.C
         $(CC) $(CFLAGS) $(MMS$SOURCE) /OBJ=$(MMS$TARGET)

PCRE2_ORD2UTF.OBJ : PCRE2_ORD2UTF.C
         $(CC) $(CFLAGS) $(MMS$SOURCE) /OBJ=$(MMS$TARGET)

PCRE2_PATTERN_INFO.OBJ : PCRE2_PATTERN_INFO.C
         $(CC) $(CFLAGS) $(MMS$SOURCE) /OBJ=$(MMS$TARGET)

PCRE2_PRINTINT.OBJ : PCRE2_PRINTINT.C
         $(CC) $(CFLAGS) $(MMS$SOURCE) /OBJ=$(MMS$TARGET)

PCRE2_SCRIPT_RUN.OBJ : PCRE2_SCRIPT_RUN.C
         $(CC) $(CFLAGS) $(MMS$SOURCE) /OBJ=$(MMS$TARGET)

PCRE2_SERIALIZE.OBJ : PCRE2_SERIALIZE.C
         $(CC) $(CFLAGS) $(MMS$SOURCE) /OBJ=$(MMS$TARGET)

PCRE2_STRING_UTILS.OBJ : PCRE2_STRING_UTILS.C
         $(CC) $(CFLAGS) $(MMS$SOURCE) /OBJ=$(MMS$TARGET)

PCRE2_STUDY.OBJ : PCRE2_STUDY.C
         $(CC) $(CFLAGS) $(MMS$SOURCE) /OBJ=$(MMS$TARGET)

PCRE2_SUBSTITUTE.OBJ : PCRE2_SUBSTITUTE.C
         $(CC) $(CFLAGS) $(MMS$SOURCE) /OBJ=$(MMS$TARGET)

PCRE2_SUBSTRING.OBJ : PCRE2_SUBSTRING.C
         $(CC) $(CFLAGS) $(MMS$SOURCE) /OBJ=$(MMS$TARGET)

PCRE2_TABLES.OBJ : PCRE2_TABLES.C
         $(CC) $(CFLAGS) $(MMS$SOURCE) /OBJ=$(MMS$TARGET)

PCRE2_UCD.OBJ : PCRE2_UCD.C
         $(CC) $(CFLAGS) $(MMS$SOURCE) /OBJ=$(MMS$TARGET)

PCRE2_UCPTABLES.OBJ : PCRE2_UCPTABLES.C
         $(CC) $(CFLAGS) $(MMS$SOURCE) /OBJ=$(MMS$TARGET)

PCRE2_VALID_UTF.OBJ : PCRE2_VALID_UTF.C
         $(CC) $(CFLAGS) $(MMS$SOURCE) /OBJ=$(MMS$TARGET)

PCRE2_XCLASS.OBJ : PCRE2_XCLASS.C
         $(CC) $(CFLAGS) $(MMS$SOURCE) /OBJ=$(MMS$TARGET)

$!
$!
$WRITE SYS$OUTPUT "DESCRIP.MMS's have been created"
$WRITE SYS$OUTPUT " "
$WRITE SYS$OUTPUT " "
$WRITE SYS$OUTPUT "Now you can type @BUILD "
$!
$EXIT:
$DEFINE SYS$ERROR _NLA0:
$DEFINE SYS$OUTPUT _NLA0:
$DEL TEST.C;*
$DEL TEST.OBJ;*
$DEL TEST.EXE;*
$DEL TEST.OPT;*
$DEAS SYS$ERROR
$DEAS SYS$OUTPUT

