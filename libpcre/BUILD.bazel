load("@bazel_skylib//rules:copy_file.bzl", "copy_file")
load("@bazel_skylib//rules:native_binary.bzl", "native_test")
load("@rules_cc//cc:defs.bzl", "cc_binary", "cc_library")

copy_file(
    name = "config_h_generic",
    src = "src/config.h.generic",
    out = "src/config.h",
)

copy_file(
    name = "pcre2_h_generic",
    src = "src/pcre2.h.generic",
    out = "src/pcre2.h",
)

copy_file(
    name = "pcre2_chartables_c",
    src = "src/pcre2_chartables.c.dist",
    out = "src/pcre2_chartables.c",
)

# Removed src/pcre2_ucptables.c below because it is #included in
# src/pcre2_tables.c. Also fixed typo: ckdint should be chkdint.
# PH, 22-March-2023.
cc_library(
    name = "pcre2",
    srcs = [
        "src/pcre2_auto_possess.c",
        "src/pcre2_chkdint.c",
        "src/pcre2_compile.c",
        "src/pcre2_compile_class.c",
        "src/pcre2_config.c",
        "src/pcre2_context.c",
        "src/pcre2_convert.c",
        "src/pcre2_dfa_match.c",
        "src/pcre2_error.c",
        "src/pcre2_extuni.c",
        "src/pcre2_find_bracket.c",
        "src/pcre2_jit_compile.c",
        "src/pcre2_maketables.c",
        "src/pcre2_match.c",
        "src/pcre2_match_data.c",
        "src/pcre2_newline.c",
        "src/pcre2_ord2utf.c",
        "src/pcre2_pattern_info.c",
        "src/pcre2_script_run.c",
        "src/pcre2_serialize.c",
        "src/pcre2_string_utils.c",
        "src/pcre2_study.c",
        "src/pcre2_substitute.c",
        "src/pcre2_substring.c",
        "src/pcre2_tables.c",
        "src/pcre2_ucd.c",
        "src/pcre2_valid_utf.c",
        "src/pcre2_xclass.c",
        ":pcre2_chartables_c",
        "src/pcre2_compile.h",
        "src/pcre2_internal.h",
        "src/pcre2_intmodedep.h",
        "src/pcre2_ucp.h",
        "src/pcre2_util.h",
        ":config_h_generic",
    ],
    textual_hdrs = [
        "src/pcre2_jit_match.c",
        "src/pcre2_jit_misc.c",
        "src/pcre2_ucptables.c",
    ],
    hdrs = [
        ":pcre2_h_generic",
    ],
    local_defines = [
        "HAVE_CONFIG_H",
        "HAVE_MEMMOVE",
        "PCRE2_CODE_UNIT_WIDTH=8",
        "PCRE2_STATIC",
        "SUPPORT_UNICODE",
    ],
    includes = ["src"],
    strip_include_prefix = "src",
    visibility = ["//visibility:public"],
)

cc_library(
    name = "pcre2-posix",
    srcs = [
        "src/pcre2posix.c",
        ":config_h_generic",
    ],
    hdrs = [
        "src/pcre2posix.h",
    ],
    local_defines = [
        "HAVE_CONFIG_H",
        "HAVE_MEMMOVE",
        "PCRE2_CODE_UNIT_WIDTH=8",
        "PCRE2_STATIC",
        "SUPPORT_UNICODE",
    ],
    includes = ["src"],
    strip_include_prefix = "src",
    visibility = ["//visibility:public"],
    deps = [":pcre2"],
)

# Totally weird issue in Bazel. It won't let you #include any files unless they
# are declared to the build system. OK, fair enough. But - for a cc_binary it
# uses the file extension to determine whether it's a header or a compilation
# unit. But... we have several .c files which are #included, rather than treated
# as a compilation unit.
#
# For cc_library() above, we can overcome this with textual_hdrs. But that
# doesn't work for cc_binary(). Here's our workaround.
#
# https://github.com/bazelbuild/bazel/issues/680
cc_library(
    name = "pcre2test_dotc_headers",
    hdrs = [
        "src/pcre2_chkdint.c",
        "src/pcre2_printint.c",
        "src/pcre2_tables.c",
        "src/pcre2_ucd.c",
        "src/pcre2_valid_utf.c",
    ],
    strip_include_prefix = "src",
    visibility = ["//visibility:private"],
)

cc_binary(
    name = "pcre2test",
    srcs = [
        "src/pcre2test.c",
        ":config_h_generic",
    ],
    local_defines = [
        "HAVE_CONFIG_H",
        "HAVE_MEMMOVE",
        "HAVE_STRERROR",
        "PCRE2_STATIC",
        "SUPPORT_UNICODE",
        "SUPPORT_PCRE2_8",
    ] + select({
        "@platforms//os:windows": [],
        "//conditions:default": ["HAVE_UNISTD_H"],
    }),
    linkopts = select({
        "@platforms//os:windows": ["-STACK:2500000"],
        "//conditions:default": [],
    }),
    visibility = ["//visibility:public"],
    deps = [":pcre2test_dotc_headers", ":pcre2", ":pcre2-posix"],
)

filegroup(
    name = "testdata",
    srcs = glob(["testdata/*"]),
)

native_test(
    name = "pcre2_test",
    src = select({
        "@platforms//os:windows": "RunTest.bat",
        "//conditions:default": "RunTest",
    }),
    out = select({
        "@platforms//os:windows": "RunTest.bat",
        "//conditions:default": "RunTest",
    }),
    data = [":pcre2test", ":testdata"],
    size = "small",
)