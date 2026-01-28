const std = @import("std");

pub const CodeUnitWidth = enum {
    @"8",
    @"16",
    @"32",
};

pub fn build(b: *std.Build) !void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const linkage = b.option(std.builtin.LinkMode, "linkage", "whether to statically or dynamically link the library") orelse @as(std.builtin.LinkMode, if (target.result.isGnuLibC()) .dynamic else .static);
    const codeUnitWidth = b.option(CodeUnitWidth, "code-unit-width", "Sets the code unit width") orelse .@"8";
    const jit = b.option(bool, "support_jit", "Enable/disable JIT compiler support") orelse false;

    const pcre2_header_dir = b.addWriteFiles();
    const pcre2_header = pcre2_header_dir.addCopyFile(b.path("src/pcre2.h.generic"), "pcre2.h");

    const config_header = b.addConfigHeader(
        .{
            .style = .{ .cmake = b.path("src/config-cmake.h.in") },
            .include_path = "config.h",
        },
        .{
            .HAVE_ASSERT_H = true,
            .HAVE_UNISTD_H = (target.result.os.tag != .windows),
            .HAVE_WINDOWS_H = (target.result.os.tag == .windows),

            .HAVE_ATTRIBUTE_UNINITIALIZED = true,
            .HAVE_BUILTIN_MUL_OVERFLOW = true,
            .HAVE_BUILTIN_UNREACHABLE = true,

            .SUPPORT_PCRE2_8 = codeUnitWidth == CodeUnitWidth.@"8",
            .SUPPORT_PCRE2_16 = codeUnitWidth == CodeUnitWidth.@"16",
            .SUPPORT_PCRE2_32 = codeUnitWidth == CodeUnitWidth.@"32",
            .SUPPORT_UNICODE = true,
            .SUPPORT_JIT = jit,

            .PCRE2_EXPORT = null,
            .PCRE2_LINK_SIZE = 2,
            .PCRE2_HEAP_LIMIT = 20000000,
            .PCRE2_MATCH_LIMIT = 10000000,
            .PCRE2_MATCH_LIMIT_DEPTH = "MATCH_LIMIT",
            .PCRE2_MAX_VARLOOKBEHIND = 255,
            .NEWLINE_DEFAULT = 2,
            .PCRE2_PARENS_NEST_LIMIT = 250,
            .PCRE2GREP_BUFSIZE = 20480,
            .PCRE2GREP_MAX_BUFSIZE = 1048576,
        },
    );

    // pcre2-8/16/32 library

    const lib_mod = b.createModule(.{
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });

    lib_mod.addCMacro("HAVE_CONFIG_H", "");
    lib_mod.addCMacro("PCRE2_CODE_UNIT_WIDTH", @tagName(codeUnitWidth));
    if (linkage == .static) {
        lib_mod.addCMacro("PCRE2_STATIC", "");
    }

    const lib = b.addLibrary(.{
        .name = b.fmt("pcre2-{s}", .{@tagName(codeUnitWidth)}),
        .root_module = lib_mod,
        .linkage = linkage,
    });

    lib.addConfigHeader(config_header);
    lib.addIncludePath(pcre2_header_dir.getDirectory());
    lib.addIncludePath(b.path("src"));

    lib.addCSourceFile(.{
        .file = b.addWriteFiles().addCopyFile(b.path("src/pcre2_chartables.c.dist"), "pcre2_chartables.c"),
    });

    lib.addCSourceFiles(.{
        .files = &.{
            "src/pcre2_auto_possess.c",
            "src/pcre2_chkdint.c",
            "src/pcre2_compile.c",
            "src/pcre2_compile_cgroup.c",
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
            "src/pcre2_match_next.c",
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
        },
    });

    lib.installHeader(pcre2_header, "pcre2.h");
    b.installArtifact(lib);

    // pcre2test

    const pcre2test_mod = b.createModule(.{
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });

    pcre2test_mod.addCMacro("HAVE_CONFIG_H", "");
    if (linkage == .static) {
        pcre2test_mod.addCMacro("PCRE2_STATIC", "");
    } else {
        pcre2test_mod.addCMacro("PCRE2POSIX_SHARED", "");
    }

    const pcre2test = b.addExecutable(.{
        .name = "pcre2test",
        .root_module = pcre2test_mod,
    });

    // pcre2-posix library

    if (codeUnitWidth == CodeUnitWidth.@"8") {
        const posixLib_mod = b.createModule(.{
            .target = target,
            .optimize = optimize,
            .link_libc = true,
        });

        posixLib_mod.addCMacro("HAVE_CONFIG_H", "");
        posixLib_mod.addCMacro("PCRE2_CODE_UNIT_WIDTH", @tagName(codeUnitWidth));
        if (linkage == .static) {
            posixLib_mod.addCMacro("PCRE2_STATIC", "");
        } else {
            posixLib_mod.addCMacro("PCRE2POSIX_SHARED", "");
        }

        const posixLib = b.addLibrary(.{
            .name = "pcre2-posix",
            .root_module = posixLib_mod,
            .linkage = linkage,
        });

        posixLib.addConfigHeader(config_header);
        posixLib.addIncludePath(pcre2_header_dir.getDirectory());
        posixLib.addIncludePath(b.path("src"));

        posixLib.addCSourceFiles(.{
            .files = &.{
                "src/pcre2posix.c",
            },
        });

        posixLib.linkLibrary(lib);

        posixLib.installHeader(b.path("src/pcre2posix.h"), "pcre2posix.h");
        b.installArtifact(posixLib);

        pcre2test.linkLibrary(posixLib);
    }

    // pcre2test (again)

    pcre2test.addConfigHeader(config_header);
    pcre2test.addIncludePath(pcre2_header_dir.getDirectory());
    pcre2test.addIncludePath(b.path("src"));

    pcre2test.addCSourceFile(.{
        .file = b.path("src/pcre2test.c"),
    });

    pcre2test.linkLibrary(lib);

    b.installArtifact(pcre2test);
}
