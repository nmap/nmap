const std = @import("std");

pub const CodeUnitWidth = enum {
    @"8",
    @"16",
    @"32",
};

pub fn build(b: *std.Build) !void {
    const optimize = b.standardOptimizeOption(.{});
    const target = b.standardTargetOptions(.{});
    const rt = target.result;

    const linkage = b.option(std.builtin.LinkMode, "linkage", "whether to statically or dynamically link the library") orelse @as(std.builtin.LinkMode, if (rt.isGnuLibC()) .dynamic else .static);
    const sanitize_c = b.option(std.zig.SanitizeC, "sanitize_c", "whether to build with undefined behaviour sanitizer enabled") orelse .off;
    const codeUnitWidth = b.option(CodeUnitWidth, "code-unit-width", "Sets the code unit width") orelse .@"8";
    const support_jit = b.option(bool, "support_jit", "Enable/disable JIT compiler support") orelse false;

    const sljit_is_checked_out = if (!support_jit)
        false
    else if (b.build_root.handle.access(
        b.graph.io,
        "deps/sljit/sljit_src/sljitLir.c",
        .{},
    )) |_| true else |err| switch (err) {
        error.FileNotFound => false,
        else => return err,
    };

    // We don't know how the sljit dependency is being provided. Either it
    // comes via a git submodule, or it may be fetched by zig itself.
    const sljit_include_path = if (!support_jit)
        null
    else if (sljit_is_checked_out)
        null
    else blk: {
        const sljit = b.lazyDependency("sljit", .{}) orelse
            break :blk null;

        const files = b.addWriteFiles();

        // Recreate the layout used by pcre2_jit_compile.c's relative include.
        _ = files.addCopyDirectory(
            sljit.path("sljit_src"),
            "deps/sljit/sljit_src",
            .{},
        );
        _ = files.add("src/.empty", "");

        break :blk files.getDirectory().path(b, "src");
    };

    const pcre2_h_dir = b.addWriteFiles();
    const pcre2_h = pcre2_h_dir.addCopyFile(b.path("src/pcre2.h.generic"), "pcre2.h");
    b.addNamedLazyPath("pcre2.h", pcre2_h);

    const is_unix = rt.os.tag != .windows;
    const is_mingw = rt.isMinGW();
    const is_musl = rt.isMuslLibC();
    const is_glibc = rt.isGnuLibC();
    const is_freebsd = rt.isFreeBSDLibC();

    const cflags = &.{
        "-fvisibility=hidden",
    };

    const config_h = b.addConfigHeader(
        .{
            .style = .{
                .cmake = b.path("src/config-cmake.h.in"),
            },
            .include_path = "config.h",
        },
        // These options should be kept in-sync with those in config-cmake.h.in, and
        // should be the same set of options (no more needed). It is permitted to
        // specify fewer options here than in config-cmake.h.in, if an option is
        // disabled in all zig build configurations.
        .{
            .HAVE_ASSERT_H = true,
            .HAVE_DIRENT_H = is_unix or is_mingw,
            .HAVE_SYS_STAT_H = true,
            .HAVE_SYS_TYPES_H = true,
            .HAVE_UNISTD_H = is_unix or is_mingw,
            .HAVE_WINDOWS_H = rt.os.tag == .windows,

            .HAVE_MEMFD_CREATE = is_musl or is_glibc or is_freebsd,
            .HAVE_SECURE_GETENV = is_musl or is_glibc or is_freebsd,
            .HAVE_SETRLIMIT = is_unix and !is_mingw,

            // all compilation is using the Zig bundled c compiler
            .HAVE_BUILTIN_ASSUME = null,
            .HAVE_BUILTIN_MUL_OVERFLOW = true,
            .HAVE_BUILTIN_UNREACHABLE = true,
            .HAVE_ATTRIBUTE_UNINITIALIZED = true,

            .SUPPORT_PCRE2_8 = codeUnitWidth == .@"8",
            .SUPPORT_PCRE2_16 = codeUnitWidth == .@"16",
            .SUPPORT_PCRE2_32 = codeUnitWidth == .@"32",
            .SUPPORT_UNICODE = true,
            .SUPPORT_JIT = support_jit,

            // As for CMake builds, use visibilty attributes for both shared and static
            // builds. Internal symbols should be hidden even in static builds, because
            // the user could be statically linking PCRE2 into their own shared library.
            .PCRE2_EXPORT = "__attribute__ ((visibility (\"default\")))",

            .PCRE2_LINK_SIZE = 2,
            .PCRE2_PARENS_NEST_LIMIT = 250,
            .PCRE2_HEAP_LIMIT = 20000000,
            .PCRE2_MAX_VARLOOKBEHIND = 255,
            .PCRE2_MATCH_LIMIT = 10000000,
            .PCRE2_MATCH_LIMIT_DEPTH = "MATCH_LIMIT",
            .PCRE2GREP_BUFSIZE = 20480,
            .PCRE2GREP_MAX_BUFSIZE = 1048576,
            .NEWLINE_DEFAULT = 2,
        },
    );

    // pcre2-8/16/32 library
    const lib_mod = b.createModule(.{
        .target = target,
        .optimize = optimize,
        .sanitize_c = sanitize_c,
        .link_libc = true,
    });

    lib_mod.addCMacro("HAVE_CONFIG_H", "");
    lib_mod.addCMacro("PCRE2_CODE_UNIT_WIDTH", @tagName(codeUnitWidth));
    switch (linkage) {
        .static => lib_mod.addCMacro("PCRE2_STATIC", ""),
        .dynamic => {},
    }
    lib_mod.addConfigHeader(config_h);
    lib_mod.addIncludePath(pcre2_h_dir.getDirectory());
    lib_mod.addIncludePath(b.path("src"));
    if (sljit_include_path) |include_path| {
        lib_mod.addIncludePath(include_path);
    }

    lib_mod.addCSourceFile(.{
        .file = b.addWriteFiles().addCopyFile(b.path("src/pcre2_chartables.c.dist"), "pcre2_chartables.c"),
        .flags = cflags,
    });
    lib_mod.addCSourceFiles(.{
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
        .flags = cflags,
    });

    const lib = b.addLibrary(.{
        .name = b.fmt("pcre2-{t}", .{codeUnitWidth}),
        .root_module = lib_mod,
        .linkage = linkage,
    });

    lib.installHeader(pcre2_h, "pcre2.h");
    b.installArtifact(lib);

    // pcre2test
    const pcre2test_mod = b.createModule(.{
        .target = target,
        .optimize = optimize,
        .sanitize_c = sanitize_c,
        .link_libc = true,
    });

    pcre2test_mod.addCMacro("HAVE_CONFIG_H", "");

    // Note: On Windows, consumers linking against the static library should
    // probably define PCRE2_STATIC themselves (e.g. via
    // addCMacro("PCRE2_STATIC", "")).
    // As far as I know, Zig's build system does not currently have a mechanism
    // to propagate compile definitions to downstream consumers (like CMake's
    // PUBLIC target_compile_definitions). On non-Windows targets this is a no-op.
    switch (linkage) {
        .static => pcre2test_mod.addCMacro("PCRE2_STATIC", ""),
        .dynamic => pcre2test_mod.addCMacro("PCRE2POSIX_SHARED", ""),
    }

    const pcre2test = b.addExecutable(.{
        .name = "pcre2test",
        .root_module = pcre2test_mod,
    });
    pcre2test_mod.addConfigHeader(config_h);
    pcre2test_mod.addIncludePath(pcre2_h_dir.getDirectory());
    pcre2test_mod.addIncludePath(b.path("src"));

    pcre2test_mod.addCSourceFile(.{
        .file = b.path("src/pcre2test.c"),
        .flags = cflags,
    });

    pcre2test_mod.linkLibrary(lib);
    b.installArtifact(pcre2test);

    // pcre2-posix library
    if (codeUnitWidth == CodeUnitWidth.@"8") {
        const posixLib_mod = b.createModule(.{
            .target = target,
            .optimize = optimize,
            .sanitize_c = sanitize_c,
            .link_libc = true,
        });

        posixLib_mod.addCMacro("HAVE_CONFIG_H", "");
        posixLib_mod.addCMacro("PCRE2_CODE_UNIT_WIDTH", @tagName(codeUnitWidth));

        switch (linkage) {
            .static => posixLib_mod.addCMacro("PCRE2_STATIC", ""),
            .dynamic => posixLib_mod.addCMacro("PCRE2POSIX_SHARED", ""),
        }

        posixLib_mod.addConfigHeader(config_h);
        posixLib_mod.addIncludePath(pcre2_h_dir.getDirectory());
        posixLib_mod.addIncludePath(b.path("src"));

        posixLib_mod.addCSourceFiles(.{
            .files = &.{
                "src/pcre2posix.c",
            },
            .flags = cflags,
        });

        posixLib_mod.linkLibrary(lib);

        const posixLib = b.addLibrary(.{
            .name = "pcre2-posix",
            .root_module = posixLib_mod,
            .linkage = linkage,
        });

        pcre2test_mod.linkLibrary(posixLib);

        b.addNamedLazyPath("pcre2posix.h", b.path("src/pcre2posix.h"));
        posixLib.installHeader(b.path("src/pcre2posix.h"), "pcre2posix.h");
        b.installArtifact(posixLib);
    }
}
