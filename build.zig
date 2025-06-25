const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const quarkz_dep = b.dependency("quarkz", .{
        .target = target,
        .optimize = optimize,
    });

    const lib = b.addStaticLibrary(.{
        .name = "msquiczig",
        .root_source_file = b.path("src/lib.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    b.installArtifact(lib);

    _ = b.addModule("msquiczig", .{
        .root_source_file = b.path("src/lib.zig"),
        .imports = &.{
            .{ .name = "quarkz", .module = quarkz_dep.module("quarkz") },
        },
    });

    const tests = b.addTest(.{
        .root_source_file = b.path("src/lib.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });

    tests.root_module.addImport("quarkz", quarkz_dep.module("quarkz"));

    const run_tests = b.addRunArtifact(tests);
    const test_step = b.step("test", "Run library tests");
    test_step.dependOn(&run_tests.step);
}
