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

    const msquiczig = b.addModule("msquiczig", .{
        .root_source_file = b.path("src/lib.zig"),
        .imports = &.{
            .{ .name = "quarkz", .module = quarkz_dep.module("quarkz") },
        },
    });

    const server_example = b.addExecutable(.{
        .name = "msquic-server",
        .root_module = b.createModule(.{
            .root_source_file = b.path("examples/server/main.zig"),
            .target = target,
            .optimize = optimize,
            .link_libc = true,
            .imports = &.{
                .{ .name = "quarkz", .module = quarkz_dep.module("quarkz") },
                .{ .name = "msquiczig", .module = msquiczig },
            },
        }),
    });

    const client_example = b.addExecutable(.{
        .name = "msquic-client",
        .root_module = b.createModule(.{
            .root_source_file = b.path("examples/client/main.zig"),
            .target = target,
            .optimize = optimize,
            .link_libc = true,
            .imports = &.{
                .{ .name = "quarkz", .module = quarkz_dep.module("quarkz") },
                .{ .name = "msquiczig", .module = msquiczig },
            },
        }),
    });

    const run_server = b.addRunArtifact(server_example);
    const run_server_step = b.step("run-server", "Run the server app");
    run_server_step.dependOn(&run_server.step);

    const run_client = b.addRunArtifact(client_example);
    const run_client_step = b.step("run-client", "Run the client app");
    run_client_step.dependOn(&run_client.step);

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
