const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{
        .preferred_optimize_mode = .ReleaseSafe
    });

    const exe = b.addExecutable(.{
        .name = "initzig",
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
        .single_threaded = true,
    });


    const getopt = b.dependency("getopt", .{
        .target = target,
        .optimize = optimize,
    });
    exe.root_module.addImport("getopt", getopt.module("getopt"));

    b.installArtifact(exe);

    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        run_cmd.addArgs(args);
    }

    const run_step = b.step("run", "Run the app");
    run_step.dependOn(&run_cmd.step);
}
