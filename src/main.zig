const std = @import("std");
const fmt = std.fmt;
const heap = std.heap;
const io = std.io;
const linux = std.os.linux;
const mem = std.mem;
const posix = std.posix;
const SIG = posix.SIG;

const getopt = @import("getopt").getopt;

fn help() void {
    usage();
    io.getStdErr().writeAll(
        \\
        \\options:
        \\  -g        Forward signals to pid1's process group.
        \\  -h        Print this help page.
        \\  -L        Print license information.
        \\  -P        Run in pause mode (no program is run and quit on SIGINT).
        \\  -V        Print version information.
        \\
    ) catch unreachable;
}

fn license() void {
    io.getStdErr().writeAll(
        \\Copyright (C) 2024 Misaki Kasumi
        \\Copyright (C) 2018-2023 SUSE LLC
        \\
        \\This program is free software; you can redistribute it and/or modify
        \\it under the terms of the GNU General Public License as published by
        \\the Free Software Foundation, either version 2 of the License, or
        \\(at your option) any later version.
        \\
        \\This program is distributed in the hope that it will be useful,
        \\but WITHOUT ANY WARRANTY; without even the implied warranty of
        \\MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
        \\GNU General Public License for more details.
        \\
        \\You should have received a copy of the GNU General Public License
        \\along with this program.  If not, see <https://www.gnu.org/licenses/>.
        \\
    ) catch unreachable;
}

fn version() void {
    io.getStdErr().writeAll("0.1.0\n") catch unreachable;
}

fn usage() void {
    io.getStdErr().writer().print("usage: {s} [-ghLPV] [--] <progname> [<arguments>...]\n", .{std.os.argv[0]}) catch unreachable;
}

const kernel_signals = [_]u5{ SIG.FPE, SIG.ILL, SIG.SEGV, SIG.BUS, SIG.ABRT, SIG.TRAP, SIG.SYS };

fn sigaddset(set: *posix.sigset_t, sig: u5) void {
    const s = sig - 1;
    set[@as(u32, s) / @bitSizeOf(u32)] |= @as(u32, 1) << s;
}

fn sigdelset(set: *posix.sigset_t, sig: u5) void {
    const s = sig - 1;
    set[@as(u32, s) / @bitSizeOf(u32)] &= ~(@as(u32, 1) << s);
}

const child_arg = struct {
    arena: mem.Allocator,
    parent_pid: posix.pid_t,
    sigmask: *posix.sigset_t,
    argv: [*:null]?[*:0]const u8,
    envp: [*:null]?[*:0]const u8,
    returned_error: ?anyerror,
};

fn rewrite_listen_pid_env(arena: mem.Allocator, envp: [*:null]?[*:0]const u8, parent_pid: posix.pid_t) !void {
    const prefix = "LISTEN_PID=";
    var i: usize = 0;
    while (envp[i]) |l| : (i += 1) {
        const line = l[0..mem.len(l)];
        if (mem.startsWith(u8, line, prefix)) {
            const value = line[prefix.len..];
            const orig_pid = fmt.parseUnsigned(u32, value, 10) catch {
                continue;
            };
            if (orig_pid == parent_pid) {
                const new_pid = linux.getpid();
                envp[i] = try fmt.allocPrintZ(arena, prefix ++ "{}", .{new_pid});
            }
        }
    }
}

fn make_foreground() !void {
    switch (posix.errno(linux.syscall2(.setpgid, 0, 0))) {
        .SUCCESS => {},
        else => |err| return posix.unexpectedErrno(err),
    }
    const rc = linux.syscall1(.getpgid, 0);
    const pgid: posix.pid_t = switch (posix.errno(rc)) {
        .SUCCESS => @intCast(rc),
        else => |err| return posix.unexpectedErrno(err),
    };
    const ttyfd = posix.open("/dev/tty", .{ .ACCMODE = .RDWR, .CLOEXEC = true }, 0) catch 0;
    switch (posix.errno(linux.tcsetpgrp(ttyfd, &pgid))) {
        .SUCCESS, .NOTTY, .BADF, .NXIO => {},
        else => |err| return posix.unexpectedErrno(err),
    }
    const ignored_signals = [_]u5{SIG.TSTP, SIG.TTOU, SIG.TTIN};
    inline for (ignored_signals) |sig| {
        var newact = mem.zeroes(posix.Sigaction);
        newact.handler.handler = SIG.IGN;
        try posix.sigaction(sig, &newact, null);
    }
}

fn spawn_pid1_inner(
    arena: mem.Allocator,
    parent_pid: posix.pid_t,
    sigmask: *posix.sigset_t,
    argv: [*:null]?[*:0]const u8,
    envp: [*:null]?[*:0]const u8,
) !noreturn {
    try rewrite_listen_pid_env(arena, envp, parent_pid);
    try make_foreground();
    posix.sigprocmask(SIG.SETMASK, sigmask, null);
    return posix.execvpeZ(argv[0].?, argv, envp);
}

fn spawn_pid1(arg: usize) callconv(.C) u8 {
    const c_arg: *child_arg = @ptrFromInt(arg);
    spawn_pid1_inner(c_arg.arena, c_arg.parent_pid, c_arg.sigmask, c_arg.argv, c_arg.envp) catch |err| {
        c_arg.returned_error = err;
        return 1;
    };
}

fn reap_zombies(child_pid: posix.pid_t, child_exitcode: *i32) !void {
    while (true) {
        var wstatus: u32 = undefined;
        const rc = linux.waitpid(-1, &wstatus, linux.W.NOHANG);
        const reap_pid: posix.pid_t = switch (posix.errno(rc)) {
            .SUCCESS => @intCast(rc),
            .CHILD => break,
            else => |err| return posix.unexpectedErrno(err),
        };

        if (reap_pid == child_pid) {
            if (linux.W.IFEXITED(wstatus)) {
                child_exitcode.* = linux.W.EXITSTATUS(wstatus);
            } else if (linux.W.IFSIGNALED(wstatus)) {
                child_exitcode.* = @intCast(linux.W.TERMSIG(wstatus) + 128);
            } else {
                child_exitcode.* = 127;
            }
        }
    }
}

pub fn dupeWithSentinel(allocator: mem.Allocator, comptime T: type, m: []const T, comptime s: T) ![:s]T {
    const new_buf = try allocator.alloc(T, m.len + 1);
    @memcpy(new_buf[0..m.len], m);
    new_buf[m.len] = s;
    return new_buf[0..m.len :s];
}

pub fn main() !u8 {
    var kill_pgid = false;
    var run_as_pause = false;

    var opts = getopt("ghLPV");
    while (true) {
        const maybe_opt = opts.next() catch {
            usage();
            return 1;
        };
        if (maybe_opt) |opt| {
            switch (opt.opt) {
                'g' => kill_pgid = true,
                'P' => run_as_pause = true,
                'h' => {
                    help();
                    return 0;
                },
                'L' => {
                    license();
                    return 0;
                },
                'V' => {
                    version();
                    return 0;
                },
                else => unreachable,
            }
        } else {
            break;
        }
    }
    const maybe_args = opts.args();

    var init_sigmask = linux.all_mask;
    var child_sigmask = posix.empty_sigset;
    inline for (kernel_signals) |sig| {
        sigdelset(&init_sigmask, sig);
    }
    posix.sigprocmask(SIG.SETMASK, &init_sigmask, &child_sigmask);
    var sfd = try posix.signalfd(-1, &init_sigmask, linux.SFD.CLOEXEC);

    const cur_pid = linux.getpid();
    if (cur_pid != 1) {
        _ = try posix.prctl(.SET_CHILD_SUBREAPER, .{ 1, 0, 0, 0 });
    }

    var child_pid: posix.pid_t = 0;
    if (!run_as_pause) {
        const stack_size = 0x8000;
        const buf = try heap.page_allocator.alloc(u8, stack_size * 2);
        defer heap.page_allocator.free(buf);
        var buf_allocator = heap.FixedBufferAllocator.init(buf);
        const arena = buf_allocator.allocator();
        const stack = try arena.alloc(u8, stack_size);
        const args = maybe_args orelse {
            usage();
            return 1;
        };
        const argv = try dupeWithSentinel(arena, ?[*:0]const u8, args, null);
        const envp = try dupeWithSentinel(arena, ?[*:0]const u8, std.os.environ, null);
        var c_arg = child_arg{
            .arena = arena,
            .parent_pid = cur_pid,
            .sigmask = &child_sigmask,
            .argv = argv,
            .envp = envp,
            .returned_error = null,
        };

        var stub: i32 = undefined;
        const rc = linux.clone(spawn_pid1, @intFromPtr(stack.ptr) + stack_size, linux.CLONE.VM | linux.CLONE.VFORK | SIG.CHLD, @intFromPtr(&c_arg), &stub, 0, &stub);
        switch (posix.errno(rc)) {
            .SUCCESS => child_pid = @intCast(rc),
            else => |err| return posix.unexpectedErrno(err),
        }

        if (c_arg.returned_error) |err| {
            return err;
        }
    } else {
        std.debug.assert(maybe_args == null);
    }

    try posix.chdir("/");
    try posix.dup2(sfd, 3);
    sfd = 3;
    if (posix.open("/dev/null", .{ .ACCMODE = .RDWR }, 0) catch null) |null_fd| {
        try posix.dup2(null_fd, 0);
        try posix.dup2(null_fd, 1);
        try posix.dup2(null_fd, 2);
    }
    switch (posix.errno(linux.syscall3(.close_range, @intCast(sfd + 1), std.math.maxInt(u32), 0))) {
        .SUCCESS => {},
        else => |err| return posix.unexpectedErrno(err),
    }

    const kill_target = if (kill_pgid) -child_pid else child_pid;
    var child_exitcode: i32 = -1;
    while (child_exitcode < 0) {
        var buf: [@sizeOf(linux.signalfd_siginfo)]u8 = undefined;
        const n = try posix.read(sfd, &buf);
        std.debug.assert(n == @sizeOf(linux.signalfd_siginfo));
        const ssi: linux.signalfd_siginfo = @bitCast(buf);

        switch (ssi.signo) {
            SIG.TSTP, SIG.TTOU, SIG.TTIN => {},
            SIG.CHLD => try reap_zombies(child_pid, &child_exitcode),
            else => |signo| {
                if (run_as_pause) {
                    if (signo == SIG.TERM or signo == SIG.INT)
                        return 0;
                } else {
                    switch (ssi.code) {
                        0 => {
                            // SI_USER
                            posix.kill(kill_target, @intCast(signo)) catch |err| {
                                if (err != error.ProcessNotFound) {
                                    return err;
                                }
                            };
                        },
                        -1 => {
                            // SI_QUEUE
                            var info = mem.zeroes(linux.siginfo_t);
                            info.signo = @bitCast(signo);
                            info.code = -1;
                            info.fields.common.first.piduid.pid = @bitCast(ssi.pid);
                            info.fields.common.first.piduid.uid = ssi.uid;
                            info.fields.common.second.value.int = ssi.int;
                            info.fields.common.second.value.ptr = @ptrFromInt(ssi.ptr);
                            switch (posix.errno(linux.syscall3(.rt_sigqueueinfo, @intCast(child_pid), signo, @intFromPtr(&info)))) {
                                .SUCCESS, .SRCH => {},
                                else => |err| return posix.unexpectedErrno(err),
                            }
                        },
                        else => {},
                    }
                }
            },
        }
    }
    return @intCast(child_exitcode);
}
