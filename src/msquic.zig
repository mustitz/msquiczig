const std = @import("std");
const Allocator = std.mem.Allocator;

const MsQuicError = @import("errors.zig").MsQuicError;
const C = @import("header.zig").C;

const Registration = @import("reg.zig").Registration;

pub const Addr = struct {
    internal: std.net.Address,

    pub fn init() Addr {
        return Addr{ .internal = std.mem.zeroes(std.net.Address) };
    }

    pub fn setFamily(self: *Addr, family: C.AddressFamily) void {
        self.internal.any.family = @intFromEnum(family);
    }

    pub fn setPort(self: *Addr, port: u16) void {
       switch (self.internal.any.family) {
           std.posix.AF.INET => self.internal.in.setPort(port),
           std.posix.AF.INET6 => self.internal.in6.setPort(port),
           std.posix.AF.UNSPEC => self.internal.in.setPort(port),
           else => unreachable,
       }
    }

    pub fn format(
        self: Addr,
        comptime fmt: []const u8,
        options: std.fmt.FormatOptions,
        out_stream: anytype,
    ) !void {
        return self.internal.format(fmt, options, out_stream);
    }
};

pub const MsQuic = struct {
    allocator: Allocator = undefined,
    lib: ?std.DynLib = null,
    open_version_export_fn: ?C.MsQuicOpenVersionFn = null,
    close_export_fn: ?C.MsQuicCloseFn = null,
    api: *const C.ApiTable = undefined,

    pub fn init(self: *MsQuic, allocator: Allocator, path: []const u8) !void {
        var lib = try std.DynLib.open(path);
        errdefer lib.close();

        const open_version = lib.lookup(C.MsQuicOpenVersionFn, "MsQuicOpenVersion")
            orelse return MsQuicError.QzOpenVersionNotFound;
        const close = lib.lookup(C.MsQuicCloseFn, "MsQuicClose")
            orelse return MsQuicError.QzCloseNotFound;

        var api: ?*const C.ApiTable = null;
        const status = open_version(2, &api);
        if (C.StatusCode.failed(status)) return C.StatusCode.toError(status);

        self.api = api orelse return MsQuicError.QzBug;
        self.allocator = allocator;
        self.open_version_export_fn = open_version;
        self.close_export_fn = close;
        self.lib = lib;
    }

    pub fn deinit(self: *MsQuic) void {
        if (self.close_export_fn) |close_fn| {
            close_fn(self.api);
        }

        self.open_version_export_fn = null;
        self.close_export_fn = null;
        if (self.lib) |*lib| {
            lib.close();
            self.lib = null;
        }
    }

    pub fn openReg(self: *MsQuic, app_name: [*:0]const u8, profile: C.ExecutionProfile) !Registration {
        const config = C.RegConfig{
            .app_name = app_name,
            .execution_profile = profile,
        };
        var handle: C.HQUIC = undefined;
        const status = self.api.reg_open(&config, &handle);
        if (C.StatusCode.failed(status)) return C.StatusCode.toError(status);

        return Registration{
            .handle = handle,
            .msquic = self
        };
    }

};

test "test libmsquic.so loading" {
    const libmsquic_path = std.posix.getenv("LIBMSQUIC_PATH") orelse {
        std.debug.print("Error: LIBMSQUIC_PATH environment variable not set\n", .{});
        std.process.exit(1);
    };

    var msquic = MsQuic{};
    defer msquic.deinit();
    try msquic.init(std.testing.allocator, libmsquic_path);
}
