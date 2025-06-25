const std = @import("std");

const MsQuicError = @import("errors.zig").MsQuicError;
const C = @import("header.zig").C;

pub const MsQuic = struct {
    lib: ?std.DynLib = null,
    open_version_export_fn: ?C.MsQuicOpenVersionFn = null,
    close_export_fn: ?C.MsQuicCloseFn = null,
    api: *const C.ApiTable = undefined,

    pub fn init(self: *MsQuic, path: []const u8) !void {
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
};

test "test libmsquic.so loading" {
    const libmsquic_path = std.posix.getenv("LIBMSQUIC_PATH") orelse {
        std.debug.print("Error: LIBMSQUIC_PATH environment variable not set\n", .{});
        std.process.exit(1);
    };

    var msquic = MsQuic{};
    defer msquic.deinit();
    try msquic.init(libmsquic_path);
}
