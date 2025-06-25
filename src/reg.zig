const C = @import("header.zig").C;
const MsQuic = @import("msquic.zig").MsQuic;

pub const Registration = struct {
    handle: C.HQUIC,
    msquic: *MsQuic,
    data: ?*anyopaque = null,

    pub fn close(self: *const Registration) void {
        self.msquic.api.reg_close(self.handle);
    }

    pub fn shutdown(self: *const Registration, flags: C.ConnShutdownFlags, error_code: C.QUIC_UINT62) void {
        self.msquic.api.reg_shutdown(self.handle, flags, error_code);
    }
};
