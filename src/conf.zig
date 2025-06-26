const C = @import("header.zig").C;
const MsQuic = @import("msquic.zig").MsQuic;

pub const Configuration = struct {
    handle: C.HQUIC,
    msquic: *MsQuic,
    data: ?*anyopaque = null,

    pub fn close(self: Configuration) void {
        self.msquic.api.conf_close(self.handle);
    }

    pub fn loadCred(self: Configuration, cred_config: *const C.CredConfig) !void {
        const status = self.msquic.api.conf_load_cred(self.handle, cred_config);
        if (C.StatusCode.failed(status)) return C.StatusCode.toError(status);
    }
};
