const C = @import("header.zig").C;
const MsQuic = @import("msquic.zig").MsQuic;
const Configuration = @import("conf.zig").Configuration;
const Settings = @import("settings.zig").Settings;

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

    pub fn openConf(
        self: *const Registration,
        alpns: []const []const u8,
        settings: *const Settings,
        data: ?*anyopaque,
    ) !Configuration {
        const QSTACK = 4;
        var stack_placeholder: [QSTACK]C.Buffer = undefined;
        var buffers: [*]C.Buffer = undefined;

        var heap_allocated = false;
        if (alpns.len <= QSTACK) {
            buffers = &stack_placeholder;
        } else {
            buffers = (try self.msquic.allocator.alloc(C.Buffer, alpns.len)).ptr;
            heap_allocated = true;
        }
        defer if (heap_allocated) {
            self.msquic.allocator.free(buffers[0..alpns.len]);
        };

        for (alpns, 0..) |alpn, i| {
            buffers[i] = C.Buffer{
                .length = @intCast(alpn.len),
                .buffer = @constCast(alpn.ptr),
            };
        }

        var handle: C.HQUIC = undefined;

        const status = self.msquic.api.conf_open(
            self.handle,
            buffers,
            @intCast(alpns.len),
            &settings.record,
            @sizeOf(C.Settings),
            null,
            &handle
        );

        if (C.StatusCode.failed(status)) return C.StatusCode.toError(status);

        return Configuration{
           .handle = handle,
           .msquic = self.msquic,
           .data = data,
        };
    }
};
