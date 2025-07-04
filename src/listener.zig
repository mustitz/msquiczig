const C = @import("header.zig").C;
const MsQuic = @import("msquic.zig").MsQuic;
const Addr = @import("msquic.zig").Addr;
const Connection = @import("conn.zig").Connection;


pub const Listener = struct {
    handle: C.HQUIC,
    msquic: *MsQuic,
    ihandler: IHandler,
    data: ?*anyopaque = null,

    pub const NewConnInfo = struct {
        quic_version: u32,
        local_address: *const Addr,
        remote_address: *const Addr,
        crypto_buffer: []const u8,
        client_alpn_list: []const u8,
        negotiated_alpn: []const u8,
        server_name: []const u8,

        fn init(data: *const C.NewConnInfo) NewConnInfo {
            return NewConnInfo{
               .quic_version = data.quic_version,
               .local_address = @ptrCast(data.local_address),
               .remote_address = @ptrCast(data.remote_address),
               .crypto_buffer = data.crypto_buffer[0..data.crypto_buffer_length],
               .client_alpn_list = data.client_alpn_list[0..data.client_alpn_list_length],
               .negotiated_alpn = data.negotiated_alpn[0..data.negotiated_alpn_length],
               .server_name = data.server_name[0..data.server_name_length],
            };
        }
    };

    pub const IHandler = struct {
       const OnNewConnection = ?*const fn(
           listener: *Listener,
           info: *const NewConnInfo,
           conn: *Connection,
       ) anyerror!void;

       const OnStopComplete = ?*const fn(
           listener: *Listener,
           app_close_in_progress: bool,
       ) anyerror!void;

       const OnDosModeChanged = ?*const fn(
           listener: *Listener,
           dos_mode_enabled: bool,
       ) anyerror!void;

       onNewConnection: OnNewConnection = null,
       onStopComplete: OnStopComplete = null,
       onDosModeChanged: OnDosModeChanged = null,
    };

    pub fn close(self: *const Listener) void {
       self.msquic.api.listener_close(self.handle);
    }

    pub fn destroy(self: *Listener) void {
        self.close();
        self.msquic.allocator.destroy(self);
    }

    pub fn start(
       self: *const Listener,
       alpns: []const []const u8,
       local_address: *const Addr,
    ) !void {
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

       const status = self.msquic.api.listener_start(
           self.handle,
           buffers,
           @intCast(alpns.len),
           &local_address.internal,
       );

       if (C.StatusCode.failed(status)) return C.StatusCode.toError(status);
    }

    pub fn stop(self: *const Listener) void {
       self.msquic.api.listener_stop(self.handle);
    }

    pub fn cb(
       listener: C.HQUIC,
       context: ?*anyopaque,
       event: *C.ListenerEvent,
    ) callconv(.C) C.QUIC_STATUS {
       const self: *Listener = @ptrCast(@alignCast(context));
       if (listener != self.handle) {
           return C.StatusCode.QUIC_STATUS_INTERNAL_ERROR;
       }

       const result = switch (event.event_type) {
           .new_conn =>
               self.cbNewConnection(&self.ihandler, &event.data.new_conn),
           .stop_complete =>
               self.cbStopComplete(&self.ihandler, &event.data.stop_complete),
           .dos_mode_changed =>
               self.cbDosModeChanged(&self.ihandler, &event.data.dos_mode_changed),
       };

       return result;
    }

    fn cbNewConnection(
        self: *Listener,
        handler: *IHandler,
        data: *const C.ListenerEvent.NewConn,
    ) C.QUIC_STATUS {
        const onNewConnection = handler.onNewConnection
            orelse return C.StatusCode.QUIC_STATUS_NOT_SUPPORTED;

        const info = NewConnInfo.init(data.info);

        const conn = self.msquic.allocator.create(Connection) catch |err|
            return C.StatusCode.fromError(err);

        conn.* = Connection{
            .handle = data.conn,
            .msquic = self.msquic,
            .ihandler = .{},
            .data = null,
        };

        self.msquic.api.set_context(data.conn, conn);
        self.msquic.api.set_callback_handler(data.conn, @ptrCast(&Connection.cb), conn);

        onNewConnection(self, &info, conn) catch |err| {
            self.msquic.allocator.destroy(conn);
            return C.StatusCode.fromError(err);
        };

        return C.StatusCode.QUIC_STATUS_SUCCESS;
    }

    fn cbStopComplete(
       self: *Listener,
       handler: *IHandler,
       data: *const C.ListenerEvent.StopComplete,
    ) C.QUIC_STATUS {
       const onStopComplete = handler.onStopComplete
           orelse return C.StatusCode.QUIC_STATUS_SUCCESS;

       onStopComplete(
           self,
           data.app_close_in_progress,
       ) catch |err| return C.StatusCode.fromError(err);

       return C.StatusCode.QUIC_STATUS_SUCCESS;
    }

    fn cbDosModeChanged(
       self: *Listener,
       handler: *IHandler,
       data: *const C.ListenerEvent.DosModeChanged,
    ) C.QUIC_STATUS {
       const onDosModeChanged = handler.onDosModeChanged
           orelse return C.StatusCode.QUIC_STATUS_SUCCESS;

       onDosModeChanged(
           self,
           data.dos_mode_enabled,
       ) catch |err| return C.StatusCode.fromError(err);

       return C.StatusCode.QUIC_STATUS_SUCCESS;
    }
};
