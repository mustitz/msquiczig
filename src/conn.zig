const C = @import("header.zig").C;
const WrapperError = @import("errors.zig").WrapperError;
const MsQuic = @import("msquic.zig").MsQuic;
const Registration = @import("reg.zig").Registration;
const Configuration = @import("conf.zig").Configuration;

pub const Connection = struct {
    handle: C.HQUIC,
    msquic: *MsQuic,
    ihandler: ?*IHandler,
    data: ?*anyopaque = null,

    pub const IHandler = struct {
        vtable: *const VTable,

        const VTable = struct {
            onConnected: *const fn(
                conn: *Connection,
                session_resumed: bool,
                negotiated_alpn: []const u8,
            ) anyerror!void,

            onShutdownInitiatedByTransport: *const fn(
                conn: *Connection,
                status: ?anyerror,
                error_code: C.QUIC_UINT62,
            ) anyerror!void,

            onShutdownInitiatedByPeer: *const fn(
                conn: *Connection,
                error_code: C.QUIC_UINT62,
            ) anyerror!void,

            onShutdownComplete: *const fn(
                conn: *Connection,
                handshake_completed: bool,
                peer_acknowledged_shutdown: bool,
                app_close_in_progress: bool,
            ) anyerror!void,

            onLocalAddressChanged: *const fn(
                conn: *Connection,
                address: *const C.Addr,
            ) anyerror!void,

            onPeerAddressChanged: *const fn(
                conn: *Connection,
                address: *const C.Addr,
            ) anyerror!void,

            onPeerStreamStarted: *const fn(
                conn: *Connection,
                stream: C.HQUIC,
                flags: C.StreamOpenFlags,
            ) anyerror!void,

            onStreamsAvailable: *const fn(
                conn: *Connection,
                bidirectional_count: u16,
                unidirectional_count: u16,
            ) anyerror!void,

            onPeerNeedsStreams: *const fn(
                conn: *Connection,
                bidirectional: bool,
            ) anyerror!void,

            onIdealProcessorChanged: *const fn(
                conn: *Connection,
                ideal_processor: u16,
                partition_index: u16,
            ) anyerror!void,

            onDatagramStateChanged: *const fn(
                conn: *Connection,
                send_enabled: bool,
                max_send_length: u16,
            ) anyerror!void,

            onDatagramReceived: *const fn(
                conn: *Connection,
                buffer: *const C.Buffer,
                flags: C.ReceiveFlags,
            ) anyerror!void,

            onDatagramSendStateChanged: *const fn(
                conn: *Connection,
                client_context: ?*anyopaque,
                state: C.DatagramSendState,
            ) anyerror!void,

            onResumed: *const fn(
                conn: *Connection,
                resumption_state: []const u8,
            ) anyerror!void,

            onResumptionTicketReceived: *const fn(
                conn: *Connection,
                resumption_ticket: []const u8,
            ) anyerror!void,

            onPeerCertReceived: *const fn(
                conn: *Connection,
                cert: ?*anyopaque,
                deferred_error_flags: u32,
                deferred_status: ?anyerror,
                chain: ?*anyopaque,
            ) anyerror!void,
        };
    };

    pub fn close(self: *const Connection) void {
        self.msquic.api.conn_close(self.handle);
    }

    pub fn destroy(self: *Connection) void {
        self.close();
        self.msquic.allocator.destroy(self);
    }

    pub fn shutdown(
        self: *const Connection,
        flags: C.ConnShutdownFlags,
        error_code: C.QUIC_UINT62,
    ) void {
        self.msquic.api.conn_shutdown(self.handle, flags, error_code);
    }

    pub fn start(
        self: *const Connection,
        conf: Configuration,
        family: C.AddressFamily,
        server_name: ?[*:0]const u8,
        server_port: u16,
    ) !void {
        const status = self.msquic.api.conn_start(
            self.handle,
            conf.handle,
            family,
            server_name,
            server_port
        );

        if (C.StatusCode.failed(status)) return C.StatusCode.toError(status);
    }

    pub fn setConf(self: *const Connection, conf: *const Configuration) !void {
        const status = self.msquic.api.conn_set_conf(self.handle, conf.handle);
        if (C.StatusCode.failed(status)) return C.StatusCode.toError(status);
    }

    pub fn sendResumptionTicket(
        self: *const Connection,
        flags: C.SendResumptionFlags,
        resumption_data: []const u8,
    ) !void {
        const status = self.msquic.api.conn_send_resumption_ticket(
            self.handle,
            flags,
            @intCast(resumption_data.len),
            resumption_data.ptr
        );

        if (C.StatusCode.failed(status)) return C.StatusCode.toError(status);
    }

    pub fn cb(
       conn: C.HQUIC,
       context: ?*anyopaque,
       event: *C.ConnEvent
    ) callconv(.C) C.QUIC_STATUS {
        const self: *Connection = @ptrCast(@alignCast(context));
        const handler = self.ihandler orelse return C.StatusCode.QUIC_STATUS_SUCCESS;
        if (conn != self.handle) {
            return WrapperError.Bug;
        }

        return switch (event.event_type) {
            .connected => self.cbConnected(handler, &event.data.connected),
            else => C.StatusCode.QUIC_STATUS_SUCCESS,
        };
    }

    fn cbConnected(self: *Connection, handler: *IHandler, data: *const C.ConnEvent.Connected) C.QUIC_STATUS {
        const negotiated_alpn = data.negotiated_alpn[0..data.negotiated_alpn_length];
        handler.vtable.onConnected(
            self,
            data.session_resumed,
            negotiated_alpn,
        ) catch |err| return C.StatusCode.fromError(err);
        return C.StatusCode.QUIC_STATUS_SUCCESS;
    }
};
