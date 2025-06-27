const C = @import("header.zig").C;
const MsQuic = @import("msquic.zig").MsQuic;
const Addr = @import("msquic.zig").Addr;
const Configuration = @import("conf.zig").Configuration;

pub const Connection = struct {
    handle: C.HQUIC,
    msquic: *MsQuic,
    ihandler: IHandler,
    data: ?*anyopaque = null,

    pub const IHandler = struct {
        const OnConnected = ?*const fn(
            conn: *Connection,
            session_resumed: bool,
            negotiated_alpn: []const u8,
        ) anyerror!void;

        const OnShutdownInitiatedByTransport = ?*const fn(
            conn: *Connection,
            status: ?anyerror,
            error_code: C.QUIC_UINT62,
        ) anyerror!void;

        const OnShutdownInitiatedByPeer = ?*const fn(
            conn: *Connection,
            error_code: C.QUIC_UINT62,
        ) anyerror!void;

        const OnShutdownComplete = ?*const fn(
            conn: *Connection,
            handshake_completed: bool,
            peer_acknowledged_shutdown: bool,
            app_close_in_progress: bool,
        ) anyerror!void;

        const OnLocalAddressChanged = ?*const fn(
            conn: *Connection,
            address: *const Addr,
        ) anyerror!void;

        const OnPeerAddressChanged = ?*const fn(
            conn: *Connection,
            address: *const Addr,
        ) anyerror!void;

        const OnPeerStreamStarted = ?*const fn(
            conn: *Connection,
            stream: C.HQUIC,
            flags: C.StreamOpenFlags,
        ) anyerror!void;

        const OnStreamsAvailable = ?*const fn(
            conn: *Connection,
            bidirectional_count: u16,
            unidirectional_count: u16,
        ) anyerror!void;

        const OnPeerNeedsStreams = ?*const fn(
            conn: *Connection,
            bidirectional: bool,
        ) anyerror!void;

        const OnIdealProcessorChanged = ?*const fn(
            conn: *Connection,
            ideal_processor: u16,
            partition_index: u16,
        ) anyerror!void;

        const OnDatagramStateChanged = ?*const fn(
            conn: *Connection,
            send_enabled: bool,
            max_send_length: u16,
        ) anyerror!void;

        const OnDatagramReceived = ?*const fn(
            conn: *Connection,
            buffer: *const C.Buffer,
            flags: C.ReceiveFlags,
        ) anyerror!void;

        const OnDatagramSendStateChanged = ?*const fn(
            conn: *Connection,
            client_context: ?*anyopaque,
            state: C.DatagramSendState,
        ) anyerror!void;

        const OnResumed = ?*const fn(
            conn: *Connection,
            resumption_state: []const u8,
        ) anyerror!void;

        const OnResumptionTicketReceived = ?*const fn(
            conn: *Connection,
            resumption_ticket: []const u8,
        ) anyerror!void;

        const OnPeerCertReceived = ?*const fn(
            conn: *Connection,
            cert: ?*anyopaque,
            deferred_error_flags: u32,
            deferred_status: ?anyerror,
            chain: ?*anyopaque,
        ) anyerror!void;

        onConnected: OnConnected = null,
        onShutdownInitiatedByTransport: OnShutdownInitiatedByTransport = null,
        onShutdownInitiatedByPeer: OnShutdownInitiatedByPeer = null,
        onShutdownComplete: OnShutdownComplete = null,
        onLocalAddressChanged: OnLocalAddressChanged = null,
        onPeerAddressChanged: OnPeerAddressChanged = null,
        onPeerStreamStarted: OnPeerStreamStarted = null,
        onStreamsAvailable: OnStreamsAvailable = null,
        onPeerNeedsStreams: OnPeerNeedsStreams = null,
        onIdealProcessorChanged: OnIdealProcessorChanged = null,
        onDatagramStateChanged: OnDatagramStateChanged = null,
        onDatagramReceived: OnDatagramReceived = null,
        onDatagramSendStateChanged: OnDatagramSendStateChanged = null,
        onResumed: OnResumed = null,
        onResumptionTicketReceived: OnResumptionTicketReceived = null,
        onPeerCertReceived: OnPeerCertReceived = null,
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
        if (conn != self.handle) {
            return C.StatusCode.QUIC_STATUS_INTERNAL_ERROR;
        }

        const result = switch (event.event_type) {
            .connected =>
                self.cbConnected(&self.ihandler,
                    &event.data.connected),
            .shutdown_initiated_by_transport =>
                self.cbShutdownInitiatedByTransport(&self.ihandler,
                    &event.data.shutdown_initiated_by_transport),
            .shutdown_initiated_by_peer =>
                self.cbShutdownInitiatedByPeer(&self.ihandler,
                    &event.data.shutdown_initiated_by_peer),
            .shutdown_complete =>
                self.cbShutdownComplete(&self.ihandler,
                    &event.data.shutdown_complete),
            .local_address_changed =>
                self.cbLocalAddressChanged(&self.ihandler,
                    &event.data.local_address_changed),
            .peer_address_changed =>
                self.cbPeerAddressChanged(&self.ihandler,
                    &event.data.peer_address_changed),
            .peer_stream_started =>
                self.cbPeerStreamStarted(&self.ihandler,
                    &event.data.peer_stream_started),
            .streams_available =>
                self.cbStreamsAvailable(&self.ihandler,
                    &event.data.streams_available),
            .peer_needs_streams =>
                self.cbPeerNeedsStreams(&self.ihandler,
                    &event.data.peer_needs_streams),
            .ideal_processor_changed =>
                self.cbIdealProcessorChanged(&self.ihandler,
                    &event.data.ideal_processor_changed),
            .datagram_state_changed =>
                self.cbDatagramStateChanged(&self.ihandler,
                    &event.data.datagram_state_changed),
            .datagram_received =>
                self.cbDatagramReceived(&self.ihandler,
                    &event.data.datagram_received),
            .datagram_send_state_changed =>
                self.cbDatagramSendStateChanged(&self.ihandler,
                    &event.data.datagram_send_state_changed),
            .resumed =>
                self.cbResumed(&self.ihandler,
                    &event.data.resumed),
            .resumption_ticket_received =>
                self.cbResumptionTicketReceived(&self.ihandler,
                    &event.data.resumption_ticket_received),
            .peer_cert_received =>
                self.cbPeerCertReceived(&self.ihandler,
                    &event.data.peer_cert_received),
        };

        return result;
    }

    fn cbConnected(
        self: *Connection,
        handler: *IHandler,
        data: *const C.ConnEvent.Connected,
    ) C.QUIC_STATUS {
        const onConnected = handler.onConnected
            orelse return C.StatusCode.QUIC_STATUS_SUCCESS;
        const negotiated_alpn = data.negotiated_alpn[0..data.negotiated_alpn_length];
        onConnected(
            self,
            data.session_resumed,
            negotiated_alpn,
        ) catch |err| return C.StatusCode.fromError(err);
        return C.StatusCode.QUIC_STATUS_SUCCESS;
    }

    fn cbShutdownInitiatedByTransport(
        self: *Connection,
        handler: *IHandler,
        data: *const C.ConnEvent.ShutdownInitiatedByTransport,
    ) C.QUIC_STATUS {
        const onShutdownInitiatedByTransport = handler.onShutdownInitiatedByTransport
            orelse return C.StatusCode.QUIC_STATUS_SUCCESS;
        const status = C.StatusCode.toStatus(data.status);
        onShutdownInitiatedByTransport(
            self,
            status,
            data.error_code,
        ) catch |err| return C.StatusCode.fromError(err);
        return C.StatusCode.QUIC_STATUS_SUCCESS;
    }

    fn cbShutdownInitiatedByPeer(
        self: *Connection,
        handler: *IHandler,
        data: *const C.ConnEvent.ShutdownInitiatedByPeer,
    ) C.QUIC_STATUS {
        const onShutdownInitiatedByPeer = handler.onShutdownInitiatedByPeer
            orelse return C.StatusCode.QUIC_STATUS_SUCCESS;
        onShutdownInitiatedByPeer(
            self,
            data.error_code,
        ) catch |err| return C.StatusCode.fromError(err);
        return C.StatusCode.QUIC_STATUS_SUCCESS;
    }

    fn cbShutdownComplete(
        self: *Connection,
        handler: *IHandler,
        data: *const C.ConnEvent.ShutdownComplete,
    ) C.QUIC_STATUS {
        const onShutdownComplete = handler.onShutdownComplete
            orelse return C.StatusCode.QUIC_STATUS_SUCCESS;
        onShutdownComplete(
            self,
            data.handshake_completed,
            data.peer_acknowledged_shutdown,
            data.app_close_in_progress,
        ) catch |err| return C.StatusCode.fromError(err);
        return C.StatusCode.QUIC_STATUS_SUCCESS;
    }

    fn cbLocalAddressChanged(
        self: *Connection,
        handler: *IHandler,
        data: *const C.ConnEvent.LocalAddressChanged,
    ) C.QUIC_STATUS {
        const onLocalAddressChanged = handler.onLocalAddressChanged
            orelse return C.StatusCode.QUIC_STATUS_SUCCESS;
        onLocalAddressChanged(
            self,
            @ptrCast(data.address),
        ) catch |err| return C.StatusCode.fromError(err);
        return C.StatusCode.QUIC_STATUS_SUCCESS;
    }

    fn cbPeerAddressChanged(
        self: *Connection,
        handler: *IHandler,
        data: *const C.ConnEvent.PeerAddressChanged,
    ) C.QUIC_STATUS {
        const onPeerAddressChanged = handler.onPeerAddressChanged
            orelse return C.StatusCode.QUIC_STATUS_SUCCESS;
        onPeerAddressChanged(
            self,
            @ptrCast(data.address),
        ) catch |err| return C.StatusCode.fromError(err);
        return C.StatusCode.QUIC_STATUS_SUCCESS;
    }

    fn cbPeerStreamStarted(
        self: *Connection,
        handler: *IHandler,
        data: *const C.ConnEvent.PeerStreamStarted,
    ) C.QUIC_STATUS {
        const onPeerStreamStarted = handler.onPeerStreamStarted
            orelse return C.StatusCode.QUIC_STATUS_SUCCESS;
        onPeerStreamStarted(
            self,
            data.stream,
            data.flags,
        ) catch |err| return C.StatusCode.fromError(err);
        return C.StatusCode.QUIC_STATUS_SUCCESS;
    }

    fn cbStreamsAvailable(
        self: *Connection,
        handler: *IHandler,
        data: *const C.ConnEvent.StreamsAvailable,
    ) C.QUIC_STATUS {
        const onStreamsAvailable = handler.onStreamsAvailable
            orelse return C.StatusCode.QUIC_STATUS_SUCCESS;
        onStreamsAvailable(
            self,
            data.bidirectional_count,
            data.unidirectional_count,
        ) catch |err| return C.StatusCode.fromError(err);
        return C.StatusCode.QUIC_STATUS_SUCCESS;
    }

    fn cbPeerNeedsStreams(
        self: *Connection,
        handler: *IHandler,
        data: *const C.ConnEvent.PeerNeedsStreams,
    ) C.QUIC_STATUS {
        const onPeerNeedsStreams = handler.onPeerNeedsStreams
            orelse return C.StatusCode.QUIC_STATUS_SUCCESS;
        onPeerNeedsStreams(
            self,
            data.bidirectional,
        ) catch |err| return C.StatusCode.fromError(err);
        return C.StatusCode.QUIC_STATUS_SUCCESS;
    }

    fn cbIdealProcessorChanged(
        self: *Connection,
        handler: *IHandler,
        data: *const C.ConnEvent.IdealProcessorChanged,
    ) C.QUIC_STATUS {
        const onIdealProcessorChanged = handler.onIdealProcessorChanged
            orelse return C.StatusCode.QUIC_STATUS_SUCCESS;
        onIdealProcessorChanged(
            self,
            data.ideal_processor,
            data.partition_index,
        ) catch |err| return C.StatusCode.fromError(err);
        return C.StatusCode.QUIC_STATUS_SUCCESS;
    }

    fn cbDatagramStateChanged(
        self: *Connection,
        handler: *IHandler,
        data: *const C.ConnEvent.DatagramStateChanged,
    ) C.QUIC_STATUS {
        const onDatagramStateChanged = handler.onDatagramStateChanged
            orelse return C.StatusCode.QUIC_STATUS_SUCCESS;
        onDatagramStateChanged(
            self,
            data.send_enabled,
            data.max_send_length,
        ) catch |err| return C.StatusCode.fromError(err);
        return C.StatusCode.QUIC_STATUS_SUCCESS;
    }

    fn cbDatagramReceived(
        self: *Connection,
        handler: *IHandler,
        data: *const C.ConnEvent.DatagramReceived,
    ) C.QUIC_STATUS {
        const onDatagramReceived = handler.onDatagramReceived
            orelse return C.StatusCode.QUIC_STATUS_SUCCESS;
        onDatagramReceived(
            self,
            data.buffer,
            data.flags,
        ) catch |err| return C.StatusCode.fromError(err);
        return C.StatusCode.QUIC_STATUS_SUCCESS;
    }

    fn cbDatagramSendStateChanged(
        self: *Connection,
        handler: *IHandler,
        data: *const C.ConnEvent.DatagramSendStateChanged,
    ) C.QUIC_STATUS {
        const onDatagramSendStateChanged = handler.onDatagramSendStateChanged
            orelse return C.StatusCode.QUIC_STATUS_SUCCESS;
        onDatagramSendStateChanged(
            self,
            data.client_context,
            data.state,
        ) catch |err| return C.StatusCode.fromError(err);
        return C.StatusCode.QUIC_STATUS_SUCCESS;
    }

    fn cbResumed(
        self: *Connection,
        handler: *IHandler,
        data: *const C.ConnEvent.Resumed,
    ) C.QUIC_STATUS {
        const onResumed = handler.onResumed
            orelse return C.StatusCode.QUIC_STATUS_SUCCESS;
        const resumption_state = data.resumption_state[0..data.resumption_state_length];
        onResumed(
            self,
            resumption_state,
        ) catch |err| return C.StatusCode.fromError(err);
        return C.StatusCode.QUIC_STATUS_SUCCESS;
    }

    fn cbResumptionTicketReceived(
        self: *Connection,
        handler: *IHandler,
        data: *const C.ConnEvent.ResumptionTicketReceived,
    ) C.QUIC_STATUS {
        const onResumptionTicketReceived = handler.onResumptionTicketReceived
            orelse return C.StatusCode.QUIC_STATUS_SUCCESS;
        const resumption_ticket = data.resumption_ticket[0..data.resumption_ticket_length];
        onResumptionTicketReceived(
            self,
            resumption_ticket,
        ) catch |err| return C.StatusCode.fromError(err);
        return C.StatusCode.QUIC_STATUS_SUCCESS;
    }

    fn cbPeerCertReceived(
        self: *Connection,
        handler: *IHandler,
        data: *const C.ConnEvent.PeerCertReceived,
    ) C.QUIC_STATUS {
        const onPeerCertReceived = handler.onPeerCertReceived
            orelse return C.StatusCode.QUIC_STATUS_SUCCESS;
        const deferred_status = C.StatusCode.toStatus(data.deferred_status);
        onPeerCertReceived(
            self,
            data.cert,
            data.deferred_error_flags,
            deferred_status,
            data.chain,
        ) catch |err| return C.StatusCode.fromError(err);
        return C.StatusCode.QUIC_STATUS_SUCCESS;
    }
};
