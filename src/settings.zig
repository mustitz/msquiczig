const C = @import("header.zig").C;

pub const Settings = struct {
    record: C.Settings = C.Settings{},

    pub fn withMaxBytesPerKey(self: *Settings, value: u64) *Settings {
        self.record.is_set.max_bytes_per_key = true;
        self.record.max_bytes_per_key = value;
        return self;
    }

    pub fn withHandshakeIdleTimeoutMs(self: *Settings, value: u64) *Settings {
        self.record.is_set.handshake_idle_timeout_ms = true;
        self.record.handshake_idle_timeout_ms = value;
        return self;
    }

    pub fn withIdleTimeoutMs(self: *Settings, value: u64) *Settings {
        self.record.is_set.idle_timeout_ms = true;
        self.record.idle_timeout_ms = value;
        return self;
    }

    pub fn withMtuDiscoverySearchCompleteTimeoutUs(self: *Settings, value: u64) *Settings {
        self.record.is_set.mtu_discovery_search_complete_timeout_us = true;
        self.record.mtu_discovery_search_complete_timeout_us = value;
        return self;
    }

    pub fn withTlsClientMaxSendBuffer(self: *Settings, value: u32) *Settings {
        self.record.is_set.tls_client_max_send_buffer = true;
        self.record.tls_client_max_send_buffer = value;
        return self;
    }

    pub fn withTlsServerMaxSendBuffer(self: *Settings, value: u32) *Settings {
        self.record.is_set.tls_server_max_send_buffer = true;
        self.record.tls_server_max_send_buffer = value;
        return self;
    }

    pub fn withStreamRecvWindowDefault(self: *Settings, value: u32) *Settings {
        self.record.is_set.stream_recv_window_default = true;
        self.record.stream_recv_window_default = value;
        return self;
    }

    pub fn withStreamRecvBufferDefault(self: *Settings, value: u32) *Settings {
        self.record.is_set.stream_recv_buffer_default = true;
        self.record.stream_recv_buffer_default = value;
        return self;
    }

    pub fn withConnFlowControlWindow(self: *Settings, value: u32) *Settings {
        self.record.is_set.conn_flow_control_window = true;
        self.record.conn_flow_control_window = value;
        return self;
    }

    pub fn withMaxWorkerQueueDelayUs(self: *Settings, value: u32) *Settings {
        self.record.is_set.max_worker_queue_delay_us = true;
        self.record.max_worker_queue_delay_us = value;
        return self;
    }

    pub fn withMaxStatelessOperations(self: *Settings, value: u32) *Settings {
        self.record.is_set.max_stateless_operations = true;
        self.record.max_stateless_operations = value;
        return self;
    }

    pub fn withInitialWindowPackets(self: *Settings, value: u32) *Settings {
        self.record.is_set.initial_window_packets = true;
        self.record.initial_window_packets = value;
        return self;
    }

    pub fn withSendIdleTimeoutMs(self: *Settings, value: u32) *Settings {
        self.record.is_set.send_idle_timeout_ms = true;
        self.record.send_idle_timeout_ms = value;
        return self;
    }

    pub fn withInitialRttMs(self: *Settings, value: u32) *Settings {
        self.record.is_set.initial_rtt_ms = true;
        self.record.initial_rtt_ms = value;
        return self;
    }

    pub fn withMaxAckDelayMs(self: *Settings, value: u32) *Settings {
        self.record.is_set.max_ack_delay_ms = true;
        self.record.max_ack_delay_ms = value;
        return self;
    }

    pub fn withDisconnectTimeoutMs(self: *Settings, value: u32) *Settings {
        self.record.is_set.disconnect_timeout_ms = true;
        self.record.disconnect_timeout_ms = value;
        return self;
    }

    pub fn withKeepAliveIntervalMs(self: *Settings, value: u32) *Settings {
        self.record.is_set.keep_alive_interval_ms = true;
        self.record.keep_alive_interval_ms = value;
        return self;
    }

    pub fn withCongestionControlAlgorithm(self: *Settings, value: u16) *Settings {
        self.record.is_set.congestion_control_algorithm = true;
        self.record.congestion_control_algorithm = value;
        return self;
    }

    pub fn withPeerBidiStreamCount(self: *Settings, value: u16) *Settings {
        self.record.is_set.peer_bidi_stream_count = true;
        self.record.peer_bidi_stream_count = value;
        return self;
    }

    pub fn withPeerUnidiStreamCount(self: *Settings, value: u16) *Settings {
        self.record.is_set.peer_unidi_stream_count = true;
        self.record.peer_unidi_stream_count = value;
        return self;
    }

    pub fn withMaxBindingStatelessOperations(self: *Settings, value: u16) *Settings {
        self.record.is_set.max_binding_stateless_operations = true;
        self.record.max_binding_stateless_operations = value;
        return self;
    }

    pub fn withStatelessOperationExpirationMs(self: *Settings, value: u16) *Settings {
        self.record.is_set.stateless_operation_expiration_ms = true;
        self.record.stateless_operation_expiration_ms = value;
        return self;
    }

    pub fn withMinimumMtu(self: *Settings, value: u16) *Settings {
        self.record.is_set.minimum_mtu = true;
        self.record.minimum_mtu = value;
        return self;
    }

    pub fn withMaximumMtu(self: *Settings, value: u16) *Settings {
        self.record.is_set.maximum_mtu = true;
        self.record.maximum_mtu = value;
        return self;
    }

    pub fn withSendBufferingEnabled(self: *Settings, value: bool) *Settings {
        self.record.is_set.send_buffering_enabled = true;
        self.record.opts.send_buffering_enabled = value;
        return self;
    }

    pub fn withPacingEnabled(self: *Settings, value: bool) *Settings {
        self.record.is_set.pacing_enabled = true;
        self.record.opts.pacing_enabled = value;
        return self;
    }

    pub fn withMigrationEnabled(self: *Settings, value: bool) *Settings {
        self.record.is_set.migration_enabled = true;
        self.record.opts.migration_enabled = value;
        return self;
    }

    pub fn withDatagramReceiveEnabled(self: *Settings, value: bool) *Settings {
        self.record.is_set.datagram_receive_enabled = true;
        self.record.opts.datagram_receive_enabled = value;
        return self;
    }

    pub fn withServerResumptionLevel(self: *Settings, value: C.ServerResumptionLevel) *Settings {
        self.record.is_set.server_resumption_level = true;
        self.record.opts.server_resumption_level = @intCast(@intFromEnum(value));
        return self;
    }

    pub fn withMaxOperationsPerDrain(self: *Settings, value: u8) *Settings {
        self.record.is_set.max_operations_per_drain = true;
        self.record.max_operations_per_drain = value;
        return self;
    }

    pub fn withMtuDiscoveryMissingProbeCount(self: *Settings, value: u8) *Settings {
        self.record.is_set.mtu_discovery_missing_probe_count = true;
        self.record.mtu_discovery_missing_probe_count = value;
        return self;
    }

    pub fn withDestCidUpdateIdleTimeoutMs(self: *Settings, value: u32) *Settings {
        self.record.is_set.dest_cid_update_idle_timeout_ms = true;
        self.record.dest_cid_update_idle_timeout_ms = value;
        return self;
    }

    pub fn withGreaseQuicBitEnabled(self: *Settings, value: bool) *Settings {
        self.record.is_set.grease_quic_bit_enabled = true;
        self.record.opts.grease_quic_bit_enabled = value;
        return self;
    }

    pub fn withEcnEnabled(self: *Settings, value: bool) *Settings {
        self.record.is_set.ecn_enabled = true;
        self.record.opts.ecn_enabled = value;
        return self;
    }

    pub fn withHyStartEnabled(self: *Settings, value: bool) *Settings {
        self.record.is_set.hy_start_enabled = true;
        self.record.flags.hy_start_enabled = value;
        return self;
    }

    pub fn withStreamRecvWindowBidiLocalDefault(self: *Settings, value: u32) *Settings {
        self.record.is_set.stream_recv_window_bidi_local_default = true;
        self.record.stream_recv_window_bidi_local_default = value;
        return self;
    }

    pub fn withStreamRecvWindowBidiRemoteDefault(self: *Settings, value: u32) *Settings {
        self.record.is_set.stream_recv_window_bidi_remote_default = true;
        self.record.stream_recv_window_bidi_remote_default = value;
        return self;
    }

    pub fn withStreamRecvWindowUnidiDefault(self: *Settings, value: u32) *Settings {
        self.record.is_set.stream_recv_window_unidi_default = true;
        self.record.stream_recv_window_unidi_default = value;
        return self;
    }
};
