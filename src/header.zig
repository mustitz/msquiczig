const std = @import("std");

const MsQuicError = @import("errors.zig").MsQuicError;

pub const C = struct {

    // Platform
    pub const QUIC_STATUS = i32;

    pub const AddressFamily = std.posix.sa_family_t;

    pub const Addr = extern union {
       ip: std.posix.sockaddr,
       ipv4: std.posix.sockaddr.in,
       ipv6: std.posix.sockaddr.in6,
    };

    pub const StatusCode = struct {
        // Success
        const QUIC_STATUS_SUCCESS: i32 = 0;
        const QUIC_STATUS_PENDING: i32 = -2;
        const QUIC_STATUS_CONTINUE: i32 = -1;

        // Offsets
        const ERROR_BASE: i32 = 200000000;                    // 0xBEBC200
        const TLS_ERROR_BASE: i32 = 256 + ERROR_BASE;         // 0xBEBC300
        const CERT_ERROR_BASE: i32 = 512 + ERROR_BASE;        // 0xBEBC400

        // Base errors
        const QUIC_STATUS_OUT_OF_MEMORY: i32 = @intFromEnum(std.posix.E.NOMEM);
        const QUIC_STATUS_INVALID_PARAMETER: i32 = @intFromEnum(std.posix.E.INVAL);
        const QUIC_STATUS_INVALID_STATE: i32 = @intFromEnum(std.posix.E.PERM);
        const QUIC_STATUS_NOT_SUPPORTED: i32 = @intFromEnum(std.posix.E.OPNOTSUPP);
        const QUIC_STATUS_NOT_FOUND: i32 = @intFromEnum(std.posix.E.NOENT);
        const QUIC_STATUS_FILE_NOT_FOUND: i32 = @intFromEnum(std.posix.E.NOENT);
        const QUIC_STATUS_BUFFER_TOO_SMALL: i32 = @intFromEnum(std.posix.E.OVERFLOW);
        const QUIC_STATUS_HANDSHAKE_FAILURE: i32 = @intFromEnum(std.posix.E.CONNABORTED);
        const QUIC_STATUS_ABORTED: i32 = @intFromEnum(std.posix.E.CANCELED);
        const QUIC_STATUS_ADDRESS_IN_USE: i32 = @intFromEnum(std.posix.E.ADDRINUSE);
        const QUIC_STATUS_INVALID_ADDRESS: i32 = @intFromEnum(std.posix.E.AFNOSUPPORT);
        const QUIC_STATUS_CONNECTION_TIMEOUT: i32 = @intFromEnum(std.posix.E.TIMEDOUT);
        const QUIC_STATUS_CONNECTION_IDLE: i32 = @intFromEnum(std.posix.E.TIME);
        const QUIC_STATUS_INTERNAL_ERROR: i32 = @intFromEnum(std.posix.E.IO);
        const QUIC_STATUS_CONNECTION_REFUSED: i32 = @intFromEnum(std.posix.E.CONNREFUSED);
        const QUIC_STATUS_PROTOCOL_ERROR: i32 = @intFromEnum(std.posix.E.PROTO);
        const QUIC_STATUS_VER_NEG_ERROR: i32 = @intFromEnum(std.posix.E.PROTONOSUPPORT);
        const QUIC_STATUS_UNREACHABLE: i32 = @intFromEnum(std.posix.E.HOSTUNREACH);
        const QUIC_STATUS_TLS_ERROR: i32 = @intFromEnum(std.posix.E.NOKEY);
        const QUIC_STATUS_USER_CANCELED: i32 = @intFromEnum(std.posix.E.OWNERDEAD);
        const QUIC_STATUS_ALPN_NEG_FAILURE: i32 = @intFromEnum(std.posix.E.NOPROTOOPT);
        const QUIC_STATUS_STREAM_LIMIT_REACHED: i32 = @intFromEnum(std.posix.E.STRPIPE);
        const QUIC_STATUS_ALPN_IN_USE: i32 = @intFromEnum(std.posix.E.PROTOTYPE);
        const QUIC_STATUS_ADDRESS_NOT_AVAILABLE: i32 = @intFromEnum(std.posix.E.ADDRNOTAVAIL);

        // TLS Alert errors
        const QUIC_STATUS_CLOSE_NOTIFY: i32 = TLS_ERROR_BASE + 0;             // 0xBEBC300
        const QUIC_STATUS_BAD_CERTIFICATE: i32 = TLS_ERROR_BASE + 42;         // 0xBEBC32A
        const QUIC_STATUS_UNSUPPORTED_CERTIFICATE: i32 = TLS_ERROR_BASE + 43; // 0xBEBC32B
        const QUIC_STATUS_REVOKED_CERTIFICATE: i32 = TLS_ERROR_BASE + 44;     // 0xBEBC32C
        const QUIC_STATUS_EXPIRED_CERTIFICATE: i32 = TLS_ERROR_BASE + 45;     // 0xBEBC32D
        const QUIC_STATUS_UNKNOWN_CERTIFICATE: i32 = TLS_ERROR_BASE + 46;     // 0xBEBC32E
        const QUIC_STATUS_REQUIRED_CERTIFICATE: i32 = TLS_ERROR_BASE + 116;   // 0xBEBC374

        // Cert errors
        const QUIC_STATUS_CERT_EXPIRED: i32 = CERT_ERROR_BASE + 1;            // 0xBEBC401
        const QUIC_STATUS_CERT_UNTRUSTED_ROOT: i32 = CERT_ERROR_BASE + 2;     // 0xBEBC402
        const QUIC_STATUS_CERT_NO_CERT: i32 = CERT_ERROR_BASE + 3;            // 0xBEBC403

        pub fn toError(status: QUIC_STATUS) MsQuicError {
           return switch (status) {
               // Base errors
               QUIC_STATUS_OUT_OF_MEMORY => MsQuicError.OutOfMemory,
               QUIC_STATUS_INVALID_PARAMETER => MsQuicError.InvalidParameter,
               QUIC_STATUS_INVALID_STATE => MsQuicError.InvalidState,
               QUIC_STATUS_NOT_SUPPORTED => MsQuicError.NotSupported,
               QUIC_STATUS_NOT_FOUND => MsQuicError.NotFound,
               // TODO: duplicate but different on Windows QUIC_STATUS_FILE_NOT_FOUND => MsQuicError.FileNotFound,
               QUIC_STATUS_BUFFER_TOO_SMALL => MsQuicError.BufferTooSmall,
               QUIC_STATUS_HANDSHAKE_FAILURE => MsQuicError.HandshakeFailure,
               QUIC_STATUS_ABORTED => MsQuicError.Aborted,
               QUIC_STATUS_ADDRESS_IN_USE => MsQuicError.AddressInUse,
               QUIC_STATUS_INVALID_ADDRESS => MsQuicError.InvalidAddress,
               QUIC_STATUS_CONNECTION_TIMEOUT => MsQuicError.ConnTimeout,
               QUIC_STATUS_CONNECTION_IDLE => MsQuicError.ConnIdle,
               QUIC_STATUS_INTERNAL_ERROR => MsQuicError.InternalError,
               QUIC_STATUS_CONNECTION_REFUSED => MsQuicError.ConnRefused,
               QUIC_STATUS_PROTOCOL_ERROR => MsQuicError.ProtocolError,
               QUIC_STATUS_VER_NEG_ERROR => MsQuicError.VersionNegError,
               QUIC_STATUS_UNREACHABLE => MsQuicError.Unreachable,
               QUIC_STATUS_TLS_ERROR => MsQuicError.TlsError,
               QUIC_STATUS_USER_CANCELED => MsQuicError.UserCanceled,
               QUIC_STATUS_ALPN_NEG_FAILURE => MsQuicError.AlpnNegFailure,
               QUIC_STATUS_STREAM_LIMIT_REACHED => MsQuicError.StreamLimitReached,
               QUIC_STATUS_ALPN_IN_USE => MsQuicError.AlpnInUse,
               QUIC_STATUS_ADDRESS_NOT_AVAILABLE => MsQuicError.AddressNotAvailable,

               // TLS errors
               QUIC_STATUS_CLOSE_NOTIFY => MsQuicError.CloseNotify,
               QUIC_STATUS_BAD_CERTIFICATE => MsQuicError.BadCert,
               QUIC_STATUS_UNSUPPORTED_CERTIFICATE => MsQuicError.UnsupportedCert,
               QUIC_STATUS_REVOKED_CERTIFICATE => MsQuicError.RevokedCert,
               QUIC_STATUS_EXPIRED_CERTIFICATE => MsQuicError.ExpiredCert,
               QUIC_STATUS_UNKNOWN_CERTIFICATE => MsQuicError.UnknownCert,
               QUIC_STATUS_REQUIRED_CERTIFICATE => MsQuicError.RequiredCert,

               // Cert errors
               QUIC_STATUS_CERT_EXPIRED => MsQuicError.CertExpired,
               QUIC_STATUS_CERT_UNTRUSTED_ROOT => MsQuicError.CertUntrustedRoot,
               QUIC_STATUS_CERT_NO_CERT => MsQuicError.CertNoCert,

               else => MsQuicError.InternalError,
           };
        }

        pub fn fromMsQuicError(err: MsQuicError) QUIC_STATUS {
            return switch (err) {
                MsQuicError.OutOfMemory => QUIC_STATUS_OUT_OF_MEMORY,
                MsQuicError.InvalidParameter => QUIC_STATUS_INVALID_PARAMETER,
                MsQuicError.InvalidState => QUIC_STATUS_INVALID_STATE,
                MsQuicError.NotSupported => QUIC_STATUS_NOT_SUPPORTED,
                MsQuicError.NotFound => QUIC_STATUS_NOT_FOUND,
                MsQuicError.FileNotFound => QUIC_STATUS_FILE_NOT_FOUND,
                MsQuicError.BufferTooSmall => QUIC_STATUS_BUFFER_TOO_SMALL,
                MsQuicError.HandshakeFailure => QUIC_STATUS_HANDSHAKE_FAILURE,
                MsQuicError.Aborted => QUIC_STATUS_ABORTED,
                MsQuicError.AddressInUse => QUIC_STATUS_ADDRESS_IN_USE,
                MsQuicError.InvalidAddress => QUIC_STATUS_INVALID_ADDRESS,
                MsQuicError.ConnTimeout => QUIC_STATUS_CONNECTION_TIMEOUT,
                MsQuicError.ConnIdle => QUIC_STATUS_CONNECTION_IDLE,
                MsQuicError.InternalError => QUIC_STATUS_INTERNAL_ERROR,
                MsQuicError.ConnRefused => QUIC_STATUS_CONNECTION_REFUSED,
                MsQuicError.ProtocolError => QUIC_STATUS_PROTOCOL_ERROR,
                MsQuicError.VersionNegError => QUIC_STATUS_VER_NEG_ERROR,
                MsQuicError.Unreachable => QUIC_STATUS_UNREACHABLE,
                MsQuicError.TlsError => QUIC_STATUS_TLS_ERROR,
                MsQuicError.UserCanceled => QUIC_STATUS_USER_CANCELED,
                MsQuicError.AlpnNegFailure => QUIC_STATUS_ALPN_NEG_FAILURE,
                MsQuicError.StreamLimitReached => QUIC_STATUS_STREAM_LIMIT_REACHED,
                MsQuicError.AlpnInUse => QUIC_STATUS_ALPN_IN_USE,
                MsQuicError.AddressNotAvailable => QUIC_STATUS_ADDRESS_NOT_AVAILABLE,
                MsQuicError.CloseNotify => QUIC_STATUS_CLOSE_NOTIFY,
                MsQuicError.BadCert => QUIC_STATUS_BAD_CERTIFICATE,
                MsQuicError.UnsupportedCert => QUIC_STATUS_UNSUPPORTED_CERTIFICATE,
                MsQuicError.RevokedCert => QUIC_STATUS_REVOKED_CERTIFICATE,
                MsQuicError.ExpiredCert => QUIC_STATUS_EXPIRED_CERTIFICATE,
                MsQuicError.UnknownCert => QUIC_STATUS_UNKNOWN_CERTIFICATE,
                MsQuicError.RequiredCert => QUIC_STATUS_REQUIRED_CERTIFICATE,
                MsQuicError.CertExpired => QUIC_STATUS_CERT_EXPIRED,
                MsQuicError.CertUntrustedRoot => QUIC_STATUS_CERT_UNTRUSTED_ROOT,
                MsQuicError.CertNoCert => QUIC_STATUS_CERT_NO_CERT,
                MsQuicError.OpenVersionNotFound,
                MsQuicError.CloseNotFound,
                MsQuicError.Bug => QUIC_STATUS_INTERNAL_ERROR,
            };
        }

        pub fn fromError(err: anyerror) QUIC_STATUS {
            const msquic_err: MsQuicError = @errorCast(err);
            if (msquic_err != null) {
                return fromMsQuicError(msquic_err);
            }

            return switch (err) {
                error.OutOfMemory => QUIC_STATUS_OUT_OF_MEMORY,
                error.InvalidArgument => QUIC_STATUS_INVALID_PARAMETER,
                error.ConnectionRefused => QUIC_STATUS_CONNECTION_REFUSED,
                error.ConnectionTimedOut => QUIC_STATUS_CONNECTION_TIMEOUT,
                error.NetworkUnreachable => QUIC_STATUS_UNREACHABLE,
                error.AddressInUse => QUIC_STATUS_ADDRESS_IN_USE,
                error.AddressNotAvailable => QUIC_STATUS_ADDRESS_NOT_AVAILABLE,
                error.OperationAborted => QUIC_STATUS_ABORTED,
                error.Canceled => QUIC_STATUS_USER_CANCELED,
                error.NotFound => QUIC_STATUS_NOT_FOUND,
                error.BufferTooSmall => QUIC_STATUS_BUFFER_TOO_SMALL,
                error.FileNotFound => QUIC_STATUS_FILE_NOT_FOUND,
                else => QUIC_STATUS_INTERNAL_ERROR,
            };
        }

        pub fn success(status: QUIC_STATUS) bool {
            return status <= 0;
        }

        pub fn failed(status: QUIC_STATUS) bool {
            return status > 0;
        }
    };



    // Common

    pub const MsQuicOpenVersionFn = *const fn(
        version: u32,
        quic_api: *?*const C.ApiTable
    ) callconv(.C) QUIC_STATUS;

    pub const MsQuicCloseFn = *const fn(
        quic_api: ?*const C.ApiTable
    ) callconv(.C) void;



    pub const HQUIC = *anyopaque;
    pub const QUIC_UINT62 = u64;



    pub const ExecutionProfile = enum(c_int) {
        low_latency = 0,
        max_throughput = 1,
        scavenger = 2,
        real_time = 3,
    };

    pub const CredType = enum(c_int) {
       none = 0,
       cert_hash = 1,
       cert_hash_store = 2,
       cert_context = 3,
       cert_file = 4,
       cert_file_protected = 5,
       cert_pkcs12 = 6,
    };

    pub const ListenerEventType = enum(c_int) {
        new_conn = 0,
        stop_complete = 1,
        dos_mode_changed = 2,
    };

    pub const ConnEventType = enum(c_int) {
        connected = 0,
        shutdown_initiated_by_transport = 1,
        shutdown_initiated_by_peer = 2,
        shutdown_complete = 3,
        local_address_changed = 4,
        peer_address_changed = 5,
        peer_stream_started = 6,
        streams_available = 7,
        peer_needs_streams = 8,
        ideal_processor_changed = 9,
        datagram_state_changed = 10,
        datagram_received = 11,
        datagram_send_state_changed = 12,
        resumed = 13,
        resumption_ticket_received = 14,
        peer_cert_received = 15,
    };

    pub const DatagramSendState = enum(c_int) {
        unknown = 0,
        sent = 1,
        lost_suspect = 2,
        lost_discarded = 3,
        acknowledged = 4,
        acknowledged_spurious = 5,
        canceled = 6,
    };

    pub const StreamEventType = enum(c_int) {
        start_complete = 0,
        receive = 1,
        send_complete = 2,
        peer_send_shutdown = 3,
        peer_send_aborted = 4,
        peer_receive_aborted = 5,
        send_shutdown_complete = 6,
        shutdown_complete = 7,
        ideal_send_buffer_size = 8,
        peer_accepted = 9,
        cancel_on_loss = 10,
    };

    pub const ServerResumptionLevel = enum(c_int) {
        no_resume = 0,
        resume_only = 1,
        resume_and_zerortt = 2,
    };



    pub const ConnShutdownFlags = packed struct(u32) {
        silent: bool = false,
        _reserved: u31 = 0,

        pub const NONE = ConnShutdownFlags{};
        pub const SILENT = ConnShutdownFlags{ .silent = true };
    };

    pub const SettingsIsSet = packed struct(u64) {
       max_bytes_per_key: bool = false,
       handshake_idle_timeout_ms: bool = false,
       idle_timeout_ms: bool = false,
       mtu_discovery_search_complete_timeout_us: bool = false,
       tls_client_max_send_buffer: bool = false,
       tls_server_max_send_buffer: bool = false,
       stream_recv_window_default: bool = false,
       stream_recv_buffer_default: bool = false,
       conn_flow_control_window: bool = false,
       max_worker_queue_delay_us: bool = false,
       max_stateless_operations: bool = false,
       initial_window_packets: bool = false,
       send_idle_timeout_ms: bool = false,
       initial_rtt_ms: bool = false,
       max_ack_delay_ms: bool = false,
       disconnect_timeout_ms: bool = false,
       keep_alive_interval_ms: bool = false,
       congestion_control_algorithm: bool = false,
       peer_bidi_stream_count: bool = false,
       peer_unidi_stream_count: bool = false,
       max_binding_stateless_operations: bool = false,
       stateless_operation_expiration_ms: bool = false,
       minimum_mtu: bool = false,
       maximum_mtu: bool = false,
       send_buffering_enabled: bool = false,
       pacing_enabled: bool = false,
       migration_enabled: bool = false,
       datagram_receive_enabled: bool = false,
       server_resumption_level: bool = false,
       max_operations_per_drain: bool = false,
       mtu_discovery_missing_probe_count: bool = false,
       dest_cid_update_idle_timeout_ms: bool = false,
       grease_quic_bit_enabled: bool = false,
       ecn_enabled: bool = false,
       hy_start_enabled: bool = false,
       stream_recv_window_bidi_local_default: bool = false,
       stream_recv_window_bidi_remote_default: bool = false,
       stream_recv_window_unidi_default: bool = false,
       _reserved: u26 = 0,
    };

    pub const SettingsOpts = packed struct(u8) {
       send_buffering_enabled: bool = false,
       pacing_enabled: bool = false,
       migration_enabled: bool = false,
       datagram_receive_enabled: bool = false,
       server_resumption_level: u2 = 0,
       grease_quic_bit_enabled: bool = false,
       ecn_enabled: bool = false,
    };

    pub const SettingsFlags = packed struct(u64) {
       hy_start_enabled: bool = false,
       _reserved: u63 = 0,
    };

    pub const CredFlags = packed struct(u32) {
        client: bool = false,
        load_asynchronous: bool = false,
        no_cert_validation: bool = false,
        enable_ocsp: bool = false,
        indicate_cert_received: bool = false,
        defer_cert_validation: bool = false,
        require_client_authentication: bool = false,
        use_tls_builtin_cert_validation: bool = false,
        revocation_check_end_cert: bool = false,
        revocation_check_chain: bool = false,
        revocation_check_chain_exclude_root: bool = false,
        ignore_no_revocation_check: bool = false,
        ignore_revocation_offline: bool = false,
        set_allowed_cipher_suites: bool = false,
        use_portable_certs: bool = false,
        use_supplied_creds: bool = false,
        use_system_mapper: bool = false,
        cache_only_url_retrieval: bool = false,
        revocation_check_cache_only: bool = false,
        inproc_peer_cert: bool = false,
        set_ca_cert_file: bool = false,
        disable_aia: bool = false,
        _reserved: u10 = 0,
    };

    pub const CertHashStoreFlags = packed struct(u32) {
        machine_store: bool = false,
        _reserved: u31 = 0,
    };

    pub const AllowedCipherSuiteFlags = packed struct(u32) {
        aes_128_gcm_sha256: bool = false,
        aes_256_gcm_sha384: bool = false,
        chacha20_poly1305_sha256: bool = false,
        _reserved: u29 = 0,
    };

    pub const StreamOpenFlags = packed struct(u32) {
        unidirectional: bool = false,
        zero_rtt: bool = false,
        delay_id_fc_updates: bool = false,
        _reserved: u29 = 0,
    };

    pub const ReceiveFlags = packed struct(u32) {
        zero_rtt: bool = false,
        fin: bool = false,
        _reserved: u30 = 0,
    };

    pub const SendResumptionFlags = packed struct(u32) {
        final: bool = false,
        _reserved: u31 = 0,
    };

    pub const StreamStartFlags = packed struct(u32) {
        immediate: bool = false,
        fail_blocked: bool = false,
        shutdown_on_fail: bool = false,
        indicate_peer_accept: bool = false,
        priority_work: bool = false,
        _reserved: u27 = 0,
    };

    pub const StreamShutdownFlags = packed struct(u32) {
        graceful: bool = false,
        abort_send: bool = false,
        abort_receive: bool = false,
        immediate: bool = false,
        instant: bool = false,
        _reserved: u27 = 0,

        pub const ABORT = StreamShutdownFlags{ .abort_send = true, .abort_receive = true };
    };

    pub const SendFlags = packed struct(u32) {
        allow_0_rtt: bool = false,
        start: bool = false,
        fin: bool = false,
        dgram_priority: bool = false,
        delay_send: bool = false,
        cancel_on_loss: bool = false,
        priority_work: bool = false,
        cancel_on_blocked: bool = false,
        _reserved: u24 = 0,
    };



    pub const Buffer = extern struct {
        length: u32,
        buffer: [*]u8,
    };

    pub const RegConfig = extern struct {
        app_name: ?[*:0]const u8,
        execution_profile: ExecutionProfile,
    };

    pub const Settings = extern struct {
       is_set: SettingsIsSet = SettingsIsSet{},
       max_bytes_per_key: u64 = undefined,
       handshake_idle_timeout_ms: u64 = undefined,
       idle_timeout_ms: u64 = undefined,
       mtu_discovery_search_complete_timeout_us: u64 = undefined,
       tls_client_max_send_buffer: u32 = undefined,
       tls_server_max_send_buffer: u32 = undefined,
       stream_recv_window_default: u32 = undefined,
       stream_recv_buffer_default: u32 = undefined,
       conn_flow_control_window: u32 = undefined,
       max_worker_queue_delay_us: u32 = undefined,
       max_stateless_operations: u32 = undefined,
       initial_window_packets: u32 = undefined,
       send_idle_timeout_ms: u32 = undefined,
       initial_rtt_ms: u32 = undefined,
       max_ack_delay_ms: u32 = undefined,
       disconnect_timeout_ms: u32 = undefined,
       keep_alive_interval_ms: u32 = undefined,
       congestion_control_algorithm: u16 = undefined,
       peer_bidi_stream_count: u16 = undefined,
       peer_unidi_stream_count: u16 = undefined,
       max_binding_stateless_operations: u16 = undefined,
       stateless_operation_expiration_ms: u16 = undefined,
       minimum_mtu: u16 = undefined,
       maximum_mtu: u16 = undefined,
       opts: SettingsOpts = undefined,
       max_operations_per_drain: u8 = undefined,
       mtu_discovery_missing_probe_count: u8 = undefined,
       dest_cid_update_idle_timeout_ms: u32 = undefined,
       flags: SettingsFlags = undefined,
       stream_recv_window_bidi_local_default: u32 = undefined,
       stream_recv_window_bidi_remote_default: u32 = undefined,
       stream_recv_window_unidi_default: u32 = undefined,
    };

    pub const CertHash = extern struct {
        sha_hash: [20]u8,
    };

    pub const CertHashStore = extern struct {
        flags: CertHashStoreFlags,
        sha_hash: [20]u8,
        store_name: [128]u8,
    };

    pub const CertFile = extern struct {
        private_key_file: ?[*:0]const u8,
        cert_file: ?[*:0]const u8,
    };

    pub const CertFileProtected = extern struct {
        private_key_file: ?[*:0]const u8,
        cert_file: ?[*:0]const u8,
        private_key_password: ?[*:0]const u8,
    };

    pub const CertPkcs12 = extern struct {
        asn1_blob: ?[*]const u8,
        asn1_blob_length: u32,
        private_key_password: ?[*:0]const u8,
    };

    pub const CredConfig = extern struct {
       cred_type: CredType,
       flags: CredFlags = CredFlags{},
       cred_data: ?*anyopaque = null, // Union replaced with generic pointer
       principal: ?[*:0]const u8 = null,
       reserved: ?*anyopaque = null,
       async_handler: CredLoadCompleteHandler = null,
       allowed_cipher_suites: AllowedCipherSuiteFlags = AllowedCipherSuiteFlags{},
       ca_cert_file: ?[*:0]const u8 = null,
    };

    pub const NewConnInfo = extern struct {
        quic_version: u32,
        local_address: *const Addr,
        remote_address: *const Addr,
        crypto_buffer_length: u32,
        client_alpn_list_length: u16,
        server_name_length: u16,
        negotiated_alpn_length: u8,
        crypto_buffer: [*]const u8,
        client_alpn_list: [*]const u8,
        negotiated_alpn: [*]const u8,
        server_name: ?[*]const u8,
    };

    pub const ListenerEvent = extern struct {
        event_type: ListenerEventType,
        data: extern union {
            new_conn: extern struct {
                info: ?*const NewConnInfo,
                conn: HQUIC,
            },
            stop_complete: packed struct(u8) {
                app_close_in_progress: bool,
                _reserved: u7 = 0,
            },
            dos_mode_changed: packed struct(u8) {
                dos_mode_enabled: bool,
                _reserved: u7 = 0,
            },
        },
    };

    pub const ConnEvent = extern struct {
        event_type: ConnEventType,
        data: extern union {
            connected: Connected,
            shutdown_initiated_by_transport: ShutdownInitiatedByTransport,
            shutdown_initiated_by_peer: ShutdownInitiatedByPeer,
            shutdown_complete: ShutdownComplete,
            local_address_changed: LocalAddressChanged,
            peer_address_changed: PeerAddressChanged,
            peer_stream_started: PeerStreamStarted,
            streams_available: StreamsAvailable,
            peer_needs_streams: PeerNeedsStreams,
            ideal_processor_changed: IdealProcessorChanged,
            datagram_state_changed: DatagramStateChanged,
            datagram_received: DatagramReceived,
            datagram_send_state_changed: DatagramSendStateChanged,
            resumed: Resumed,
            resumption_ticket_received: ResumptionTicketReceived,
            peer_cert_received: PeerCertReceived,
        },

        pub const Connected = extern struct {
            session_resumed: bool,
            negotiated_alpn_length: u8,
            negotiated_alpn: [*]const u8,
        };

        pub const ShutdownInitiatedByTransport = extern struct {
            status: QUIC_STATUS,
            error_code: QUIC_UINT62,
        };

        pub const ShutdownInitiatedByPeer = extern struct {
            error_code: QUIC_UINT62,
        };

        pub const ShutdownComplete = extern struct {
            handshake_completed: bool,
            peer_acknowledged_shutdown: bool,
            app_close_in_progress: bool,
        };

        pub const LocalAddressChanged = extern struct {
            address: *const Addr,
        };

        pub const PeerAddressChanged = extern struct {
            address: *const Addr,
        };

        pub const PeerStreamStarted = extern struct {
            stream: HQUIC,
            flags: StreamOpenFlags,
        };

        pub const StreamsAvailable = extern struct {
            bidirectional_count: u16,
            unidirectional_count: u16,
        };

        pub const PeerNeedsStreams = extern struct {
            bidirectional: bool,
        };

        pub const IdealProcessorChanged = extern struct {
            ideal_processor: u16,
            partition_index: u16,
        };

        pub const DatagramStateChanged = extern struct {
            send_enabled: bool,
            max_send_length: u16,
        };

        pub const DatagramReceived = extern struct {
            buffer: *const Buffer,
            flags: ReceiveFlags,
        };

        pub const DatagramSendStateChanged = extern struct {
            client_context: ?*anyopaque,
            state: DatagramSendState,
        };

        pub const Resumed = extern struct {
            resumption_state_length: u16,
            resumption_state: [*]const u8,
        };

        pub const ResumptionTicketReceived = extern struct {
            resumption_ticket_length: u32,
            resumption_ticket: [*]const u8,
        };

        pub const PeerCertReceived = extern struct {
            cert: ?*anyopaque,
            deferred_error_flags: u32,
            deferred_status: QUIC_STATUS,
            chain: ?*anyopaque,
        };
    };

    pub const StreamEvent = extern struct {
        event_type: StreamEventType,
        data: extern union {
            start_complete: extern struct {
                status: QUIC_STATUS,
                id: QUIC_UINT62,
                peer_accepted: bool,
            },
            receive: extern struct {
                absolute_offset: u64,
                total_buffer_length: u64,
                buffers: [*]const Buffer,
                buffer_count: u32,
                flags: ReceiveFlags,
            },
            send_complete: extern struct {
                canceled: bool,
                client_context: ?*anyopaque,
            },
            peer_send_aborted: extern struct {
                error_code: QUIC_UINT62,
            },
            peer_receive_aborted: extern struct {
                error_code: QUIC_UINT62,
            },
            send_shutdown_complete: extern struct {
                graceful: bool,
            },
            shutdown_complete: extern struct {
                conn_shutdown: bool,
                app_close_in_progress: bool,
                conn_shutdown_by_app: bool,
                conn_closed_remotely: bool,
                conn_error_code: QUIC_UINT62,
                conn_close_status: QUIC_STATUS,
            },
            ideal_send_buffer_size: extern struct {
                byte_count: u64,
            },
            cancel_on_loss: extern struct {
                error_code: QUIC_UINT62,
            },
        },
    };




    pub const CredLoadCompleteHandler = ?*const fn(
        conf: HQUIC,
        context: ?*anyopaque,
        status: QUIC_STATUS
    ) callconv(.C) void;

    pub const ListenerCallbackHandler = *const fn(
        listener: HQUIC,
        context: ?*anyopaque,
        event: *ListenerEvent,
    ) callconv(.C) QUIC_STATUS;

    pub const ConnCallbackHandler = *const fn(
       conn: HQUIC,
       context: ?*anyopaque,
       event: *ConnEvent
    ) callconv(.C) QUIC_STATUS;

    pub const StreamCallbackHandler = *const fn(
       stream: HQUIC,
       context: ?*anyopaque,
       event: *StreamEvent
    ) callconv(.C) QUIC_STATUS;



    pub const SetContextFn = *const fn(
        handle: HQUIC,
        context: ?*anyopaque
    ) callconv(.C) void;

    pub const GetContextFn = *const fn(
        handle: HQUIC
    ) callconv(.C) ?*anyopaque;

    pub const SetCallbackHandlerFn = *const fn(
        handle: HQUIC,
        handler: *anyopaque,
        context: ?*anyopaque
    ) callconv(.C) void;


    pub const SetParamFn = *const fn(
       handle: HQUIC,
       param: u32,
       buffer_length: u32,
       buffer: *const anyopaque
    ) callconv(.C) QUIC_STATUS;

    pub const GetParamFn = *const fn(
       handle: HQUIC,
       param: u32,
       buffer_length: *u32,
       buffer: ?*anyopaque
    ) callconv(.C) QUIC_STATUS;


    pub const RegOpenFn = *const fn(
       config: ?*const RegConfig,
       reg: *HQUIC
    ) callconv(.C) QUIC_STATUS;

    pub const RegCloseFn = *const fn(
       reg: HQUIC
    ) callconv(.C) void;

    pub const RegShutdownFn = *const fn(
       reg: HQUIC,
       flags: ConnShutdownFlags,
       error_code: QUIC_UINT62
    ) callconv(.C) void;


    pub const ConfOpenFn = *const fn(
       reg: HQUIC,
       alpn_buffers: [*]const Buffer,
       alpn_buffer_count: u32,
       settings: ?*const Settings,
       settings_size: u32,
       context: ?*anyopaque,
       conf: *HQUIC
    ) callconv(.C) QUIC_STATUS;

    pub const ConfCloseFn = *const fn(
        conf: HQUIC
    ) callconv(.C) void;

    pub const ConfLoadCredFn = *const fn(
       conf: HQUIC,
       cred_config: *const CredConfig
    ) callconv(.C) QUIC_STATUS;


    pub const ListenerOpenFn = *const fn(
        reg: HQUIC,
        handler: ListenerCallbackHandler,
        context: ?*anyopaque,
        listener: *HQUIC
    ) callconv(.C) QUIC_STATUS;

    pub const ListenerCloseFn = *const fn(
        listener: HQUIC
    ) callconv(.C) void;

    pub const ListenerStartFn = *const fn(
        listener: HQUIC,
        alpn_buffers: [*]const Buffer,
        alpn_buffer_count: u32,
        local_address: ?*const Addr
    ) callconv(.C) QUIC_STATUS;

    pub const ListenerStopFn = *const fn(
        listener: HQUIC
    ) callconv(.C) void;


    pub const ConnOpenFn = *const fn(
        reg: HQUIC,
        handler: ConnCallbackHandler,
        context: ?*anyopaque,
        conn: *HQUIC
    ) callconv(.C) QUIC_STATUS;

    pub const ConnCloseFn = *const fn(
        conn: HQUIC
    ) callconv(.C) void;

    pub const ConnShutdownFn = *const fn(
        conn: HQUIC,
        flags: ConnShutdownFlags,
        error_code: QUIC_UINT62
    ) callconv(.C) void;

    pub const ConnStartFn = *const fn(
        conn: HQUIC,
        conf: HQUIC,
        family: AddressFamily,
        server_name: ?[*:0]const u8,
        server_port: u16
    ) callconv(.C) QUIC_STATUS;

    pub const ConnSetConfFn = *const fn(
        conn: HQUIC,
        conf: HQUIC
    ) callconv(.C) QUIC_STATUS;

    pub const ConnSendResumptionTicketFn = *const fn(
        conn: HQUIC,
        flags: SendResumptionFlags,
        data_length: u16,
        resumption_data: ?[*]const u8
    ) callconv(.C) QUIC_STATUS;


    pub const StreamOpenFn = *const fn(
        conn: HQUIC,
        flags: StreamOpenFlags,
        handler: StreamCallbackHandler,
        context: ?*anyopaque,
        stream: *HQUIC
    ) callconv(.C) QUIC_STATUS;

    pub const StreamCloseFn = *const fn(
        stream: HQUIC
    ) callconv(.C) void;

    pub const StreamStartFn = *const fn(
        stream: HQUIC,
        flags: StreamStartFlags
    ) callconv(.C) QUIC_STATUS;

    pub const StreamShutdownFn = *const fn(
        stream: HQUIC,
        flags: StreamShutdownFlags,
        error_code: QUIC_UINT62
    ) callconv(.C) QUIC_STATUS;

    pub const StreamSendFn = *const fn(
        stream: HQUIC,
        buffers: [*]const Buffer,
        buffer_count: u32,
        flags: SendFlags,
        client_send_context: ?*anyopaque
    ) callconv(.C) QUIC_STATUS;

    pub const StreamReceiveCompleteFn = *const fn(
        stream: HQUIC,
        buffer_length: u64
    ) callconv(.C) void;

    pub const StreamReceiveSetEnabledFn = *const fn(
        stream: HQUIC,
        is_enabled: bool
    ) callconv(.C) QUIC_STATUS;


    pub const DatagramSendFn = *const fn(
        conn: HQUIC,
        buffers: [*]const Buffer,
        buffer_count: u32,
        flags: SendFlags,
        client_send_context: ?*anyopaque
    ) callconv(.C) QUIC_STATUS;



    pub const ApiTable = struct {
        set_context: SetContextFn,
        get_context: GetContextFn,
        set_callback_handler: SetCallbackHandlerFn,

        set_param: SetParamFn,
        get_param: GetParamFn,

        reg_open: RegOpenFn,
        reg_close: RegCloseFn,
        reg_shutdown: RegShutdownFn,

        conf_open: ConfOpenFn,
        conf_close: ConfCloseFn,
        conf_load_cred: ConfLoadCredFn,

        listener_open: ListenerOpenFn,
        listener_close: ListenerCloseFn,
        listener_start: ListenerStartFn,
        listener_stop: ListenerStopFn,

        conn_open: ConnOpenFn,
        conn_close: ConnCloseFn,
        conn_shutdown: ConnShutdownFn,
        conn_start: ConnStartFn,
        conn_set_conf: ConnSetConfFn,
        conn_send_resumption_ticket: ConnSendResumptionTicketFn,

        stream_open: StreamOpenFn,
        stream_close: StreamCloseFn,
        stream_start: StreamStartFn,
        stream_shutdown: StreamShutdownFn,
        stream_send: StreamSendFn,
        stream_receive_complete: StreamReceiveCompleteFn,
        stream_receive_set_enabled: StreamReceiveSetEnabledFn,

        datagram_send: DatagramSendFn,
    };
};
