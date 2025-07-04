const std = @import("std");
const quarkz = @import("quarkz");
const msquiczig = @import("msquiczig");

const Allocator = std.mem.Allocator;
const Location = std.builtin.SourceLocation;

const Atom = quarkz.Atom;
const Cosmos = quarkz.Cosmos;
const MsQuic = msquiczig.MsQuic;
const Registration = msquiczig.Registration;
const Configuration = msquiczig.Configuration;
const Settings = msquiczig.Settings;
const Connection = msquiczig.Connection;
const Listener = msquiczig.Listener;
const CredFlags = msquiczig.CredFlags;
const CertFile = msquiczig.CertFile;
const CertFileProtected = msquiczig.CertFileProtected;
const CredConfig = msquiczig.CredConfig;
const Addr = msquiczig.Addr;

const IDLE_TIMEOUT = 1000;
const ALPNS = [_][]const u8{ "sample"};
const SERVER_PORT = 3690;

const CERT_PATH = "tls/server.cert";
const KEY_PATH = "tls/server.key";
const PASSWORD = "";

var stdout_tracer = quarkz.cosmos.FileRecorder{
    .min_level = .trace,
};

const Signals = struct {
    var shutdown_semaphore = std.Thread.Semaphore{};

    pub fn init() void {
        var sa: std.posix.Sigaction = .{
            .handler = .{ .handler = &handler },
            .mask = std.posix.sigemptyset(),
            .flags = 0,
        };

        std.posix.sigaction(std.posix.SIG.INT, &sa, null);
    }

    pub fn deinit() void {
    }

    pub fn wait() void {
        shutdown_semaphore.wait();
    }

    fn handler(sig: i32) callconv(.c) void {
        _ = sig;
        shutdown_semaphore.post();
    }
};

const ServerConnHandler = struct {
    fn onConnected(
        conn: *Connection,
        session_resumed: bool,
        negotiated_alpn: []const u8,
    ) anyerror!void {
        _ = session_resumed;
        _ = negotiated_alpn;

        const server: *Server = @ptrCast(@alignCast(conn.data));
        const atom = server.enter(@src(), "Server.Conn.onConnected");
        defer server.leave(@src(), atom);

        const conn_addr = @intFromPtr(conn.handle);
        atom.?.infoFmt(@src(), "[conn][0x{x}] Connected", .{conn_addr}, .{});

        try conn.sendResumptionTicket(.{}, &.{});
        atom.?.debug(@src(), "Resumption ticket sent", .{});
    }

    fn onShutdownInitiatedByTransport(
        conn: *Connection,
        status: ?anyerror,
        error_code: u64,
    ) anyerror!void {
        const server: *Server = @ptrCast(@alignCast(conn.data));
        const atom = server.enter(@src(), "Server.Conn.onShutdownInitiatedByTransport");
        defer server.leave(@src(), atom);

        const conn_addr = @intFromPtr(conn.handle);
        if (status) |err| {
            if (err == msquiczig.MsQuicError.QzConnIdle) {
                atom.?.infoFmt(@src(), "[0x{x}] Successfully shut down on idle.", .{conn_addr}, .{});
            } else {
                atom.?.infoFmt(@src(), "[0x{x}] Shut down by transport, {any}", .{conn_addr, err}, .{});
            }
        } else {
            atom.?.infoFmt(@src(), "[0x{x}] Shut down by transport, error_code: 0x{x}", .{conn_addr, error_code}, .{});
        }
    }

    fn onShutdownInitiatedByPeer(
        conn: *Connection,
        error_code: u64,
    ) anyerror!void {
        const server: *Server = @ptrCast(@alignCast(conn.data));
        const atom = server.enter(@src(), "Server.Conn.onShutdownInitiatedByPeer");
        defer server.leave(@src(), atom);

        const conn_addr = @intFromPtr(conn.handle);
        atom.?.infoFmt(@src(), "[0x{x}] Shut down by peer, 0x{x}",
            .{conn_addr, error_code}, .{});
    }

    fn onShutdownComplete(
        conn: *Connection,
        handshake_completed: bool,
        peer_acknowledged_shutdown: bool,
        app_close_in_progress: bool,
    ) anyerror!void {
        _ = handshake_completed;
        _ = peer_acknowledged_shutdown;
        _ = app_close_in_progress;

        const server: *Server = @ptrCast(@alignCast(conn.data));
        const atom = server.enter(@src(), "Server.Conn.onShutdownComplete");
        defer server.leave(@src(), atom);

        const conn_addr = @intFromPtr(conn.handle);
        atom.?.infoFmt(@src(), "[0x{x}] All done", .{conn_addr}, .{});

        conn.destroy();
        atom.?.debug(@src(), "Connection closed & destroyed", .{});
    }
};

const ServerListenerHandler = struct {
    fn onNewConnection(
        listener: *Listener,
        info: *const Listener.NewConnInfo,
        conn: *Connection,
    ) anyerror!void {
        const server: *Server = @ptrCast(@alignCast(listener.data));
        const atom = server.enter(@src(), "Server.Listener.onNewConnection");
        defer server.leave(@src(), atom);

        const listener_addr = @intFromPtr(listener.handle);
        atom.?.infoFmt(@src(), "[0x{x}] New connection from {any} to {any}",
            .{listener_addr, info.remote_address, info.local_address}, .{});
        atom.?.infoFmt(@src(), "  QUIC version: 0x{x}", .{info.quic_version}, .{});
        atom.?.infoFmt(@src(), "  Server name: {s}", .{info.server_name}, .{});
        atom.?.infoFmt(@src(), "  Negotiated ALPN: {s}", .{info.negotiated_alpn}, .{});

        conn.data = server;
        conn.ihandler.onConnected = ServerConnHandler.onConnected;
        conn.ihandler.onShutdownInitiatedByTransport = ServerConnHandler.onShutdownInitiatedByTransport;
        conn.ihandler.onShutdownInitiatedByPeer = ServerConnHandler.onShutdownInitiatedByPeer;
        conn.ihandler.onShutdownComplete = ServerConnHandler.onShutdownComplete;

        const conn_addr = @intFromPtr(conn.handle);

        try conn.setConf(&server.conf);
        atom.?.debug(@src(), "[0x{x}] Connection configured & accepted", .{conn_addr});
    }
};

const Server = struct {
    allocator: Allocator,
    cosmos: *Cosmos,
    msquic: *MsQuic,
    reg: Registration,
    conf: Configuration,

    fn init(allocator: Allocator) !Server {
        const new_cosmos = try Cosmos.create(allocator);
        errdefer new_cosmos.destroy();

        try new_cosmos.addRecorder(stdout_tracer.get());

        const atom_name = "Server.init";
        const atom: ?*Atom = new_cosmos.newAtom(atom_name) catch null;
        atom.?.traceFmt(@src(), "-----> {s}", .{atom_name}, .{});
        defer {
            atom.?.traceFmt(@src(), "<----- {s}", .{atom_name}, .{});
            atom.?.destroy();
        }

        const libmsquic_path = std.posix.getenv("LIBMSQUIC_PATH") orelse {
            atom.?.err(@src(), "Env variable LIBMSQUIC_PATH is not set", .{});
            return error.LibPathNotSet;
        };
        atom.?.infoFmt(@src(), "Try to load: {s}", .{libmsquic_path}, .{});

        const new_msquic = try allocator.create(MsQuic);
        errdefer allocator.destroy(new_msquic);

        new_msquic.* = MsQuic{};
        try new_msquic.init(allocator, libmsquic_path);
        errdefer new_msquic.deinit();
        atom.?.debug(@src(), "MsQuic library loaded successfully", .{});

        const new_reg = try new_msquic.openReg("server-example", .low_latency);
        errdefer new_reg.close();
        atom.?.debug(@src(), "Registration opened successfully", .{});

        var settings = Settings{};
        _ = settings
            .withIdleTimeoutMs(IDLE_TIMEOUT)
            .withServerResumptionLevel(.resume_and_zerortt)
            .withPeerBidiStreamCount(1)
            ;

        const new_conf = try new_reg.openConf(&ALPNS, &settings, null);
        errdefer new_conf.close();
        atom.?.debug(@src(), "Configuration opened successfully", .{});

        const has_password = PASSWORD.len > 0;
        var cred = CredConfig{
            .cred_type = if (has_password) .cert_file else .cert_file_protected,
            .flags = CredFlags{},
        };

        atom.?.infoFmt(@src(),
            "Loading server certificates: cert={s}, key={s}, password={s}",
            .{CERT_PATH, KEY_PATH, if (has_password) "yes" else "no"}, .{});

        if (has_password) {
            var cert_file = CertFile{
                .cert_file = CERT_PATH.ptr,
                .private_key_file = KEY_PATH.ptr,
            };
            cred.cred_data = &cert_file;
        } else {
            var cert_file_protected = CertFileProtected{
                .cert_file = CERT_PATH.ptr,
                .private_key_file = KEY_PATH.ptr,
                .private_key_password = PASSWORD.ptr,
            };
            cred.cred_data = &cert_file_protected;
        }

        try new_conf.loadCred(&cred);
        atom.?.debug(@src(), "Configuration credentials loaded successfully", .{});

        return Server{
            .allocator = allocator,
            .cosmos = new_cosmos,
            .msquic = new_msquic,
            .reg = new_reg,
            .conf = new_conf,
        };
    }

    fn deinit(self: *Server) void {
        {
            const atom = self.enter(@src(), "Server.deinit");
            defer self.leave(@src(), atom);

            self.conf.close();
            atom.?.debug(@src(), "Configuration closed", .{});

            self.reg.close();
            atom.?.debug(@src(), "Registration closed", .{});

            self.msquic.deinit();
            self.allocator.destroy(self.msquic);
            atom.?.debug(@src(), "MsQuic library unloaded", .{});
        }

        self.cosmos.destroy();
    }

    fn enter(self: *Server, loc: Location, name: []const u8) ?*Atom {
        const atom = self.cosmos.newAtom(name) catch { return null; };
        atom.traceFmt(loc, "-----> {s}", .{name}, .{});
        return atom;
    }

    fn leave(self: *Server, loc: Location, atom: ?*Atom) void {
        _ = self;
        if (atom) |a| {
            a.traceFmt(loc, "<----- {s}", .{a.name}, .{});
            a.destroy();
        }
    }

    fn run(self: *Server) !void {
        const atom = self.enter(@src(), "Server.run");
        defer self.leave(@src(), atom);

        Signals.init();
        defer Signals.deinit();

        const server_listener_handler = Listener.IHandler{
            .onNewConnection = ServerListenerHandler.onNewConnection,
        };

        const listener = try self.reg.openListener(&server_listener_handler, self);
        defer {
            listener.destroy();
            atom.?.debug(@src(), "Listener closed & destroyed", .{});
        }

        atom.?.debug(@src(), "Listener opened successfully", .{});

        var addr = Addr.init();
        addr.setFamily(.unspec);
        addr.setPort(SERVER_PORT);

        try listener.start(&ALPNS, &addr);
        atom.?.debug(@src(), "Listener started successfully", .{});

        atom.?.notice(@src(), "Server is running. Press Ctrl+C to stop...", .{});
        Signals.wait();
        atom.?.notice(@src(), "Received SIGINT, shutting down gracefully...", .{});
    }
};

pub fn main() !void {
    const GPA = std.heap.GeneralPurposeAllocator(.{
        .safety = true,
        .retain_metadata = true,
    });

    var gpa = GPA{};
    defer {
        const leaked = gpa.deinit();
        if (leaked == .leak) {
            std.debug.print("MEMORY LEAK DETECTED!\n", .{});
        }
    }

    var server = try Server.init(gpa.allocator());
    defer server.deinit();
    try server.run();
}
