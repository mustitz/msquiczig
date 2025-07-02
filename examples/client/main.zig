const std = @import("std");
const quarkz = @import("quarkz");
const msquiczig = @import("msquiczig");

const Allocator = std.mem.Allocator;
const Location = std.builtin.SourceLocation;

const Atom = quarkz.Atom;
const Cosmos = quarkz.Cosmos;
const MsQuic = msquiczig.MsQuic;
const MsQuicError = msquiczig.MsQuicError;
const InternalErrorCode = msquiczig.InternalErrorCode;
const Registration = msquiczig.Registration;
const Configuration = msquiczig.Configuration;
const Settings = msquiczig.Settings;
const CredConfig = msquiczig.CredConfig;
const CredFlags = msquiczig.CredFlags;
const Connection = msquiczig.Connection;

const IDLE_TIMEOUT = 1000;
const ALPNS = [_][]const u8{ "sample"};
const SERVER_NAME = "localhost";
const SERVER_PORT = 3690;

var stdout_tracer = quarkz.cosmos.FileRecorder{
    .min_level = .trace,
};

const ClientConnHandler = struct {
    fn onConnected(
        conn: *Connection,
        session_resumed: bool,
        negotiated_alpn: []const u8,
    ) anyerror!void {
        const client: *Client = @ptrCast(@alignCast(conn.data));
        const atom = client.enter(@src(), "Client.Conn.onConnected");
        defer client.leave(@src(), atom);

        const conn_addr = @intFromPtr(conn.handle);
        atom.?.infoFmt(@src(),
            "[0x{x}] Connected: alpn={s}, resumed={}",
            .{conn_addr, negotiated_alpn, session_resumed}, .{});

        // TBD: ClientSend(Connection);
        atom.?.notice(@src(), "TBD: ClientSend implementation", .{});
    }

    fn onShutdownInitiatedByTransport(
        conn: *Connection,
        status: ?anyerror,
        error_code: InternalErrorCode,
    ) anyerror!void {
        const client: *Client = @ptrCast(@alignCast(conn.data));
        const atom = client.enter(@src(), "Client.Conn.onShutdownInitiatedByTransport");
        defer client.leave(@src(), atom);

        const conn_addr = @intFromPtr(conn.handle);
        if (status) |err| {
            if (err == MsQuicError.QzConnIdle) {
                atom.?.infoFmt(@src(), "[0x{x}] Successfully shut down on idle, error_code: {}",
                    .{conn_addr, error_code}, .{});
            } else {
                atom.?.warnFmt(@src(), "[0x{x}] Shut down by transport, status: {any}, error_code: {}",
                    .{conn_addr, err, error_code}, .{});
            }
        } else {
            atom.?.warnFmt(@src(), "[0x{x}] Shut down by transport, no status, error_code: {}",
                .{conn_addr, error_code}, .{});
        }
    }

    fn onShutdownInitiatedByPeer(
        conn: *Connection,
        error_code: InternalErrorCode,
    ) anyerror!void {
        const client: *Client = @ptrCast(@alignCast(conn.data));
        const atom = client.enter(@src(), "Client.Conn.onShutdownInitiatedByPeer");
        defer client.leave(@src(), atom);

        const conn_addr = @intFromPtr(conn.handle);
        atom.?.warnFmt(@src(), "[0x{x}] Shut down by peer, error_code: {}",
            .{conn_addr, error_code}, .{});
    }

    fn onShutdownComplete(
        conn: *Connection,
        handshake_completed: bool,
        peer_acknowledged_shutdown: bool,
        app_close_in_progress: bool,
    ) anyerror!void {
        const client: *Client = @ptrCast(@alignCast(conn.data));
        const atom = client.enter(@src(), "Client.Conn.onShutdownComplete");
        defer client.leave(@src(), atom);

        const conn_addr = @intFromPtr(conn.handle);
        atom.?.infoFmt(@src(),
            "[0x{x}] all done: handshake_completed: {}, peer_acknowledged_shutdown: {}, app_close_in_progress: {}",
            .{conn_addr, handshake_completed, peer_acknowledged_shutdown, app_close_in_progress}, .{});

        if (!app_close_in_progress) {
            conn.destroy();
            atom.?.debug(@src(), "Connection closed & destroyed", .{});
        }
    }

    fn onIdealProcessorChanged(
        conn: *Connection,
        ideal_processor: u16,
        partition_index: u16,
    ) anyerror!void {
        const client: *Client = @ptrCast(@alignCast(conn.data));
        const atom = client.enter(@src(), "Client.Conn.onIdealProcessorChanged");
        defer client.leave(@src(), atom);

        const conn_addr = @intFromPtr(conn.handle);
        atom.?.infoFmt(@src(),
            "[0x{x}] Ideal Processor is: {}, Partition Index: {}",
            .{conn_addr, ideal_processor, partition_index}, .{});
    }
};


const Client = struct {
    allocator: Allocator,
    cosmos: *Cosmos,
    msquic: *MsQuic,
    reg: Registration,
    conf: Configuration,

    fn init(allocator: Allocator, unsecure: bool) !Client {
        const new_cosmos = try Cosmos.create(allocator);
        errdefer new_cosmos.destroy();

        try new_cosmos.addRecorder(stdout_tracer.get());

        const atom_name = "Client.init";
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

        const new_reg = try new_msquic.openReg("client-example", .low_latency);
        errdefer new_reg.close();
        atom.?.debug(@src(), "Registration opened successfully", .{});

        var settings = Settings{};
        _ = settings
            .withIdleTimeoutMs(IDLE_TIMEOUT)
            ;

        const new_conf = try new_reg.openConf(&ALPNS, &settings, null);
        errdefer new_conf.close();
        atom.?.debug(@src(), "Configuration opened successfully", .{});

        var cred = CredConfig{
            .cred_type = .none,
            .flags = CredFlags{ .client = true },
        };

        if (unsecure) {
            cred.flags.no_cert_validation = true;
        }

        try new_conf.loadCred(&cred);
        atom.?.debug(@src(), "Configuration credentials loaded successfully", .{});

        return Client{
            .allocator = allocator,
            .cosmos = new_cosmos,
            .msquic = new_msquic,
            .reg = new_reg,
            .conf = new_conf,
        };
    }

    fn deinit(self: *Client) void {
        {
            const atom = self.enter(@src(), "Client.deinit");
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

    fn enter(self: *Client, loc: Location, name: []const u8) ?*Atom {
        const atom = self.cosmos.newAtom(name) catch { return null; };
        atom.traceFmt(loc, "-----> {s}", .{name}, .{});
        return atom;
    }

    fn leave(self: *Client, loc: Location, atom: ?*Atom) void {
        _ = self;
        if (atom) |a| {
            a.traceFmt(loc, "<----- {s}", .{a.name}, .{});
            a.destroy();
        }
    }

    fn run(self: *Client) !void {
        const atom = self.enter(@src(), "Client.run");
        defer self.leave(@src(), atom);

        const client_conn_handler = Connection.IHandler{
            .onConnected = ClientConnHandler.onConnected,
            .onShutdownInitiatedByTransport = ClientConnHandler.onShutdownInitiatedByTransport,
            .onShutdownInitiatedByPeer = ClientConnHandler.onShutdownInitiatedByPeer,
            .onShutdownComplete = ClientConnHandler.onShutdownComplete,
            .onIdealProcessorChanged = ClientConnHandler.onIdealProcessorChanged,
        };

        const conn = try self.reg.openConn(&client_conn_handler, self);
        errdefer {
            conn.destroy();
        }
        atom.?.debug(@src(), "Connection opened successfully", .{});

        try conn.start(self.conf, .unspec, SERVER_NAME, SERVER_PORT);
        atom.?.debug(@src(), "Connection started successfully", .{});
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

    var client = try Client.init(gpa.allocator(), true);
    defer client.deinit();
    try client.run();
}
