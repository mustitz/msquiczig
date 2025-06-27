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
const CredFlags = msquiczig.CredFlags;
const CertFile = msquiczig.CertFile;
const CertFileProtected = msquiczig.CertFileProtected;
const CredConfig = msquiczig.CredConfig;

const IDLE_TIMEOUT = 1000;
const ALPNS = [_][]const u8{ "sample"};

const CERT_PATH = "tls/server.cert";
const KEY_PATH = "tls/server.key";
const PASSWORD = "";

var stdout_tracer = quarkz.cosmos.FileRecorder{
    .min_level = .trace,
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

    fn run(self: *Server) void {
        const atom = self.enter(@src(), "Server.run");
        defer self.leave(@src(), atom);

        atom.?.notice(@src(), "Running!", .{});
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
    server.run();
}
