const std = @import("std");
const Allocator = std.mem.Allocator;

const MsQuicError = @import("errors.zig").MsQuicError;
const C = @import("header.zig").C;

const Registration = @import("reg.zig").Registration;

pub const Addr = struct {
    internal: std.net.Address,

    pub fn init() Addr {
        return Addr{ .internal = std.mem.zeroes(std.net.Address) };
    }

    pub fn setFamily(self: *Addr, family: C.AddressFamily) void {
        self.internal.any.family = @intFromEnum(family);
    }

    pub fn setPort(self: *Addr, port: u16) void {
       switch (self.internal.any.family) {
           std.posix.AF.INET => self.internal.in.setPort(port),
           std.posix.AF.INET6 => self.internal.in6.setPort(port),
           std.posix.AF.UNSPEC => self.internal.in.setPort(port),
           else => unreachable,
       }
    }

    pub fn format(
        self: Addr,
        comptime fmt: []const u8,
        options: std.fmt.FormatOptions,
        out_stream: anytype,
    ) !void {
        return self.internal.format(fmt, options, out_stream);
    }
};

pub const Chunk = struct {
    const CHUNK_ALIGN = @alignOf(Chunk);
    const CHUNK_SZ = @sizeOf(Chunk);
    const ALIGNMENT = std.mem.Alignment.fromByteUnits(CHUNK_ALIGN);

    allocator: Allocator,
    size: usize,

    pub fn init(allocator: Allocator, size: usize) !*Chunk {
        const total_size = CHUNK_SZ + size;
        const buffer = try allocator.alignedAlloc(u8, ALIGNMENT, total_size);

        const chunk: *Chunk = @ptrCast(buffer.ptr);
        chunk.* = Chunk{
            .allocator = allocator,
            .size = size,
        };
        return chunk;
    }

    fn getSelfPtr(self: *Chunk) [*]align(CHUNK_ALIGN) u8 {
        return @as([*]align(CHUNK_ALIGN) u8, @ptrCast(self));
    }

    pub fn getPtr(self: *Chunk) [*]u8 {
        return @as([*]u8, @ptrCast(self)) + CHUNK_SZ;
    }

    pub fn destroy(self: *Chunk) void {
        const total_size = CHUNK_SZ + self.size;
        const buffer = self.getSelfPtr()[0..total_size];
        self.allocator.free(buffer);
    }

    pub fn getSlice(self: *Chunk) []u8 {
        return self.getPtr()[0..self.size];
    }
};

pub const SendContext = extern struct {
    const Self = @This();
    const ALIGN = @alignOf(Self);
    const SIZE = @sizeOf(Self);
    const ALIGNMENT = std.mem.Alignment.fromByteUnits(ALIGN);

    count: u32,
    buffers: [*]C.Buffer,
    user: ?*anyopaque,
    msquic: *const MsQuic,
    first_buffer: C.Buffer,

    pub fn init(msquic: *const MsQuic, count: u32, user: ?*anyopaque) !*SendContext {
        const additional = if (count > 1) count - 1 else 0;
        const total_size = SIZE + additional * @sizeOf(C.Buffer);
        const buffer = try msquic.allocator.alignedAlloc(u8, ALIGNMENT, total_size);

        const self: *Self = @ptrCast(buffer.ptr);
        self.* = Self{
            .count = count,
            .buffers = @ptrCast(&self.first_buffer),
            .user = user,
            .msquic = msquic,
            .first_buffer = undefined,
        };

        return self;
    }

    fn getSelfPtr(self: *Self) [*]align(ALIGN) u8 {
        return @as([*]align(ALIGN) u8, @ptrCast(self));
    }

    pub fn destroy(self: *Self) void {
        const additional = if (self.count > 1) self.count - 1 else 0;
        const total_size = SIZE + additional * @sizeOf(C.Buffer);
        const buffer = self.getSelfPtr()[0..total_size];
        self.msquic.allocator.free(buffer);
    }
};

pub const MsQuic = struct {
    allocator: Allocator = undefined,
    lib: ?std.DynLib = null,
    open_version_export_fn: ?C.MsQuicOpenVersionFn = null,
    close_export_fn: ?C.MsQuicCloseFn = null,
    api: *const C.ApiTable = undefined,

    pub fn init(self: *MsQuic, allocator: Allocator, path: []const u8) !void {
        var lib = try std.DynLib.open(path);
        errdefer lib.close();

        const open_version = lib.lookup(C.MsQuicOpenVersionFn, "MsQuicOpenVersion")
            orelse return MsQuicError.QzOpenVersionNotFound;
        const close = lib.lookup(C.MsQuicCloseFn, "MsQuicClose")
            orelse return MsQuicError.QzCloseNotFound;

        var api: ?*const C.ApiTable = null;
        const status = open_version(2, &api);
        if (C.StatusCode.failed(status)) return C.StatusCode.toError(status);

        self.api = api orelse return MsQuicError.QzBug;
        self.allocator = allocator;
        self.open_version_export_fn = open_version;
        self.close_export_fn = close;
        self.lib = lib;
    }

    pub fn deinit(self: *MsQuic) void {
        if (self.close_export_fn) |close_fn| {
            close_fn(self.api);
        }

        self.open_version_export_fn = null;
        self.close_export_fn = null;
        if (self.lib) |*lib| {
            lib.close();
            self.lib = null;
        }
    }

    pub fn openReg(self: *MsQuic, app_name: [*:0]const u8, profile: C.ExecutionProfile) !Registration {
        const config = C.RegConfig{
            .app_name = app_name,
            .execution_profile = profile,
        };
        var handle: C.HQUIC = undefined;
        const status = self.api.reg_open(&config, &handle);
        if (C.StatusCode.failed(status)) return C.StatusCode.toError(status);

        return Registration{
            .handle = handle,
            .msquic = self
        };
    }

};

test "test libmsquic.so loading" {
    const libmsquic_path = std.posix.getenv("LIBMSQUIC_PATH") orelse {
        std.debug.print("Error: LIBMSQUIC_PATH environment variable not set\n", .{});
        std.process.exit(1);
    };

    var msquic = MsQuic{};
    defer msquic.deinit();
    try msquic.init(std.testing.allocator, libmsquic_path);
}

test "Chunk init, write, read, destroy" {
    const allocator = std.testing.allocator;

    const message = "Hello, QUIC World!";
    const chunk = try Chunk.init(allocator, message.len);
    defer chunk.destroy();

    const slice1 = chunk.getSlice();
    try std.testing.expectEqual(message.len, slice1.len);

    @memcpy(slice1, message);

    const slice2 = chunk.getSlice();
    try std.testing.expectEqualStrings(message, slice2);
}

test "SendContext basic" {
    const msquic = MsQuic{
        .allocator = std.testing.allocator,
    };

    const context = try SendContext.init(&msquic, 3, null);
    defer context.destroy();

    try std.testing.expect(context.count == 3);

    context.buffers[0].length = 12;
    context.buffers[1].length = 0xFFFFFFFF;
    context.buffers[2].length = 0xDEAD;

    var data: [7]u8 = .{ 1, 2, 3, 4, 5, 6, 7 };
    context.buffers[0].buffer = @ptrCast(&data[6]);
    context.buffers[1].buffer = @ptrCast(&data[2]);
    context.buffers[2].buffer = @ptrCast(&data[0]);

    try std.testing.expectEqual(context.buffers[0].length, 12);
    try std.testing.expectEqual(context.buffers[1].length, 0xFFFFFFFF);
    try std.testing.expectEqual(context.buffers[2].length, 0xDEAD);
}
