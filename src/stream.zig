const std = @import("std");
const Allocator = std.mem.Allocator;

const C = @import("header.zig").C;
const MsQuic = @import("msquic.zig").MsQuic;
const WrapperError = @import("errors.zig").WrapperError;

pub const Stream = struct {
    handle: C.HQUIC,
    msquic: *MsQuic,
    ihandler: IHandler,
    data: ?*anyopaque = null,

    const SendContext = extern struct {
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

    pub const IHandler = struct {
        const OnStartComplete = ?*const fn(
            stream: *Stream,
            status: ?anyerror,
            id: C.QUIC_UINT62,
            peer_accepted: bool,
        ) anyerror!void;

        const OnReceive = ?*const fn(
            stream: *Stream,
            absolute_offset: u64,
            buffers: []const []const u8,
            flags: C.ReceiveFlags,
        ) anyerror!void;

        const OnSendComplete = ?*const fn(
            stream: *Stream,
            canceled: bool,
            client_context: ?*anyopaque,
        ) anyerror!void;

        const OnPeerSendShutdown = ?*const fn(
            stream: *Stream,
        ) anyerror!void;

        const OnPeerSendAborted = ?*const fn(
            stream: *Stream,
            error_code: C.QUIC_UINT62,
        ) anyerror!void;

        const OnPeerReceiveAborted = ?*const fn(
            stream: *Stream,
            error_code: C.QUIC_UINT62,
        ) anyerror!void;

        const OnSendShutdownComplete = ?*const fn(
            stream: *Stream,
            graceful: bool,
        ) anyerror!void;

        const OnShutdownComplete = ?*const fn(
            stream: *Stream,
            conn_shutdown: bool,
            app_close_in_progress: bool,
            conn_shutdown_by_app: bool,
            conn_closed_remotely: bool,
            conn_error_code: C.QUIC_UINT62,
            conn_close_status: ?anyerror,
        ) anyerror!void;

        const OnIdealSendBufferSize = ?*const fn(
            stream: *Stream,
            byte_count: u64,
        ) anyerror!void;

        const OnPeerAccepted = ?*const fn(
            stream: *Stream,
        ) anyerror!void;

        const OnCancelOnLoss = ?*const fn(
            stream: *Stream,
            error_code: C.QUIC_UINT62,
        ) anyerror!void;

        onStartComplete: OnStartComplete = null,
        onReceive: OnReceive = null,
        onSendComplete: OnSendComplete = null,
        onPeerSendShutdown: OnPeerSendShutdown = null,
        onPeerSendAborted: OnPeerSendAborted = null,
        onPeerReceiveAborted: OnPeerReceiveAborted = null,
        onSendShutdownComplete: OnSendShutdownComplete = null,
        onShutdownComplete: OnShutdownComplete = null,
        onIdealSendBufferSize: OnIdealSendBufferSize = null,
        onPeerAccepted: OnPeerAccepted = null,
        onCancelOnLoss: OnCancelOnLoss = null,
    };

    pub fn close(self: *const Stream) void {
        self.msquic.api.stream_close(self.handle);
    }

    pub fn destroy(self: *Stream) void {
        self.close();
        self.msquic.allocator.destroy(self);
    }

    pub fn start(self: *const Stream, flags: C.StreamStartFlags) !void {
        const status = self.msquic.api.stream_start(self.handle, flags);
        if (C.StatusCode.failed(status)) return C.StatusCode.toError(status);
    }

    pub fn shutdown(
        self: *const Stream,
        flags: C.StreamShutdownFlags,
        error_code: C.QUIC_UINT62,
    ) !void {
        const status = self.msquic.api.stream_shutdown(self.handle, flags, error_code);
        if (C.StatusCode.failed(status)) return C.StatusCode.toError(status);
    }

    pub fn send(
        self: *const Stream,
        data: []const []const u8,
        flags: C.SendFlags,
        user: ?*anyopaque,
    ) !void {
        const count = std.math.cast(u32, data.len) orelse {
            return WrapperError.QzBufOverflow;
        };

        const context = try SendContext.init(self.msquic, count, user);

        for (data, 0..) |item, i| {
            context.buffers[i].length = @intCast(item.len);
            context.buffers[i].buffer = @constCast(item.ptr);
        }

        const status = self.msquic.api.stream_send(
            self.handle,
            context.buffers,
            context.count,
            flags,
            context,
        );

        if (C.StatusCode.failed(status)) return C.StatusCode.toError(status);
    }

    pub fn receiveComplete(self: *const Stream, buffer_length: u64) void {
        self.msquic.api.stream_receive_complete(self.handle, buffer_length);
    }

    pub fn receiveSetEnabled(self: *const Stream, is_enabled: bool) !void {
        const status = self.msquic.api.stream_receive_set_enabled(self.handle, is_enabled);
        if (C.StatusCode.failed(status)) return C.StatusCode.toError(status);
    }

    pub fn cb(
        stream: C.HQUIC,
        context: ?*anyopaque,
        event: *C.StreamEvent
    ) callconv(.C) C.QUIC_STATUS {
        const self: *Stream = @ptrCast(@alignCast(context));
        if (stream != self.handle) {
            return C.StatusCode.QUIC_STATUS_INTERNAL_ERROR;
        }

        const result = switch (event.event_type) {
            .start_complete =>
                self.cbStartComplete(&self.ihandler, &event.data.start_complete),
            .receive =>
                self.cbReceive(&self.ihandler, &event.data.receive),
            .send_complete =>
                self.cbSendComplete(&self.ihandler, &event.data.send_complete),
            .peer_send_shutdown =>
                self.cbPeerSendShutdown(&self.ihandler),
            .peer_send_aborted =>
                self.cbPeerSendAborted(&self.ihandler, &event.data.peer_send_aborted),
            .peer_receive_aborted =>
                self.cbPeerReceiveAborted(&self.ihandler, &event.data.peer_receive_aborted),
            .send_shutdown_complete =>
                self.cbSendShutdownComplete(&self.ihandler, &event.data.send_shutdown_complete),
            .shutdown_complete =>
                self.cbShutdownComplete(&self.ihandler, &event.data.shutdown_complete),
            .ideal_send_buffer_size =>
                self.cbIdealSendBufferSize(&self.ihandler, &event.data.ideal_send_buffer_size),
            .peer_accepted =>
                self.cbPeerAccepted(&self.ihandler),
            .cancel_on_loss =>
                self.cbCancelOnLoss(&self.ihandler, &event.data.cancel_on_loss),
        };

        return result;
    }

    fn cbStartComplete(
        self: *Stream,
        handler: *IHandler,
        data: *const C.StreamEvent.StartComplete,
    ) C.QUIC_STATUS {
        const onStartComplete = handler.onStartComplete
            orelse return C.StatusCode.QUIC_STATUS_SUCCESS;
        const status = C.StatusCode.toStatus(data.status);
        onStartComplete(
            self,
            status,
            data.id,
            data.flags.peer_accepted,
        ) catch |err| return C.StatusCode.fromError(err);
        return C.StatusCode.QUIC_STATUS_SUCCESS;
    }

    fn cbReceive(
        self: *Stream,
        handler: *IHandler,
        data: *const C.StreamEvent.Receive,
    ) C.QUIC_STATUS {
        const onReceive = handler.onReceive
            orelse return C.StatusCode.QUIC_STATUS_SUCCESS;

        const QSTACK = 4;
        var stack_placeholder: [QSTACK][]const u8 = undefined;
        var buffers: [][]const u8 = undefined;

        var heap_allocated = false;
        if (data.buffer_count <= QSTACK) {
            buffers = stack_placeholder[0..data.buffer_count];
        } else {
            buffers = self.msquic.allocator.alloc([]const u8, data.buffer_count) catch
                return C.StatusCode.QUIC_STATUS_OUT_OF_MEMORY;
            heap_allocated = true;
        }
        defer if (heap_allocated) {
            self.msquic.allocator.free(buffers);
        };

        const bufs = data.buffers[0..data.buffer_count];
        for (bufs, 0..) |buf, i| {
            buffers[i] = buf.buffer[0..buf.length];
        }

        onReceive(
            self,
            data.absolute_offset,
            buffers,
            data.flags,
        ) catch |err| return C.StatusCode.fromError(err);

        return C.StatusCode.QUIC_STATUS_SUCCESS;
    }

    fn cbSendComplete(
        self: *Stream,
        handler: *IHandler,
        data: *const C.StreamEvent.SendComplete,
    ) C.QUIC_STATUS {
        const onSendComplete = handler.onSendComplete
            orelse return C.StatusCode.QUIC_STATUS_SUCCESS;

        const context: *SendContext = @ptrCast(@alignCast(data.client_context));
        defer context.destroy();

        onSendComplete(
            self,
            data.canceled,
            context.user,
        ) catch |err| return C.StatusCode.fromError(err);

        return C.StatusCode.QUIC_STATUS_SUCCESS;
    }

    fn cbPeerSendShutdown(
        self: *Stream,
        handler: *IHandler,
    ) C.QUIC_STATUS {
        const onPeerSendShutdown = handler.onPeerSendShutdown
            orelse return C.StatusCode.QUIC_STATUS_SUCCESS;
        onPeerSendShutdown(self) catch |err|
            return C.StatusCode.fromError(err);
        return C.StatusCode.QUIC_STATUS_SUCCESS;
    }

    fn cbPeerSendAborted(
        self: *Stream,
        handler: *IHandler,
        data: *const C.StreamEvent.PeerSendAborted,
    ) C.QUIC_STATUS {
        const onPeerSendAborted = handler.onPeerSendAborted
            orelse return C.StatusCode.QUIC_STATUS_SUCCESS;
        onPeerSendAborted(self, data.error_code) catch |err|
            return C.StatusCode.fromError(err);
        return C.StatusCode.QUIC_STATUS_SUCCESS;
    }

    fn cbPeerReceiveAborted(
        self: *Stream,
        handler: *IHandler,
        data: *const C.StreamEvent.PeerReceiveAborted,
    ) C.QUIC_STATUS {
        const onPeerReceiveAborted = handler.onPeerReceiveAborted
            orelse return C.StatusCode.QUIC_STATUS_SUCCESS;
        onPeerReceiveAborted(self, data.error_code) catch |err|
            return C.StatusCode.fromError(err);
        return C.StatusCode.QUIC_STATUS_SUCCESS;
    }

    fn cbSendShutdownComplete(
        self: *Stream,
        handler: *IHandler,
        data: *const C.StreamEvent.SendShutdownComplete,
    ) C.QUIC_STATUS {
        const onSendShutdownComplete = handler.onSendShutdownComplete
            orelse return C.StatusCode.QUIC_STATUS_SUCCESS;
        onSendShutdownComplete(self, data.graceful) catch |err|
            return C.StatusCode.fromError(err);
        return C.StatusCode.QUIC_STATUS_SUCCESS;
    }

    fn cbShutdownComplete(
        self: *Stream,
        handler: *IHandler,
        data: *const C.StreamEvent.ShutdownComplete,
    ) C.QUIC_STATUS {
        const onShutdownComplete = handler.onShutdownComplete
            orelse return C.StatusCode.QUIC_STATUS_SUCCESS;
        const conn_close_status = C.StatusCode.toStatus(data.conn_close_status);
        onShutdownComplete(
            self,
            data.conn_shutdown,
            data.flags.app_close_in_progress,
            data.flags.conn_shutdown_by_app,
            data.flags.conn_closed_remotely,
            data.conn_error_code,
            conn_close_status,
        ) catch |err| return C.StatusCode.fromError(err);
        return C.StatusCode.QUIC_STATUS_SUCCESS;
    }

    fn cbIdealSendBufferSize(
        self: *Stream,
        handler: *IHandler,
        data: *const C.StreamEvent.IdealSendBufferSize,
    ) C.QUIC_STATUS {
        const onIdealSendBufferSize = handler.onIdealSendBufferSize
            orelse return C.StatusCode.QUIC_STATUS_SUCCESS;
        onIdealSendBufferSize(self, data.byte_count) catch |err|
            return C.StatusCode.fromError(err);
        return C.StatusCode.QUIC_STATUS_SUCCESS;
    }

    fn cbPeerAccepted(
        self: *Stream,
        handler: *IHandler,
    ) C.QUIC_STATUS {
        const onPeerAccepted = handler.onPeerAccepted
            orelse return C.StatusCode.QUIC_STATUS_SUCCESS;
        onPeerAccepted(self) catch |err|
            return C.StatusCode.fromError(err);
        return C.StatusCode.QUIC_STATUS_SUCCESS;
    }

    fn cbCancelOnLoss(
        self: *Stream,
        handler: *IHandler,
        data: *const C.StreamEvent.CancelOnLoss,
    ) C.QUIC_STATUS {
        const onCancelOnLoss = handler.onCancelOnLoss
            orelse return C.StatusCode.QUIC_STATUS_SUCCESS;
        onCancelOnLoss(self, data.error_code) catch |err|
            return C.StatusCode.fromError(err);
        return C.StatusCode.QUIC_STATUS_SUCCESS;
    }
};

test "SendContext basic" {
    const msquic = MsQuic{
        .allocator = std.testing.allocator,
    };

    const context = try Stream.SendContext.init(&msquic, 3, null);
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
