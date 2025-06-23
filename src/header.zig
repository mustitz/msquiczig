pub const C = struct {
    pub const QUIC_STATUS = i32;

    pub const MsQuicOpenVersionFn = *const fn(
        version: u32,
        quic_api: *?*const anyopaque
    ) callconv(.C) QUIC_STATUS;

    pub const MsQuicCloseFn = *const fn(
        quic_api: ?*const anyopaque
    ) callconv(.C) void;
};
