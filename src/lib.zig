pub const msquic = @import("msquic.zig");
pub const MsQuic = msquic.MsQuic;

test {
    @import("std").testing.refAllDecls(@This());
}
