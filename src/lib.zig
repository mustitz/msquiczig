pub const msquic = @import("msquic.zig");
pub const MsQuic = msquic.MsQuic;

pub const reg = @import("reg.zig");
pub const Registration = reg.Registration;

test {
    @import("std").testing.refAllDecls(@This());
}
