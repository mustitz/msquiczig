pub const msquic = @import("msquic.zig");
pub const MsQuic = msquic.MsQuic;
pub const Addr = msquic.Addr;

pub const reg = @import("reg.zig");
pub const Registration = reg.Registration;

pub const conf = @import("conf.zig");
pub const Configuration = conf.Configuration;

pub const settings = @import("settings.zig");
pub const Settings = settings.Settings;

pub const conn = @import("conn.zig");
pub const Connection = conn.Connection;

pub const listener = @import("listener.zig");
pub const Listener = listener.Listener;

pub const header = @import("header.zig");
pub const CredFlags = header.C.CredFlags;
pub const CertHash = header.C.CertHash;
pub const CertHashStore = header.C.CertHashStore;
pub const CertFile = header.C.CertFile;
pub const CertFileProtected = header.C.CertFileProtected;
pub const CertPkcs12 = header.C.CertPkcs12;
pub const CredConfig = header.C.CredConfig;

pub const errors = @import("errors.zig");
pub const MsQuicError = errors.MsQuicError;
pub const InternalErrorCode = header.C.QUIC_UINT62;

test {
    @import("std").testing.refAllDecls(@This());
}
