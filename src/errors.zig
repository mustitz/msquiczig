pub const WrapperError = error{
    OpenVersionNotFound,
    CloseNotFound,
};

// Base System Errors
pub const BaseError = error{
    OutOfMemory,
    InvalidParameter,
    InvalidState,
    NotSupported,
    NotFound,
    FileNotFound,
    BufferTooSmall,
    HandshakeFailure,
    Aborted,
    AddressInUse,
    InvalidAddress,
    ConnTimeout,
    ConnIdle,
    InternalError,
    ConnRefused,
    ProtocolError,
    VersionNegError,
    Unreachable,
    TlsError,
    UserCanceled,
    AlpnNegFailure,
    StreamLimitReached,
    AlpnInUse,
    AddressNotAvailable
};

// TLS Alert Errors
pub const TlsError = error{
    CloseNotify,
    BadCert,
    UnsupportedCert,
    RevokedCert,
    ExpiredCert,
    UnknownCert,
    RequiredCert
};

// Cert Errors
pub const CertError = error{
    CertExpired,
    CertUntrustedRoot,
    CertNoCert
};

pub const MsQuicError = WrapperError || BaseError || TlsError || CertError;
