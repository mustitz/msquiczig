pub const WrapperError = error{
    QzOpenVersionNotFound,
    QzCloseNotFound,
    QzBug,
    QzBufOverflow,
};

// Base System Errors
pub const BaseError = error{
    QzOutOfMemory,
    QzInvalidParameter,
    QzInvalidState,
    QzNotSupported,
    QzNotFound,
    QzFileNotFound,
    QzBufferTooSmall,
    QzHandshakeFailure,
    QzAborted,
    QzAddressInUse,
    QzInvalidAddress,
    QzConnTimeout,
    QzConnIdle,
    QzInternalError,
    QzConnRefused,
    QzProtocolError,
    QzVersionNegError,
    QzUnreachable,
    QzTlsError,
    QzUserCanceled,
    QzAlpnNegFailure,
    QzStreamLimitReached,
    QzAlpnInUse,
    QzAddressNotAvailable
};

// TLS Alert Errors
pub const TlsError = error{
    QzCloseNotify,
    QzBadCert,
    QzUnsupportedCert,
    QzRevokedCert,
    QzExpiredCert,
    QzUnknownCert,
    QzRequiredCert
};

// Cert Errors
pub const CertError = error{
    QzCertExpired,
    QzCertUntrustedRoot,
    QzCertNoCert
};

pub const MsQuicError = WrapperError || BaseError || TlsError || CertError;
