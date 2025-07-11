# msquiczig

A Zig wrapper library for Microsoft's QUIC implementation (MsQuic), providing a modern, type-safe interface for high-performance network programming.

## Features

- **Complete QUIC API Coverage**: Implements all MsQuic API features (pre-v2.2)
- **Type-Safe Zig Interface**: Leverages Zig's compile-time safety and error handling
- **Dynamic Loading**: No static linking required - just point to the MsQuic shared library
- **POSIX Compatible**: Tested on Linux with POSIX-only dependencies
- **Memory Management**: Custom buffer management with proper cleanup
- **Structured Logging**: Built-in logging system using the quarkz library

## Quick Start

### Prerequisites

- Zig 0.15.0 or later
- MsQuic shared library (libmsquic.so)
- For TLS: OpenSSL certificates

### Installation

Add to your `build.zig.zon`:

```zig
.dependencies = .{
    .msquiczig = .{
        .url = "https://github.com/mustitz/msquiczig/archive/v0.0.1.tar.gz",
        .hash = "...", // Add actual hash
    },
},
```

### Setup

1. **Install MsQuic library**:
   ```bash
   # Download from Microsoft's releases or build from source
   # Place libmsquic.so in a known location
   ```

2. **Set environment variable**:
   ```bash
   export LIBMSQUIC_PATH=/path/to/libmsquic.so
   ```

3. **Generate TLS certificates** (for server):
   ```bash
   mkdir -p tls

   # Generate private key
   openssl genrsa -out tls/server.key 2048

   # Generate self-signed certificate
   openssl req -new -x509 -key tls/server.key -out tls/server.cert -days 365 \
     -subj "/C=US/ST=State/L=City/O=Organization/CN=localhost"
   ```

## Examples

### Running the Sample Server

```bash
# Build the examples
zig build

# Set the library path
export LIBMSQUIC_PATH=/usr/local/lib/libmsquic.so

# Run the server (listens on port 3690)
zig build run-server

# Kill the server
kill -s INT <pid>
```

### Running the Sample Client

```bash
# In another terminal, run the client
zig build run-client
```

The client will connect to `localhost:3690`, send "Hello, Server!" and receive "Hello, Client!" back.

## API Overview

### Core Components

- **MsQuic**: Main library interface and dynamic loader
- **Registration**: Application registration with the QUIC stack
- **Configuration**: Connection configuration and credentials
- **Connection**: QUIC connection management
- **Stream**: Bidirectional and unidirectional data streams
- **Listener**: Server-side connection acceptance

## Testing

```bash
# Test with MsQuic library
LIBMSQUIC_PATH=/path/to/libmsquic.so zig build test

# Run all tests
zig build test
```

## Limitations

- **Platform Support**: Currently tested only on Linux with POSIX APIs
- **MsQuic Version**: Supports MsQuic API (excludes v2.2+ features)
- **TLS Backend**: Embedded in msquic

## Dependencies

- **quarkz**: Logging and intrusive data structures (v0.0.1)
- **MsQuic**: Microsoft QUIC library (v2.1 compatible)

## License

MIT

---

**Version**: v0.0.1
**Zig Version**: 0.15.0+
