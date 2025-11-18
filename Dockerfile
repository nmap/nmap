# 2025 Best Practice: Multi-stage Rust Docker build with Google Distroless
# Final image: ~20MB (vs 1.5GB+ with full Rust image)

# ============================================================================
# Stage 1: Build the application
# ============================================================================
FROM rust:1.75-slim-bookworm AS builder

# Install build dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Create app directory
WORKDIR /app

# Copy manifests
COPY Cargo.toml Cargo.lock ./
COPY crates/ ./crates/
COPY src/ ./src/

# Build for release with optimizations
ENV CARGO_REGISTRIES_CRATES_IO_PROTOCOL=sparse
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/app/target \
    cargo build --release --bin rmap && \
    cp /app/target/release/rmap /app/rmap

# Strip symbols to reduce binary size
RUN strip /app/rmap

# ============================================================================
# Stage 2: Runtime image (Google Distroless)
# ============================================================================
FROM gcr.io/distroless/cc-debian12:nonroot

# Copy the binary from builder
COPY --from=builder /app/rmap /usr/local/bin/rmap

# Metadata
LABEL org.opencontainers.image.title="R-Map"
LABEL org.opencontainers.image.description="Rust network scanner - nmap alternative"
LABEL org.opencontainers.image.url="https://github.com/Ununp3ntium115/R-map"
LABEL org.opencontainers.image.source="https://github.com/Ununp3ntium115/R-map"
LABEL org.opencontainers.image.licenses="MIT OR Apache-2.0"

# Distroless runs as non-root by default (UID 65532)
# No shell, no package manager = minimal attack surface

# Expose ports (if running API server)
EXPOSE 8080 3001

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD ["/usr/local/bin/rmap", "--version"]

# Run the binary
ENTRYPOINT ["/usr/local/bin/rmap"]
CMD ["--help"]
