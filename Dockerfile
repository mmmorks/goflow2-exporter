FROM --platform=$BUILDPLATFORM rust:1 AS builder

ARG TARGETPLATFORM
ARG BUILDPLATFORM
WORKDIR /app

# Install musl tools and cross-compilation tools
RUN apt-get update && apt-get install -y musl-tools gcc-aarch64-linux-gnu

# Determine the Rust target based on platform
RUN echo "Building for platform: $TARGETPLATFORM" && \
    case "$TARGETPLATFORM" in \
    "linux/amd64") RUST_TARGET="x86_64-unknown-linux-musl" ;; \
    "linux/arm64") RUST_TARGET="aarch64-unknown-linux-musl" ;; \
    *) RUST_TARGET="x86_64-unknown-linux-musl" ;; \
    esac && \
    echo "$RUST_TARGET" > /tmp/rust-target && \
    rustup target add $RUST_TARGET

# Set up cross-compilation for ARM if needed
RUN if [ "$(cat /tmp/rust-target)" = "aarch64-unknown-linux-musl" ]; then \
    mkdir -p ~/.cargo && \
    echo '[target.aarch64-unknown-linux-musl]' >> ~/.cargo/config.toml && \
    echo 'linker = "aarch64-linux-gnu-gcc"' >> ~/.cargo/config.toml; \
    fi

COPY Cargo.toml ./
COPY src ./src

# Build for the detected target
RUN cargo build --release --target $(cat /tmp/rust-target)

FROM netsampler/goflow2:latest

ARG TARGETPLATFORM
USER root

WORKDIR /app

RUN apk add --no-cache ca-certificates

# Copy all possible target directories and select the right binary
COPY --from=builder /app/target /tmp/target
COPY --from=builder /tmp/rust-target /tmp/rust-target

RUN RUST_TARGET=$(cat /tmp/rust-target) && \
    cp /tmp/target/$RUST_TARGET/release/goflow2-exporter /app/goflow2-exporter && \
    chmod +x /app/goflow2-exporter && \
    rm -rf /tmp/target /tmp/rust-target

COPY data/ /app/data/

EXPOSE 2055/udp
EXPOSE 9090

ENV RUST_LOG=info

CMD ["/bin/sh", "-c", "/goflow2 -listen netflow://:2055 | ./goflow2-exporter"]
