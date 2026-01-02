FROM rust:1 AS builder

WORKDIR /app

COPY Cargo.toml ./
COPY src ./src

RUN cargo build --release

FROM netsampler/goflow2:latest

USER root

RUN apk add --no-cache ca-certificates

COPY --from=builder /app/target/release/goflow2-exporter /usr/local/bin/goflow2-exporter
COPY data/ /app/data/

WORKDIR /app

EXPOSE 2055/udp
EXPOSE 9090

ENV RUST_LOG=info

CMD ["/bin/sh", "-c", "goflow2 -listen netflow://:2055 | goflow2-exporter"]
