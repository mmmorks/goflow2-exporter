FROM rust:1.75 as builder

WORKDIR /app

COPY Cargo.toml ./
COPY src ./src

RUN cargo build --release

FROM netsampler/goflow2:latest

USER root

RUN apk add --no-cache ca-certificates

COPY --from=builder /app/target/release/goflow2-aggregator /usr/local/bin/goflow2-aggregator

EXPOSE 2055/udp
EXPOSE 9090

ENV RUST_LOG=info

CMD ["/bin/sh", "-c", "goflow2 -listen netflow://:2055 | goflow2-aggregator"]
