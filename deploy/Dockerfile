FROM rust:1.92-bookworm AS builder
WORKDIR /app
COPY . .
RUN cargo build --release -p ab-app

FROM debian:bookworm-slim AS runner
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/target/release/ab-app /usr/local/bin/ab-app
COPY --from=builder /app/static ./static
RUN mkdir -p /data/uploads /data/templates
ENV APP_HOST=0.0.0.0
ENV APP_PORT=3000
EXPOSE 3000
CMD ["ab-app"]
