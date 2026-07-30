FROM eclipse-temurin:26-jdk-alpine-3.23
COPY --from=ghcr.io/astral-sh/uv:0.11.33-alpine3.23 / /
RUN apk add --no-cache procps
RUN addgroup \
  --gid "1000" \
  node \
  && adduser \
  --disabled-password \
  --gecos "" \
  --ingroup node \
  --uid 1000 \
  node
USER node