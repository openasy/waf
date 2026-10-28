# syntax=docker/dockerfile:1

# The proxy (Go: Coraza with the OWASP Core Rule Set) is cross-compiled on the machine that builds, for the platform
# being built, with the pinned toolchain the script checks against its checksum (ADR 0027, 0069). Go fetches Coraza and
# the rule set as proxy/go.sum pins them, which needs the CA certificates.
FROM --platform=$BUILDPLATFORM node:26.12.0-trixie-slim AS proxy
ARG TARGETARCH
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY scripts/proxy.ts scripts/
COPY proxy proxy
RUN node scripts/proxy.ts linux "${TARGETARCH:-amd64}" /out

FROM node:26.12.0-trixie-slim AS build
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY . .
RUN npm run build && npm prune --omit=dev && mkdir -p /out/data

# Node runs the TypeScript sources directly; only production dependencies are copied. The proxy is one static binary,
# so the image needs nothing else (ADR 0069).
FROM gcr.io/distroless/nodejs26-debian13:nonroot
WORKDIR /app
COPY --from=build /app/package.json /app/openapi.json ./
COPY --from=build /app/node_modules ./node_modules
COPY --from=build /app/server ./server
COPY --from=build /app/dist/web ./dist/web
COPY --from=build /app/dist/docs ./dist/docs
COPY --from=proxy /out/waf-proxy ./vendor/waf-proxy
COPY --from=build --chown=nonroot:nonroot /out/data /data
# SQLite lives in /data; the proxy's config and the request bodies Coraza buffers to disk are in /tmp (tmpfs in
# compose), so the root filesystem can be read-only (ADR 0022).
ENV NODE_ENV=production PORT=8080 WAF_PROXY_PORT=8000 WAF_DATA=/data
VOLUME /data
# 8080: UI and API. 8000: the sites, for the TLS proxy in front.
EXPOSE 8080 8000
USER nonroot
HEALTHCHECK --interval=30s --timeout=3s --start-period=20s \
  CMD ["/nodejs/bin/node", "-e", "fetch('http://127.0.0.1:8080/healthz').then(r => process.exit(r.ok ? 0 : 1), () => process.exit(1))"]
CMD ["server/main.ts"]
