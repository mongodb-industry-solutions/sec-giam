# ── GIAM, the identity and access authority ───────────────────────
# Build context: repo root (docker compose sets context: .), because the backend installs the shared
# workspace packages under packages/ through file: paths.
# ──────────────────────────────────────────────────────────────────

FROM node:22-slim

RUN apt-get update && \
    apt-get install -y --no-install-recommends wget ca-certificates && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

# crypt_shared 8.2.4, the SAME version the other services download. GIAM runs Queryable Encryption
# against its OWN key vault, so it shares no key material, but the library version still has to match
# what the cluster expects: a mismatch surfaces as a generic connection failure rather than as a
# crypto error, which is the expensive way to find it.
RUN ARCH=$(dpkg --print-architecture) && \
    if [ "$ARCH" = "arm64" ]; then \
        wget -q https://downloads.mongodb.com/linux/mongo_crypt_shared_v1-linux-aarch64-enterprise-ubuntu2204-8.2.4.tgz -O crypt.tgz; \
    else \
        wget -q https://downloads.mongodb.com/linux/mongo_crypt_shared_v1-linux-x86_64-enterprise-ubuntu2204-8.2.4.tgz -O crypt.tgz; \
    fi && \
    tar -xzf crypt.tgz && \
    mkdir -p /usr/local/lib && \
    cp lib/mongo_crypt_v1.so /usr/local/lib/ && \
    rm -rf crypt.tgz lib

ENV MONGODB_CRYPT_SHARED_LIB_PATH=/usr/local/lib/mongo_crypt_v1.so
ENV GIAM_CRYPT_SHARED_LIB_PATH=/usr/local/lib/mongo_crypt_v1.so
ENV PORT=8080
ENV GIAM_PORT=8080

# ── Dependencies ──────────────────────────────────────────────────
# Shared workspace packages first: the backend installs them through file:, and their prepare script
# builds dist/ during the install.
COPY tsconfig.base.json ./
COPY packages/ packages/
RUN cd packages/eventbus && npm install
RUN cd packages/platform-links && npm install

COPY backend/package.json backend/
RUN cd backend && npm install

# ── Source ────────────────────────────────────────────────────────
COPY backend/ backend/

RUN cd backend && npm run build

# Where the instance-local key provider holds THIS replica's private key. Created before the ownership
# change so the non-root user can write it, and never baked into the image: a signing key in an image
# is a signing key in a registry, and this one signs every token on the platform.
RUN mkdir -p /app/backend/keys

# ── Runtime (non-root) ────────────────────────────────────────────
RUN chown -R node:node /app
USER node

EXPOSE 8080

ENV NODE_ENV=production
ENV GIAM_SEED_DATA_DIR=/app/backend/data

CMD ["node", "backend/dist/bin/server.js"]
