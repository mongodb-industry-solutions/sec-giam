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
# The root checkout first, for the ops panel's own commands (setup:check, test:unit,
# test:integration, openapi): those run `npm run <script>` from the repo root the same way an
# operator at a terminal would, and the root scripts, vitest.config.ts and test/ sources are what
# makes that a real command rather than an error the ops panel has to word-smith around.
# `type-check`'s frontend leg is the one exception: it needs frontend/'s own toolchain, deliberately
# not bundled here. Installed BEFORE packages/: npm's dependency-tree walk from the root trips over
# already-populated node_modules nested under it (a known npm arborist bug), so root install has to
# happen while there is nothing nested yet to trip over.
COPY tsconfig.base.json package.json vitest.config.ts ./
COPY test/ test/
COPY docs/ docs/
# --legacy-peer-deps: npm 10's arborist crashes ("Cannot read properties of null (reading
# 'edgesOut')") walking vitest 4's peer set (the @vitejs/devtools* family) on a clean install with
# no lockfile to shortcut it. The simpler peer resolution this flag falls back to sidesteps that
# arborist bug rather than working around it with a newer npm.
RUN npm install --legacy-peer-deps

# Shared workspace packages: the backend installs them through file:, and their prepare script
# builds dist/ during the install.
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
