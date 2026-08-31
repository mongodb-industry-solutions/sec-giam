# ── GIAM console ──────────────────────────────────────────────────
# Build context: frontend/ (docker compose sets context: ./frontend).
# ──────────────────────────────────────────────────────────────────

FROM node:20-alpine
WORKDIR /app

# Routing stays a RUNTIME decision: the console reaches the identity API same-origin through the
# Next.js rewrites, resolved from GIAM_API_PRIVATE_URL inside the server, so one image is correct in
# every environment. These two are the exception, because Next inlines NEXT_PUBLIC_* into the browser
# bundle at build time and src/lib/constants.ts reads them: an empty API URL selects the same-origin
# proxy, and the public URL is what the operations panel links a person to. Without these the bundle
# falls back to http://localhost:8085, which is wrong anywhere but a laptop.
ARG NEXT_PUBLIC_GIAM_API_URL=""
ARG NEXT_PUBLIC_GIAM_API_PUBLIC_URL=""
ENV NEXT_PUBLIC_GIAM_API_URL=$NEXT_PUBLIC_GIAM_API_URL
ENV NEXT_PUBLIC_GIAM_API_PUBLIC_URL=$NEXT_PUBLIC_GIAM_API_PUBLIC_URL

# Full install, not --omit=dev: `next build` needs typescript, the type packages and tailwind, all of
# which are devDependencies.
COPY package*.json ./
RUN npm install

COPY . .
RUN npm run build

# node:20-alpine ships a built-in `node` user (uid 1000).
RUN chown -R node:node /app
USER node

ENV NODE_ENV=production
# The deploy platform probes this port, and the container answers on it in every environment.
ENV PORT=8080
EXPOSE 8080

CMD ["npm", "run", "start"]
