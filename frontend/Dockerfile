FROM node:20-alpine
WORKDIR /app

# No NEXT_PUBLIC_* build arguments, deliberately.
#
# The console reaches the identity API same-origin through the Next.js rewrites, resolved at RUNTIME
# inside the server. Nothing about where the API lives is inlined into the browser bundle, so one
# image is correct in every environment and promoting it is a matter of environment variables rather
# than a rebuild.

COPY package*.json ./
RUN npm ci --omit=dev || npm install --omit=dev

COPY . .
RUN npm run build

ENV NODE_ENV=production
# The deploy platform probes this port, and the container answers on it in every environment.
ENV PORT=8080
EXPOSE 8080

CMD ["npm", "run", "start"]
