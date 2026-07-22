FROM node:22-slim

WORKDIR /app

COPY package.json package-lock.json ./
# npm ci installs exactly what the lockfile pins (reproducible, fails on drift),
# instead of npm install which can silently resolve to newer transitive versions.
RUN npm ci --no-audit --no-fund

COPY . .
RUN node scripts/build-web.js

# data/files holds uploaded attachment ciphertext; created here (before the
# chown) so a named volume mounted on top inherits app ownership
RUN mkdir -p /app/data/files && useradd -m app && chown -R app:app /app
USER app

ENV PORT=8790 MEAN_DELAY_MS=60 NODE_ENV=production
EXPOSE 8790

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s \
  CMD node -e "fetch('http://127.0.0.1:8790/healthz').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"

CMD ["node", "apps/server/server.js"]
