FROM node:22-slim

WORKDIR /app
ENV PYTHONUNBUFFERED=1

COPY package.json package-lock.json ./
RUN npm install --no-audit --no-fund

COPY . .
RUN node scripts/build-web.js

RUN useradd -m app && chown -R app:app /app
USER app

ENV PORT=8790 MEAN_DELAY_MS=60
EXPOSE 8790

HEALTHCHECK --interval=30s --timeout=5s --start-period=8s \
  CMD node -e "fetch('http://127.0.0.1:8790/api/net').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"

CMD ["node", "apps/server/server.js"]
