LAYERS, PER_LAYER, PROVIDERS = 3, 2, 2

nodes = []
for l in range(LAYERS):
    for n in range(PER_LAYER):
        nodes.append(f"mix-L{l}-{n}")
for p in range(PROVIDERS):
    nodes.append(f"provider-{p}")

def node_block(label):
    svc = label.lower()
    return f"""  {svc}:
    image: noblechat:local
    container_name: nc-{svc}
    command: ["node", "apps/node/node.js"]
    restart: unless-stopped
    environment:
      NODE_LABEL: "{label}"
      NET_SEED: ${{NET_SEED}}
      INTERNAL_TOKEN: ${{INTERNAL_TOKEN}}
      GATEWAY_URL: "http://noblechat:8790"
      MEAN_DELAY_MS: "60"
      LAYERS: "{LAYERS}"
      PER_LAYER: "{PER_LAYER}"
      PROVIDERS: "{PROVIDERS}"
      PORT: "8890"
    networks:
      - noblechat_internal
    healthcheck:
      test: ["CMD", "node", "-e", "fetch('http://127.0.0.1:8890/healthz').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"]
      interval: 20s
      timeout: 5s
      retries: 5
"""

header = """services:
  db:
    image: postgres:16-alpine
    container_name: noblechat-db
    restart: unless-stopped
    environment:
      POSTGRES_USER: ${POSTGRES_USER}
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD}
      POSTGRES_DB: ${POSTGRES_DB}
    volumes:
      - noblechat-db:/var/lib/postgresql/data
    networks:
      - noblechat_internal
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U ${POSTGRES_USER} -d ${POSTGRES_DB}"]
      interval: 10s
      timeout: 5s
      retries: 12

  noblechat:
    build: .
    image: noblechat:local
    container_name: noblechat
    restart: unless-stopped
    depends_on:
      db:
        condition: service_healthy
    environment:
      PORT: "8790"
      MEAN_DELAY_MS: "60"
      NET_SEED: ${NET_SEED}
      DATABASE_URL: ${DATABASE_URL}
      ADMIN_TOKEN: ${ADMIN_TOKEN}
      INTERNAL_TOKEN: ${INTERNAL_TOKEN}
      LAYERS: "%d"
      PER_LAYER: "%d"
      PROVIDERS: "%d"
      MIX_PORT: "8890"
      FILES_DIR: /app/data/files
    volumes:
      - noblechat-files:/app/data/files
    expose:
      - "8790"
    networks:
      - jarvis20_default
      - noblechat_internal
""" % (LAYERS, PER_LAYER, PROVIDERS)

footer = """
networks:
  jarvis20_default:
    external: true
  noblechat_internal:
    driver: bridge

volumes:
  noblechat-db:
  noblechat-files:
"""

out = header + "\n" + "\n".join(node_block(l) for l in nodes) + footer
open("docker-compose.yml", "w").write(out)
print("wrote docker-compose.yml with", len(nodes), "mix nodes:", ", ".join(nodes))
