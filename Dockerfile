FROM debian:bullseye-slim

ENV DEBIAN_FRONTEND=noninteractive \
    GLAMA_VERSION="1.0.0"

RUN (apt-get update) && (apt-get install -y --no-install-recommends build-essential curl wget software-properties-common libssl-dev zlib1g-dev git) && (rm -rf /var/lib/apt/lists/*) && (curl -fsSL https://deb.nodesource.com/setup_22.x | bash -) && (apt-get install -y nodejs) && (apt-get clean) && (npm install -g mcp-proxy@^4) && (npm install -g pnpm@9.15.5) && (npm install -g bun@1.1.42) && (node --version) && (curl -LsSf https://astral.sh/uv/install.sh | UV_INSTALL_DIR="/usr/local/bin" sh) && (uv python install 3.12 --default --preview) && (ln -s $(uv python find) /usr/local/bin/python) && (python --version) && (apt-get clean) && (rm -rf /var/lib/apt/lists/*) && (rm -rf /tmp/*) && (rm -rf /var/tmp/*) && (uv python install 3.12 --default --preview && python --version)

WORKDIR /app

RUN git clone https://github.com/taylorwilsdon/google_workspace_mcp . && git checkout 43d8f5bcc3b2ed1c3763e5cf22f27f32a3833b9e

RUN (uv sync)

CMD ["mcp-proxy","uv","run","google-workspace-mcp"]

