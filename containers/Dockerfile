# ---------------------------------------------------------------------------
# Builder stage: compile the Go tools here so the Go toolchain (~225MB) and the
# module/build caches never reach the runtime image. The resulting binaries are
# statically linked and copied into the final stage.
# ---------------------------------------------------------------------------
# Pin the Kali base image to control when OS updates are absorbed.
# To update: docker pull kalilinux/kali-rolling:latest, get the new digest with
#   docker inspect kalilinux/kali-rolling:latest --format '{{index .RepoDigests 0}}'
# then update KALI_TAG below and rebuild.
ARG KALI_TAG=latest
FROM kalilinux/kali-rolling:${KALI_TAG} AS gobuilder

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y kali-archive-keyring && \
    apt-get update && \
    apt-get install -y --no-install-recommends golang-go git ca-certificates

ENV GOBIN=/out/bin
RUN go telemetry off && \
    mkdir -p /out/bin && \
    go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest && \
    go install -v github.com/projectdiscovery/katana/cmd/katana@latest && \
    go install -v github.com/projectdiscovery/cvemap/cmd/cvemap@latest && \
    go install -v github.com/jaeles-project/gospider@latest && \
    go install -v github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest && \
    go install -v golang.org/x/vuln/cmd/govulncheck@latest && \
    go install -v github.com/fullstorydev/grpcurl/cmd/grpcurl@latest && \
    go install -v github.com/tomnomnom/waybackurls@latest && \
    go install -v github.com/lc/gau/v2/cmd/gau@latest && \
    go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest && \
    go install -v github.com/hakluke/hakrawler@latest && \
    go install -v github.com/Emoe/kxss@latest && \
    go install -v github.com/owasp-amass/amass/v4/...@latest

# ---------------------------------------------------------------------------
# Runtime stage
# ---------------------------------------------------------------------------
FROM kalilinux/kali-rolling:${KALI_TAG}

LABEL description="AI Agent Penetration Testing Environment with Comprehensive Automated Tools"

ENV DEBIAN_FRONTEND=noninteractive
ENV PIP_DISABLE_PIP_VERSION_CHECK=1
ENV NPM_CONFIG_AUDIT=false
ENV NPM_CONFIG_FUND=false
ENV NPM_CONFIG_UPDATE_NOTIFIER=false

RUN apt-get update && \
    apt-get install -y kali-archive-keyring sudo && \
    apt-get update && \
    apt-get upgrade -y

RUN useradd -m -s /bin/bash pentester && \
    usermod -aG sudo pentester && \
    echo "pentester ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers && \
    touch /home/pentester/.hushlogin

RUN mkdir -p /home/pentester/tools /app/certs && \
    chown -R pentester:pentester /app/certs /home/pentester/tools

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    wget curl git vim nano unzip tar \
    apt-transport-https ca-certificates gnupg lsb-release \
    software-properties-common \
    gcc libc6-dev \
    python3 python3-pip python3-venv python3-setuptools \
    python3.13 python3.13-venv \
    net-tools dnsutils whois \
    file xxd \
    jq parallel ripgrep grep \
    less procps htop \
    iproute2 iputils-ping netcat-traditional \
    nmap ncat ndiff \
    sqlmap nuclei subfinder naabu ffuf exploitdb \
    nodejs npm pipx \
    golang-go \
    libcap2-bin \
    gdb ltrace strace \
    libnss3-tools \
    chromium fonts-liberation \
    radare2 \
    hashcat \
    afl++ \
    checksec \
    qemu-user-static \
    masscan \
    ldap-utils \
    swaks \
    protobuf-compiler \
    commix \
    default-jdk-headless \
    nikto \
    gobuster \
    hydra \
    medusa \
    wfuzz \
    socat \
    binwalk \
    binutils \
    whatweb \
    httping \
    mosquitto-clients \
    redis-tools \
    docker.io \
    padbuster \
    feroxbuster \
    libxmlsec1-dev pkg-config \
    wapiti theharvester \
    bsdmainutils

RUN go telemetry off

RUN setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip $(which nmap)
RUN setcap cap_sys_ptrace+eip $(which strace) && setcap cap_sys_ptrace+eip $(which ltrace)

USER pentester
RUN go telemetry off

RUN openssl ecparam -name prime256v1 -genkey -noout -out /app/certs/ca.key && \
    openssl req -x509 -new -key /app/certs/ca.key \
    -out /app/certs/ca.crt \
    -days 3650 \
    -subj "/C=US/ST=CA/O=Security Testing/CN=Testing Root CA" \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,digitalSignature,keyEncipherment,keyCertSign" && \
    openssl pkcs12 -export \
    -out /app/certs/ca.p12 \
    -inkey /app/certs/ca.key \
    -in /app/certs/ca.crt \
    -passout pass:"" \
    -name "Testing Root CA" && \
    chmod 644 /app/certs/ca.crt && \
    chmod 600 /app/certs/ca.key && \
    chmod 600 /app/certs/ca.p12

USER root
RUN cp /app/certs/ca.crt /usr/local/share/ca-certificates/ca.crt && \
    update-ca-certificates

RUN curl -LsSf https://astral.sh/uv/install.sh | env UV_INSTALL_DIR=/usr/local/bin sh

USER pentester
WORKDIR /tmp

# Go tools are built in the gobuilder stage; copy the static binaries only.
COPY --from=gobuilder --chown=pentester:pentester /out/bin/ /home/pentester/go/bin/

RUN nuclei -update-templates

RUN pipx install arjun && \
    pipx install dirsearch && \
    pipx inject dirsearch 'setuptools<81' && \
    pipx install wafw00f && \
    pipx install pacu && \
    pipx install pip-audit && \
    pipx install scoutsuite

ENV NPM_CONFIG_PREFIX=/home/pentester/.npm-global
RUN mkdir -p /home/pentester/.npm-global

RUN npm install -g retire@latest && \
    npm install -g eslint@latest && \
    npm install -g js-beautify@latest && \
    npm install -g @ast-grep/cli@latest && \
    npm install -g tree-sitter-cli@latest && \
    npm install -g agent-browser@0.38.1 && \
    npm cache clean --force && \
    # ast-grep ships two identical binaries (`ast-grep` and `sg`); dedupe (~52MB)
    ln -sf ast-grep /home/pentester/.npm-global/lib/node_modules/@ast-grep/cli/sg

ENV AGENT_BROWSER_EXECUTABLE_PATH=/usr/bin/chromium
ENV AGENT_BROWSER_USER_AGENT="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
ENV AGENT_BROWSER_ARGS="--disable-blink-features=AutomationControlled,--no-first-run,--no-default-browser-check,--lang=en-US"
ENV AGENT_BROWSER_SCREENSHOT_DIR=/workspace/.agent-browser-screenshots
ENV AGENT_BROWSER_IDLE_TIMEOUT_MS=180000
ENV AGENT_BROWSER_CA_CERT=/app/certs/ca.crt
USER root
RUN set -eu; \
    { \
        for var in AGENT_BROWSER_EXECUTABLE_PATH AGENT_BROWSER_USER_AGENT \
                   AGENT_BROWSER_ARGS AGENT_BROWSER_SCREENSHOT_DIR \
                   AGENT_BROWSER_IDLE_TIMEOUT_MS AGENT_BROWSER_CA_CERT; do \
            eval "value=\${$var}"; \
            printf 'export %s="${%s:-%s}"\n' "$var" "$var" "$value"; \
        done; \
    } > /tmp/agent-browser.sh; \
    install -m 0644 /tmp/agent-browser.sh /etc/profile.d/agent-browser.sh; \
    rm /tmp/agent-browser.sh; \
    env -i bash -lc 'test "${AGENT_BROWSER_IDLE_TIMEOUT_MS}" = "180000"'
USER pentester
RUN /home/pentester/.npm-global/bin/agent-browser doctor --offline --quick

RUN set -eux; \
    TS_PARSER_DIR="/home/pentester/.tree-sitter/parsers"; \
    mkdir -p "${TS_PARSER_DIR}"; \
    for repo in tree-sitter-java tree-sitter-javascript tree-sitter-python tree-sitter-go tree-sitter-bash tree-sitter-json tree-sitter-yaml tree-sitter-typescript; do \
        if [ "$repo" = "tree-sitter-yaml" ]; then \
            repo_url="https://github.com/tree-sitter-grammars/${repo}.git"; \
        else \
            repo_url="https://github.com/tree-sitter/${repo}.git"; \
        fi; \
        if [ ! -d "${TS_PARSER_DIR}/${repo}" ]; then \
            git clone --depth 1 "${repo_url}" "${TS_PARSER_DIR}/${repo}"; \
        fi; \
    done; \
    if [ -d "${TS_PARSER_DIR}/tree-sitter-typescript/typescript" ]; then \
        ln -sfn "${TS_PARSER_DIR}/tree-sitter-typescript/typescript" "${TS_PARSER_DIR}/tree-sitter-typescript-typescript"; \
    fi; \
    if [ -d "${TS_PARSER_DIR}/tree-sitter-typescript/tsx" ]; then \
        ln -sfn "${TS_PARSER_DIR}/tree-sitter-typescript/tsx" "${TS_PARSER_DIR}/tree-sitter-typescript-tsx"; \
    fi; \
    tree-sitter init-config >/dev/null 2>&1 || true; \
    TS_CONFIG="/home/pentester/.config/tree-sitter/config.json"; \
    mkdir -p "$(dirname "${TS_CONFIG}")"; \
    [ -f "${TS_CONFIG}" ] || printf '{}\n' > "${TS_CONFIG}"; \
    TMP_CFG="$(mktemp)"; \
    jq --arg p "${TS_PARSER_DIR}" '.["parser-directories"] = ((.["parser-directories"] // []) + [$p] | unique)' "${TS_CONFIG}" > "${TMP_CFG}"; \
    mv "${TMP_CFG}" "${TS_CONFIG}"

WORKDIR /home/pentester/tools
RUN git clone https://github.com/aravind0x7/JS-Snooper.git && \
    chmod +x JS-Snooper/js_snooper.sh && \
    git clone https://github.com/xchopath/jsniper.sh.git && \
    chmod +x jsniper.sh/jsniper.sh && \
    git clone https://github.com/ticarpi/jwt_tool.git && \
    chmod +x jwt_tool/jwt_tool.py && \
    git clone --depth 1 https://github.com/drwetter/testssl.sh.git && \
    chmod +x testssl.sh/testssl.sh && \
    git clone --depth 1 https://github.com/epinna/tplmap.git && \
    git clone --depth 1 https://github.com/defparam/smuggler.git

USER root

# Pin the initial TruffleHog binary and wrap it below with --no-update so
# runtime scans do not perform self-update checks.
ARG TRUFFLEHOG_VERSION=3.97.9
RUN curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b /home/pentester/.local/bin "v${TRUFFLEHOG_VERSION}" && \
    chown -R pentester:pentester /home/pentester/.local
RUN set -eux; \
    ARCH="$(uname -m)"; \
    case "$ARCH" in \
        x86_64) GITLEAKS_ARCH="x64" ;; \
        aarch64|arm64) GITLEAKS_ARCH="arm64" ;; \
        *) echo "Unsupported architecture: $ARCH" >&2; exit 1 ;; \
    esac; \
    TAG="$(curl -fsSL https://api.github.com/repos/gitleaks/gitleaks/releases/latest | jq -r .tag_name)"; \
    curl -fsSL "https://github.com/gitleaks/gitleaks/releases/download/${TAG}/gitleaks_${TAG#v}_linux_${GITLEAKS_ARCH}.tar.gz" -o /tmp/gitleaks.tgz; \
    tar -xzf /tmp/gitleaks.tgz -C /tmp; \
    install -m 0755 /tmp/gitleaks /usr/local/bin/gitleaks; \
    rm -f /tmp/gitleaks /tmp/gitleaks.tgz

RUN curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin

ARG DALFOX_VERSION=3.2.3
RUN set -eux; \
    ARCH="$(uname -m)"; \
    case "$ARCH" in \
        x86_64) DALFOX_ARCH="x86_64" ;; \
        aarch64|arm64) DALFOX_ARCH="aarch64" ;; \
        *) echo "Unsupported architecture: $ARCH" >&2; exit 1 ;; \
    esac; \
    curl -fsSL "https://github.com/hahwul/dalfox/releases/download/v${DALFOX_VERSION}/dalfox-v${DALFOX_VERSION}-linux-${DALFOX_ARCH}-musl.tar.gz" -o /tmp/dalfox.tar.gz; \
    tar -xzf /tmp/dalfox.tar.gz --strip-components=1 -C /tmp; \
    install -m 0755 /tmp/dalfox /usr/local/bin/dalfox; \
    rm -f /tmp/dalfox /tmp/dalfox.tar.gz

RUN set -eux; \
    ARCH="$(uname -m)"; \
    case "$ARCH" in \
        x86_64)        WEBSOCAT_ARCH="x86_64-unknown-linux-musl" ;; \
        aarch64|arm64) WEBSOCAT_ARCH="aarch64-unknown-linux-musl" ;; \
        *) echo "Unsupported: $ARCH" >&2; exit 1 ;; \
    esac; \
    TAG="$(curl -fsSL https://api.github.com/repos/vi/websocat/releases/latest | jq -r .tag_name)"; \
    curl -fsSL "https://github.com/vi/websocat/releases/download/${TAG}/websocat.${WEBSOCAT_ARCH}" \
        -o /usr/local/bin/websocat; \
    chmod 0755 /usr/local/bin/websocat

USER pentester

RUN pipx install semgrep && \
    pipx install bandit

ENV SEMGREP_ENABLE_VERSION_CHECK=0
ENV SEMGREP_SEND_METRICS=off

RUN npm install -g jshint && \
    npm install -g eslint-plugin-security

USER root
RUN set -eux; \
    for bin in \
        /usr/bin/nuclei \
        /usr/bin/subfinder \
        /usr/bin/naabu \
        /home/pentester/go/bin/httpx \
        /home/pentester/go/bin/katana \
        /home/pentester/go/bin/interactsh-client \
        /home/pentester/go/bin/dnsx; do \
        [ -x "$bin" ] || continue; \
        mv "$bin" "${bin}.real"; \
        { \
            printf '%s\n' '#!/bin/sh'; \
            printf 'real=%s\n' "${bin}.real"; \
            printf '%s\n' 'for arg in "$@"; do'; \
            printf '%s\n' '    case "$arg" in'; \
            printf '%s\n' '        -duc|--disable-update-check) exec "$real" "$@" ;;'; \
            printf '%s\n' '    esac'; \
            printf '%s\n' 'done'; \
            printf '%s\n' 'exec "$real" -duc "$@"'; \
        } > "$bin"; \
        chmod 0755 "$bin"; \
    done; \
    if [ -x /home/pentester/.local/bin/trufflehog ]; then \
        mv /home/pentester/.local/bin/trufflehog /home/pentester/.local/bin/trufflehog.real; \
        { \
            printf '%s\n' '#!/bin/sh'; \
            printf '%s\n' 'real=/home/pentester/.local/bin/trufflehog.real'; \
            printf '%s\n' 'for arg in "$@"; do'; \
            printf '%s\n' '    case "$arg" in'; \
            printf '%s\n' '        --no-update|--no-no-update|-h|--help|--version|version) exec "$real" "$@" ;;'; \
            printf '%s\n' '    esac'; \
            printf '%s\n' 'done'; \
            printf '%s\n' 'exec "$real" "$@" --no-update'; \
        } > /home/pentester/.local/bin/trufflehog; \
        chmod 0755 /home/pentester/.local/bin/trufflehog; \
        chown pentester:pentester /home/pentester/.local/bin/trufflehog /home/pentester/.local/bin/trufflehog.real; \
    fi

ARG GHIDRA_VERSION=11.2.1
ARG GHIDRA_DATE=20241105
RUN set -eux; \
    curl -fsSL \
        "https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_${GHIDRA_VERSION}_build/ghidra_${GHIDRA_VERSION}_PUBLIC_${GHIDRA_DATE}.zip" \
        -o /tmp/ghidra.zip; \
    unzip -q /tmp/ghidra.zip -d /opt/; \
    mv "/opt/ghidra_${GHIDRA_VERSION}_PUBLIC" /opt/ghidra; \
    rm /tmp/ghidra.zip; \
    ln -sf /opt/ghidra/support/analyzeHeadless /usr/local/bin/ghidra-headless; \
    chown -R pentester:pentester /opt/ghidra

ARG CODEQL_VERSION=2.19.4
RUN set -eux; \
    curl -fsSL \
        "https://github.com/github/codeql-cli-binaries/releases/download/v${CODEQL_VERSION}/codeql-linux64.zip" \
        -o /tmp/codeql.zip; \
    unzip -q /tmp/codeql.zip -d /opt/; \
    ln -sf /opt/codeql/codeql /usr/local/bin/codeql; \
    rm /tmp/codeql.zip; \
    chown -R pentester:pentester /opt/codeql

RUN set -eux; \
    ARCH="$(uname -m)"; \
    case "$ARCH" in \
        x86_64)        AWS_ARCH="x86_64" ;; \
        aarch64|arm64) AWS_ARCH="aarch64" ;; \
        *) echo "Unsupported: $ARCH" >&2; exit 1 ;; \
    esac; \
    curl -fsSL "https://awscli.amazonaws.com/awscli-exe-linux-${AWS_ARCH}.zip" -o /tmp/awscliv2.zip; \
    unzip -q /tmp/awscliv2.zip -d /tmp/awscli-install/; \
    /tmp/awscli-install/aws/install; \
    rm -rf /tmp/awscliv2.zip /tmp/awscli-install/

RUN set -eux; \
    ARCH="$(uname -m)"; \
    case "$ARCH" in \
        x86_64)        K8S_ARCH="amd64" ;; \
        aarch64|arm64) K8S_ARCH="arm64" ;; \
        *) echo "Unsupported: $ARCH" >&2; exit 1 ;; \
    esac; \
    K8S_VER="$(curl -fsSL https://dl.k8s.io/release/stable.txt)"; \
    curl -fsSL "https://dl.k8s.io/release/${K8S_VER}/bin/linux/${K8S_ARCH}/kubectl" -o /tmp/kubectl; \
    install -m 0755 /tmp/kubectl /usr/local/bin/kubectl; \
    rm /tmp/kubectl

RUN ln -sf /home/pentester/tools/testssl.sh/testssl.sh /usr/local/bin/testssl.sh && \
    ln -sf /usr/local/bin/testssl.sh /usr/local/bin/testssl && \
    printf '%s\n' '#!/bin/sh' \
        'exec /app/.venv/bin/python /home/pentester/tools/tplmap/tplmap.py "$@"' \
        > /usr/local/bin/tplmap && chmod 0755 /usr/local/bin/tplmap && \
    printf '%s\n' '#!/bin/sh' \
        'exec /app/.venv/bin/python /home/pentester/tools/smuggler/smuggler.py "$@"' \
        > /usr/local/bin/smuggler && chmod 0755 /usr/local/bin/smuggler


RUN git clone --depth 1 https://github.com/danielmiessler/SecLists.git /opt/SecLists && \
    chown -R pentester:pentester /opt/SecLists

RUN apt-get autoremove -y && \
    apt-get autoclean && \
    rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/* && \
    # Purge non-English locales (~160MB)
    find /usr/share/locale -mindepth 1 -maxdepth 1 -type d \
        ! -name 'en' ! -name 'en_US' ! -name 'C' -exec rm -rf {} + && \
    # Remove package documentation and man pages not needed at runtime (~95MB)
    rm -rf /usr/share/doc/* /usr/share/doc-base/* /usr/share/man/*

ENV PATH="/home/pentester/go/bin:/home/pentester/.local/bin:/home/pentester/.npm-global/bin:/app/.venv/bin:$PATH"
ENV VIRTUAL_ENV="/app/.venv"

WORKDIR /app

ARG CAIDO_VERSION=0.58.3
RUN ARCH=$(uname -m) && \
    if [ "$ARCH" = "x86_64" ]; then \
        CAIDO_ARCH="x86_64"; \
    elif [ "$ARCH" = "aarch64" ] || [ "$ARCH" = "arm64" ]; then \
        CAIDO_ARCH="aarch64"; \
    else \
        echo "Unsupported architecture: $ARCH" && exit 1; \
    fi && \
    wget -O caido-cli.tar.gz "https://caido.download/releases/v${CAIDO_VERSION}/caido-cli-v${CAIDO_VERSION}-linux-${CAIDO_ARCH}.tar.gz" && \
    tar -xzf caido-cli.tar.gz && \
    chmod +x caido-cli && \
    rm caido-cli.tar.gz && \
    mv caido-cli /usr/local/bin/

ENV REQUESTS_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt
ENV SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt

RUN mkdir -p /workspace && chown -R pentester:pentester /workspace /app

USER pentester
# Main venv (Python 3.14) — web/API/crypto tools
RUN python3 -m venv /app/.venv && \
    /app/.venv/bin/pip install --no-cache-dir caido-sdk-client && \
    /app/.venv/bin/pip install --no-cache-dir \
        requests httpx beautifulsoup4 lxml pyjwt cryptography \
        pycryptodome aiohttp pyotp boto3 graphw00f clairvoyance r2pipe && \
    /app/.venv/bin/pip install --no-cache-dir cloud_enum || true && \
    { /app/.venv/bin/pip install --no-cache-dir python3-saml || true; } && \
    /app/.venv/bin/pip install --no-cache-dir -r /home/pentester/tools/jwt_tool/requirements.txt && \
    printf '%s\n' \
        '#!/bin/bash' \
        'exec /app/.venv/bin/python /home/pentester/tools/jwt_tool/jwt_tool.py "$@"' \
        > /home/pentester/.local/bin/jwt_tool && \
    chmod +x /home/pentester/.local/bin/jwt_tool

# Binary exploitation venv (Python 3.13) — pwntools and angr have no Python 3.14 wheels;
# bitstring<4.0 pins pyvex to the API it expects (ConstBitStream removed in v4)
RUN python3.13 -m venv /app/.venv313 && \
    /app/.venv313/bin/pip install --no-cache-dir pwntools && \
    /app/.venv313/bin/pip install --no-cache-dir angr "bitstring<4.0"

# jwt_tool 2.3.0 + Python 3.14: configparser.write() raises InvalidWriteError on
# keys containing ':' (used as comment stubs in jwt_tool's config). Skip createConfig()
# entirely by pre-writing a clean jwtconf.ini and generating the RSA/EC keys directly.
RUN mkdir -p /home/pentester/.jwt_tool && \
    openssl genrsa -out /home/pentester/.jwt_tool/jwttool_custom_private_RSA.pem 2048 2>/dev/null && \
    openssl rsa -in /home/pentester/.jwt_tool/jwttool_custom_private_RSA.pem \
        -pubout -out /home/pentester/.jwt_tool/jwttool_custom_public_RSA.pem 2>/dev/null && \
    openssl ecparam -name prime256v1 -genkey -noout \
        -out /home/pentester/.jwt_tool/jwttool_custom_private_EC.pem 2>/dev/null && \
    openssl ec -in /home/pentester/.jwt_tool/jwttool_custom_private_EC.pem \
        -pubout -out /home/pentester/.jwt_tool/jwttool_custom_public_EC.pem 2>/dev/null && \
    printf '[crypto]\npubkey = /home/pentester/.jwt_tool/jwttool_custom_public_RSA.pem\nprivkey = /home/pentester/.jwt_tool/jwttool_custom_private_RSA.pem\necpubkey = /home/pentester/.jwt_tool/jwttool_custom_public_EC.pem\necprivkey = /home/pentester/.jwt_tool/jwttool_custom_private_EC.pem\njwks = /home/pentester/.jwt_tool/jwttool_custom_jwks.json\n\n[customising]\nuseragent = Mozilla/5.0 (Windows NT 10.0; Win64; x64) jwt_tool\njwks_kid = jwt_tool\n\n[services]\njwt_tool_version = 2.3.0\nproxy = 127.0.0.1:8080\nredir = True\njwksloc = \nhttplistener = \n\n[input]\nwordlist = jwt-common.txt\ncommonHeaders = common-headers.txt\ncommonPayloads = common-payloads.txt\n\n[argvals]\nsigType = \ntargetUrl = \nrate = 999999999\ncookies = \nkey = \nkeyList = \nkeyFile = \nheaderLoc = \npayloadclaim = \nheaderclaim = \npayloadvalue = \nheadervalue = \ncanaryvalue = \nheader = \nexploitType = \nscanMode = \nreqMode = \npostData = \nresCode = \nresSize = \nresContent = \noverridesub = false\n' \
        > /home/pentester/.jwt_tool/jwtconf.ini

COPY --chown=pentester:pentester strix/tools/proxy/caido_api.py /opt/strix-python/caido_api.py
ENV PYTHONPATH=/opt/strix-python

# Login shells (e.g. `bash -lc`) source /etc/profile, which on Debian/Kali
# hard-resets PATH and drops the image's ENV PATH entries. Re-add the same
# directories here — including /app/.venv/bin — so `python3`/`pip` resolve to
# the venv (which ships requests, httpx, bs4, lxml, pyjwt, cryptography, and the
# Caido SDK) instead of the externally-managed system interpreter.
RUN echo 'export PATH="/home/pentester/go/bin:/home/pentester/.local/bin:/home/pentester/.npm-global/bin:/app/.venv/bin:$PATH"' >> /home/pentester/.bashrc && \
    echo 'export PATH="/home/pentester/go/bin:/home/pentester/.local/bin:/home/pentester/.npm-global/bin:/app/.venv/bin:$PATH"' >> /home/pentester/.profile

USER root
COPY containers/nuclei-parse containers/sqlmap-parse containers/semgrep-parse \
     containers/ffuf-parse containers/httpx-parse \
     containers/grpcurl-parse containers/oauth2-pkce containers/race-burst \
     containers/cloud-metadata-probe containers/env-dump containers/llm-probe \
     containers/gobuster-parse containers/hydra-parse containers/nikto-parse \
     containers/whatweb-parse containers/tplmap-parse containers/smuggler-parse \
     containers/binwalk-parse \
     containers/nmap-parse containers/wfuzz-parse containers/feroxbuster-parse \
     containers/amass-parse containers/testssl-parse \
     containers/container-escape containers/docker-probe containers/totp-bruteforce \
     /usr/local/bin/
RUN chmod +x /usr/local/bin/nuclei-parse /usr/local/bin/sqlmap-parse \
             /usr/local/bin/semgrep-parse /usr/local/bin/ffuf-parse \
             /usr/local/bin/httpx-parse /usr/local/bin/grpcurl-parse \
             /usr/local/bin/oauth2-pkce /usr/local/bin/race-burst \
             /usr/local/bin/cloud-metadata-probe /usr/local/bin/env-dump \
             /usr/local/bin/llm-probe /usr/local/bin/gobuster-parse \
             /usr/local/bin/hydra-parse /usr/local/bin/nikto-parse \
             /usr/local/bin/whatweb-parse /usr/local/bin/tplmap-parse \
             /usr/local/bin/smuggler-parse /usr/local/bin/binwalk-parse \
             /usr/local/bin/nmap-parse /usr/local/bin/wfuzz-parse \
             /usr/local/bin/feroxbuster-parse /usr/local/bin/amass-parse \
             /usr/local/bin/testssl-parse /usr/local/bin/container-escape \
             /usr/local/bin/docker-probe /usr/local/bin/totp-bruteforce

COPY containers/docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

USER pentester
WORKDIR /workspace

ENTRYPOINT ["docker-entrypoint.sh"]
