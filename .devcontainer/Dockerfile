FROM mcr.microsoft.com/devcontainers/base:ubuntu-24.04

# CodeQL CLI 版本, 可通过 devcontainer.json 的 build.args 覆盖
ARG CODEQL_VERSION=v2.25.2

USER root

# 基础工具链
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates curl wget unzip git \
        build-essential libssl-dev pkg-config \
        pipx \
    && rm -rf /var/lib/apt/lists/*

# uv (项目用它管理 Python 环境)
RUN curl -LsSf https://astral.sh/uv/install.sh | env UV_INSTALL_DIR=/usr/local/bin sh

# CodeQL CLI, 解压到 /opt 并软链到 PATH
# 说明: GitHub 直连下载大文件可能被 HTTP/2 中断 (curl error 92), 故强制 HTTP/1.1,
#       并用 -C - 断点续传: 连接中断后从已下载字节处继续, 不会从头重来
RUN set -eux; \
    url="https://github.com/github/codeql-cli-binaries/releases/download/${CODEQL_VERSION}/codeql-linux64.zip"; \
    for attempt in $(seq 1 10); do \
        echo "==> 下载 CodeQL (第 ${attempt}/10 次尝试)"; \
        size_before=$(stat -c %s /tmp/codeql.zip 2>/dev/null || echo 0); \
        timeout 1800 curl -fL --http1.1 --connect-timeout 30 \
            -C - -o /tmp/codeql.zip "$url" || true; \
        if unzip -tq /tmp/codeql.zip > /dev/null 2>&1; then \
            echo "==> CodeQL 下载完成并通过完整性校验"; \
            break; \
        fi; \
        size_after=$(stat -c %s /tmp/codeql.zip 2>/dev/null || echo 0); \
        if [ "$size_after" -eq "$size_before" ]; then \
            echo "==> 本次尝试无进展, 清除残留文件后重试"; \
            rm -f /tmp/codeql.zip; \
        fi; \
        sleep 5; \
    done; \
    unzip -tq /tmp/codeql.zip > /dev/null; \
    unzip -q /tmp/codeql.zip -d /opt; \
    rm -f /tmp/codeql.zip; \
    ln -s /opt/codeql/codeql /usr/local/bin/codeql; \
    chmod -R a+rX /opt/codeql

# Semgrep, 用 pipx 装成独立环境, 避免污染系统 Python
ENV PIPX_HOME=/opt/pipx \
    PIPX_BIN_DIR=/usr/local/bin
RUN pipx install semgrep

ARG UBUNTU_MIRROR=https://mirrors.tuna.tsinghua.edu.cn/ubuntu
RUN set -eux; \
    for f in /etc/apt/sources.list /etc/apt/sources.list.d/ubuntu.sources; do \
        if [ -f "$f" ]; then \
            sed -i \
                -e "s|http://archive.ubuntu.com/ubuntu|${UBUNTU_MIRROR}|g" \
                -e "s|http://security.ubuntu.com/ubuntu|${UBUNTU_MIRROR}|g" \
                "$f"; \
        fi; \
    done; \
    printf 'Acquire::Retries "5";\nAcquire::http::Timeout "30";\nAcquire::https::Timeout "30";\n' \
        > /etc/apt/apt.conf.d/99-network-retries; \
    apt-get update; \
    rm -rf /var/lib/apt/lists/*

USER vscode
