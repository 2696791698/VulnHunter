#!/usr/bin/env bash
# devcontainer 首次创建后执行: 准备 Python 依赖、CodeQL MCP server 与 CodeBadger(Joern) 服务
set -e

# 以脚本所在位置推导仓库根目录 (.devcontainer/ 的上一级), 不依赖外部环境变量
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE="$(dirname "$SCRIPT_DIR")"
cd "$WORKSPACE"

echo "==> 等待容器内的 Docker daemon 就绪 (DinD)"
for _ in $(seq 1 60); do
    if docker info >/dev/null 2>&1; then
        echo "    Docker daemon 已就绪"
        break
    fi
    sleep 2
done
if ! docker info >/dev/null 2>&1; then
    echo "!! 容器内的 Docker daemon 未启动成功, 请检查 docker-in-docker feature" >&2
    exit 1
fi

echo "==> 同步 Python 依赖及桥接服务依赖 (uv sync)"
# bridge 是默认依赖组, 后续 uv sync / uv run 也会保留 fastapi 和 uvicorn。
uv sync

echo "==> 准备 docker-mcp 的独立环境"
# docker-mcp 是独立的 uv 项目, 环境放在 $HOME 下而不是仓库里 (与 README 一致)
if [ -f ./docker-mcp/pyproject.toml ]; then
    ( cd ./docker-mcp && UV_PROJECT_ENVIRONMENT="$HOME/.venvs/docker-mcp" uv sync )
else
    echo "    未找到 docker-mcp/pyproject.toml, 跳过"
fi

echo "==> 安装 CodeQL MCP server (官方最新版)"
npm install -g codeql-development-mcp-server@latest

echo "==> 准备 CodeBadger"
if [ ! -d ./codebadger ] && [ -f ./codebadger.zip ]; then
    unzip -q ./codebadger.zip
fi
if [ -d ./codebadger ] && [ -f ./codebadger/docker-compose.yml ]; then
    # devcontainer 的 UV_PROJECT_ENVIRONMENT 指向主项目环境, 子项目必须单独覆盖。
    ( cd ./codebadger && UV_PROJECT_ENVIRONMENT="${CODEBADGER_PROJECT_ENVIRONMENT:-$HOME/.venvs/codebadger}" uv sync --locked )
    # codebadger 的 .env 默认 DOCKER_HOST=unix:///var/run/docker.sock,
    # 在 DinD 环境下该 socket 指向容器内的 dockerd, 无需修改
    ( cd ./codebadger && docker compose up -d )
else
    echo "    未找到 codebadger/docker-compose.yml, 跳过"
    echo "    (可手动解压 codebadger.zip 后运行 docker compose up -d)"
fi

echo ""
echo "==> 完成。下一步:"
echo "    1. 复制 .env.example 为 .env 并填写配置"
echo "    2. 启动 docker-mcp 服务 (监听 \$Docker_MCP_URL, 默认 19000)"
echo "    3. uv run check_environment.py"
