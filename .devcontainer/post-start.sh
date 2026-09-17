#!/usr/bin/env bash
# devcontainer 每次启动后执行: 拉起常驻服务。
# 管五样: Joern 容器、CodeBadger MCP (4242)、环境自检桥接 (8901)、前端 dev server (5173)、
# docker-mcp (19000)。docker-manager (15000) 不在这里 —— 它是 DinD 里的容器, 靠自身的
# restart 策略随 daemon 恢复。
# 与 post-create.sh 的分工: 那边做一次性的重活 (装依赖、构建镜像), 这边只管"把服务跑起来",
# 所以容器每次启动都会执行, 且必须尽快返回 (长驻进程要放到后台)。
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE="$(dirname "$SCRIPT_DIR")"

CODEBADGER_LOG="/tmp/codebadger-mcp.log"
BRIDGE_LOG="/tmp/vulnhunter-bridge.log"
VITE_LOG="/tmp/vulnhunter-vite.log"
DOCKER_MCP_LOG="/tmp/docker-mcp.log"

# 桥接服务和面板是项目自己的常驻进程, 要用项目 venv 的解释器/依赖
VENV_PYTHON="${UV_PROJECT_ENVIRONMENT:-/home/vscode/.venv}/bin/python"
# docker-mcp 是独立的 uv 项目, 环境在 $HOME 下 (见 README), 不在仓库里
DOCKER_MCP_PYTHON="$HOME/.venvs/docker-mcp/bin/python"

echo "==> 等待容器内的 Docker daemon 就绪 (DinD)"
for _ in $(seq 1 60); do
    if docker info >/dev/null 2>&1; then
        echo "    Docker daemon 已就绪"
        break
    fi
    sleep 2
done
if ! docker info >/dev/null 2>&1; then
    echo "!! 容器内的 Docker daemon 未启动成功, 跳过服务启动" >&2
    exit 1
fi

if [ ! -d "$WORKSPACE/codebadger" ]; then
    echo "!! 未找到 codebadger 目录 (可先解压 codebadger.zip), 跳过"
    exit 0
fi

echo "==> 启动 Joern 容器"
# compose 是幂等的: 镜像已构建且容器在跑时, 这里什么都不做
( cd "$WORKSPACE/codebadger" && docker compose up -d )

echo "==> 启动 CodeBadger MCP server (监听 4242)"
# 已在运行就不重复启动; /health 是 codebadger 自带的健康检查端点
if curl -sf --max-time 3 http://127.0.0.1:4242/health >/dev/null 2>&1; then
    echo "    已在运行, 跳过"
else
    # setsid 让进程脱离当前会话, 否则 devcontainer CLI 结束命令时可能把它一起带走
    ( cd "$WORKSPACE/codebadger" && setsid nohup uv run main.py \
        > "$CODEBADGER_LOG" 2>&1 < /dev/null & )
    # 给它几秒钟起来, 顺便让日志里的早期报错直接显示出来
    for _ in $(seq 1 15); do
        if curl -sf --max-time 2 http://127.0.0.1:4242/health >/dev/null 2>&1; then
            echo "    启动成功"
            break
        fi
        sleep 1
    done
    if ! curl -sf --max-time 2 http://127.0.0.1:4242/health >/dev/null 2>&1; then
        echo "    !! 启动后 15 秒内未就绪, 请查看日志: $CODEBADGER_LOG" >&2
    fi
fi

echo "==> 启动环境自检桥接服务 (监听 8901)"
# 面板的数据源: 读仓库根的 .env 和 check_environment.py, 必须在项目 venv 里跑
if [ ! -x "$VENV_PYTHON" ]; then
    echo "    !! 未找到 $VENV_PYTHON (先跑一次 uv sync), 跳过" >&2
elif curl -sf --max-time 3 http://127.0.0.1:8901/api/bridge/info >/dev/null 2>&1; then
    echo "    已在运行, 跳过"
else
    ( cd "$WORKSPACE" && setsid nohup "$VENV_PYTHON" web/server/main.py \
        > "$BRIDGE_LOG" 2>&1 < /dev/null & )
    for _ in $(seq 1 15); do
        if curl -sf --max-time 2 http://127.0.0.1:8901/api/bridge/info >/dev/null 2>&1; then
            echo "    启动成功"
            break
        fi
        sleep 1
    done
    if ! curl -sf --max-time 2 http://127.0.0.1:8901/api/bridge/info >/dev/null 2>&1; then
        echo "    !! 启动后 15 秒内未就绪, 请查看日志: $BRIDGE_LOG" >&2
    fi
fi

echo "==> 启动前端 dev server (监听 5173)"
# --host 0.0.0.0 不能省: vite.config.ts 没设 host, 不传就只绑 localhost
if ! command -v npm >/dev/null 2>&1; then
    echo "    !! 未找到 npm, 跳过前端" >&2
elif [ ! -x "$WORKSPACE/web/node_modules/.bin/vite" ]; then
    echo "    !! node_modules 里没有 vite (命名卷是空的?), 先在容器内 cd web && npm install, 跳过" >&2
elif curl -sf --max-time 3 http://127.0.0.1:5173/ >/dev/null 2>&1; then
    echo "    已在运行, 跳过"
else
    ( cd "$WORKSPACE/web" && setsid nohup npm run dev -- --host 0.0.0.0 \
        > "$VITE_LOG" 2>&1 < /dev/null & )
    for _ in $(seq 1 20); do
        if curl -sf --max-time 2 http://127.0.0.1:5173/ >/dev/null 2>&1; then
            echo "    启动成功"
            break
        fi
        sleep 1
    done
    if ! curl -sf --max-time 2 http://127.0.0.1:5173/ >/dev/null 2>&1; then
        echo "    !! 启动后 20 秒内未就绪, 请查看日志: $VITE_LOG" >&2
    fi
fi

echo "==> 启动 docker-mcp 服务 (监听 19000)"
# docker-manager (15000) 不用管: 它是 DinD 里的容器, restart: unless-stopped 会自己恢复
# /sse 是 SSE 长连接: curl -f 会一直挂着直到 --max-time 超时并以 28 退出, 看着像失败,
# 所以这里只解析返回码, 不看 curl 自己的退出码。
if [ ! -x "$DOCKER_MCP_PYTHON" ]; then
    echo "    !! 未找到 $DOCKER_MCP_PYTHON (先跑一次 post-create), 跳过" >&2
elif curl -s -o /dev/null --max-time 3 -w '%{http_code}' http://127.0.0.1:19000/sse 2>/dev/null | grep -q '^200$'; then
    echo "    已在运行, 跳过"
else
    ( cd "$WORKSPACE/docker-mcp" && setsid nohup "$DOCKER_MCP_PYTHON" main.py \
        > "$DOCKER_MCP_LOG" 2>&1 < /dev/null & )
    for _ in $(seq 1 15); do
        if curl -s -o /dev/null --max-time 3 -w '%{http_code}' http://127.0.0.1:19000/sse 2>/dev/null | grep -q '^200$'; then
            echo "    启动成功"
            break
        fi
        sleep 1
    done
    if ! curl -s -o /dev/null --max-time 3 -w '%{http_code}' http://127.0.0.1:19000/sse 2>/dev/null | grep -q '^200$'; then
        echo "    !! 启动后 15 秒内未就绪, 请查看日志: $DOCKER_MCP_LOG" >&2
    fi
fi

echo ""
echo "==> 服务已就绪。"
echo "    面板:        http://localhost:5173"
echo "    MCP 日志:    $CODEBADGER_LOG"
echo "    桥接日志:    $BRIDGE_LOG"
echo "    前端日志:    $VITE_LOG"
echo "    docker-mcp:  $DOCKER_MCP_LOG"
