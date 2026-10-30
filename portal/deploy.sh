#!/usr/bin/env bash
# Portal 服务器一键部署脚本（Ubuntu / Debian）
#   ./deploy.sh docker   使用 Docker 部署（推荐）
#   ./deploy.sh local    裸机部署（python venv + systemd）
#   ./deploy.sh check    环境与端口自检
set -euo pipefail

APP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SERVICE="portal-server"
GREEN=$'\033[32m'; RED=$'\033[31m'; YELLOW=$'\033[33m'; NC=$'\033[0m'
info() { echo "${GREEN}[OK]${NC} $*"; }
warn() { echo "${YELLOW}[!!]${NC} $*"; }
fail() { echo "${RED}[ERR]${NC} $*"; exit 1; }

require_config() {
  if grep -q "CHANGE_ME" "$APP_DIR/config.yaml"; then
    warn "config.yaml 里还有 CHANGE_ME 未替换的项，请先改完再启动："
    grep -n "CHANGE_ME" "$APP_DIR/config.yaml" | sed 's/^/     /'
    echo
    read -r -p "仍要继续？(y/N) " ans
    [[ "${ans:-N}" =~ ^[Yy]$ ]] || exit 1
  fi
}

check_env() {
  echo "--- 环境自检 ---"
  if command -v docker >/dev/null 2>&1; then
    info "docker: $(docker --version)"
  else
    warn "未安装 docker"
  fi
  if command -v python3 >/dev/null 2>&1; then
    info "python3: $(python3 --version)"
  else
    warn "未安装 python3"
  fi
  if command -v ss >/dev/null 2>&1; then
    for p in 8080 50100; do
      if ss -lntup 2>/dev/null | grep -q ":$p "; then
        warn "端口 $p 已被占用"
      else
        info "端口 $p 空闲"
      fi
    done
  fi
  echo
  echo "--- RADIUS 连通性（需要装 freeradius-utils） ---"
  if command -v radtest >/dev/null 2>&1; then
    host=$(awk '/^radius:/{f=1} f&&/host:/{print $2; exit}' "$APP_DIR/config.yaml" | tr -d '"')
    warn "手工验证: radtest <账号> <密码> ${host:-RADIUS_IP} 0 <secret>"
  else
    warn "未安装 radtest，跳过（apt install freeradius-utils）"
  fi
}

deploy_docker() {
  command -v docker >/dev/null 2>&1 || fail "未安装 docker"
  require_config
  cd "$APP_DIR"
  docker compose up -d --build
  sleep 2
  docker compose ps
  echo
  info "Web 界面: http://$(hostname -I | awk '{print $1}'):8080/portal"
  info "管理后台: http://$(hostname -I | awk '{print $1}'):8080/admin"
  info "查看日志: docker compose logs -f"
}

deploy_local() {
  command -v python3 >/dev/null 2>&1 || fail "未安装 python3"
  require_config
  cd "$APP_DIR"

  if [[ ! -d .venv ]]; then
    python3 -m venv .venv
    info "已创建虚拟环境 .venv"
  fi
  .venv/bin/pip install -q --upgrade pip
  .venv/bin/pip install -q -r requirements.txt -i https://pypi.tuna.tsinghua.edu.cn/simple
  info "依赖安装完成"

  mkdir -p data
  cat > "/etc/systemd/system/${SERVICE}.service" <<EOF
[Unit]
Description=Huawei AC Portal Server
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=${APP_DIR}
ExecStart=${APP_DIR}/.venv/bin/python ${APP_DIR}/app.py -c ${APP_DIR}/config.yaml
Restart=always
RestartSec=3
StandardOutput=append:/var/log/${SERVICE}.log
StandardError=append:/var/log/${SERVICE}.log

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  systemctl enable --now "${SERVICE}"
  sleep 2
  systemctl --no-pager --lines=15 status "${SERVICE}" || true
  echo
  info "Web 界面: http://$(hostname -I | awk '{print $1}'):8080/portal"
  info "日志: tail -f /var/log/${SERVICE}.log"
}

case "${1:-}" in
  docker) deploy_docker ;;
  local)  deploy_local ;;
  check)  check_env ;;
  *)      echo "用法: $0 {docker|local|check}"; exit 1 ;;
esac
