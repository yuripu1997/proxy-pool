#!/usr/bin/env bash
# 一键部署到 Linux 服务器（systemd）
# 用法：sudo bash deploy/install.sh [安装目录] [端口]
set -euo pipefail

APP_DIR="${1:-/opt/proxy-pool}"
PORT="${2:-8787}"
SERVICE=proxypool
SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if [[ $EUID -ne 0 ]]; then
  echo "请用 sudo 运行：sudo bash deploy/install.sh"
  exit 1
fi

command -v python3 >/dev/null || { echo "缺少 python3"; exit 1; }
PYV=$(python3 -c 'import sys;print("%d%d"%sys.version_info[:2])')
[[ "$PYV" -ge 38 ]] || { echo "需要 Python 3.8+，当前 $PYV"; exit 1; }

echo "==> 安装到 $APP_DIR"
mkdir -p "$APP_DIR/data" "$APP_DIR/static"
cp "$SRC/server.py" "$SRC/core.py" "$SRC/proxy-check.py" "$APP_DIR/"
cp -r "$SRC/static/." "$APP_DIR/static/"

id -u proxypool >/dev/null 2>&1 || useradd -r -s /usr/sbin/nologin proxypool
chown -R proxypool:proxypool "$APP_DIR"

echo "==> 写入 systemd 服务"
sed -e "s#/opt/proxy-pool#$APP_DIR#g" \
    -e "s#--port 8787#--port $PORT#g" \
    "$SRC/deploy/proxypool.service" > "/etc/systemd/system/$SERVICE.service"

# 用非 root 用户跑
sed -i "/^\[Service\]/a User=proxypool\nGroup=proxypool" "/etc/systemd/system/$SERVICE.service"

systemctl daemon-reload
systemctl enable "$SERVICE" >/dev/null
systemctl restart "$SERVICE"
sleep 2

if systemctl is-active --quiet "$SERVICE"; then
  IP=$(hostname -I 2>/dev/null | awk '{print $1}')
  echo
  echo "✔ 部署完成"
  echo "  面板   http://${IP:-服务器IP}:$PORT"
  echo "  接口   http://${IP:-服务器IP}:$PORT/proxy?format=txt"
  echo "  日志   journalctl -u $SERVICE -f"
  echo "  数据   $APP_DIR/data/pool.db"
else
  echo "✘ 启动失败，看日志：journalctl -u $SERVICE -n 50 --no-pager"
  exit 1
fi
