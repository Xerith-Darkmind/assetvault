#!/usr/bin/env bash
# Stop the AssetVault dashboard and remove its URL/PID files.
ROOT="${ASSETVAULT_ROOT:-/workspace/assetvault}"
PIDF="$ROOT/.dashboard.pid"
if [[ -f "$PIDF" ]]; then
  PID="$(tr -dc 0-9 < "$PIDF")"
  if [[ -n "$PID" ]] && grep -q dashboard "/proc/$PID/cmdline" 2>/dev/null; then
    kill -TERM "$PID" 2>/dev/null
    for _ in $(seq 1 50); do kill -0 "$PID" 2>/dev/null || break; sleep 0.1; done
    kill -0 "$PID" 2>/dev/null && kill -KILL "$PID" 2>/dev/null
    echo "dashboard (pid $PID) stopped"
  else
    echo "no running dashboard for pid file"
  fi
else
  echo "no pid file; dashboard not running"
fi
rm -f "$PIDF" "$ROOT/.dashboard_url"
