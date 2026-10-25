#!/usr/bin/env bash
# AssetVault installer.
#   ./install.sh            install or repair (copies missing code, creates .venv, installs requirements)
#   ./install.sh --update   replace code files only (bin/, ui/, VERSION); never touches vault data or .venv
# Target: $ASSETVAULT_ROOT (default /workspace/assetvault).
# Piped use (curl ... | bash) clones $ASSETVAULT_REPO at $ASSETVAULT_REF to a temp dir and runs from there.
set -euo pipefail
umask 077

REPO="${ASSETVAULT_REPO:-https://github.com/Xerith-Darkmind/assetvault.git}"
REF="${ASSETVAULT_REF:-main}"
ROOT="${ASSETVAULT_ROOT:-/workspace/assetvault}"
MODE=install
for a in "$@"; do
  case "$a" in
    --update) MODE=update ;;
    -h|--help) sed -n '2,6p' "${BASH_SOURCE[0]:-/dev/null}" 2>/dev/null || true; exit 0 ;;
    *) echo "install.sh: unknown option: $a" >&2; exit 64 ;;
  esac
done

die() { echo "install.sh: $*" >&2; exit 1; }

# ---- locate source tree (or fetch it when piped from curl)
SELF="${BASH_SOURCE[0]:-}"
SRC=""
if [[ -n "$SELF" && -f "$SELF" ]]; then
  d="$(cd "$(dirname "$SELF")" && pwd)"
  [[ -f "$d/assetvault/bin/avcore.py" ]] && SRC="$d"
fi
if [[ -z "$SRC" ]]; then
  command -v git >/dev/null || die "git is required to fetch AssetVault"
  TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
  git clone -q --depth 1 --branch "$REF" "$REPO" "$TMP/src" || die "could not clone $REPO ($REF)"
  bash "$TMP/src/install.sh" "$@"
  exit $?
fi

# ---- python check (sqlite3 deserialize needs 3.11+)
PY="${PYTHON:-python3}"
command -v "$PY" >/dev/null || die "python3 not found"
"$PY" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)' || die "Python 3.11+ required"

VERSION="$(cat "$SRC/VERSION" 2>/dev/null || echo unknown)"
mkdir -p "$ROOT"; mkdir -p "$ROOT/bin" "$ROOT/ui"

# ---- code files (data files are never named here)
copy_code() {   # $1 = overwrite (1) or only-if-missing (0)
  local f rel dst mode
  for f in "$SRC"/assetvault/bin/*.py "$SRC"/assetvault/bin/*.sh "$SRC"/assetvault/ui/*; do
    [[ -f "$f" ]] || continue
    rel="${f#"$SRC"/assetvault/}"; dst="$ROOT/$rel"
    [[ "$1" == 0 && -e "$dst" ]] && continue
    mode=644; [[ -x "$f" ]] && mode=755
    install -m "$mode" "$f" "$dst.new.$$" && mv -f "$dst.new.$$" "$dst"
  done
  install -m 644 "$SRC/VERSION" "$ROOT/VERSION.new.$$" && mv -f "$ROOT/VERSION.new.$$" "$ROOT/VERSION"
}

if [[ "$MODE" == update ]]; then
  [[ -f "$ROOT/bin/avcore.py" ]] || die "no existing install at $ROOT (run without --update first)"
  copy_code 1
  find "$ROOT/bin" "$ROOT/ui" -name __pycache__ -type d -prune -exec rm -rf {} + 2>/dev/null || true
  [[ -x "$ROOT/.venv/bin/python" ]] || echo "install.sh: warning: $ROOT/.venv missing; run ./install.sh to create it" >&2
  echo "AssetVault $VERSION code updated in $ROOT (vault data untouched)"
  exit 0
fi

copy_code 0
for d in blobs exports connectors; do
  [[ -e "$ROOT/$d" ]] || mkdir -m 700 "$ROOT/$d"
done
if [[ ! -x "$ROOT/.venv/bin/python" ]]; then
  "$PY" -m venv "$ROOT/.venv" || die "could not create venv (on Debian/Ubuntu: apt install python3-venv)"
fi
"$ROOT/.venv/bin/python" -m pip install -q --disable-pip-version-check -r "$SRC/requirements.txt" || die "pip install failed"
echo "AssetVault $VERSION installed in $ROOT (start: ASSETVAULT_ROOT=$ROOT $ROOT/.venv/bin/python $ROOT/bin/dashboard.py)"
