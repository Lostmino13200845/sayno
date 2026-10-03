#!/usr/bin/env sh
# SAYNO launcher for macOS and Linux. Needs Python 3.10+, nothing else.
cd "$(dirname "$0")" || exit 1
for c in python3 python; do
  if command -v "$c" >/dev/null 2>&1 && "$c" -c 'import sys; sys.exit(sys.version_info < (3, 10))' 2>/dev/null; then
    PY="$c"; break
  fi
done
[ -n "$PY" ] || { echo "Python 3.10 or newer is required: https://www.python.org/downloads/"; exit 1; }
[ -f config.json ] || cp config.example.json config.json
exec "$PY" server/app.py "$@"
