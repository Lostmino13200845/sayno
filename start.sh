#!/usr/bin/env sh
cd "$(dirname "$0")"
[ -f config.json ] || cp config.example.json config.json
exec python3 server/app.py
