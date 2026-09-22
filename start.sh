#!/bin/sh
# Use this checkout, not an older globally installed draxen package.
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$ROOT"
if command -v python3 >/dev/null 2>&1; then
    exec python3 -m draxen "$@"
elif command -v python >/dev/null 2>&1; then
    exec python -m draxen "$@"
fi
printf '%s\n' 'Python 3.9+ gerekli. Termux: pkg install python | iSH: apk add python3' >&2
exit 127
