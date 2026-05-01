#!/bin/ash

cd /app
pip install --no-cache-dir -r requirements.txt
SCRIPT="${1}"
exec python "$SCRIPT"
