#!/bin/bash
# membrane-inflammatory.sh — Inflammatory response watchdog
#
# Checks skunky-ingest heartbeat. If stale for >180s, activates
# inflammatory Caddyfile. When heartbeat returns, skunky-ingest
# itself restores the normal Caddyfile on startup.
#
# Run by: membrane-inflammatory.timer (every 2 min)

set -euo pipefail

HEARTBEAT="/run/membrane/skunky-ingest.heartbeat"
CADDYFILE="/etc/membrane/Caddyfile"
INFLAMMATORY="/etc/membrane/Caddyfile.inflammatory"
NORMAL_BACKUP="/etc/membrane/Caddyfile.normal"
STATE_FILE="/run/membrane/inflammatory.state"
MAX_STALE_SECS=180
CADDY_BIN="/opt/membrane/caddy"

log() {
    logger -t membrane-inflammatory "$1"
    echo "$(date -u +%FT%T) $1"
}

# Check if inflammatory config exists
if [ ! -f "$INFLAMMATORY" ]; then
    log "ERROR: $INFLAMMATORY not found — cannot activate inflammatory response"
    exit 1
fi

# Check heartbeat
if [ ! -f "$HEARTBEAT" ]; then
    log "WARN: heartbeat file missing — skunky-ingest may not be running"
    heartbeat_age=999999
else
    heartbeat_epoch=$(cat "$HEARTBEAT" 2>/dev/null || echo 0)
    now_epoch=$(date +%s)
    heartbeat_age=$(( now_epoch - heartbeat_epoch ))
fi

already_inflammatory=false
if [ -f "$STATE_FILE" ] && [ "$(cat "$STATE_FILE")" = "inflammatory" ]; then
    already_inflammatory=true
fi

if [ "$heartbeat_age" -gt "$MAX_STALE_SECS" ]; then
    if [ "$already_inflammatory" = true ]; then
        log "inflammatory response still active (heartbeat stale ${heartbeat_age}s)"
        exit 0
    fi

    log "🔴 INFLAMMATORY ACTIVATION — heartbeat stale for ${heartbeat_age}s, locking membrane"

    # Back up the normal Caddyfile (only if not already backed up)
    if [ ! -f "$NORMAL_BACKUP" ]; then
        cp "$CADDYFILE" "$NORMAL_BACKUP"
        log "normal Caddyfile backed up to $NORMAL_BACKUP"
    fi

    # Activate inflammatory config
    cp "$INFLAMMATORY" "$CADDYFILE"
    if "$CADDY_BIN" reload --config "$CADDYFILE" --address localhost:2019 2>&1; then
        log "inflammatory Caddyfile activated and Caddy reloaded"
    else
        log "ERROR: Caddy reload failed after inflammatory activation"
        # Restore backup
        cp "$NORMAL_BACKUP" "$CADDYFILE"
        exit 1
    fi

    echo "inflammatory" > "$STATE_FILE"

else
    if [ "$already_inflammatory" = true ]; then
        log "🟢 INFLAMMATORY RESOLVED — heartbeat healthy (${heartbeat_age}s), restoring membrane"

        if [ -f "$NORMAL_BACKUP" ]; then
            cp "$NORMAL_BACKUP" "$CADDYFILE"
            if "$CADDY_BIN" reload --config "$CADDYFILE" --address localhost:2019 2>&1; then
                log "normal Caddyfile restored and Caddy reloaded"
            else
                log "ERROR: Caddy reload failed during inflammatory resolution"
                exit 1
            fi
            rm -f "$NORMAL_BACKUP"
        fi

        echo "normal" > "$STATE_FILE"
    fi
fi
