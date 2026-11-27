#!/usr/bin/env bash
# The hub's standby as its container starts it (docs/hub.md, "The
# standby"): hub.sqlite restored from the hub's newest replica, then
# `licash-hub` run with the arguments given. The standby stops with exit
# code 75 when its ledger is older than a contract's step, for this to
# restore a newer one: its container restarts it.
#
# Never restored over: a ledger the standby acted on (standby-acted), its
# own from then on, nor one this script did not restore (no
# standby-restored), as one a standby of an earlier version ran on.
#
#   LICASH_STANDBY_REPLICA  the hub.sqlite replica, as `litestream restore`
#                           takes it (file:///replica/hub)
#   LICASH_HUB_DATA         the data directory, /data, the hub's too (it
#                           takes no --data here)
#   LICASH_STANDBY_RESTORE_TIMEOUT
#                           seconds a restore may take, 300: an unreachable
#                           replica never keeps the standby down
set -euo pipefail

data="${LICASH_HUB_DATA:-/data}"
for arg in "$@"; do
    case "$arg" in
    --data | --data=*)
        printf 'standby: set LICASH_HUB_DATA, not --data: this restores the ledger the hub runs on\n' >&2
        exit 2
        ;;
    esac
done
export LICASH_HUB_DATA="$data"
replica="${LICASH_STANDBY_REPLICA:?the hub.sqlite replica to restore, as litestream restore takes it}"
litestream="${LICASH_LITESTREAM:-litestream}"
hub="${LICASH_HUB:-licash-hub}"
within="${LICASH_STANDBY_RESTORE_TIMEOUT:-300}"
db="$data/hub.sqlite"
part="$db.restoring"
acted="$data/standby-acted"
restored="$data/standby-restored"
unrestored="$data/standby-unrestored"

say() { printf 'standby: %s\n' "$*" >&2; }

# What an interrupted restore left.
rm -rf -- "$part" "$part"-* "$part".*

# The newest replica in $part, whole, or nothing there and why in
# $unrestored, for the hub to alert of.
restore() {
    local code=0
    timeout "$within" "$litestream" restore -o "$part" "$replica" || code=$?
    if [[ $code -eq 0 ]]; then
        # Its file alone, not every disk the machine has.
        sync -- "$part"
        return 0
    fi
    rm -rf -- "$part" "$part"-* "$part".*
    printf 'litestream restore of %s exited %s at %s\n' "$replica" "$code" "$(date -u +%FT%TZ)" >"$unrestored"
    return 1
}

# A ledger restored: in place, its old write-ahead log gone, and the
# notification cursors of the one replaced (the hub's events in the new one
# are the hub's to tell).
put() {
    rm -f -- "$db-wal" "$db-shm" "$data/notify.json" "$unrestored"
    mv -- "$part" "$db"
    sync -- "$db" "$data"
    say "restored from $replica"
}

if [[ -e "$acted" ]]; then
    if [[ ! -e "$db" ]]; then
        say "it acted on its own ledger ($acted) and $db is gone: not restored over" \
            "from the hub's replica. Bring its own back, or remove $acted to start it anew."
        exit 1
    fi
    # Never restored again: no restore to alert of.
    rm -f -- "$unrestored"
    say "it acted on its own ledger ($(cat -- "$acted")): not restored from the hub's replica"
elif [[ ! -e "$db" ]]; then
    restore
    # Written first: one restored and not yet renamed is restored again.
    touch -- "$restored"
    sync -- "$restored" "$data"
    put
elif [[ -e "$restored" ]]; then
    if restore; then
        put
    else
        say "not restored from $replica: started on the ledger restored before"
    fi
else
    say "$db was not restored here, as one a standby of an earlier version ran on: not" \
        "replaced. If it never acted on it (no answer of its own posted), adopt it with" \
        "'touch $restored'; it is then restored at each start."
fi

exec "$hub" "$@"
