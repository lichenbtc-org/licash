#!/usr/bin/env bash
# Feeds the hub's standbys (docs/deploy.md): every LICASH_SYNC_EVERY
# seconds, to each of LICASH_STANDBYS, the files a standby plays with, then
# the hub's Litestream replica as it was before those files were read, so
# that a standby's replica never names a file it lacks (docs/hub.md:
# copy the database first, then the files).
#
# The files are the finished ones only: each opening's instances, the
# header chain's receipts, and each dispute's frozen input, chain receipt
# and proof. Never a file half written (.part, .new, .tmp) nor a proof's
# resumable work, which the hub replaces as it goes. A file the hub
# replaced (a receipt after a reorganization, a proof made again) replaces
# the standby's, as its ledger is the hub's; none is deleted there. Once
# a standby acted (data/standby-acted), its ledger and files are its own:
# it is sent the replica alone.
#
#   LICASH_STANDBYS     space-separated rsync destinations, each a
#                       directory holding data/ and replica/:
#                       licash@10.73.0.2:/srv/licash-standby
#   LICASH_SYNC_EVERY   seconds between rounds, 10
#   LICASH_SYNC_RSH     the remote shell rsync runs, ssh with /ssh's key
#   LICASH_SYNC_ONCE    set: one round, its exit code the round's
#
# Reads /data (the hub's, read-only) and /replica (Litestream's); keeps
# its snapshot in /stage. Each destination's last good round is
# /stage/.ok-<n> (n its place in LICASH_STANDBYS), for the healthcheck.
set -uo pipefail

every="${LICASH_SYNC_EVERY:-10}"
read -r -a targets <<<"${LICASH_STANDBYS:?the standbys to feed, as rsync destinations}"
rsh="${LICASH_SYNC_RSH:-ssh -i /ssh/id_ed25519 -o UserKnownHostsFile=/ssh/known_hosts -o StrictHostKeyChecking=yes -o BatchMode=yes -o ConnectTimeout=10 -o ServerAliveInterval=10 -o ServerAliveCountMax=3}"
data="${LICASH_SYNC_DATA:-/data}"
replica="${LICASH_SYNC_REPLICA:-/replica}"
stage="${LICASH_SYNC_STAGE:-/stage}"

say() { printf '%s standby-sync: %s\n' "$(date -u +%FT%TZ)" "$*" >&2; }

# rsync, a file vanishing as it is read (Litestream's compactions) no
# failure.
copy() {
    rsync "$@"
    local code=$?
    [[ $code -eq 0 || $code -eq 24 ]]
}

# The finished files of the hub's data, to standby $1 unless it acted.
files() {
    local code=0
    rsync --list-only -e "$rsh" "$1/data/standby-acted" >/dev/null 2>&1 || code=$?
    case $code in
    0) return 0 ;;   # It acted: none.
    23) ;;           # No such file: it did not.
    *) return 1 ;;   # Unreachable.
    esac
    local d
    for d in opening-instances header-chain hp-proofs; do
        [[ -d "$data/$d" ]] || continue
        local filter=()
        case $d in
        # <id>/<number>, written as .<number>.<nonce>.new and renamed.
        opening-instances) filter=(--exclude='.*') ;;
        # <program>/receipt-<count>; not the batches under way.
        header-chain) filter=(--exclude='*.part' --include='/*/' --include='/*/receipt-*' --exclude='*') ;;
        # <id>/ as frozen and proven; not its work, nor the bench.
        hp-proofs) filter=(--include='/*/' --include='/*/input.bin' --include='/*/chain.receipt'
            --include='/*/proof.json' --exclude='*') ;;
        esac
        copy -rltO --prune-empty-dirs "${filter[@]}" -e "$rsh" "$data/$d/" "$1/data/$d/" || return 1
    done
}

round() {
    mkdir -p "$stage/replica"
    # Litestream writes each file under .tmp and renames it whole: the
    # rest never change, so the snapshot copies only what is new.
    if ! copy -a --delete --exclude='*.tmp' "$replica/" "$stage/replica/"; then
        say "the replica in $replica could not be read"
        return 1
    fi
    local failed=0 i=0 t
    for t in "${targets[@]}"; do
        i=$((i + 1))
        # Files first.
        if ! files "$t"; then
            say "the files did not reach $t"
            failed=1
            continue
        fi
        # Then the replica, its files removed there only once the new ones
        # are in: whole at any moment it is restored from.
        if ! copy -rltO --delete-after --exclude='*.tmp' -e "$rsh" "$stage/replica/" "$t/replica/"; then
            say "the replica did not reach $t"
            failed=1
            continue
        fi
        date +%s >"$stage/.ok-$i"
    done
    return "$failed"
}

if [[ -n "${LICASH_SYNC_ONCE:-}" ]]; then
    round
    exit
fi
say "feeding ${#targets[@]} standby(s) every ${every}s"
while :; do
    round || true
    sleep "$every"
done
