#!/usr/bin/env bash
# The standby's feed, end to end on this machine (docs/deploy.md): a ledger
# written as the hub writes it (each instance's file before the row naming
# it), replicated by Litestream, fed by standby-sync.sh to a standby
# directory, and restored there by the standby's entrypoint
# (apps/hub/standby.sh) after every round. Each restored ledger must be
# whole and name no file the standby lacks. Only finished files reach it,
# a file the hub replaced replacing its own; once it acted, the replica
# alone. Needs Docker (Litestream's image), python3 and rsync.
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
mkdir -p "$root/tmp"
work="$(mktemp -d "$root/tmp/deploy-test.XXXXXX")"
trap 'kill $(jobs -p) 2>/dev/null || true; [[ -n "${KEEP:-}" ]] || rm -rf "$work"' EXIT
export LICASH_LITESTREAM_ROOT="$work"
litestream="$root/regtest/litestream-docker.sh"
seconds="${LICASH_DEPLOY_TEST_SECONDS:-90}"

hub="$work/hub" standby="$work/standby"
mkdir -p "$hub/data/opening-instances" "$hub/data/hp-proofs" "$hub/data/header-chain" \
    "$hub/replica" "$standby/data" "$standby/replica"
# Finished files, and what is not: half written, a proof's work, the
# bench.
mkdir -p "$hub/data/hp-proofs/d1/stark-cpu-19" "$hub/data/header-chain/p1/batch-120" \
    "$standby/data/hp-proofs/d1"
echo "the hub's machine's" >"$hub/data/hp-proofs/bench.json"
echo input >"$hub/data/hp-proofs/d1/input.bin"
echo "made here" >"$hub/data/hp-proofs/d1/proof.json"
echo "made there, before the hub's" >"$standby/data/hp-proofs/d1/proof.json"
echo progress >"$hub/data/hp-proofs/d1/stark-cpu-19/joined"
echo half >"$hub/data/hp-proofs/d1/input.part"
echo receipt >"$hub/data/header-chain/p1/receipt-10"
echo half >"$hub/data/header-chain/p1/receipt-11.part"
echo batch >"$hub/data/header-chain/p1/batch-120/batch.bin"
echo half >"$hub/data/opening-instances/.7.abc.new"

db="$hub/data/hub.sqlite"
python3 - "$db" <<'EOF'
import sqlite3, sys
c = sqlite3.connect(sys.argv[1])
c.execute("pragma journal_mode=wal")
c.execute("create table openings(i integer primary key, v blob)")
c.commit()
EOF
cat >"$work/litestream.yml" <<EOF
dbs:
  - path: $db
    replica:
      type: file
      path: $hub/replica/hub
EOF
"$litestream" replicate -config "$work/litestream.yml" >"$work/replicate.log" 2>&1 &

# The hub: an instance's file, then the row naming it.
python3 - "$db" "$hub/data/opening-instances" "$seconds" <<'EOF' &
import os, sqlite3, sys, time
db, dir, seconds = sys.argv[1], sys.argv[2], float(sys.argv[3])
c = sqlite3.connect(db, timeout=30)
end, i = time.time() + seconds, 0
while time.time() < end:
    i += 1
    path = os.path.join(dir, f"{i}.bin")
    with open(path + ".part", "wb") as f:
        f.write(os.urandom(20000))
    os.rename(path + ".part", path)
    with c:
        c.execute("insert into openings(i, v) values (?, ?)", (i, os.urandom(3000)))
    time.sleep(0.02)
EOF
writer=$!

# The hub's stand-in at the standby: the ledger it starts on whole, and
# every instance it names there.
cat >"$work/check-hub" <<'EOF'
#!/usr/bin/env bash
exec python3 - "$LICASH_HUB_DATA" <<'PY'
import os, sqlite3, sys
data = sys.argv[1]
c = sqlite3.connect(os.path.join(data, "hub.sqlite"))
assert c.execute("pragma integrity_check").fetchone()[0] == "ok"
rows = [i for (i,) in c.execute("select i from openings")]
missing = [i for i in rows if not os.path.exists(os.path.join(data, "opening-instances", f"{i}.bin"))]
assert not missing, f"named, not there: {missing[:5]}"
print(len(rows))
PY
EOF
chmod +x "$work/check-hub"

export LICASH_STANDBYS="$standby" LICASH_SYNC_RSH=ssh LICASH_SYNC_ONCE=1 \
    LICASH_SYNC_DATA="$hub/data" LICASH_SYNC_REPLICA="$hub/replica" LICASH_SYNC_STAGE="$work/stage"
sleep 5
rounds=0 most=0
while kill -0 "$writer" 2>/dev/null; do
    if ! "$root/deploy/hub/sync/standby-sync.sh"; then
        echo "round $((rounds + 1)) not fed"
        continue
    fi
    "$root/deploy/hub/sync/healthy.sh"
    # Before Litestream's first file, nothing to restore yet.
    [[ -e "$standby/replica/hub" ]] || continue
    rows=$(LICASH_HUB_DATA="$standby/data" LICASH_STANDBY_REPLICA="file://$standby/replica/hub" \
        LICASH_LITESTREAM="$litestream" LICASH_HUB="$work/check-hub" \
        bash "$root/apps/hub/standby.sh" 2>"$work/standby.log") || {
        cat "$work/standby.log"
        exit 1
    }
    rounds=$((rounds + 1))
    ((rows >= most)) || {
        echo "restored $rows rows after $most"
        exit 1
    }
    most=$rows
done
wait "$writer"
((rounds >= 3)) || {
    echo "only $rounds rounds restored"
    exit 1
}
fail() {
    echo "$*"
    exit 1
}
sd="$standby/data"
for f in hp-proofs/bench.json hp-proofs/d1/stark-cpu-19 hp-proofs/d1/input.part \
    header-chain/p1/receipt-11.part header-chain/p1/batch-120 opening-instances/.7.abc.new; do
    [[ ! -e "$sd/$f" ]] || fail "$f reached the standby"
done
[[ -e "$sd/hp-proofs/d1/input.bin" && -e "$sd/header-chain/p1/receipt-10" ]] ||
    fail "a finished file did not reach the standby"
[[ "$(cat "$sd/hp-proofs/d1/proof.json")" == "made here" ]] ||
    fail "the hub's proof did not replace the standby's"
# A receipt the hub made again after a reorganization: the standby's
# replaced too.
sleep 1
echo "after the reorganization" >"$hub/data/header-chain/p1/receipt-10"
"$root/deploy/hub/sync/standby-sync.sh"
[[ "$(cat "$sd/header-chain/p1/receipt-10")" == "after the reorganization" ]] ||
    fail "a replaced receipt was not replaced at the standby"
# Acted: its files are its own, the replica still sent.
echo "300 ab" >"$sd/standby-acted"
echo "made there, acting" >"$sd/hp-proofs/d1/proof.json"
echo "made again here" >"$hub/data/hp-proofs/d1/proof.json"
echo new >"$hub/data/opening-instances/new.bin"
before=$(find "$standby/replica" -type f | wc -l)
python3 -c 'import sqlite3, sys
c = sqlite3.connect(sys.argv[1])
with c:
    c.execute("insert into openings(i, v) values (?, ?)", (10**9, b"after"))' "$db"
sleep 3
"$root/deploy/hub/sync/standby-sync.sh"
[[ "$(cat "$sd/hp-proofs/d1/proof.json")" == "made there, acting" ]] ||
    fail "a file of a standby that acted was replaced"
[[ ! -e "$sd/opening-instances/new.bin" ]] || fail "a standby that acted was sent files"
(($(find "$standby/replica" -type f | wc -l) > before)) || fail "a standby that acted was sent no replica"
echo "standby fed and restored whole $rounds times, up to $most openings"
