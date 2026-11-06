# forge-node Slice N5-prep — scope (STEP 0)

Branch `n5prep` (forge-node, base `main` 7a46e8b = N4 merged) and branch `n5prep` in forge-ops (base `master` 77df871). BUILD ONLY: no merge, nothing installed on any host, no hub started in production, no firewall change applied.
Goal: the owner can install forge-node T0 on all four hosts (install readiness; BRIEF_forge-nodeinstallguide n-cd6ac08f, report section 0).

## 1. The six items (task text)

1. **Release CLI** - `release build` (and `release sign`) subcommand of the forge-node CLI around `release/build.py:build_release()`; signing with the owner's passphrase-protected Ed25519 key via `ssh-keygen -Y sign -n forge-node-release` must work interactively (passphrase prompt on the owner's Mac, NOT via `capture_output`). Tests with a throwaway key.
2. **T0 profile for every host** (Betriebsleiter decision): ALL hosts (g2, g3, g1, g4) install the `t0` profile for now: no forge-root volume, no loop volume, no `selftest.noop` code, policy `global_mode` observe, `tiers_enabled` [0]. `release/policies.py` templates accordingly (g2/g3 currently default to `full`); `full` stays available for later T1. Tests: each host template validates as T0-only; privd rejects any policy above T0 for the t0 profile.
3. **Hub**: prepare the production hub deploy (forge-core secrets `nodehub`, listener 8094, design 13.B) as a ready-to-send GO text in the report (not run). List the exact secrets/files it needs.
4. **Firewall 8094**: the rule lives only on forge-ops branch `n1`. Port it onto current forge-ops master on a new branch (`bin/forge-docker-user.sh` `--hub`, with `--dry-run` / 5-minute timer / `--confirm`). Tests / dry-run output only.
5. **Order**: design 13.D (g2 -> g3 -> g1 -> g4; g4 last, live-trading host).
6. **Owner Mac steps** (13.A A1/A2: `owner_ed25519` with passphrase, `allowed_signers`, CA): exact copy-paste commands.

## 2. SPEC check: does the design contradict the t0 decision?

**No - it narrows, it does not contradict. No SPEC-QUESTION.** Basis:
- 13 (validity paragraph) names both artifacts `forge-node-<VER>-full.tar` / `-t0.tar`; the `t0` artifact, its op-free privd and its policy schema (`profile t0 enables tier 0 only`, no forge roots, `policy_full.py`) already exist and are what g1/g4 run. The T0 acceptance (14.1) and round 0 need only T0 ops; `inv.*`, `metrics.sample` and `doctor` per-op selfcheck of the T0 ops are identical in both profiles.
- 13.D / 4.7 list `full` + loop volume + "Tiers 0,1,2 observe" for g2 and "0 (+1,2 dry_run_only)" for g3 as the *first policy*. The design's own Gated-features decision (header, "Gated features"; 14.1 acceptance (11)) already makes every `tiers_enabled` > 0 invalid until gates A-D are met in code, so those T1/T2 columns could not have been signed today anyway. 15 P1/P2: g2 and the others are `observe`, T0 first; P3 (T1/T2 on g2) is a later phase.
- Deltas to the 13.C/13.D text that follow from the decision (recorded in the report's owner guide): `PROFILE=t0`, `FORGE_ROOT=none`, `FORGE_ROOT_BYTES=0`, `MIN_FREE_BYTES=0` on all four hosts, so C1 free-space check and the C3 loop-volume block are skipped; the `forge root volume` doctor check reports `skip`; no `forge_roots` in the policy. 14.1 W1/W2 (`selftest.noop` kill-9 test on g2, volume workloads) and 14.2 M2 (20 GiB write test in the forge root) are NOT round 0 and need the `full` profile later.
- **Consequence to know (not a contradiction):** `node.nodes.profile` is immutable in the hub schema (`guard_immutable('node_id','profile','created_at')`, migration 0001). A node registered as `t0` cannot later become `full` in place; the later T1 step on g2/g3 needs a new node registration (revoke + new row) or an explicit migration. The install guide registers g2/g3 as `t0`.

## 3. Design text 13.A-13.D (verbatim from docs/design/FORGE_NODE.md, revision 6)

~~~~markdown
## 13. Install procedure (exact owner commands)

> **Validity:** these commands become executable once implementation slices N1–N3 deliver the signed per-profile release artifacts `forge-node-<VER>-full.tar` / `forge-node-<VER>-t0.tar` (+ `.sig`) and the policy templates. Until then they are the specification of the owner's steps. Keep one SSH session open per server for the whole block (rollback anchor). **Never run during 02:00–05:45 Berlin or before 06:00 on a Sunday.** Order: **carlgpu2 → carlgpu3 → carlgpu1 → carlgpu4** with ≥ 1 day of observation between servers. SSH as the owner's existing `carl` account with the existing key; no sshd change anywhere.

### 13.A Once, on the Mac (private keys stay here)

```bash
umask 077
mkdir -p ~/forge-node-owner/{ca,issued,release,policy} && cd ~/forge-node-owner

# A1 owner signing key (set a passphrase). With a FIDO2 key use: -t ed25519-sk
ssh-keygen -t ed25519 -a 100 -C "forge-node-owner" -f owner_ed25519
printf 'owner@forge namespaces="forge-node-policy,forge-node-approval,forge-node-release" %s\n' \
  "$(cut -d' ' -f1,2 owner_ed25519.pub)" > allowed_signers
ssh-keygen -lf owner_ed25519.pub            # note this fingerprint; compare on every server

# A2 mTLS CA (EC P-256, 5 years); the key never leaves this Mac
cat > ca/ca.cnf <<'EOF'
[req]
distinguished_name=dn
x509_extensions=v3_ca
prompt=no
[dn]
CN=forge-node-ca
[v3_ca]
basicConstraints=critical,CA:TRUE,pathlen:0
keyUsage=critical,keyCertSign,cRLSign
subjectKeyIdentifier=hash
EOF
openssl ecparam -name prime256v1 -genkey -noout -out ca/ca.key
openssl req -x509 -new -key ca/ca.key -sha256 -days 1825 -config ca/ca.cnf -out ca/ca.crt
openssl x509 -in ca/ca.crt -noout -fingerprint -sha256 -dates
```

### 13.B Hub on carlgpu2 (once; after slice N1 has delivered the `forge-nodehub` compose service)

```bash
# on the Mac: build the hub server cert request after generating the key on carlgpu2
ssh -t -i ~/.ssh/sshcarljump01 carl@192.168.10.4
# --- on carlgpu2 ---
sudo install -d -m 0750 -o forge -g forgebox /srv/forge/work/forge-core/secrets/nodehub
sudo -u forge sh -c 'umask 077; openssl ecparam -name prime256v1 -genkey -noout -out /srv/forge/work/forge-core/secrets/nodehub/hub.key'
sudo -u forge openssl req -new -key /srv/forge/work/forge-core/secrets/nodehub/hub.key \
  -subj "/CN=forge-nodehub" -out /srv/forge/work/forge-core/secrets/nodehub/hub.csr
# hub gate key (signs jobs and leases; no passphrase, it is a service key; the public part goes into every node policy)
sudo -u forge ssh-keygen -t ed25519 -N '' -C forge-node-hub-gate -f /srv/forge/work/forge-core/secrets/nodehub/gate_ed25519
exit
# --- on the Mac ---
scp -i ~/.ssh/sshcarljump01 carl@192.168.10.4:/srv/forge/work/forge-core/secrets/nodehub/hub.csr ~/forge-node-owner/issued/
scp -i ~/.ssh/sshcarljump01 carl@192.168.10.4:/srv/forge/work/forge-core/secrets/nodehub/gate_ed25519.pub ~/forge-node-owner/issued/hub_gate_ed25519.pub
cd ~/forge-node-owner
printf 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\nsubjectAltName=IP:192.168.10.4,DNS:forge-nodehub.lan\n' > issued/ext_hub.cnf
openssl x509 -req -in issued/hub.csr -CA ca/ca.crt -CAkey ca/ca.key -CAcreateserial -days 365 -sha256 \
  -extfile issued/ext_hub.cnf -out issued/hub.crt
scp -i ~/.ssh/sshcarljump01 issued/hub.crt ca/ca.crt carl@192.168.10.4:/tmp/
ssh -t -i ~/.ssh/sshcarljump01 carl@192.168.10.4 \
  'sudo install -m 0644 -o forge -g forgebox /tmp/hub.crt /tmp/ca.crt /srv/forge/work/forge-core/secrets/nodehub/ && rm /tmp/hub.crt /tmp/ca.crt'
```
Then the hub is started by the normal forge GO flow (build + digest re-pin + migrate, no owner step), and the firewall rule is applied by the owner **with the existing timer protocol** (after the forge-ops slice has added TCP 8094 from the two rack /29s):
```bash
sudo /srv/forge/work/forge-ops/bin/forge-docker-user.sh --dry-run      # review the 8094 lines
sudo /srv/forge/work/forge-ops/bin/forge-docker-user.sh                # applies, 5-minute rollback timer
sudo /srv/forge/work/forge-ops/bin/forge-docker-user.sh --confirm      # within 5 minutes, after the checks below
```

### 13.C Per server (common body; the values per server are in 13.D)

**Environment contract (fixes the "variables never assigned remotely" gap).** Shell variables do not survive `ssh`. Every server-side block therefore **starts by sourcing a small env file** that the Mac block copies over, and fails if anything is missing. The Mac creates `fn.env` once per server from 13.D:

On the Mac:
```bash
cd ~/forge-node-owner
cat > fn.env <<EOF
NID=g2
IP=192.168.10.4
VER=<VER>
PROFILE=full
FORGE_ROOT=/srv/forge/node
FORGE_ROOT_BYTES=107374182400
MIN_FREE_BYTES=214748364800
EOF
set -a; . ./fn.env; set +a                                   # the Mac shell needs the same values for the scp names
scp -i ~/.ssh/sshcarljump01 fn.env release/forge-node-$VER-$PROFILE.tar release/forge-node-$VER-$PROFILE.tar.sig allowed_signers carl@$IP:/tmp/
ssh -t -i ~/.ssh/sshcarljump01 carl@$IP
```
On the server (**segment 1**; keep the session open):
```bash
set -a; . /tmp/fn.env; set +a; : "${NID:?}" "${IP:?}" "${VER:?}" "${PROFILE:?}" "${FORGE_ROOT:?}" "${FORGE_ROOT_BYTES:?}" "${MIN_FREE_BYTES:?}"

# C1 preflight (read-only) — stop and tell the Betriebsleiter if anything is off
date; TZ=Europe/Berlin date +%H:%M; timedatectl | grep -E 'Time zone|synchronized'
free -m | sed -n 1,3p; df -h / /srv/models /srv/kmu-ai 2>/dev/null
ss -tlnH | grep -c ':8094 ' || true            # must be 0 on g1/g3/g4; on g2 only after the hub is up
python3 --version; id forgenode 2>&1 | head -1                 # 'no such user' expected
AVAIL=$(df -B1 --output=avail / | tail -1); echo "free on /: $AVAIL"
[ "$FORGE_ROOT" = none ] || [ "$AVAIL" -gt $((FORGE_ROOT_BYTES + MIN_FREE_BYTES)) ] || echo "NOT ENOUGH FREE SPACE ON / FOR THE FORGE VOLUME - STOP"
ls /etc/sudoers.d/ | grep -i forge || echo "no forge sudoers (expected: none, forever)"

# C2 verify the release (compare the fingerprint with the one noted on the Mac)
awk '{print $3,$4}' /tmp/allowed_signers | ssh-keygen -lf -
ssh-keygen -Y verify -f /tmp/allowed_signers -I owner@forge -n forge-node-release \
  -s /tmp/forge-node-$VER-$PROFILE.tar.sig < /tmp/forge-node-$VER-$PROFILE.tar        # expect: Good "forge-node-release" signature

# C3 user, directories, root-owned log directories, forge root volume on the SYSTEM DISK
sudo useradd --system --user-group --home-dir /var/lib/forge-node --create-home --shell /usr/sbin/nologin forgenode
sudo install -d -m 0755 -o root -g root /etc/forge-node /etc/forge-node/policy
printf 'FORGE_NODE_NODE_ID=%s\n' "$NID" | sudo tee /etc/forge-node/node.env >/dev/null     # the ONLY per-host value of the units (EnvironmentFile); the node id is never taken from the artifact or the policy
sudo install -d -m 0700 -o forgenode -g forgenode /etc/forge-node/pki
sudo install -d -m 0755 -o root -g root /opt/forge-node /opt/forge-node/releases
sudo install -d -m 0700 -o root -g root /var/lib/forge-node-priv
# audit/priv log directories are ROOT-owned: the agent must have no write permission on any directory in the privileged path (files are created by 'privctl audit-init' in C4)
sudo install -d -m 0750 -o root -g forgenode /var/log/forge-node-priv
sudo install -d -m 0755 -o root -g root      /var/log/forge-node-agent
sudo install -m 0644 -o root -g root /tmp/allowed_signers /etc/forge-node/allowed_signers

# forge root = fully allocated loop-ext4 volume on the SYSTEM DISK (hard bound for everything forge puts on this node)
if [ "$FORGE_ROOT" != none ]; then
  sudo install -d -m 0700 -o root -g root /var/lib/forge-node-img
  sudo fallocate -l "$FORGE_ROOT_BYTES" /var/lib/forge-node-img/forge-root.img          # space is reserved NOW
  sudo chmod 0600 /var/lib/forge-node-img/forge-root.img
  sudo mkfs.ext4 -q -F -m 0 -L fnroot /var/lib/forge-node-img/forge-root.img
  sudo mkdir -p "$FORGE_ROOT" && sudo chattr +i "$FORGE_ROOT"                           # unmounted mountpoint can never receive writes
  UNIT=$(systemd-escape -p --suffix=mount "$FORGE_ROOT")
  printf '[Unit]\nDescription=forge-node forge root volume\n[Mount]\nWhat=/var/lib/forge-node-img/forge-root.img\nWhere=%s\nType=ext4\nOptions=loop,nodev,nosuid\n[Install]\nWantedBy=local-fs.target\n' "$FORGE_ROOT" | sudo tee /etc/systemd/system/$UNIT >/dev/null
  sudo systemctl daemon-reload && sudo systemctl enable --now "$UNIT"
  sudo chown forgenode:forgenode "$FORGE_ROOT" && sudo chmod 0750 "$FORGE_ROOT"
  findmnt -no TARGET,FSTYPE,SOURCE,OPTIONS "$FORGE_ROOT"; df -h "$FORGE_ROOT"
  echo "backing-file dev: $(stat -c %d /var/lib/forge-node-img/forge-root.img)   root dev: $(stat -c %d /)"
fi
# CHECK: TARGET is $FORGE_ROOT, FSTYPE ext4, SOURCE /dev/loopN, options contain nodev,nosuid, backing-file dev == root dev.
# Never /srv/models or /srv/kmu-ai. If anything differs: stop, 'sudo systemctl disable --now "$UNIT"', remove the image, tell the Betriebsleiter.

# C4 release tree (root-owned; the artifact for this PROFILE contains only that profile's op scripts) and units
sudo mkdir -p /opt/forge-node/releases/$VER
sudo tar -xf /tmp/forge-node-$VER-$PROFILE.tar -C /opt/forge-node/releases/$VER --strip-components=1 --no-same-owner
sudo chown -R root:root /opt/forge-node/releases/$VER
sudo install -m 0755 -o root -g root /opt/forge-node/releases/$VER/sbin/forge-node-release /usr/local/sbin/forge-node-release
sudo /usr/local/sbin/forge-node-release install-first $VER     # verifies the signed manifest, sets 'current', links units, daemon-reload
sudo /opt/forge-node/current/bin/privctl audit-init             # proves the seal protocol on the log filesystem (canary file: +a, +i, descriptors held across), creates privd's root-only state dirs and the LEDGER (N4: `ledger.sqlite`, schema 1, 0600 — only here; privd, privctl and the switcher refuse a node whose ledger is missing or schema-less, `audit-init` does not re-create it on an installed node), then the first log generations + CURRENT + lock files with the owners/modes of section 8.2 (+a)
ls -l /opt/forge-node/current /var/log/forge-node-priv /var/log/forge-node-agent; ls -l /etc/systemd/system | grep forge-node

# C5 node key + CSR (generated here, as forgenode)
sudo -u forgenode sh -c 'umask 077; openssl ecparam -name prime256v1 -genkey -noout -out /etc/forge-node/pki/node.key'
sudo -u forgenode sh -c 'umask 022; openssl req -new -key /etc/forge-node/pki/node.key -subj "/CN=forge-node-'"$NID"'" -out /var/lib/forge-node/'"$NID"'.csr'
exit
```
On the Mac (sign, pin, send back):
```bash
cd ~/forge-node-owner; set -a; . ./fn.env; set +a
scp -i ~/.ssh/sshcarljump01 carl@$IP:/var/lib/forge-node/$NID.csr issued/
printf "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=clientAuth\nsubjectAltName=URI:urn:forge:node:$NID\n" > issued/ext_$NID.cnf
openssl x509 -req -in issued/$NID.csr -CA ca/ca.crt -CAkey ca/ca.key -CAcreateserial -days 90 -sha256 -extfile issued/ext_$NID.cnf -out issued/$NID.crt
openssl x509 -in issued/$NID.crt -noout -fingerprint -sha256 -subject -enddate        # note the fingerprint for the Cockpit approval

# policy: template from the release; fill in the hub trust values (from 13.B), check this server's forge_roots values (13.D), then sign
tar -xOf release/forge-node-$VER-$PROFILE.tar forge-node-$VER/policy/policy-$NID.json > policy/policy-$NID.json
HUB_PIN=$(openssl x509 -in issued/hub.crt -outform der | openssl dgst -sha256 -hex | awk '{print $NF}')
HUB_GATE=$(cut -d' ' -f1,2 issued/hub_gate_ed25519.pub)
sed -i.bak -e "s|__HUB_TLS_PIN__|$HUB_PIN|" -e "s|__HUB_GATE_PUB__|$HUB_GATE|" policy/policy-$NID.json && rm policy/policy-$NID.json.bak
grep -n "__" policy/policy-$NID.json && echo "UNFILLED PLACEHOLDERS - stop" || echo "placeholders filled"
less policy/policy-$NID.json                                     # read it once; global_mode must be 'observe'
ssh-keygen -Y sign -f owner_ed25519 -n forge-node-policy policy/policy-$NID.json      # writes policy-$NID.json.sig
scp -i ~/.ssh/sshcarljump01 issued/$NID.crt ca/ca.crt policy/policy-$NID.json policy/policy-$NID.json.sig carl@$IP:/tmp/
ssh -t -i ~/.ssh/sshcarljump01 carl@$IP
```
On the server (**segment 2**, a new shell ⇒ source the env file again):
```bash
set -a; . /tmp/fn.env; set +a; : "${NID:?}" "${IP:?}" "${VER:?}" "${PROFILE:?}" "${FORGE_ROOT:?}" "${FORGE_ROOT_BYTES:?}" "${MIN_FREE_BYTES:?}"

# C6 certificates, then policy (verified by privd/privctl: signature, node, serial, schema, root-fs forge roots, no apt apply)
sudo install -m 0644 -o forgenode -g forgenode /tmp/$NID.crt /etc/forge-node/pki/node.crt
sudo install -m 0644 -o forgenode -g forgenode /tmp/ca.crt   /etc/forge-node/pki/ca.crt
sudo systemctl enable --now forge-node-privd.socket
sudo /opt/forge-node/current/bin/privctl policy-apply /tmp/policy-$NID.json /tmp/policy-$NID.json.sig
sudo /opt/forge-node/current/bin/privctl status                          # policy serial 1, mode observe, lease: none yet

# C7 doctor (selfcheck of every enabled op inside its real transient unit), then the agent
sudo -u forgenode env FORGE_NODE_NODE_ID=$NID /usr/bin/python3 -I /opt/forge-node/current/forge-node.pyz doctor          # clock, certs, hub reachability+pin, policy, privd, forge root volume mounted, per-op selfcheck; expect OK (hub: 'unregistered'); exit status 0 OK, 1 FAILED, 4 INDETERMINATE (hub answered 5xx on 4 attempts: neither pass nor fail — wait for the hub, run it again; the agent is NOT enabled on 4)
sudo systemctl enable --now forge-node-agent.service forge-node-audit-rotate.timer
sudo systemctl status forge-node-agent.service forge-node-privd.socket --no-pager | head -12
rm -f /tmp/forge-node-$VER-$PROFILE.tar /tmp/forge-node-$VER-$PROFILE.tar.sig /tmp/allowed_signers /tmp/$NID.crt /tmp/ca.crt /tmp/policy-$NID.json /tmp/policy-$NID.json.sig /tmp/fn.env
exit
```
Register the node: open Cockpit **/nodes**, compare the shown certificate SHA-256 with the value noted on the Mac, click **Approve**. The first policy is `global_mode: observe` — nothing mutates; round 0 (§14) starts.

### 13.D Per-server values and deltas

| | carlgpu2 | carlgpu3 | carlgpu1 | carlgpu4 |
|---|---|---|---|---|
| `NID` / `IP` | `g2` / `192.168.10.4` | `g3` / `192.168.30.3` | `g1` / `192.168.10.3` | `g4` / `192.168.30.4` |
| `PROFILE` (artifact) | `full` | `full` | `t0` | `t0` |
| `FORGE_ROOT` (mount point of the loop volume on the system disk) | `/srv/forge/node` | `/var/lib/forge-node/data` | `none` | `none` |
| `FORGE_ROOT_BYTES` / `MIN_FREE_BYTES` (policy `size_bytes` / `min_free_bytes`) | 107374182400 (100 GiB) / 214748364800 (200 GiB) | 53687091200 (50 GiB) / 161061273600 (150 GiB) | `0` / `0` | `0` / `0` |
| Tiers (first policy) | 0,1,2 — all `observe` | 0 (+1,2 `dry_run_only`) | 0 | 0 |
| Extra pre-checks | hub up (`curl -s --cacert ca.crt https://192.168.10.4:8094/healthz`); DOCKER-USER rule confirmed; **do not restart docker** | check M022 job state with the pe_packer owner; `free -m` | no ufw change needed (outbound only); do not touch n8n/Redis rules | `free -m` shows ≥ 300 MiB available **and** owner agrees; trading hours considered; sshd untouched |
| Connectivity test before C6 | loopback/LAN | `openssl s_client -connect 192.168.10.4:8094 -brief </dev/null` must succeed; else owner adds router rule TCP/8094 from `192.168.30.0/29` | same as g2 (same /29) | same as g3 |
| Wait before next | 1 day | 1 day | 1 day | — |

Order: **carlgpu2 → carlgpu3 → carlgpu1 → carlgpu4** (OQ-3: g4 last, read-only).
~~~~
