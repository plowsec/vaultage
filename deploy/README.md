# Deploying vaultaged

Renamed from Coffer: `cofferd` → `vaultaged`, `COFFER_*` → `VAULTAGE_*` (old env names still work).
State locations keep the old names so existing servers keep their data: compose project `coffer` /
volume `coffer_coffer-data`, `/var/lib/coffer`, `/etc/coffer`. Wire format unchanged (`X-Coffer-Enroll`).

Plain HTTP on `:8787`; Caddy (or Cloud Run) terminates TLS in front.
Storage: local filesystem (default) or a GCS bucket (`--store gcs://…`, see (d)).

## Config

| Flag | Env | Default |
|---|---|---|
| `--store <fs\|gcs://bucket[/prefix]>` | `VAULTAGE_STORE` | `fs` |
| `--data <dir>` | `VAULTAGE_DATA` | `./data` (fs only) |
| `--listen <addr>` | `VAULTAGE_LISTEN` | `127.0.0.1:8787` (image: `0.0.0.0:8787`) |
| `--enroll-token-file <path>` | `VAULTAGE_ENROLL_TOKEN_FILE` | none |
| — | `VAULTAGE_ENROLL_TOKEN` (value) | none |
| `--gc-grace-secs <n>` | `VAULTAGE_GC_GRACE_SECS` | `86400` |
| `--vault-quota-bytes <n>` | `VAULTAGE_VAULT_QUOTA_BYTES` | none (unlimited) |
| `--chunks <bucket\|gdrive://folder-id>` | `VAULTAGE_CHUNKS` | `bucket`; Drive needs a gcs store, see (f) |
| — | `VAULTAGE_GDRIVE_CLIENT_ID`, `VAULTAGE_GDRIVE_CLIENT_SECRET`, `VAULTAGE_GDRIVE_REFRESH_TOKEN` | none; required with Drive |
| — | `VAULTAGE_GCS_TOKEN` | none → metadata-server token |
| — | `VAULTAGE_GCS_ENDPOINT` / `STORAGE_EMULATOR_HOST` | `https://storage.googleapis.com`; set = no auth unless `VAULTAGE_GCS_TOKEN` |

No token = vault creation disabled (`POST /v1/vaults` → 403). Clients send it as `X-Coffer-Enroll`.

| Behaviour | Value |
|---|---|
| Prune | `POST /v1/vaults/{vid}/prune`: old revisions → placeholders, blob erased from the live store; unreferenced chunks older than the grace period deleted |
| GC grace | protects uploads whose commit hasn't arrived yet; keep ≥ 1 h. `0` = tests only (unsafe with >1 GCS instance) |
| Quota | chunk PUT over quota → 507; re-PUT of an existing chunk never fails; prune frees space |
| Rate limits (per instance, 1-min window) | `GET header`: 30/vault id · failed signatures: 20/vault id (then 429; valid signatures pass) · bad enrollment token: 10 global → 429 + `Retry-After` |
| Erasure caveat | pruned bytes leave the live files/objects; filesystem free blocks, disk snapshots, backups and GCS soft-delete may still hold them |

```sh
openssl rand -hex 32 > enroll_token     # generate the enrollment token
curl -fsS https://$VAULTAGE_DOMAIN/healthz   # → ok
```

## Backups

- The data dir is all state. It holds ciphertext only.
- Snapshots / copies of a live dir are safe: every ack is fsynced; a torn last log record is dropped on start.
- Restore = put the dir back, start vaultaged.
- Lose the dir = lose the vaults. Back it up.
- GCS: the bucket (prefix) is all state. `gcloud storage cp -r gs://$BUCKET/vaultage ./backup`. Restore = copy back while vaultaged is stopped.

## (a) Linux + Docker Compose

```sh
git clone <repo> vaultage && cd vaultage
docker build -f deploy/Dockerfile -t vaultaged:0.1.0 .
cd deploy
echo "VAULTAGE_DOMAIN=vault.example.com" > .env          # DNS A/AAAA → this host
mkdir -p secrets && openssl rand -hex 32 > secrets/enroll_token
sudo chown 65532 secrets/enroll_token && sudo chmod 400 secrets/enroll_token   # container uid
docker compose up -d
docker compose logs -f vaultaged
```

| Task | Command |
|---|---|
| Upgrade | `git pull && docker build -f deploy/Dockerfile -t vaultaged:0.1.0 . && docker compose -f deploy/compose.yaml up -d` |
| Backup | `docker run --rm -v coffer_coffer-data:/d:ro -v "$PWD":/b debian:13.3-slim tar czf /b/coffer-$(date +%F).tgz -C /d .` |
| Data path on host | `docker volume inspect coffer_coffer-data -f '{{.Mountpoint}}'` |

Ports 80+443 open. Caddy gets the cert automatically, sends HSTS.

## (b) Bare metal (systemd)

```sh
cargo build --release --locked -p vaultage-server
sudo install -m 0755 target/release/vaultaged /usr/local/bin/vaultaged
sudo install -d -m 0700 /etc/coffer
openssl rand -hex 32 | sudo tee /etc/coffer/enroll_token >/dev/null && sudo chmod 600 /etc/coffer/enroll_token
sudo install -m 0644 deploy/vaultaged.service /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now vaultaged
journalctl -u vaultaged -f
```

Caddy (distro package) in front:

```sh
sudo apt-get install -y caddy
sudo install -m 0644 deploy/Caddyfile /etc/caddy/Caddyfile
sudo systemctl edit caddy     # add:
#   [Service]
#   Environment=VAULTAGE_DOMAIN=vault.example.com VAULTAGE_UPSTREAM=127.0.0.1:8787
sudo systemctl restart caddy
```

| Item | Value |
|---|---|
| Data dir | `/var/lib/coffer` (→ `/var/lib/private/coffer`, DynamicUser) |
| Backup | snapshot the FS, or `sudo tar czf vaultage.tgz -C /var/lib/private/coffer .` |
| Hardening check | `systemd-analyze security vaultaged` |

Needs systemd ≥ 248 (`%d` credentials dir).

## (c) Google Cloud: one Compute Engine VM

Debian 13 VM + Docker, persistent disk mounted at `/var/lib/docker` (holds vaultaged data and Caddy certs), static IP, daily snapshots.

```sh
PROJECT=my-project REGION=europe-west6 ZONE=europe-west6-a VM=vaultage
gcloud config set project $PROJECT
gcloud services enable compute.googleapis.com

gcloud compute addresses create vaultage-ip --region $REGION
gcloud compute addresses describe vaultage-ip --region $REGION --format='value(address)'   # → DNS A record

gcloud compute disks create vaultage-data --zone $ZONE --size 20GB --type pd-balanced

gcloud compute resource-policies create snapshot-schedule vaultage-daily \
  --region $REGION --daily-schedule --start-time 03:00 \
  --max-retention-days 14 --on-source-disk-delete keep-auto-snapshots
gcloud compute disks add-resource-policies vaultage-data --zone $ZONE --resource-policies vaultage-daily

gcloud compute instances create $VM --zone $ZONE --machine-type e2-small \
  --image-family debian-13 --image-project debian-cloud --boot-disk-size 10GB \
  --address vaultage-ip --tags vaultage-https \
  --disk name=vaultage-data,device-name=vaultage-data,mode=rw,boot=no,auto-delete=no

gcloud compute firewall-rules create vaultage-allow-https --network default \
  --direction INGRESS --action allow --rules tcp:443,udp:443,tcp:80 \
  --target-tags vaultage-https --source-ranges 0.0.0.0/0
```

Port 80 is only for HTTP→HTTPS redirect and ACME HTTP-01. Without it, Caddy uses TLS-ALPN on 443.

On the VM (`gcloud compute ssh $VM --zone $ZONE`):

```sh
D=/dev/disk/by-id/google-vaultage-data
sudo mkfs.ext4 -m 0 -E lazy_itable_init=0,lazy_journal_init=0,discard $D    # first time only
sudo mkdir -p /var/lib/docker
echo "$D /var/lib/docker ext4 discard,defaults,nofail 0 2" | sudo tee -a /etc/fstab
sudo mount -a
sudo apt-get update && sudo apt-get install -y docker.io docker-compose
mkdir -p ~/vaultage/secrets
```

From your workstation (build here; e2-small is slow at compiling Rust):

```sh
docker buildx build --platform linux/amd64 -f deploy/Dockerfile -t vaultaged:0.1.0 --load .
docker save vaultaged:0.1.0 | gzip | gcloud compute ssh $VM --zone $ZONE -- 'gunzip | sudo docker load'
gcloud compute scp deploy/compose.yaml deploy/Caddyfile $VM:~/vaultage/ --zone $ZONE
```

On the VM:

```sh
cd ~/vaultage
echo "VAULTAGE_DOMAIN=vault.example.com" > .env
openssl rand -hex 32 > secrets/enroll_token
sudo chown 65532 secrets/enroll_token && sudo chmod 400 secrets/enroll_token
sudo docker compose up -d
```

| Task | Command |
|---|---|
| List snapshots | `gcloud compute snapshots list --filter="sourceDisk~vaultage-data"` |
| Manual snapshot | `gcloud compute disks snapshot vaultage-data --zone $ZONE` |
| Restore | `gcloud compute disks create vaultage-data-restored --zone $ZONE --source-snapshot <snap>`, stop VM, detach old, attach new with `--device-name=vaultage-data` |
| Resize VM | `gcloud compute instances set-machine-type $VM --zone $ZONE --machine-type e2-medium` (VM stopped) |

e2-micro works for a few users; e2-small recommended. Snapshots are crash-consistent, which the store tolerates.

## (d) Google Cloud Run + GCS bucket

All state in one bucket; Cloud Run terminates TLS (no Caddy).
**GCS backend is tested against an in-process fake only. Trial it with non-critical data first.**

```sh
PROJECT=my-project REGION=europe-west6 BUCKET=$PROJECT-vaultage SA=vaultaged
gcloud config set project $PROJECT
gcloud services enable run.googleapis.com artifactregistry.googleapis.com secretmanager.googleapis.com storage.googleapis.com

# Bucket: uniform access, no public access, no soft delete (else pruned data lingers 7+ days), versioning off (default).
gcloud storage buckets create gs://$BUCKET --location=$REGION \
  --uniform-bucket-level-access --public-access-prevention --soft-delete-duration=0
gcloud storage buckets describe gs://$BUCKET --format="default(soft_delete_policy,versioning)"

# Service account: object read/write on this bucket only.
gcloud iam service-accounts create $SA
SA_EMAIL=$SA@$PROJECT.iam.gserviceaccount.com
gcloud storage buckets add-iam-policy-binding gs://$BUCKET \
  --member=serviceAccount:$SA_EMAIL --role=roles/storage.objectUser

# Enrollment token in Secret Manager.
openssl rand -hex 32 | gcloud secrets create vaultage-enroll-token --data-file=-
gcloud secrets add-iam-policy-binding vaultage-enroll-token \
  --member=serviceAccount:$SA_EMAIL --role=roles/secretmanager.secretAccessor

# Image → Artifact Registry.
gcloud artifacts repositories create vaultage --repository-format=docker --location=$REGION
gcloud auth configure-docker $REGION-docker.pkg.dev
IMG=$REGION-docker.pkg.dev/$PROJECT/vaultage/vaultaged:0.1.0
docker buildx build --platform linux/amd64 -f deploy/Dockerfile -t $IMG --push .

# Deploy.
gcloud run deploy vaultaged --image $IMG --region $REGION \
  --service-account $SA_EMAIL --no-invoker-iam-check \
  --port 8787 --max-instances 1 --min-instances 0 --cpu-boost \
  --memory 512Mi --timeout 300 \
  --set-env-vars VAULTAGE_STORE=gcs://$BUCKET/vaultage \
  --set-secrets VAULTAGE_ENROLL_TOKEN=vaultage-enroll-token:latest
URL=$(gcloud run services describe vaultaged --region $REGION --format='value(status.url)')
curl -sS $URL/v1/vaults/00000000000000000000000000000000/header   # → {"error":"no such vault"}
```

| Item | Note |
|---|---|
| Auth to GCS | metadata-server token of `--service-account`; nothing to configure |
| `--no-invoker-iam-check` | required: clients sign requests themselves (`Authorization: Coffer …`). `--allow-unauthenticated` is not enough: the IAM check still rejects a non-`Bearer` Authorization header with 401 "lacked OIDC mandated 'Bearer' prefix" |
| `/healthz` | reserved by Cloud Run (Google 404 page); probe any API path instead, as above |
| `--max-instances 1` | recommended. Correctness with 2+ instances relies on GCS preconditions; then also: rate limits and quota are per instance, a rekey reaches other instances' auth cache within 2 s, GC safety needs grace > 0 |
| `--min-instances 0` | scales to zero; first request after idle pays a cold start (`--cpu-boost` helps) |
| Custom domain | `gcloud beta run domain-mappings create --service vaultaged --domain vault.example.com --region $REGION` (not in all regions), or an external Application Load Balancer + serverless NEG |
| Request size | Cloud Run caps HTTP/1 request bodies (32 MiB); chunk PUTs are ≤ 4 MiB, very large commits may hit it |
| Data dir | unused with `--store gcs://…`; the image's `/data` volume stays empty |
| Local dev | `FAKE_GCS_SECS=600 cargo test -p vaultage-server --test gcs serve_fake -- --ignored --nocapture` prints `<addr>`; then `STORAGE_EMULATOR_HOST=<addr> vaultaged --store gcs://test-bucket/pfx` |

Layout: `gs://$BUCKET/vaultage/vaults/<vid>/{meta.json,log/<seq>,chunks/<cid>}`. One object per record.

Cost/latency:
- First sync of a big vault = one GET per record (10k records = 10k GETs, 8 in parallel); later syncs fetch only new records.
- Each request: 1 list (log head) + 1 GET per record/chunk; each commit: 1 list + 1 stat per ref (+ metadata patch for refs older than grace/4) + 1 insert.
- Class A/B operation charges dominate for small files; storage is ciphertext size.

## (e) Tailnet only (Tailscale)

vaultaged stays on `127.0.0.1:8787`; only tailnet devices reach it. Clients still need `https://`: they refuse `http://` to anything but loopback (a `100.x` address is routed to whatever network is up when the VPN is down).

| TLS from | Server | Client URL | Pin on clients |
|---|---|---|---|
| Tailscale (Let's Encrypt cert for the MagicDNS name) | admin console: enable MagicDNS + HTTPS certificates; `sudo tailscale serve --bg 8787` | `https://<host>.<tailnet>.ts.net` | not needed |
| Caddy's own CA | Caddyfile site block with `tls internal` | same | Caddy root: `<caddy data>/pki/authorities/local/root.crt` |
| Self-signed | cert below + any TLS terminator in front of `:8787` | `https://<name in the cert>` | the cert itself |

```sh
tailscale serve status                     # what is exposed
curl -fsS https://<host>.<tailnet>.ts.net/healthz   # from another tailnet device → ok

# Self-signed server certificate. CA:FALSE is required: a CA certificate is refused as a server certificate.
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 825 \
  -keyout key.pem -out cert.pem -subj "/CN=vaultage" \
  -addext "subjectAltName=DNS:<host>.<tailnet>.ts.net" \
  -addext "basicConstraints=critical,CA:FALSE" -addext "extendedKeyUsage=serverAuth"
```

Pin: `vaultage trust https://<host> --ca cert.pem` · iOS: Certificate Pinning (new/join vault, vault settings, app settings). A pinned server is accepted only if its chain ends in a pinned certificate; public CAs no longer count for it.

| Client state | Behaviour |
|---|---|
| Tailscale disconnected | sync shows offline; edits queue in the encrypted journal; pushed when the tailnet is back |
| Wrong network answers (captive portal, proxy) | certificate check fails; nothing is sent; app shows "identity couldn't be verified" |
| Link stalls mid-transfer | request fails after 20 s without progress; only missing chunks are re-sent |

## (f) Cloud Run + GCS bucket + Google Drive for chunk bytes

Same as (d), but chunk bytes (the bulk) go to a folder in your Google Drive. Storage is billed by your Google One plan, not GCS.
**Drive backend: tested against an in-process fake and one live deployment. Trial it with non-critical data first.**

| Where | What |
|---|---|
| GCS bucket | meta, record log, one empty pointer object per chunk (`d`=Drive file id, `n`=size), Drive folder ids. Small |
| Drive folder | `<vault id>/<0-f>/<chunk hash>`: encrypted chunks, written once, never changed |

Google sees what any server operator sees (ciphertext, sizes, counts, times). See docs/SECURITY.md.

One-time OAuth setup (Cloud console, same project; `gcloud` can't create these):

1. `gcloud services enable drive.googleapis.com`
2. Google Auth Platform → Branding/Audience: External, add your account. **Publish to "In production"**: in "Testing", refresh tokens expire after 7 days. `drive.file` is a non-sensitive scope, so no verification review (per Google's docs, check).
3. Clients → Create client → type **Desktop app** → client id + secret.

On your workstation (opens a consent page; the account picked owns the storage):

```sh
export VAULTAGE_GDRIVE_CLIENT_ID=… VAULTAGE_GDRIVE_CLIENT_SECRET=…
vaultaged gdrive-login | gcloud secrets create vaultage-gdrive-refresh --data-file=-   # stderr prints --chunks gdrive://<folder-id>
printf %s "$VAULTAGE_GDRIVE_CLIENT_SECRET" | gcloud secrets create vaultage-gdrive-secret --data-file=-
for s in vaultage-gdrive-refresh vaultage-gdrive-secret; do
  gcloud secrets add-iam-policy-binding $s --member=serviceAccount:$SA_EMAIL --role=roles/secretmanager.secretAccessor
done
```

Deploy (after the bucket, service account and image steps of (d)):

```sh
FOLDER=<folder-id from gdrive-login>
gcloud run deploy vaultaged --image $IMG --region $REGION \
  --service-account $SA_EMAIL --no-invoker-iam-check \
  --port 8787 --max-instances 1 --min-instances 0 --cpu-boost \
  --memory 512Mi --timeout 300 \
  --set-env-vars VAULTAGE_STORE=gcs://$BUCKET/vaultage,VAULTAGE_CHUNKS=gdrive://$FOLDER,VAULTAGE_GDRIVE_CLIENT_ID=$VAULTAGE_GDRIVE_CLIENT_ID \
  --set-secrets VAULTAGE_ENROLL_TOKEN=vaultage-enroll-token:latest,VAULTAGE_GDRIVE_CLIENT_SECRET=vaultage-gdrive-secret:latest,VAULTAGE_GDRIVE_REFRESH_TOKEN=vaultage-gdrive-refresh:latest
gcloud run services logs read vaultaged --region $REGION --limit 20   # "chunks in Drive folder …"
```

| Item | Note |
|---|---|
| Scope | `drive.file`: the server sees only files it created. The folder must come from `gdrive-login`, not the Drive UI |
| Several instances | safe: every decision is a GCS precondition; Drive only stores immutable files |
| Startup | refuses to start if the folder is missing or not visible to the client; starts (with a warning) if Drive is unreachable |
| Refresh token revoked/expired | chunk reads and writes return 503; log says `invalid_grant`. Fix: `vaultaged gdrive-login --no-folder`, new secret version, redeploy (same client: the old folder stays visible) |
| Drive full | chunk PUT → 507 |
| Lost upload replies, lost races | leave unreferenced Drive files; each prune deletes those older than max(grace, 15 min) |
| Prune / empty trash | deletes pointer, then the Drive file, permanently (no Drive trash) |
| Don't | delete, trash or edit files in the folder. Moving or renaming the folder is fine (ids) |
| Limits | 750 GB upload per day per Google account; ≤ 5 MB per upload (chunks are ≤ 4 MiB) |
| Existing (d) deployment | add `VAULTAGE_CHUNKS`: old chunks stay in the bucket and stay readable; new chunks go to Drive. No migration tool |
| Backups | bucket as in (d), plus the Drive folder (Google Takeout or `rclone`). Both are ciphertext; you need both |
| Erasure caveat | Drive's own retention/backups of deleted files are Google's business |
