# Set up sync

For a server already deployed per `deploy/README.md` (f): Cloud Run + GCS bucket + Google Drive.

```
Mac / iPhone / CLI ──► Cloud Run (vaultaged) ──► GCS bucket: log, index (small)
                                             └─► Google Drive folder: encrypted chunks (the bulk)
```

Everything leaving a device is ciphertext. Google sees sizes and times, not content.

Set these first (`gcloud` from `/opt/homebrew/bin` if not on PATH):

```sh
SERVICE=vaultaged      # Cloud Run service name
REGION=europe-west6
P=vaultage             # secret name prefix: $P-enroll-token, $P-gdrive-secret, $P-gdrive-refresh
E=VAULTAGE             # env prefix on the service (COFFER for a pre-rename deployment)
```

## 1. Put the chunks in your own Google Drive

Only needed if the server's Drive folder belongs to another Google account. Do it before creating vaults: existing synced vaults lose their chunks (no migration).

```sh
cargo build --release --locked -p vaultage-server
export VAULTAGE_GDRIVE_CLIENT_ID=<Cloud console → Google Auth Platform → Clients → Desktop client>
export VAULTAGE_GDRIVE_CLIENT_SECRET="$(gcloud secrets versions access latest --secret=$P-gdrive-secret)"
./target/release/vaultaged gdrive-login | gcloud secrets versions add $P-gdrive-refresh --data-file=-
```

- A browser opens: **pick the account that will hold the files.**
- "Google hasn't verified this app": Advanced → Go to … (it's your own app).
- stderr ends with `--chunks gdrive://<folder-id>`. Copy the id.

```sh
gcloud run services update $SERVICE --region $REGION --update-env-vars ${E}_CHUNKS=gdrive://<folder-id>
gcloud run services logs read $SERVICE --region $REGION --limit 20   # expect: chunks in Drive folder <folder-id>
```

Then delete the old folder from the old account's Drive (optional).

## 2. Create the vault (Mac)

```sh
gcloud run services describe $SERVICE --region $REGION --format='value(status.url)'   # server URL
gcloud secrets versions access latest --secret=$P-enroll-token | pbcopy               # token
```

New Vault… → Synced → paste URL and token → Create Vault. **Save the recovery key.**

Existing local vault: right-click it → Sync with a Server….

## 3. Add your other devices

On the Mac: Vault Settings → Sharing → Invite Someone… → Create Invite (one-time, 24 h).

| Device | Do |
|---|---|
| iPhone | Join Existing Vault → Invite → Scan QR Code |
| Another Mac | Join Existing Vault… → paste the invite |
| CLI | `vaultage join <vault name> --invite` |

Each device gets its own recovery key. Save it.

## Good to know

| Want | Do |
|---|---|
| Remove a device or person | Vault Settings → Rotate Keys…; devices that stay unlock with the new passphrase or recovery key |
| Free space | empty the trash (permanent, on every device) |
| Roll back the server | `gcloud run services update $SERVICE --region $REGION --image <old image>`. Not a revision rollback: revisions also pin the Drive folder |
| Drive folder | don't delete or edit files in it; moving or renaming the folder is fine |

- First request after idle takes a few seconds (Cloud Run cold start).
- Drive backend is new: trial it with non-critical data first.
