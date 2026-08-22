# Backup and restore

A runbook for maintainerd-secret. Written to be followed under pressure, so the
order is the order you do things in and every command is complete.

> ## Read this paragraph before anything else
>
> **The root key is not in the database.** A PostgreSQL backup of this service
> contains ciphertext and *wrapped* data-encryption keys. The key that unwraps them
> comes from outside the database — an environment variable, a sealed file, or a
> cloud KMS — and it is never written to any table.
>
> **A database backup alone is unrestorable.** If you have the dump and not the root
> key, every secret in it is permanently unreadable. There is no recovery path, no
> support escalation, and no cryptographic shortcut: that is the property the design
> exists to provide. Backing up the database without separately capturing the root
> key is the single most common way to lose a vault, and it looks like a working
> backup strategy right up until the restore.
>
> Section 1 tells you what to capture for each provider. Do that part first.

---

## Contents

1. [What to back up](#1-what-to-back-up)
2. [Backing up the database](#2-backing-up-the-database)
3. [Restoring](#3-restoring)
4. [The append-only triggers](#4-the-append-only-triggers)
5. [Verifying a restore](#5-verifying-a-restore)
6. [Root-key rotation and backups](#6-root-key-rotation-and-backups)
7. [Protecting the backup artifacts](#7-protecting-the-backup-artifacts)
8. [Quick reference](#8-quick-reference)

---

## 1. What to back up

There are **two independent things**, and they must be captured separately and
stored separately. Either one alone is worthless: the database without the key is
undecryptable, the key without the database unlocks nothing.

### 1.1 The PostgreSQL database

One dump covers all of it:

| Contents | Table(s) | Sensitivity |
|---|---|---|
| Secret **ciphertext** and **wrapped DEKs** | `secret_versions` | Encrypted. Useless without the root key |
| Secret **metadata** — names, paths, tags, descriptions, rotation policy | `secrets`, `folders`, `projects`, `environments`, `tenants` | **NOT encrypted.** An inventory of every credential you hold |
| The **root-key registry** | `root_keys` | Key *identifiers* and states. **No key material** |
| The **audit trail** | `audit_log` | Who read which secret, when. Not encrypted |
| Setup state, imports, webhook endpoints | `setup_state`, `scope_imports`, `webhook_endpoints` | Configuration |
| Rate-limit buckets | `rate_limit_buckets` | Disposable — see §2.4 |

### 1.2 The root key — captured from its provider, not from the database

`root_keys` records **which key wrapped what**, never the key itself. Each row holds
a `kek_id`, which is a fingerprint (the provider name plus a truncated SHA-256 of the
key material) — enough to identify a key, not enough to reconstruct one.

What you must capture depends on `SECRET_ROOT_KEY_PROVIDER`:

| Provider | What to capture | How it is lost |
|---|---|---|
| `env` | The **value** of `SECRET_ROOT_KEY` (32 bytes, hex or base64). | The deployment is torn down and the variable existed only in a pipeline, a shell, or a since-deleted orchestrator secret. |
| `file` | The **sealed key file** at `SECRET_ROOT_KEY_FILE`, byte for byte, with its `0600` mode. | The host or volume it lived on is replaced. A container image rebuild does not carry it. |
| `aws_kms` | The **KMS key must continue to exist**: record the key ARN and alias, and enable deletion protection. AWS schedules key deletion 7–30 days out — after that window the key is gone. | Somebody schedules deletion, the account is closed, or the key is left out of a region migration. |
| `gcp_kms` | The **key and the specific key version** must continue to exist. Record the full resource name; a destroyed key version cannot be recovered after its 24-hour scheduled-destruction window. | A key version is destroyed as part of a rotation cleanup. |
| `azure_kv` | The **key** must continue to exist. Enable **soft-delete and purge protection** on the vault, and record the key identifier including its version. | The vault is purged, or a key version is deleted without purge protection. |
| `ephemeral` | **Nothing — and nothing can be.** This is a development-only provider whose key dies with the process. The service refuses to boot with it outside `APP_ENV=development`. A backup of an `ephemeral` deployment is not restorable, by construction. | Every restart. |

**For a KMS provider the rule is inverted from the others:** you are not copying a
secret anywhere, you are guaranteeing a key is never deleted. Write the key
identifier into your disaster-recovery documentation and put deletion protection on
it. A KMS root key is the safest option precisely because the material never leaves
the KMS — which also means there is no copy of it for you to restore.

**Capture every key that still has versions wrapped under it, not just the active
one.** A rotation that has not finished rewrapping leaves rows depending on the old
key. `root_keys.state` tells you:

```sql
SELECT rk.kek_id, rk.provider, rk.state, count(sv.version_id) AS versions
FROM root_keys rk
LEFT JOIN secret_versions sv USING (kek_id)
GROUP BY rk.kek_id, rk.provider, rk.state
ORDER BY rk.state, rk.kek_id;
```

Any key with `versions > 0` is a key you still need. A key in `retiring` with
`versions > 0` means **a rewrap is pending** — the service warns about exactly this
at every boot.

### 1.3 Store the two halves apart

Do **not** put the root key in the same bucket, vault, or archive as the database
dump. Doing so recombines the two halves and converts two independent secrets into
one: an attacker who reaches that location has plaintext access to every credential
you have ever stored. Different storage system, different credentials, different
access policy.

---

## 2. Backing up the database

### 2.1 The command

```bash
pg_dump \
  --host="$DB_HOST" --port="$DB_PORT" \
  --username="$DB_USER" --dbname="$DB_NAME" \
  --format=custom \
  --compress=9 \
  --serializable-deferrable \
  --quote-all-identifiers \
  --encoding=UTF8 \
  --file="secret-$(date -u +%Y%m%dT%H%M%SZ).dump"
```

### 2.2 Why those flags

| Flag | Why it matters here |
|---|---|
| `--format=custom` | The only format that supports selective restore (`--table`, `--list`) and `pg_restore`'s ordering logic. A plain-SQL dump forces you to restore everything, in file order, with no ability to skip a table — which is exactly the flexibility you want at 3am. |
| `--serializable-deferrable` | Waits for a snapshot that cannot see a serialization anomaly. `pg_dump` is already consistent, but this service writes a `secret_versions` row and an `audit_log` row in the same transaction, and this is the flag that guarantees a dump never contains one without the other. |
| `--quote-all-identifiers` | Makes the dump restorable on a PostgreSQL version with different reserved words than the one that produced it. Cheap insurance on the artifact you only read during an incident. |
| `--compress=9` | Ciphertext does not compress, but the metadata, audit trail and JSONB do. |
| `--encoding=UTF8` | Secret paths and descriptions are UTF-8; pinning it stops a client-encoding surprise on restore. |

**Do not use `--data-only` for your primary backup.** It omits the schema, the
constraints, and — critically — the **append-only triggers** (§4). A data-only dump
plus an empty database gives you rows with none of the guarantees that made them
trustworthy.

**Do not use `--exclude-table` to skip `audit_log`** because it is large. The audit
trail is the record of who read which secret; a restore without it is a vault with
no history at the exact moment you most need history. If size is a problem, apply
age-based retention in the live database instead.

### 2.3 Point-in-time recovery

A nightly `pg_dump` bounds your worst-case data loss at 24 hours. For a secret store
that is usually too coarse — a secret written at 09:00 and lost at 17:00 leaves every
consumer of it broken. Enable **WAL archiving / PITR** (`archive_mode`,
`archive_command`, or your provider's managed equivalent) and treat `pg_dump` as the
periodic base backup and the portable artifact.

The root-key rule is unchanged and worth restating: PITR restores the database to any
instant, and every one of those instants is undecryptable without the root key that
was active then.

### 2.4 One table you may safely ignore

`rate_limit_buckets` is disposable. It holds the current rate-limit window's
reservations, nothing is ever audited from it, and every row is worthless once its
window closes. Restoring it or not makes no difference beyond one window of
per-replica metering. It is included in a full dump; there is no need to treat it
specially.

---

## 3. Restoring

### 3.1 Before you touch anything: confirm you have the key

```bash
# env provider
test -n "$SECRET_ROOT_KEY" && echo "root key present" || echo "STOP — no root key"

# file provider
ls -l "$SECRET_ROOT_KEY_FILE"     # expect -rw------- (0600)

# KMS providers — prove you can still use the key, not merely that it is named
aws kms describe-key --key-id "$KEY_ARN"        # aws_kms
gcloud kms keys versions list --key=... --keyring=... --location=...   # gcp_kms
az keyvault key show --vault-name ... --name ...                       # azure_kv
```

Restoring a database you cannot decrypt wastes the outage. Check first.

### 3.2 Full restore into a fresh database

This is the path to prefer: it is the one that reproduces the schema, the
constraints and the triggers exactly as the dump captured them.

```bash
# 1. A brand-new, empty database.
createdb --host="$DB_HOST" --port="$DB_PORT" --username="$DB_USER" maintainerd_secret_restored

# 2. Restore, all or nothing.
pg_restore \
  --host="$DB_HOST" --port="$DB_PORT" \
  --username="$DB_USER" --dbname=maintainerd_secret_restored \
  --single-transaction \
  --no-owner --no-privileges \
  --verbose \
  secret-20260822T031500Z.dump
```

| Flag | Why |
|---|---|
| `--single-transaction` | All or nothing. Without it a failure halfway leaves a **partially populated vault** — some secrets present, some absent, and no way to tell which from the outside. It also implies `--exit-on-error`, so the first problem stops the restore instead of scrolling past. |
| `--no-owner --no-privileges` | Lets you restore as a different role than the one that made the dump, which is normal in a recovery account. Grants are re-applied by your provisioning, not by the dump. |
| `--verbose` | You will want the object-by-object log if it fails. |

`--single-transaction` and `--jobs` are **mutually exclusive**. Parallel restore is
faster on a large store but gives up atomicity; if you use `--jobs`, restore into a
throwaway database and only cut over after §5 passes.

### 3.3 The service's first boot after a restore

Point the service at the restored database and start it. It will:

1. Load the root key from its provider and derive the `kek_id`. **Because `kek_id` is
   a fingerprint of the key material, the same key always produces the same
   `kek_id`** — this is what lets a restored database recognise the key it was
   encrypted with. A *different* key produces a different `kek_id`, and you will see
   it registered as a new active key while every restored row still points at the old
   one.
2. Run migrations. This is safe and expected: every migration is
   `CREATE TABLE IF NOT EXISTS` / `CREATE OR REPLACE FUNCTION` and the dump carries
   `goose_db_version`, so nothing re-runs and nothing is rewritten.
3. Register the active root key and **warn about every superseded key that still has
   versions wrapped under it**. Read those warnings — they are the list of extra keys
   this instance needs supplied.

### 3.4 Partial and data-only restores

Sometimes you want one table back, not the whole store. Two things will bite you.

**Foreign keys constrain the order.** `secret_versions.kek_id` references
`root_keys` with `ON DELETE RESTRICT`, and `secrets` references the hierarchy. So:

```
tenants → projects → environments → folders → root_keys → secrets → secret_versions → audit_log
```

Restoring `secret_versions` without its `root_keys` rows fails on the foreign key —
which is the constraint doing its job. `ON DELETE RESTRICT` exists precisely so a
root key cannot be removed while rows still depend on it, because that would be
unrecoverable data loss.

**The append-only triggers may fight you.** See §4 — read it before running a
data-only restore.

---

## 4. The append-only triggers

Two tables are protected by row-level triggers created by their migrations:

| Table | Trigger | Function | Fires on |
|---|---|---|---|
| `secret_versions` | `trg_secret_versions_immutable` | `prevent_secret_version_mutation()` | `BEFORE UPDATE OR DELETE` |
| `audit_log` | `trg_audit_log_immutable` | `prevent_audit_log_mutation()` | `BEFORE UPDATE OR DELETE` |

They are the reason secret history cannot be rewritten by a bug, a stray migration,
or a compromised service account. What that means for a restore:

### 4.1 A full restore recreates them, and that is correct

The triggers and their functions are schema objects. `pg_dump` captures them,
`pg_restore` recreates them, and the restored database has the same immutability
guarantee as the original. **Verify it did** (§5.4) — a restored vault whose triggers
silently did not come back looks identical and has lost a core property.

### 4.2 They do NOT block an ordinary restore

Both triggers fire on `UPDATE` and `DELETE` only. A restore is `COPY`/`INSERT`, so
the normal path in §3.2 never touches them.

### 4.3 Where a data-only restore fights them

| Operation | Blocked? | Notes |
|---|---|---|
| `COPY` / `INSERT` (what a restore does) | No | Not covered by the triggers. |
| `TRUNCATE secret_versions` | **No** | `TRUNCATE` does not fire row-level triggers. This is the honest gap: truncation bypasses the append-only guard entirely. Treat `TRUNCATE` on these two tables as a destructive administrative act with no safety net. |
| `DELETE FROM secret_versions` | **Yes** | Refused unless the transaction sets the sanctioned GUC. |
| `DELETE FROM audit_log` | **Yes** | Same. |
| `UPDATE secret_versions` | **Yes** | Only a root-key rewrap is permitted, and only on the three wrap columns. |
| `UPDATE audit_log` | **Yes** | Never permitted, for any reason. |

So: **a data-only restore into a database that already holds rows** is the case that
fights the triggers, because clearing the old rows first is a `DELETE` (refused) or a
`TRUNCATE` (permitted, and unguarded). Prefer restoring into a **fresh** database.

If you genuinely must clear a table, use the GUC the trigger sanctions rather than
disabling the trigger — it keeps the column-level checks in force:

```sql
BEGIN;
SET LOCAL maintainerd.allow_secret_version_delete = 'retention';
DELETE FROM secret_versions WHERE secret_id = 12345;
COMMIT;
```

Accepted values are `retention`, `secret_destroy` and `tenant_delete` for
`secret_versions`, and `retention` or `tenant_delete` for `audit_log`. They are
transaction-local (`SET LOCAL`), so the exemption cannot leak past the `COMMIT`.

### 4.4 The blunt instrument, and when it is justified

`pg_restore --disable-triggers` sets `session_replication_role = replica`, which
disables **all** triggers for the session. It requires superuser and it is only
needed if your restore performs `UPDATE`s or `DELETE`s.

Use it only when a full restore into a fresh database is genuinely impossible, know
that it also disables foreign-key enforcement for the session, and **re-verify the
triggers exist and function afterwards** (§5.4). A restore that quietly left the
append-only guarantee off is worse than a failed restore, because it looks like it
worked.

---

## 5. Verifying a restore

A restore is not finished when `pg_restore` exits zero. It is finished when you have
proven a secret decrypts. Run all five.

### 5.1 Decrypt a canary secret — the only test that proves the key matches the data

Keep a **canary secret** in every environment: an ordinary secret at a known path,
whose value you hold independently of this service (in your password manager, in the
runbook, wherever). It exists to be read after a restore.

```bash
curl -sS \
  -H "Authorization: Bearer $TOKEN" \
  "https://$SECRET_HOST/api/v1/secrets/reveal?project=platform&environment=production&path=/ops&key=restore-canary"
```

The value must come back and it must equal the value you hold. This single check
proves, all at once, that the ciphertext survived, the wrapped DEK survived, the
`kek_id` resolved, the root key provider is reachable, and the key is the *right*
key. Nothing else proves that.

If you have no canary yet, create one now — before you need it. Any secret whose
plaintext you know independently will do.

### 5.2 Exactly one active root key

```sql
SELECT state, count(*) FROM root_keys GROUP BY state ORDER BY state;
```

Expect **exactly one** row in `active`. A unique partial index enforces this, so more
than one means the restore did not bring the index with it. Rows in `retiring` are
normal and mean a rewrap is pending; rows in `retired` are decommissioned and should
have no versions.

### 5.3 Every version's `kek_id` resolves to an available provider

The foreign key already guarantees every `kek_id` exists in `root_keys`. What it
cannot guarantee is that the **key material** for it is available to the process —
that lives outside the database. So enumerate what the data needs:

```sql
SELECT rk.kek_id,
       rk.provider,
       rk.state,
       count(sv.version_id) AS versions_wrapped
FROM root_keys rk
LEFT JOIN secret_versions sv USING (kek_id)
GROUP BY rk.kek_id, rk.provider, rk.state
ORDER BY versions_wrapped DESC;
```

For **every row with `versions_wrapped > 0`**, confirm that key is supplied to the
service. Then cross-check against the boot log, which reports the active key and
warns about each superseded key that still has versions:

```
INFO  active root key registered kek_id=env:9f2c… provider=env
WARN  superseded root key still has versions wrapped under it; a rewrap is pending kek_id=env:41ab… provider=env
```

A `WARN` you cannot satisfy is the alarm: those rows are currently unreadable, and
they stay unreadable until that key is supplied.

Also confirm nothing is orphaned in a retired key:

```sql
-- Must return zero rows. A retired key with versions is data nobody can read.
SELECT rk.kek_id, count(*) AS versions
FROM root_keys rk JOIN secret_versions sv USING (kek_id)
WHERE rk.state = 'retired'
GROUP BY rk.kek_id;
```

### 5.4 The append-only triggers came back

```sql
SELECT c.relname AS table_name, t.tgname AS trigger_name, t.tgenabled
FROM pg_trigger t
JOIN pg_class c ON c.oid = t.tgrelid
WHERE NOT t.tgisinternal
  AND c.relname IN ('secret_versions', 'audit_log')
ORDER BY c.relname;
```

Expect `trg_audit_log_immutable` and `trg_secret_versions_immutable`, both with
`tgenabled = 'O'` (enabled, origin). Then prove one actually refuses:

```sql
-- Must FAIL with 'audit_log rows are immutable and cannot be updated'.
BEGIN;
UPDATE audit_log SET reason = 'tamper test' WHERE event_id = (SELECT min(event_id) FROM audit_log);
ROLLBACK;
```

If that `UPDATE` succeeds, the restore lost the immutability guarantee. Re-apply the
migrations for `secret_versions` and `audit_log` before putting the instance back in
service.

### 5.5 Readiness and row counts

```bash
curl -sS "https://$SECRET_HOST/readyz"     # database + auth must both pass
```

```sql
SELECT
  (SELECT count(*) FROM secrets)         AS secrets,
  (SELECT count(*) FROM secret_versions) AS versions,
  (SELECT count(*) FROM audit_log)       AS audit_rows,
  (SELECT max(created_at) FROM secret_versions) AS newest_version;
```

Compare against the source. `newest_version` is the practical measure of how much
you lost: everything written after it is gone.

---

## 6. Root-key rotation and backups

This is the interaction that turns a good backup into an unrestorable one, so it gets
its own section.

### 6.1 What a rotation does

Rotating the root key does **not** re-encrypt secrets. Envelope encryption exists so
it does not have to: each version's payload is sealed under its own DEK, and only the
**wrapped DEK** (a few dozen bytes) is re-wrapped under the new root key.
`ciphertext` is never touched. A vault with a terabyte of secrets rotates its root of
trust by rewriting three columns per row.

Mechanically: the new key becomes `active`, the old key becomes `retiring`, and
`RewrapAll` walks every version still wrapped under the old key.

### 6.2 Restoring a backup taken BEFORE a rotation

**The rows in that backup are wrapped under the OLD root key.** The current key
cannot unwrap them.

So to restore a pre-rotation backup you must supply the **old** key, not just the
current one — which means the old key material must still exist. This is the failure
mode:

> A rotation completes. The old key is retired, and somebody deletes it as cleanup —
> the env var is removed, the sealed file is shredded, the KMS key is scheduled for
> deletion. Three weeks later a pre-rotation backup has to be restored, and every
> secret in it is permanently unreadable.

**The rule: keep every root key for at least as long as the oldest backup you would
ever restore.** If you retain backups for 90 days, retain root keys for 90 days plus
a margin. Retiring a key in `root_keys` is a *database* state change; destroying the
*material* is the irreversible one, and they should not happen on the same day.

Supply an old key alongside the current one and the service will register both, use
the active one for new writes, and unwrap old rows with the key their `kek_id` names.
Then run a rewrap to bring the restored rows onto the current key.

### 6.3 Restoring a backup taken DURING a rotation

Entirely survivable, and worth understanding because it is the common case for any
store large enough that a rewrap takes real time.

A mid-rotation backup contains a **mixture**: some versions wrapped under the old
key, some under the new. Both keys must be supplied. Every row is readable, because
each carries the `kek_id` that says which key applies to it. There is no "corrupt"
state to repair — a partially rewrapped store is a *valid* store.

### 6.4 Why `RewrapAll` is resumable

Re-running the rewrap after a restore finishes the job, and it is safe to run as many
times as you like. Three properties make that true:

- **Progress lives in the data, not in a cursor.** The work queue is the query "every
  version still wrapped under the old key", and a row that has been re-wrapped no
  longer matches it. There is no checkpoint to persist, so there is nothing for a
  restore to make stale, and no way for a restart to skip a row or repeat one.
- **It is batched.** Work is taken in `SECRET_REWRAP_BATCH_SIZE` chunks (default
  500), each in its own transaction. An interrupted rewrap has simply completed fewer
  batches — it has not left a half-written one.
- **It is idempotent, and guarded at the row.** `RewrapVersion` is conditioned on the
  *source* key id, so a row another worker already moved is not moved twice. Running
  against a fully rewrapped store finds nothing and reports zero.

Which is why the safe sequence after restoring a mixed backup is simply: supply both
keys, start the service, run the rewrap, and re-run it until it reports
`remaining = 0`. Only then does the old key get retired — and the service retires it
by **counting** the remaining references, not by inferring that the pass finished. A
key retired while rows still point at it would make those rows permanently
unreadable, so the check is a `COUNT`, never an assumption.

### 6.5 After a rotation completes, take a fresh backup

Once `remaining = 0` and the old key is `retired`, take a new base backup
immediately. That is the first backup that is restorable with the current key alone,
and it is what lets you eventually shorten the retention on the old key material.

---

## 7. Protecting the backup artifacts

### 7.1 A dump contains ciphertext, not plaintext — and is still sensitive

State it precisely, because both halves matter:

**It contains no plaintext secret values.** Every value in `secret_versions` is
AES-256-GCM ciphertext under a per-version DEK, and the DEK is itself wrapped. An
attacker with only the dump has no credentials.

**It is still sensitive, for four reasons:**

1. **It is one key away from being plaintext.** Pair it with the root key and it is a
   complete dump of every credential you hold. Its confidentiality requirement is
   therefore the root key's, not the ciphertext's.
2. **Metadata is not encrypted.** Secret names, folder paths, tags and descriptions
   are stored in the clear. `/prod/payments/stripe-live-key` tells an attacker what
   you run, where, and what is worth attacking — before they decrypt anything.
3. **The audit trail is not encrypted.** `audit_log` names every principal, every MRN
   and every read. It is a map of which service accounts can reach which credentials.
4. **Ciphertext is a bet on time.** Harvest now, decrypt later, if the root key ever
   leaks. Every dump you keep extends the window in which a future key compromise is
   retroactive.

So: **treat a backup as sensitive at the level of the secrets it holds**, not at the
level of "it's only ciphertext".

### 7.2 Concretely

- **Encrypt the artifact at rest**, independently of the database's own encryption
  — SSE-KMS on the bucket, or `age`/`gpg` on the file. Use a *different* key from the
  vault's root key: encrypting the backup with the key the backup needs to be
  restorable is a circular dependency you discover during a disaster.
- **Encrypt in transit.** Run `pg_dump` over TLS (`sslmode=require` or stricter);
  this service already refuses `DB_SSLMODE=disable` outside development.
- **Restrict read access** to the recovery role. A backup bucket every engineer can
  list is a copy of the vault every engineer can list.
- **Separate the storage from the root key's** (§1.3).
- **Log access to the backup store.** Reads of the dump are as interesting as reveals
  in `audit_log`, and this service cannot see them.
- **Retention:** at least as long as `SECRET_RECOVERY_WINDOW` (default `720h` / 30
  days), since a soft-deleted secret is restorable for that long and a backup is the
  fallback if it is destroyed early. Beyond that, keep the shortest retention that
  satisfies your compliance obligation — every extra copy is extra exposure, and
  §6.2 means every extra day of backups is an extra day you must retain old root
  keys.
- **Delete expired backups for real,** including versioned-bucket noncurrent
  versions and any replica in another region.
- **Rehearse the restore.** An untested backup is a hypothesis. Restore into a
  throwaway database on a schedule and run §5 — most backup failures are
  discovered during rehearsal or during an outage, and you get to choose which.

---

## 8. Quick reference

```bash
# ---- BACK UP -------------------------------------------------------------
pg_dump --host="$DB_HOST" --username="$DB_USER" --dbname="$DB_NAME" \
        --format=custom --compress=9 --serializable-deferrable \
        --quote-all-identifiers --encoding=UTF8 \
        --file="secret-$(date -u +%Y%m%dT%H%M%SZ).dump"
# AND capture the root key from its provider (§1.2). The dump alone is unrestorable.

# ---- RESTORE -------------------------------------------------------------
createdb maintainerd_secret_restored
pg_restore --dbname=maintainerd_secret_restored \
           --single-transaction --no-owner --no-privileges --verbose \
           secret-20260822T031500Z.dump

# ---- VERIFY --------------------------------------------------------------
# 1. decrypt the canary secret          <- the only test that proves key + data match
# 2. SELECT state, count(*) FROM root_keys GROUP BY state;        -> exactly one active
# 3. every kek_id with versions > 0 has its key material supplied
# 4. the two append-only triggers exist AND refuse an UPDATE
# 5. curl /readyz, and compare row counts against the source
```

| Symptom after a restore | Cause | Action |
|---|---|---|
| Canary reveal returns a decryption error | Wrong root key — the `kek_id` will not match | Supply the key that was active when the backup was taken (§6.2) |
| Boot warns "superseded root key still has versions wrapped under it" | A rewrap was pending when the dump was taken | Supply the old key too, then run the rewrap until `remaining = 0` (§6.4) |
| `UPDATE audit_log` succeeds | The append-only triggers did not come back | Re-apply the `secret_versions` and `audit_log` migrations before returning to service (§5.4) |
| Foreign-key violation on `secret_versions` | `root_keys` restored after it, or not at all | Restore in dependency order, or do a full restore into a fresh database (§3.4) |
| `DELETE` refused during a data-only restore | The append-only trigger is doing its job | Restore into a fresh database instead, or use the sanctioned GUC (§4.3) |
| More than one `active` root key | The unique partial index was not restored | Re-apply the `root_keys` migration; do not resolve it by editing rows |

---

*Related: the root-of-trust and store-policy sections of the [README](../README.md)
for the environment variables named here.*
