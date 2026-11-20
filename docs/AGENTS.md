# Using vcd_shadow_cleaner from an AI agent

The analysis subcommands let an agent find out which shadow VMs belong to which vApp templates, with the evidence
for each match, and write a delete plan for a person to review. **Deleting is out of an agent's reach in this
release:** no subcommand sends a delete (they use a read-only client that allows only GETs and the login POST), and
`plan` changes nothing. A person deletes, in the GUI or with the terminal-confirmed `--cli`.

Every subcommand writes one JSON document on stdout (or to `--out FILE`, mode 0600) and nothing else; logs and
progress go to stderr. Run `python vcd_shadow_cleaner.py <subcommand> --help` for the full flags.

## Credentials: never on argv

- `--profile P` uses a server profile a person saved in the GUI (matched by id, display name or hostname); its
  credential comes from the OS keyring. `profiles list` shows the profiles, never their credentials.
- Or `--server HOST --token-stdin`, or `--server HOST --username U --password-stdin`: the secret is the first line
  of stdin, e.g. `printf '%s\n' "$TOKEN" | python vcd_shadow_cleaner.py orgs --server vcd.example --token-stdin`.
- The subcommands refuse `--token` and `--password`, and ignore `VCD_*` env vars and `.env`. Usage errors never
  echo unrecognized arguments.

## Workflow: discover, scan, plan, hand over

```bash
# 1. Discover: names and IDs
python vcd_shadow_cleaner.py profiles list
python vcd_shadow_cleaner.py orgs       --profile lab
python vcd_shadow_cleaner.py catalogs   --profile lab [--org OrgA]
python vcd_shadow_cleaner.py datastores --profile lab        # one name can exist on several vCenters

# 2. Scan (repeat --catalog/--datastore for more; IDs or hrefs work too)
python vcd_shadow_cleaner.py scan --profile lab --catalog Gold --datastore ds1 \
    [--org OrgA] [--template 'web-*'] [--exclude-template web-old] [--include-unmatched] --out scan.json

# 3. Plan, offline: no VCD calls
python vcd_shadow_cleaner.py plan --scan scan.json [--include-weak] [--template ...] [--exclude ...] \
    [--limit 25] --out plan.json
```

4. Hand `plan.json` to a person, with its `plan_sha256`, the item count and anything in `excluded` or `warnings`
   they should know about.

- **Names must resolve to exactly one object.** A name that matches none, or several (the same catalog name in two
  orgs, the same datastore name on two vCenters), exits 2. Each error lists the `candidates` with their `id`.
  Retry with `--catalog-id` / `--datastore-id`, which accept the id, the href or the bare UUID.
- **Match strength.** `exact`: the shadow VM's parent template reference is a selected template. `name` and
  `substring` are **weak**: they come from names alone and can be wrong. `plan` leaves weak matches out unless
  `--include-weak`. `match.evidence` names the record field and value that decided each match; `record` is the
  raw VCD record.
- **Template filters** (`--template`, `--exclude-template`; exact names or case-sensitive globs) apply after
  matching, so they never move a shadow VM to another template. A pattern that matches no template adds a warning.
- **Plan reasons.** Each `excluded` entry lists why: `weak_match`, `other_template`, `unmatched`,
  `template_not_included`, `template_excluded`, `limit`, `source_scan_incomplete`, `duplicate_shadow_id`,
  `no_shadow_id`, `no_template_id`, `no_datastore_id` or `unknown_match_strength`. `--limit N` keeps exact matches
  first, then lowest shadow id.
- **Plan hash.** `plan_sha256` is the SHA-256 of
  `json.dumps({"server": <host, lower-case>, "items": [{"shadow_id", "datastore_id", "template_id", "match_strength"}, ...]}, sort_keys=True, separators=(",", ":"))`
  in UTF-8, with the items sorted by `shadow_id`. It leaves out names and doesn't depend on input order.
  `source_scan_sha256` is the SHA-256 of the scan file's bytes.
- **Incomplete means incomplete.** If any query failed, `complete` is `false`, `errors` says what failed, and the
  exit code is 4. `plan` refuses an incomplete scan: no items, `plan_sha256: null`.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Success, results complete |
| 1 | Internal error |
| 2 | Usage error, or a name that doesn't resolve to exactly one object (see `errors[].candidates`) |
| 3 | Authentication failed, or the profile has no stored credential |
| 4 | VCD or network error; results incomplete (`complete: false`) |
| 130 | Interrupted |

Codes 5 to 7 belong to deleting, which only the legacy `--cli` does.

## Schemas

| Document | `schema` field | JSON Schema |
|---|---|---|
| `profiles list` | `vcd-shadow-cleaner.profiles/1` | [`schemas/profiles-1.schema.json`](../schemas/profiles-1.schema.json) |
| `orgs`, `catalogs`, `datastores` | `vcd-shadow-cleaner.discovery/1` (`kind` says which) | [`schemas/discovery-1.schema.json`](../schemas/discovery-1.schema.json) |
| `scan` | `vcd-shadow-cleaner.scan/1` | [`schemas/scan-1.schema.json`](../schemas/scan-1.schema.json) |
| `plan` | `vcd-shadow-cleaner.plan/1` | [`schemas/plan-1.schema.json`](../schemas/plan-1.schema.json) |

Every document has `complete`, `errors`, `warnings` and `counts`.
