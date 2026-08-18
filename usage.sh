# shellcheck shell=bash
# Help text. Nothing else.
usage() {
cat <<'USAGE'
cf — Cloudflare DNS CLI

  Every mutating command previews the change, snapshots the zone first, and
  asks before applying. Nothing is written without confirmation.

AUTH
  cf auth login                    acquire and store a token (least privilege)
  cf auth status                   verify the stored token against Cloudflare
  cf auth logout                   forget it locally (does NOT revoke)

RECORDS
  cf dns ls [selectors]            list records
  cf dns add    --name N --type T --content C [--ttl N] [--priority N]
                [--proxy true|false] [--tags a,b] [--comment "..."] [--force]
  cf dns rm     <selectors>
  cf dns update <selectors> [--set-content C] [--ttl N] [--priority N]
                [--proxy true|false] [--tags a,b] [--comment "..."]

SELECTORS  (AND together; a selection that would sweep the zone is refused)
  --name N        exact name; @ means the apex
  --type T        record type
  --content S     substring match on the value
  --tags a,b      record must carry all listed tags
  --id ID         exact Cloudflare record id

DESIRED STATE
  cf dns sync --pull               live zone  -> config/masterDNS.json
  cf dns sync                      preview file -> zone   (dry run)
  cf dns sync --apply              apply it
  cf dns restore --file <snap>     roll back to a snapshot
  cf dns validate                  offline syntax check of the file

ANALYSIS
  cf dns doctor                    live zone analysis with remediation
  cf dns doctor --llm-safe --out report.md     redacted, safe to share
      --format text|md|json        default text (md with --llm-safe)
      --redact none|standard|strict
      --file <snapshot.json>       analyse a file instead of the live zone

INTEGRITY  (of this CLI's own code)
  cf doctor                        evidentiary changelog of code changes
  cf integrity show|pin|verify|diff|manifest
  cf seal                          report on the release signature

OTHER
  cf snapshots                     list saved zone snapshots
  --zone Z        act on a different zone
  --yes           skip confirmation for non-destructive plans only

ENVIRONMENT
  CFDNS_ROOT             where state lives (default: OS config dir)
  CFDNS_NO_BANNER=1      suppress the build-hash banner
  CFDNS_ASSUME_YES=1     skip all confirmations (for automation; be careful)
USAGE
}
