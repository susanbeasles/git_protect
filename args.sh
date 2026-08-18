# shellcheck shell=bash
# Argument parsing. It sets variables and does nothing else: no validation, no
# dispatch, no side effects. Validation belongs to the module that owns the field.
#
# The REC_*/SEL_*/REPORT_* variables are consumed by lib/cmd/ and lib/dns/. Those
# files are analysed separately by the linter, which therefore reports them unused.
# (A comment line must not begin with the linter's own name, or it is parsed as a
# directive rather than prose.)
# shellcheck disable=SC2034
parse_args() {
  while [ $# -gt 0 ]; do
    case "$1" in
      # selection
      --name)         REC_NAME="$2"; SEL_NAME="$2"; shift 2 ;;
      --type)         REC_TYPE="$(printf '%s' "$2" | tr '[:lower:]' '[:upper:]')"
                      SEL_TYPE="$REC_TYPE"; shift 2 ;;
      --content)      REC_CONTENT="$2"; SEL_CONTENT="$2"; shift 2 ;;
      --tags)         REC_TAGS="$2"; SEL_TAGS="$2"; shift 2 ;;
      --id)           SEL_ID="$2"; shift 2 ;;
      # mutation
      --set-content)  SET_CONTENT="$2"; shift 2 ;;
      --ttl)          REC_TTL="$2"; shift 2 ;;
      --priority)     REC_PRIORITY="$2"; shift 2 ;;
      --proxy)        REC_PROXY="$2"; shift 2 ;;
      --comment|--description) REC_COMMENT="$2"; shift 2 ;;
      --force)        FORCE=1; shift ;;
      --yes|-y)       ASSUME_YES=1; shift ;;
      # sync
      --pull)         SYNC_PULL=1; shift ;;
      --apply)        unset DRY_RUN; APPLY=1; shift ;;
      --file|--inputFile) MASTER_FILE="$2"; shift 2 ;;
      # reporting
      --format)       REPORT_FORMAT="$2"; shift 2 ;;
      --redact)       REPORT_REDACT="$2"; shift 2 ;;
      --llm-safe)     REPORT_REDACT="${REPORT_REDACT:-standard}"
                      REPORT_FORMAT="${REPORT_FORMAT:-md}"; shift ;;
      --out)          REPORT_OUT="$2"; shift 2 ;;
      # global
      --zone)         CFDNS_ZONE="$2"; shift 2 ;;
      -h|--help)      usage; exit 0 ;;
      --) shift; break ;;
      -*) die "unknown flag: $1  (see: cf --help)" ;;
      *)  POSITIONAL+=("$1"); shift ;;
    esac
  done
}
