# shellcheck shell=bash
# Record shape: naming, field validation, API body construction.
# Pure-ish: no network, no state beyond the configured zone.

PROXYABLE_TYPES='A AAAA CNAME'
PRIORITY_TYPES='MX SRV URI'

# fqdn <name> <zone>  — "@"/""/zone -> zone; bare label -> label.zone
fqdn() {
  local name="$1" zone="$2"
  case "$name" in
    ''|'@') printf '%s' "$zone" ;;
    "$zone") printf '%s' "$zone" ;;
    *".$zone") printf '%s' "$name" ;;
    *) printf '%s.%s' "$name" "$zone" ;;
  esac
}

# relative_name <fqdn> <zone> — inverse of fqdn, for display and fix commands
relative_name() {
  local name="$1" zone="$2"
  if [ "$name" = "$zone" ]; then printf '@'; return; fi
  case "$name" in
    *".$zone") printf '%s' "${name%".$zone"}" ;;
    *) printf '%s' "$name" ;;
  esac
}

type_is() {   # type_is <type> <space-separated list>
  case " $2 " in *" $1 "*) return 0 ;; *) return 1 ;; esac
}

# Validate field values before they reach the API, with messages that say what to do.
validate_fields() {
  local type="$1" ttl="$2" priority="$3" proxied="$4"

  case "$type" in
    ''|*[!A-Z0-9]*) die "--type must be a DNS record type (A, AAAA, CNAME, TXT, MX, SRV, NS, CAA...)" ;;
  esac

  case "$ttl" in
    ''|*[!0-9]*) die "--ttl must be an integer (1 = Cloudflare 'auto', or 60-86400)" ;;
  esac
  if [ "$ttl" -ne 1 ] && { [ "$ttl" -lt 60 ] || [ "$ttl" -gt 86400 ]; }; then
    die "--ttl must be 1 (auto) or between 60 and 86400"
  fi

  if type_is "$type" "$PRIORITY_TYPES"; then
    [ -n "$priority" ] || die "--priority is required for $type records (e.g. --priority 10)"
  fi
  if [ -n "$priority" ]; then
    case "$priority" in ''|*[!0-9]*) die "--priority must be an integer 0-65535" ;; esac
    [ "$priority" -le 65535 ] || die "--priority must be 0-65535"
  fi

  if [ -n "$proxied" ] && [ "$proxied" != false ]; then
    type_is "$type" "$PROXYABLE_TYPES" \
      || die "--proxy only applies to $PROXYABLE_TYPES records; Cloudflare rejects it on $type"
  fi

  case "$proxied" in ''|true|false) ;; *) die "--proxy must be true or false" ;; esac
}

# record_body — the single place an API payload is constructed. Fields Cloudflare
# rejects for a given type are omitted rather than sent as null.
record_body() {
  local name="$1" type="$2" content="$3" ttl="$4" proxied="$5" comment="$6" tags="$7" priority="$8"
  jq -cn \
    --arg name "$name" --arg type "$type" --arg content "$content" \
    --argjson ttl "${ttl:-1}" --arg proxied "${proxied:-}" \
    --arg comment "${comment:-}" --arg tags "${tags:-}" --arg priority "${priority:-}" \
    --arg proxyable "$PROXYABLE_TYPES" --arg prioritytypes "$PRIORITY_TYPES" '
    {name: $name, type: $type, content: $content, ttl: $ttl, comment: $comment}
    + (if ($proxyable | split(" ") | index($type)) and $proxied != ""
       then {proxied: ($proxied == "true")} else {} end)
    + (if ($prioritytypes | split(" ") | index($type)) and $priority != ""
       then {priority: ($priority | tonumber)} else {} end)
    + (if $tags == "" then {} else {tags: ($tags | split(","))} end)'
}

# One rendering of a record list, used by every preview and listing.
render_records() {
  jq -r '
    if (. | length) == 0 then "  (none)"
    else .[] |
      "  " + (.type + "      ")[0:6] + "  " + .name
      + (if (.priority // null) != null then "  prio=" + (.priority|tostring) else "" end)
      + "\n      " + (.content[0:110]) + (if (.content|length) > 110 then "…" else "" end)
      + "\n      ttl=" + (.ttl|tostring)
      + (if .proxied then " proxied" else "" end)
      + (if ((.tags // []) | length) > 0 then " tags=" + ((.tags|sort)|join(",")) else "" end)
      + (if (.comment // "") != "" then "  # " + .comment else "" end)
    end'
}
