# shellcheck shell=bash
# The desired-state file: locate, validate, normalise. One concern — turning a
# masterDNS.json into the canonical record shape the planner compares against.
# It does not read the live zone and it does not decide anything.

desired_path() { printf '%s' "${MASTER_FILE:-$CFDNS_MASTER_DEFAULT}"; }

# Structural problems worth rejecting before any API call, with messages that say
# what to do rather than what went wrong.
desired_validate() {
  local file="$1"
  jq -e '.records | type == "array"' "$file" >/dev/null 2>&1 \
    || die "$file is not valid — expected {\"zone\": ..., \"records\": [...]}"

  local bad
  bad="$(jq -r '.records[] | select((.name == null) or (.type == null) or (.content == null))
                | "  incomplete: \(. | tojson)"' "$file")"
  if [ -n "$bad" ]; then
    printf '%s\n' "$bad" >&2
    die "every record needs name, type, and content"
  fi

  bad="$(jq -r '.records[] | select((.type == "MX" or .type == "SRV") and (.priority == null))
                | "  \(.type) \(.name) has no priority"' "$file")"
  if [ -n "$bad" ]; then
    printf '%s\n' "$bad" >&2
    die "Cloudflare rejects MX and SRV records without a priority"
  fi
}

# Canonical form: absolute names, defaults filled, tags sorted, exact duplicates
# dropped, and an index so the planner can pair records deterministically.
desired_normalise() {
  local file="$1" zone="$2"
  jq --arg z "$zone" '
    .records
    | map(. + {name: (if (.name == "@" or .name == "" or .name == $z) then $z
                      elif (.name | endswith("." + $z)) then .name
                      else .name + "." + $z end)})
    | map({name, type, content,
           ttl: (.ttl // 1),
           proxied: (.proxied // false),
           comment: (.comment // ""),
           tags: ((.tags // []) | sort),
           priority: (.priority // null)})
    | unique
    | to_entries | map(.value + {_i: .key})' "$file"
}

desired_load() {
  local file="$1" zone="$2"
  desired_validate "$file"
  desired_normalise "$file" "$zone"
}

# A snapshot stores provider state under .state; a desired-state file stores it under
# .records. This adapter is the only place that difference is known, so neither the
# snapshot primitive nor the planner has to care about the other's shape.
desired_from_snapshot() {
  local path="$1" zone="$2"
  snapshot_read "$path" | jq --arg z "$zone" '{zone: $z, records: .}'
}

# Write the live zone out as a desired-state file, backing up whatever was there.
desired_capture() {
  local file="$1" zone="$2"
  if [ -f "$file" ]; then
    local backup="$file.bak.$(now_stamp)"
    cp "$file" "$backup"
    ok "backed up existing file -> $backup"
  fi
  mkdir -p "$(dirname "$file")"
  fetch_live | jq --arg z "$zone" '{
      zone: $z, generated: (now|todate),
      records: [ .[] | {name,type,content,ttl,proxied,comment,tags,priority} ]
    }' > "$file"
}
