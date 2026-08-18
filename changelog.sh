# shellcheck shell=bash
# The code-change event log: append, and render. One concern — the history of
# observed bundle changes. It does not decide whether a change is acceptable, and it
# does not compute hashes.

# changelog_diff_paths <old-manifest-file> <new-manifest-text> -> changed paths
changelog_diff_paths() {
  local old="$1" new="$2"
  [ -f "$old" ] || return 0
  { diff "$old" <(printf '%s\n' "$new") 2>/dev/null || true; } \
    | awk '/^[<>]/ {print $4}' | LC_ALL=C sort -u
}

# changelog_file_evidence <bundle-root> <old-manifest-file> <path> -> one JSON object
#
# Records mtime AND ctime. A normal edit moves both together; ctime later than mtime
# means the file was written and then had its mtime pushed backwards, which is what a
# cover-up looks like. mtime is forgeable with touch, ctime is not.
changelog_file_evidence() {
  local root="$1" old="$2" path="$3"
  local size mtime ctime state st

  if [ -e "$root/$path" ]; then
    st="$(stat -c '%s %Y %Z' "$root/$path" 2>/dev/null || stat -f '%z %m %c' "$root/$path")"
    size="$(awk '{print $1}' <<<"$st")"
    mtime="$(awk '{print $2}' <<<"$st")"
    ctime="$(awk '{print $3}' <<<"$st" | cut -d. -f1)"
    if grep -q " $path\$" "$old" 2>/dev/null; then state=modified; else state=added; fi
  else
    size=0; mtime=0; ctime=0; state=removed
  fi

  jq -cn --arg p "$path" --arg s "$state" \
        --argjson size "${size:-0}" --argjson mtime "${mtime:-0}" --argjson ctime "${ctime:-0}" \
        --arg mt "$(epoch_to_local "${mtime:-0}")" --arg ct "$(epoch_to_local "${ctime:-0}")" \
    '{path:$p, state:$s, size:$size,
      mtime:$mtime, mtime_local:$mt,
      ctime:$ctime, ctime_local:$ct,
      backdated: ($ctime > ($mtime + 2))}'
}

# changelog_append <bundle-root> <previous-hash> <new-hash> <manifest-text> <old-manifest-file>
changelog_append() {
  local root="$1" previous="$2" new="$3" manifest="$4" old="$5"
  local changed='[]' path

  while IFS= read -r path; do
    [ -z "$path" ] && continue
    changed="$(jq -c --argjson e "$(changelog_file_evidence "$root" "$old" "$path")" \
                 '. + [$e]' <<<"$changed")"
  done <<< "$(changelog_diff_paths "$old" "$manifest")"

  jq -cn --arg at "$(now_utc)" --argjson epoch "$(now_epoch)" \
         --arg local "$(epoch_to_local "$(now_epoch)")" \
         --arg prev "$previous" --arg new "$new" \
         --arg user "${USER:-$(id -un 2>/dev/null || echo unknown)}" \
         --arg tty "$(if tty -s 2>/dev/null; then tty; else echo 'no tty'; fi)" \
         --argjson changed "$changed" \
    '{observed_at:$at, observed_epoch:$epoch, observed_local:$local,
      previous_hash:$prev, new_hash:$new,
      observed_by:$user, tty:$tty, changed_files:$changed}' \
    >> "$CFDNS_INTEGRITY_LOG"
  chmod 600 "$CFDNS_INTEGRITY_LOG" 2>/dev/null || true
}

changelog_count() {
  [ -s "$CFDNS_INTEGRITY_LOG" ] || { printf '0'; return; }
  wc -l < "$CFDNS_INTEGRITY_LOG" | tr -d ' '
}

changelog_render() {
  [ -s "$CFDNS_INTEGRITY_LOG" ] || {
    printf '\n  No code changes have been observed since this store was created.\n\n'; return 0; }

  printf '\n%s  (%s event(s), oldest first)\n\n' \
    "$(_c '1;37' 'OBSERVED CHANGES')" "$(changelog_count)"
  local event
  while IFS= read -r event; do
    printf '  %s  %s\n' \
      "$(_c '1;36' "$(jq -r '.observed_local' <<<"$event")")" \
      "$(jq -r '"(seen by " + .observed_by + " on " + .tty + ")"' <<<"$event")"
    printf '    %s -> %s\n' \
      "$(jq -r '.previous_hash[0:16]' <<<"$event")" "$(jq -r '.new_hash[0:16]' <<<"$event")"
    if [ "$(jq '.changed_files | length' <<<"$event")" -eq 0 ]; then
      printf '    (no per-file detail — no prior manifest existed at the time)\n'
    else
      jq -r '.changed_files[]
             | "    " + ((.state | ascii_upcase) + "        ")[0:9] + " " + .path
               + (if .state == "removed" then " (no longer on disk)"
                  else "\n              written " + .mtime_local
                       + "   inode changed " + .ctime_local
                       + (if .backdated then "   <-- BACK-DATED" else "" end)
                  end)' <<<"$event"
    fi
    printf '\n'
  done < "$CFDNS_INTEGRITY_LOG"
}

# Files whose mtime was pushed backwards after the write. Returned rather than
# printed so the caller decides how loudly to say it.
changelog_backdated() {
  [ -s "$CFDNS_INTEGRITY_LOG" ] || return 0
  jq -r 'select(.changed_files) | .changed_files[] | select(.backdated)
         | "    " + .path + "  written " + .mtime_local
           + " but inode changed " + .ctime_local' \
    "$CFDNS_INTEGRITY_LOG" 2>/dev/null || true
}
