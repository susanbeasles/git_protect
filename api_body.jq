# Shape a record into a Cloudflare API payload.
#
# One definition, used by both the create and update paths. Fields Cloudflare
# rejects for a given type are omitted rather than sent as null.
#
# Note the `.type | IN(...)` form. Writing `(["A","AAAA"] | index(.type))` looks
# equivalent but is not: inside that pipe `.` is the array, so `.type` indexes an
# array and jq errors. That bug shipped once and every write failed.

def proxyable: ["A", "AAAA", "CNAME"];
def prioritised: ["MX", "SRV", "URI"];

def api_body:
  . as $r
  | {name: $r.name, type: $r.type, content: $r.content,
     ttl: ($r.ttl // 1), comment: ($r.comment // "")}
  + (if ($r.type | IN(proxyable[])) then {proxied: ($r.proxied // false)} else {} end)
  + (if ($r.type | IN(prioritised[])) and (($r.priority // null) != null)
     then {priority: $r.priority} else {} end)
  + {tags: (($r.tags // []) | sort)};

# Which of the matched records do NOT support a given field?
# Returns a comma-separated list of offending types, or "".
#
# Uses `.type | IN($list[])`. The tempting `($list | index(.type))` is wrong for
# the same reason as above: inside that pipe `.` is the list, not the record.
def unsupported_types($allowed):
  [ .[] | select((.type | IN($allowed[])) | not) | .type ] | unique | join(", ");

def types_needing_priority: [ .[] | select(.type | IN(prioritised[])) | .type ] | unique;
