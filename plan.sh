#!/usr/bin/env bash
# Unit tests for lib/dns/plan.jq — the diff engine that decides create/update/delete.
# Pure jq, no shell stubs, no network. Each case is a fixture in, assertion out.
set +e
cd "$(dirname "$0")/.." || exit 1

fail=0
t() { printf '  %-54s ' "$1"; }
ok_() { echo PASS; }
no_() { echo FAIL; fail=1; }

# plan <live-json> <desired-json>  -> plan JSON
plan() {
  jq -n --argjson live "$1" \
        --argjson desired "$(jq -c 'to_entries | map(.value + {_i: .key})' <<<"$2")" \
        -f lib/dns/plan.jq
}
# counts <plan> -> "create update delete"
counts() { jq -r '"\(.create|length) \(.update|length) \(.delete|length)"' <<<"$1"; }

R() { # R <id> <name> <type> <content> [ttl] [comment]
  jq -cn --arg id "$1" --arg n "$2" --arg t "$3" --arg c "$4" \
         --argjson ttl "${5:-1}" --arg cm "${6:-}" \
    '{id:$id, name:$n, type:$t, content:$c, ttl:$ttl, proxied:false,
      comment:$cm, tags:[], priority:null}'
}
D() { # D <name> <type> <content> [ttl] [comment]  (desired: no id)
  jq -cn --arg n "$1" --arg t "$2" --arg c "$3" \
         --argjson ttl "${4:-1}" --arg cm "${5:-}" \
    '{name:$n, type:$t, content:$c, ttl:$ttl, proxied:false,
      comment:$cm, tags:[], priority:null}'
}

# ---------------------------------------------------------------- identical
t "identical live and desired produces an empty plan"
p="$(plan "[$(R id1 a.test TXT hello)]" "[$(D a.test TXT hello)]")"
[ "$(counts "$p")" = "0 0 0" ] && ok_ || { no_; echo "      $(counts "$p")"; }

# ---------------------------------------------------------------- create only
t "a record only in desired is a CREATE"
p="$(plan '[]' "[$(D new.test TXT x)]")"
[ "$(counts "$p")" = "1 0 0" ] && ok_ || { no_; echo "      $(counts "$p")"; }

# ---------------------------------------------------------------- delete only
t "a record only in live is a DELETE"
p="$(plan "[$(R id1 gone.test TXT x)]" '[]')"
[ "$(counts "$p")" = "0 0 1" ] && ok_ || { no_; echo "      $(counts "$p")"; }

# ---------------------------------------------------------------- the critical one
t "metadata-only change is an UPDATE, never delete+create"
p="$(plan "[$(R id1 a.test TXT hello 1 '')]" "[$(D a.test TXT hello 300 'note')]")"
[ "$(counts "$p")" = "0 1 0" ] && ok_ || { no_; echo "      $(counts "$p")"; }

t "  and it carries the live record id so it can be PUT in place"
[ "$(jq -r '.update[0].id' <<<"$p")" = "id1" ] && ok_ || no_

t "content change on a unique name+type is an in-place UPDATE"
p="$(plan "[$(R id1 a.test TXT old)]" "[$(D a.test TXT new)]")"
[ "$(counts "$p")" = "0 1 0" ] \
  && [ "$(jq -r '.update[0].to.content' <<<"$p")" = new ] \
  && [ "$(jq -r '.update[0].id' <<<"$p")" = id1 ] && ok_ || { no_; echo "      $(counts "$p")"; }

# This is the SPF case that motivated the whole design: an SPF record must never
# be absent, even for a moment, so a content swap must be a PUT not a DELETE+POST.
t "SPF content swap never appears in the delete set"
p="$(plan "[$(R id1 z.test TXT 'v=spf1 include:old.example -all')]" \
          "[$(D z.test TXT 'v=spf1 include:new.example -all')]")"
[ "$(jq '.delete | length' <<<"$p")" = 0 ] && [ "$(jq '.update | length' <<<"$p")" = 1 ] \
  && ok_ || { no_; echo "      $(counts "$p")"; }

# ---------------------------------------------------------------- duplicates
t "two identical live records, one desired -> 1 delete, 0 update"
p="$(plan "[$(R id1 d.test TXT same),$(R id2 d.test TXT same)]" "[$(D d.test TXT same)]")"
[ "$(counts "$p")" = "0 0 1" ] && ok_ || { no_; echo "      $(counts "$p")"; }

t "duplicate _dmarc collapsed to one different record -> 1 update + 1 delete"
p="$(plan "[$(R id1 _dmarc.test TXT 'v=DMARC1; p=none'),$(R id2 _dmarc.test TXT 'v=DMARC1; p=none')]" \
          "[$(D _dmarc.test TXT 'v=DMARC1; p=quarantine; sp=quarantine')]")"
[ "$(counts "$p")" = "0 1 1" ] && ok_ || { no_; echo "      $(counts "$p")"; }

t "  the surviving record is patched, not recreated"
[ "$(jq -r '.update[0].to.content' <<<"$p")" = 'v=DMARC1; p=quarantine; sp=quarantine' ] \
  && ok_ || no_

# ---------------------------------------------------------------- multi-record names
t "multiple distinct records on one name are matched individually"
live="[$(R id1 m.test MX mx1.test),$(R id2 m.test MX mx2.test)]"
des="[$(D m.test MX mx1.test),$(D m.test MX mx3.test)]"
p="$(plan "$live" "$des")"
# mx1 matches exactly; mx2 -> mx3 pairs on name+type as an in-place update
[ "$(counts "$p")" = "0 1 0" ] && ok_ || { no_; echo "      $(counts "$p")"; }

t "three live, one desired on the same name -> 2 deletes"
live="[$(R id1 t.test TXT a),$(R id2 t.test TXT b),$(R id3 t.test TXT c)]"
p="$(plan "$live" "[$(D t.test TXT a)]")"
[ "$(counts "$p")" = "0 0 2" ] && ok_ || { no_; echo "      $(counts "$p")"; }

t "one live, three desired on the same name -> 2 creates"
p="$(plan "[$(R id1 t.test TXT a)]" "[$(D t.test TXT a),$(D t.test TXT b),$(D t.test TXT c)]")"
[ "$(counts "$p")" = "2 0 0" ] && ok_ || { no_; echo "      $(counts "$p")"; }

# ---------------------------------------------------------------- different types
t "same name, different types are never paired with each other"
p="$(plan "[$(R id1 x.test TXT val)]" "[$(D x.test A 1.2.3.4)]")"
[ "$(counts "$p")" = "1 0 1" ] && ok_ || { no_; echo "      $(counts "$p")"; }

# ---------------------------------------------------------------- edges
t "empty live and empty desired is an empty plan"
p="$(plan '[]' '[]')"
[ "$(counts "$p")" = "0 0 0" ] && ok_ || no_

t "priority change is an UPDATE, not delete+create"
live="$(jq -cn '{id:"id1",name:"m.test",type:"MX",content:"mx.test",ttl:1,proxied:false,comment:"",tags:[],priority:10}')"
des="$(jq -cn '{name:"m.test",type:"MX",content:"mx.test",ttl:1,proxied:false,comment:"",tags:[],priority:20}')"
p="$(plan "[$live]" "[$des]")"
[ "$(counts "$p")" = "0 1 0" ] \
  && [ "$(jq -r '.update[0].to.priority' <<<"$p")" = 20 ] && ok_ || { no_; echo "      $(counts "$p")"; }

t "tag-only change is an UPDATE"
live="$(jq -cn '{id:"id1",name:"w.test",type:"A",content:"1.2.3.4",ttl:1,proxied:true,comment:"",tags:[],priority:null}')"
des="$(jq -cn '{name:"w.test",type:"A",content:"1.2.3.4",ttl:1,proxied:true,comment:"",tags:["web"],priority:null}')"
p="$(plan "[$live]" "[$des]")"
[ "$(counts "$p")" = "0 1 0" ] && ok_ || { no_; echo "      $(counts "$p")"; }

printf '\n'
[ "$fail" -eq 0 ] && echo "PLANNER TESTS PASS" || echo "PLANNER TESTS FAILED"
exit "$fail"
