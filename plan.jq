# plan.jq — diff live vs desired without ever creating a window where a record
# is absent. Anything that can be a PATCH becomes a PATCH.
#
# in : $live (array, each has .id), $desired (array, each has ._i)
# out: {noop:[], update:[{id,from,to}], create:[], delete:[]}

def rkey: "\(.type)|\(.name)|\(.content)";
def nkey: "\(.type)|\(.name)";
def meta: {ttl, proxied, comment, tags, priority};

def plan($live; $desired):
  ( ([$live[] | rkey] + [$desired[] | rkey]) | unique ) as $keys

  # ---- pass 1: pair records with identical name+type+content, multiplicity-aware
  | reduce $keys[] as $k (
      {upd: [], noop: [], c: [], d: []};
      ([$live[]    | select(rkey == $k)]) as $lg
    | ([$desired[] | select(rkey == $k)]) as $dg
    | ($lg | length) as $nl
    | ($dg | length) as $nd
    | ([$nl, $nd] | min) as $m
    | reduce range(0; $m) as $i (.;
        ($lg[$i]) as $lr | ($dg[$i]) as $dr
        | if ($lr | meta) == ($dr | meta)
          then .noop += [$dr]
          else .upd += [{id: $lr.id, from: $lr, to: $dr, why: "metadata"}]
          end )
    | (if $nd > $m then .c += $dg[$m:] else . end)
    | (if $nl > $m then .d += $lg[$m:] else . end)
    )

  # ---- pass 2: leftover create+delete on the same name+type becomes an
  #      in-place content PATCH. This is what stops SPF/DMARC from ever
  #      vanishing mid-sync.
  | reduce ([.c[] | nkey] | unique)[] as $n (.;
      ([.c[] | select(nkey == $n)]) as $cg
    | ([.d[] | select(nkey == $n)]) as $dg
    | ([($cg | length), ($dg | length)] | min) as $m
    | if $m == 0 then .
      else
        ( [range(0; $m) | {id: $dg[.].id, from: $dg[.], to: $cg[.], why: "content"}] ) as $pairs
        | ( [$cg[0:$m][]._i] ) as $usedc
        | ( [$dg[0:$m][].id] ) as $usedd
        | .upd += $pairs
        | .c |= map(select(._i as $x | ($usedc | index($x)) == null))
        | .d |= map(select(.id  as $x | ($usedd | index($x)) == null))
      end )

  | {noop: .noop, update: .upd, create: .c, delete: .d};

plan($live; $desired)
