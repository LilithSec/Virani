# The hosts index and host pruning

Time narrows a search to the PCAPs overlapping the window; the filter still
has to be run against every one of them, and on a busy hoard that is the
expensive part. The hosts index exists to shrink it: a per-PCAP record of
which IP endpoints appear inside, kept beside the cache, so a filter that
requires specific hosts can skip the PCAPs that can not possibly hold a
match before any tcpdump or tshark is spent on them.

It is two separate pieces — an indexer you cron, and a pruning gate you
enable — and both default to off (unbuilt, and `host_pruning = false`).

## Building the index... update-pcap-hosts

```shell
virani --update-pcap-hosts --set wan
```

Each PCAP of the set is run through `tshark -n -q -z endpoints,ipv4 -z
endpoints,ipv6` and the addresses found are written, one per line, to
`$cache/pcap_hosts/<set>/<path relative to the set path>`. The run is
incremental and safe to repeat...

- An entry as new as its PCAP (by mtime) is current and skipped; a PCAP
  modified since it was indexed is reindexed.
- A PCAP modified less than `pcap_hosts_min_age` seconds ago (default 120)
  is skipped — it is likely still being written to, and indexing it now
  would record a partial host list as if it were the whole truth.
- Entries whose PCAP has rotated away are pruned, so the index does not
  grow forever.
- Entries are written to a tmp file and renamed into place, so a reader
  never sees a half-written list; `workers` of them are indexed in
  parallel.

It is intended for cron on the box holding the PCAPs, paced to the set's
rotation...

```
*/5 * * * * virani -q --update-pcap-hosts --set wan
```

A JSON summary comes back (`indexed`, `fresh`, `too_new`, `pruned`,
`failed`), and `-q` leaves just that. Per-PCAP lists are readable from Perl
via `Virani->read_pcap_hosts`.

## The pruning gate... host_pruning

With `host_pruning = true` (globally or per set) and a filter that requires
one or more IP hosts, `get_pcap_local` reduces the filter to
**OR-of-AND-groups** of hosts and keeps a time-matched PCAP only when its
indexed host list fully contains at least one group...

```
host A                       ->  [ [A] ]        keep if A indexed
host A or host B             ->  [ [A], [B] ]   keep if A or B indexed
host A and host B            ->  [ [A, B] ]     keep only if BOTH indexed
host A or host B and host C  ->  [ [A], [B, C] ]
```

That whole-group requirement is what makes the `and` case strong: `host A
and host B` skips a PCAP that indexed A but not B, not just one that indexed
neither. The groups come from the BPF for the `tcpdump` and `bpf2tshark`
types, and from the native display filter (`ip.addr == ...`,
`ipv6.src == ...`, joined with `&&`/`||`) for the `tshark` type.

The reasoning leans on and/or precedence and on hosts being genuine
requirements, so anything that muddies it makes the whole filter
unprunable — the gate simply steps aside and every time-matched PCAP is
filtered as normal...

- negation (`not`, `!`, `!=`) — a negated host is no longer required
- explicit parentheses — they can override the precedence the flat walk
  assumes
- bare `port`/`tcp`/`udp`/`icmp`/`ether` terms (BPF) or any non-IP-host
  field (tshark) — such a term can match with no host involved
- hostnames, CIDRs, MAC addresses — not IP literals, not in the index

And a PCAP with no current index entry — never indexed, too new, or
modified since — is **always kept**. Skipping is only ever done on positive
knowledge; an unindexed or half-indexed set just degrades to full
filtering, never to lost packets.

When the gate runs, the metadata JSON records what it did under
`host_pruning`... the derived `groups`, the `candidates` count, `kept`,
`pruned`, and `unindexed_kept`.

## The honest caveat

The index knows IP endpoints as tshark's dissection saw them. A filter
anchored on hosts that appear only as ARP traffic, or on inner addresses of
tunneled traffic the endpoint tables did not surface, can in principle be
pruned wrongly — which is why `host_pruning` defaults to off and is a
deliberate opt-in for hoards where those cases do not apply (or do not
matter against the speedup). If in doubt, leave it off; if a specific
search must be exhaustive, `--nc` on its own does not disable pruning, but
an unprunable filter shape — parentheses around it suffice — does.
