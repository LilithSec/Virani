# Cached searches

Every answer Virani generates lands in the cache dir (default
`/var/cache/virani`) as two files...

```
/var/cache/virani/
├── <set>-<type>-<start>-<end>-<md5>          the carved PCAP
└── <set>-<type>-<start>-<end>-<md5>.json     the metadata... how it was made
```

The basename is the **cache ID**: the set, the resolved filter type, the
unpadded start and end epochs, and the MD5 of the whitespace-normalized
filter. Ask the same question again — same set, type, window, and filter,
whitespace be damned — and the cached answer is returned without touching
the hoard. `--nc` (or `no_cache`) forces a regeneration.

Two properties worth knowing...

- **A failed search leaves its metadata.** If nothing could be processed the
  PCAP is never written, but the `.json` is — so the failure and its reasons
  are inspectable afterwards, and such entries show `has_pcap: 0` in
  listings.
- **A search written straight to an output file may bypass the cache.** If
  the cache dir is unusable and an output file was given, the answer goes
  only there (`auto_no_cache`); it then has no cache ID and will not appear
  in listings.

## Listing and refetching

```shell
# what is in the cache, as JSON... --set to limit to one set
virani --list-cached
virani --list-cached --set wan

# pull a past answer back out by its ID
virani --cached wan-tcpdump-1752400000-1752403600-9a0364b9e99bb480dd25e1f0284c8555 -w again.pcap

# just its metadata
virani --cached wan-tcpdump-1752400000-1752403600-9a0364b9e99bb480dd25e1f0284c8555 --meta
```

All three work identically against a remote with `-r`, and over HTTP as
`list_cached=1` and `cached=<id>` (plus `get_meta=1`) — see
[usage.md](usage.md). A listing entry carries the ID, set, type, window
(`start_s`/`end_s`), when it was generated, `has_pcap`, and the filter,
final size, and generation time from the metadata.

## The metadata JSON

The `.json` is the full accounting of the search, and the same hash
`get_pcap_local` returns. The interesting keys...

| key                          | what                                                          |
|------------------------------|----------------------------------------------------------------|
| `filter`, `type`, `set`      | the question as resolved                                       |
| `start`/`start_s`, `end`/`end_s` | the window, stamp and epoch forms, padding not included     |
| `padding`                    | the padding that was applied around it                         |
| `pcaps`, `pcap_count`        | the PCAPs the window matched                                   |
| `failed`, `failed_count`     | the ones that could not be processed, path to reason           |
| `success_count`              | the ones that could                                            |
| `total_size`, `success_size`, `failed_size`, `tmp_size`, `final_size` | bytes in, bytes through, bytes out |
| `merge_error`                | the mergecap error if merging failed, else null                |
| `host_pruning`               | pruning stats when it ran — see [host-pruning.md](host-pruning.md) |
| `path`                       | where the result sits... null if nothing could be generated    |
| `cache_id`                   | the ID for refetching it... null if it bypassed the cache      |
| `req_start`, `req_end`, `req_time` | when the work ran and how many seconds it took           |
| `using_cache`                | whether this answer came from the cache                        |

A nonzero `failed_count` with a healthy `success_count` is normal life — the
newest PCAP in the window is often still being written to and fails
validation; the padding and the next rotation are why that traffic is not
lost. `merge_error` set, or `path` null, means the answer itself is suspect.

## Care and feeding

Virani never prunes the cache — every answer stays until something else
removes it. The cached PCAPs are carved traffic and exactly as sensitive as
the hoard they came from (see [security.md](security.md)), so treat the dir
accordingly and sweep it on whatever schedule fits...

```sh
# drop cached answers untouched for two weeks... their .json goes with them
find /var/cache/virani -maxdepth 1 -type f -atime +14 -delete
```

The `pcap_hosts/` subdirectory is the hosts index, not cached answers — it
prunes itself as PCAPs rotate away and is covered in
[host-pruning.md](host-pruning.md).
