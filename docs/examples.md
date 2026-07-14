# Examples

Worked scenarios to copy from. Paths assume the defaults; adjust to taste.
Mind [security.md](security.md) before any of these serve real traffic.

## daemonlogger on FreeBSD, searched locally

The classic pairing. daemonlogger writes timestamped PCAPs, Virani reads
them. In `/etc/rc.conf`...

```
daemonlogger_enable="YES"
daemonlogger_flags="-f /usr/local/etc/daemonlogger.bpf -d -l /var/log/daemonlogger -t 120"
```

`/usr/local/etc/virani.toml` — the default regex already fits
daemonlogger's names...

```toml
allowed_subnets = ["192.168.14.0/23", "127.0.0.1/8"]

[sets.default]
path = "/var/log/daemonlogger"
```

Then...

```shell
# a known two minutes around an event
virani -s 2026-07-13T11:00:18 -e 2026-07-13T11:02:18 port 53

# the last minute of DNS, relative times
virani -s now-1m -e now port 53

# one host's last hour, to a named file
virani -s now-1h -e now -w suspect.pcap host 192.168.14.42
```

## Reading a Lamashtu hoard

Lamashtu writes; Virani reads. Her `rotate = "secs"` sets stamp the epoch
into the name as `<set>.pcap-<epoch>`, so the set just needs the matching
regex...

```toml
default_set = "wan"

[sets.wan]
path  = "/var/log/lamashtu/pcap/wan"
regex = '\.pcap-(?<timestamp>\d+)$'
```

```shell
virani -s now-1h -e now port 53
```

A `rotate = "size"` Lamashtu set carries no timestamp in its names and can
not be searched by time — capture with `secs` or `both` on anything you
intend to hand to Virani.

## Everything in a window

An empty filter matches everything, so the matched PCAPs are merged whole —
the fastest way to hand a whole incident window to another tool...

```shell
virani -s 2026-07-13T03:10:00 -e 2026-07-13T03:25:00 -w incident.pcap -f ''
```

## When tcpdump can not see it... the tshark types

On a trunk port or an odd encapsulation, BPF quietly misses what tshark's
dissection catches. Same BPF, translated and run via tshark...

```shell
virani -t bpf2tshark -s now-10m -e now 'host 10.9.9.9 and port 443'
```

...or a native display filter for full control...

```shell
virani -t tshark -s now-10m -e now 'ip.addr == 10.9.9.9 && tls'
```

Both are significantly slower than tcpdump; setting `type` per set (see
[configuration.md](configuration.md)) reserves them for the hoards that
need them.

## A filter too big for a command line

`-f` pointing at a file reads the filter from it, comments and line breaks
stripped...

```shell
cat > watchlist.bpf <<'EOF'
# the watchlist, one clause per line
host 192.0.2.10 or
host 192.0.2.24 or   # the sketchy NAS
host 198.51.100.7
EOF
virani -s now-1h -e now -f watchlist.bpf
```

## Serving the hoard... mojo-virani at boot

On the sensor, from the source tree...

```shell
install -m 555 rc/freebsd/virani /usr/local/etc/rc.d/
sysrc virani_enable=YES
sysrc virani_flags="daemon -m production -l http://192.168.14.1:8080"
service virani start
```

With `allowed_subnets` in the sensor's `virani.toml` tightened to the
analyst hosts. To require a key as well...

```toml
auth_by_IP_only = false
apikey          = "wouldnotyouliketoknow"
```

## Asking from afar

Directly by URL...

```shell
virani -r http://192.168.14.1:8080/ -s now-1h -e now port 53
```

Or name the sensor once in `/usr/local/etc/virani.d/sensor1.toml`...

```toml
url    = "https://sensor1.example.com:8080/"
apikey = "wouldnotyouliketoknow"
```

...and thereafter...

```shell
virani -r sensor1 -s now-1h -e now port 53
virani -r sensor1 --list-sets
```

The PCAP lands in `out.pcap` (or `-w`), the metadata JSON prints, and the
answer stays cached on the sensor for the next asker.

## Asking the same question twice

The second ask is free — same set, type, window, and filter comes straight
from the cache...

```shell
virani -s 2026-07-13T03:10:00 -e 2026-07-13T03:25:00 host 192.0.2.10
virani --list-cached
virani --cached default-tcpdump-1752376200-1752377100-<md5> -w again.pcap
virani --nc -s 2026-07-13T03:10:00 -e 2026-07-13T03:25:00 host 192.0.2.10   # force a regen
```

The same works remotely with `-r sensor1` — see [cache.md](cache.md).

## Speeding up host hunts with the index

On the sensor, cron the indexer and enable the gate for the set...

```
# crontab... index new PCAPs every five minutes
*/5 * * * * virani -q --update-pcap-hosts --set wan
```

```toml
[sets.wan]
path         = "/var/log/lamashtu/pcap/wan"
regex        = '\.pcap-(?<timestamp>\d+)$'
host_pruning = true
```

Now `virani -s now-24h -e now host 192.0.2.10` only runs tcpdump over the
PCAPs that actually saw `192.0.2.10`, instead of a day's worth of hoard.
The metadata's `host_pruning` key shows what was skipped. Mind the caveats
in [host-pruning.md](host-pruning.md) before leaning on it.
