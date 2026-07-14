# Virani documentation

Virani is the dark one — the reader of the LilithSec household. She does not
watch the wire and she keeps nothing of her own; she descends into the hoard
that [Lamashtu](https://github.com/LilithSec/Lamashtu) (or
[daemonlogger](https://github.com/Cisco-Talos/Daemonlogger), or any full
packet capture writing timestamped PCAPs) leaves on disk, and comes back with
exactly what was asked for.

In the world above she is a PCAP fetcher: given a span of time and a filter,
she finds the PCAP files whose filename timestamps overlap the window, carves
the matching packets out of each with tcpdump or tshark, merges the pieces
with mergecap, and hands back one distilled capture plus a JSON accounting of
how it was made. Asked from the same box that holds the PCAPs, the `virani`
CLI does it directly; asked from afar, `mojo-virani` serves the same searches
over HTTP, with the CLI or `Virani::Client` on the far end. Every answer is
cached, so asking the same question twice only costs once.

She serves the whole household.
[Baphomet](https://github.com/LilithSec/Baphomet) accuses,
[Ereshkigal](https://github.com/LilithSec/Ereshkigal) punishes,
[Lamashtu](https://github.com/LilithSec/Lamashtu) remembers, and
[Lilith](https://github.com/LilithSec/Lilith) knows — and when Lilith wants
the packets behind an alert in her annals, it is Virani she sends to fetch
them. See [architecture](architecture.md) for how she relates.

- [architecture](architecture.md) :: the one library and its two faces,
  how a time window becomes a capture, the filter types, and where Virani
  sits in the pantheon

- [install](install.md) :: dependencies in detail, per-OS install, and
  running mojo-virani at boot

- [configuration](configuration.md) :: the `virani.toml` reference, sets
  and their timestamp regexes, and the remote configs under `virani.d/`

- [usage](usage.md) :: the `virani` CLI, time formats, remote fetching,
  and the mojo-virani HTTP parameters

- [cache](cache.md) :: cached searches — the cache IDs, the metadata
  JSON, and listing and refetching past answers

- [host-pruning](host-pruning.md) :: the PCAP hosts index and how it lets
  host filters skip PCAPs that can not possibly match

- [security](security.md) :: the heavy part — the hoard is raw traffic,
  and mojo-virani is a window onto it

- [examples](examples.md) :: copy-paste scenarios

Also...

- [Virani](https://metacpan.org/pod/Virani)
- [Virani::Client](https://metacpan.org/pod/Virani::Client)
- [virani](https://metacpan.org/dist/Virani/view/bin/virani)
- [mojo-virani](https://metacpan.org/dist/Virani/view/bin/mojo-virani)
