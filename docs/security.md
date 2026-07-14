# Security considerations

Virani reads raw traffic and, through mojo-virani, serves it over HTTP. She
keeps no hoard of her own, but everything said about the hoard's
sensitivity in the household's other docs applies with full force to what
she carves out of it. Read this before the HTTP face listens anywhere real.

## What she reads and returns is raw traffic

A carved PCAP is packet headers and payloads both — credentials, session
tokens, cookies, and personal data in the clear, unless the traffic itself
was encrypted end to end. Consequences...

- **Local `virani` access is hoard access.** Anyone who can run a search
  against a set path can extract anything in it. The read permission on the
  set path is the actual access control; do not widen it casually.
- **The cache is a second hoard.** `/var/cache/virani` accumulates the
  carved results of every past search, plus metadata naming the filters and
  windows people cared about. Guard it like the set paths, and remember it
  never prunes itself — see [cache](cache.md).
- **The hosts index is a map.** `pcap_hosts/` lists every IP endpoint seen
  per PCAP — far less than the packets, but a tidy reconnaissance summary
  of your network all the same.

## mojo-virani is a window onto the hoard

The HTTP face runs every search its config allows and returns the packets
to whoever asks acceptably. Its gate has two bars...

- **The IP allow-list, always.** `allowed_subnets` is checked on every
  request. The default covers RFC 1918 space and loopback — tighten it to
  the actual analyst hosts before real use.
- **The API key, only if you turn it on.** `auth_by_IP_only` defaults to
  *true*, meaning the `apikey` config is ignored and an IP match is the
  whole gate. Set `auth_by_IP_only = false` and an `apikey` to require
  both.

Prefer not exposing it off-host at all: bind loopback and let analysts in
over SSH or a VPN. Where it must listen wider, keep the subnets tight, use
a key, and put TLS in front — mojo-virani itself speaks plain HTTP unless
you hand Mojolicious certs (`-l 'https://...?cert=...&key=...'`), and
without TLS the packets, and the API key with them, cross the network in
the clear.

Two sharp edges to know about...

- **The key travels in the query string.** Query strings land in access
  logs and proxy logs. TLS keeps it off the wire, but treat any log of the
  URL as containing the key.
- **Reverse proxies defeat the IP check.** The allow-list sees the address
  of whoever connected — behind a proxy, that is the proxy, for every
  client it forwards. Do not front mojo-virani with a proxy whose IP is in
  `allowed_subnets` and call the list an access control; if a proxy is
  unavoidable, make the key mandatory.

There is no rate limiting and a search is expensive by design — tcpdump
across a window of a busy hoard is real CPU and IO. Anyone inside the gate
can keep the box busy. One more reason the gate should be small.

## The filter is handled carefully, but it is still a filter

Filters are passed to tcpdump/tshark/mergecap in list form — no shell is
ever involved — and a filter beginning with `-` is refused outright, so a
remote filter can not become switches or a command. What remains is that
the filter decides what traffic comes back, and within the gate that is the
point: there is no finer-grained authorization than the gate itself. Cache
IDs fetched via `cached=` are validated against a strict pattern before
touching the filesystem, so they can not traverse outside the cache dir.

## Whose privileges she runs with

Virani only ever needs **read** on the set paths and **write** on the cache
dir. The shipped FreeBSD rc script runs mojo-virani as `www` — a sensible
shape: not root, no capture privilege, nothing writable but the cache. Give
the user reading rights via group membership on the hoard rather than
loosening the hoard itself, and remember that whatever can read the config
can read the API key, so keep `virani.toml` unreadable to bystanders. The
`virani.d/` remote configs on analyst machines hold keys too, and deserve
the same.

## Capture has consequences

The packets Virani serves were recorded off a network, with all the legal,
regulatory, and policy weight that carries — wiretap and privacy law,
PCI/HIPAA/GDPR-style regimes, your organization's own rules. Making the
hoard *searchable and fetchable over HTTP* widens who can effectively read
it; make that call knowingly, and with authorization, before the window
opens.
