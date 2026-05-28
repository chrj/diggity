# diggity

A focused DNS health checker for one or more hostnames.

`diggity` walks the delegation chain, samples TTLs, validates the DNSSEC chain
of trust from the root, and compares answers across authoritative servers. It
tells you what is wrong in a single pass. It is not a `dig` replacement; it is
a verdict tool that returns **pass / warn / fail** for each check, with exit
codes you can for example drop into CI.

```
$ diggity cloudflare.com
cloudflare.com
├─ ✓ delegation   parent and child agree on 5 NS: ns3.cloudflare.com, ns4.cloudflare.com, ns5.cloudflare.com, ns6.cloudflare.com, ns7.cloudflare.com
├─ ✓ ttl          5 pass
│     ✓ SOA TTL 4m59s
│     ✓ NS TTL 24h0m0s
│     ✓ A TTL 3m11s
│     ✓ AAAA TTL 3m31s
│     ✓ MX TTL 18m33s
├─ ⚠ dnssec       3 pass, 1 warn
│     ✓ . root DNSKEY matches bundled trust anchor (key tag 20326)
│     ✓ com DS at parent matches DNSKEY (key tag 19718)
│     ✓ cloudflare.com DS at parent matches DNSKEY (key tag 2371)
│     ⚠ cloudflare.com SOA RRSIG expires in 25h0m0s (at 2026-05-29T11:46:00Z)
└─ ✓ consistency  4 pass
      ✓ all servers agree on SOA serial: 2405012788
      ✓ all servers agree on NS cloudflare.com: ns3.cloudflare.com., ns4.cloudflare.com., ns5.cloudflare.com., ns6.cloudflare.com., ns7.cloudflare.com.
      ✓ all servers agree on A cloudflare.com: 104.16.132.229, 104.16.133.229
      ✓ all servers agree on AAAA cloudflare.com: 2606:4700::6810:84e5, 2606:4700::6810:85e5

3 ✓ · 1 ⚠ · 0 ✗ · 0 ⊘
diggity: 127.0.0.53 refused DNSSEC queries; used 1.1.1.1, 8.8.8.8 instead (override with -r)
```

`diggity` can also trace its path through the chain of authority by optionally
specifying the `--trace` flag:

```
$ diggity --trace cloudflare.com
iterative walk for cloudflare.com:
   1. @a.root-servers.net (198.41.0.4:53)  rcode=NOERROR
        referral to com:
          - a.gtld-servers.net
          - b.gtld-servers.net
          - c.gtld-servers.net
          - d.gtld-servers.net
          - e.gtld-servers.net
          - f.gtld-servers.net
          - g.gtld-servers.net
          - h.gtld-servers.net
          - i.gtld-servers.net
          - j.gtld-servers.net
          - k.gtld-servers.net
          - l.gtld-servers.net
          - m.gtld-servers.net
          + a.gtld-servers.net A 192.5.6.30
          + a.gtld-servers.net AAAA 2001:503:a83e::2:30
          + b.gtld-servers.net A 192.33.14.30
          + b.gtld-servers.net AAAA 2001:503:231d::2:30
          + c.gtld-servers.net A 192.26.92.30
          + c.gtld-servers.net AAAA 2001:503:83eb::30
          + d.gtld-servers.net A 192.31.80.30
          + d.gtld-servers.net AAAA 2001:500:856e::30
          + e.gtld-servers.net A 192.12.94.30
          + e.gtld-servers.net AAAA 2001:502:1ca1::30
          + f.gtld-servers.net A 192.35.51.30
          + f.gtld-servers.net AAAA 2001:503:d414::30
          + g.gtld-servers.net A 192.42.93.30
          + g.gtld-servers.net AAAA 2001:503:eea3::30
          + h.gtld-servers.net A 192.54.112.30
          + h.gtld-servers.net AAAA 2001:502:8cc::30
          + i.gtld-servers.net A 192.43.172.30
          + i.gtld-servers.net AAAA 2001:503:39c1::30
          + j.gtld-servers.net A 192.48.79.30
          + j.gtld-servers.net AAAA 2001:502:7094::30
          + k.gtld-servers.net A 192.52.178.30
          + k.gtld-servers.net AAAA 2001:503:d2d::30
          + l.gtld-servers.net A 192.41.162.30
          + l.gtld-servers.net AAAA 2001:500:d937::30
          + m.gtld-servers.net A 192.55.83.30
          + m.gtld-servers.net AAAA 2001:501:b1f9::30
   2. @l.gtld-servers.net (192.41.162.30:53)  rcode=NOERROR
        referral to cloudflare.com:
          - ns3.cloudflare.com
          - ns4.cloudflare.com
          - ns5.cloudflare.com
          - ns6.cloudflare.com
          - ns7.cloudflare.com
          + ns3.cloudflare.com A 162.159.0.33
          + ns3.cloudflare.com A 162.159.7.226
          + ns3.cloudflare.com AAAA 2400:cb00:2049:1::a29f:21
          + ns3.cloudflare.com AAAA 2400:cb00:2049:1::a29f:7e2
          + ns4.cloudflare.com A 162.159.1.33
          + ns4.cloudflare.com A 162.159.8.55
          + ns4.cloudflare.com AAAA 2400:cb00:2049:1::a29f:121
          + ns4.cloudflare.com AAAA 2400:cb00:2049:1::a29f:837
          + ns5.cloudflare.com A 162.159.2.9
          + ns5.cloudflare.com A 162.159.9.55
          + ns5.cloudflare.com AAAA 2400:cb00:2049:1::a29f:209
          + ns5.cloudflare.com AAAA 2400:cb00:2049:1::a29f:937
          + ns6.cloudflare.com A 162.159.3.11
          + ns6.cloudflare.com A 162.159.5.6
          + ns6.cloudflare.com AAAA 2400:cb00:2049:1::a29f:30b
          + ns6.cloudflare.com AAAA 2400:cb00:2049:1::a29f:506
          + ns7.cloudflare.com A 162.159.4.8
          + ns7.cloudflare.com A 162.159.6.6
          + ns7.cloudflare.com AAAA 2400:cb00:2049:1::a29f:408
          + ns7.cloudflare.com AAAA 2400:cb00:2049:1::a29f:606
   3. @ns3.cloudflare.com (162.159.0.33:53)  rcode=NOERROR  AA
        NS cloudflare.com:
          - ns3.cloudflare.com
          - ns4.cloudflare.com
          - ns5.cloudflare.com
          - ns6.cloudflare.com
          - ns7.cloudflare.com
          + ns3.cloudflare.com A 162.159.0.33
          + ns3.cloudflare.com A 162.159.7.226
          + ns3.cloudflare.com AAAA 2400:cb00:2049:1::a29f:21
          + ns3.cloudflare.com AAAA 2400:cb00:2049:1::a29f:7e2
          + ns4.cloudflare.com A 162.159.1.33
          + ns4.cloudflare.com A 162.159.8.55
          + ns4.cloudflare.com AAAA 2400:cb00:2049:1::a29f:121
          + ns4.cloudflare.com AAAA 2400:cb00:2049:1::a29f:837
          + ns6.cloudflare.com AAAA 2400:cb00:2049:1::a29f:30b
          + ns6.cloudflare.com AAAA 2400:cb00:2049:1::a29f:506
          + ns7.cloudflare.com AAAA 2400:cb00:2049:1::a29f:408
          + ns7.cloudflare.com AAAA 2400:cb00:2049:1::a29f:606

cloudflare.com
├─ ✓ delegation   parent and child agree on 5 NS: ns3.cloudflare.com, ns4.cloudflare.com, ns5.cloudflare.com, ns6.cloudflare.com, ns7.cloudflare.com
├─ ⚠ ttl          4 pass, 1 warn
│     ✓ SOA TTL 4m59s
│     ✓ NS TTL 1h39m58s
│     ✓ A TTL 2m36s
│     ✓ AAAA TTL 1m54s
│     ⚠ MX TTL 25s below ttl-min 1m0s
├─ ⚠ dnssec       3 pass, 1 warn
│     ✓ . root DNSKEY matches bundled trust anchor (key tag 20326)
│     ✓ com DS at parent matches DNSKEY (key tag 19718)
│     ✓ cloudflare.com DS at parent matches DNSKEY (key tag 2371)
│     ⚠ cloudflare.com SOA RRSIG expires in 25h0m0s (at 2026-05-29T12:06:02Z)
└─ ✓ consistency  4 pass
      ✓ all servers agree on SOA serial: 2405012788
      ✓ all servers agree on NS cloudflare.com: ns3.cloudflare.com., ns4.cloudflare.com., ns5.cloudflare.com., ns6.cloudflare.com., ns7.cloudflare.com.
      ✓ all servers agree on A cloudflare.com: 104.16.132.229, 104.16.133.229
      ✓ all servers agree on AAAA cloudflare.com: 2606:4700::6810:84e5, 2606:4700::6810:85e5

2 ✓ · 2 ⚠ · 0 ✗ · 0 ⊘
diggity: 127.0.0.53 refused DNSSEC queries; used 1.1.1.1, 8.8.8.8 instead (override with -r)
```

## What it checks

| Check          | What it verifies                                                                 |
| -------------- | -------------------------------------------------------------------------------- |
| `delegation`   | Parent vs. child NS sets agree, glue is present, every NS responds authoritatively |
| `ttl`          | TTLs for SOA / NS / A / AAAA / MX (and any `-t` extras) fall within sane bounds  |
| `dnssec`       | DNSKEY / DS / RRSIG chain validates from the zone up to the bundled root KSK     |
| `consistency`  | Every authoritative server returns the same SOA serial and matching record sets  |

Any check can be skipped with `--no-delegation`, `--no-ttl`, `--no-dnssec`,
or `--no-consistency`.

## Install

```sh
go install github.com/chrj/diggity@latest
```

Or build from source:

```sh
git clone https://github.com/chrj/diggity
cd diggity
go build .
```

The root KSK is bundled into the binary, so DNSSEC validation works on minimal
hosts with no `/usr/share/dns/root.key`.

## Usage

```
diggity [flags] <hostname>...
```

A few common patterns:

```sh
# Check a single hostname against the system resolver
diggity example.com

# Multiple hostnames, skipping DNSSEC
diggity --no-dnssec example.com sub.example.com

# Trace the iterative walk from the root, printing every hop to stderr
diggity --trace example.com

# Pin to specific resolvers
diggity -r 1.1.1.1 -r 8.8.8.8 example.com

# Machine-readable output, piped through jq
diggity -o json example.com | jq '.results[] | select(.status!="pass")'
```

### Output formats

`-o text` (default), `json`, `ndjson`, or `sarif`. SARIF makes `diggity`
droppable into GitHub code-scanning and other security dashboards.

### Exit codes

| Code | Meaning                                       |
| ---: | --------------------------------------------- |
|  `0` | all checks passed                             |
|  `1` | warnings only                                 |
|  `2` | one or more checks failed                     |
|  `3` | usage error                                   |
|  `4` | network / resolver error before any check ran |

## Flags

```
      --no-delegation          skip the delegation check
      --no-ttl                 skip the TTL check
      --no-dnssec              skip the DNSSEC check
      --no-consistency         skip the authoritative-consistency check

  -r, --resolver strings       resolver address (repeatable; default: system)
      --trace                  iterative walk from the root; print every hop
  -4, --ipv4                   restrict to IPv4 transport
  -6, --ipv6                   restrict to IPv6 transport
      --tcp                    force TCP
      --timeout duration       per-query timeout (default 3s)
      --retries int            retries per query (default 2)
  -t, --type strings           extra record type(s) to sample (repeatable)

  -o, --output string          output format: text | json | ndjson | sarif
  -q, --quiet                  only print failures
      --no-color               disable ANSI colour
      --ttl-min duration       warn below this TTL (default 1m)
      --ttl-max duration       warn above this TTL (default 24h)
      --expiry-warn duration   warn if any RRSIG expires within this window (default 72h)

  -V, --version                show version
```

## CI example

```yaml
- name: DNS health
  run: diggity -o sarif example.com > diggity.sarif
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: diggity.sarif
```

Non-zero exit codes fail the step naturally; SARIF surfaces the per-check
findings in the GitHub Security tab.

## Scope

`diggity` deliberately stays narrow. CAA, SPF / DMARC / DKIM, reverse DNS, and
mail-flow checks are **not** in scope — there are good single-purpose tools for
each of those, and bundling them here would dilute what `diggity` is for.

## License

MIT.
