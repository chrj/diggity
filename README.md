# diggity

A focused DNS health checker for one or more hostnames.

`diggity` walks the delegation chain, samples TTLs, validates the DNSSEC chain
of trust from the root, and compares answers across authoritative servers — and
tells you what is wrong in a single pass. It is not a `dig` replacement; it is
a verdict tool that returns **pass / warn / fail** for each check, with exit
codes you can drop into CI.

```
$ ./diggity cloudflare.com
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
