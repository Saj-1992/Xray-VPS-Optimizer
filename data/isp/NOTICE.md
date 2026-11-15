# Iranian ISP address ranges

The `*.ipv4` files in this directory are the IPv4 ranges used by the Iran ISP
blocker (Security -> Iran ISP blocker). One file per ISP, one range per line.

They originate from **Kiya6955/IR-ISP-Blocker**
(https://github.com/Kiya6955/IR-ISP-Blocker, snapshot `004954a`, 2024-11-08),
distributed under that project's license, reproduced in
[LICENSE.upstream](LICENSE.upstream). Its copyright and permission notice
applies to these files.

They are embedded into the built `server-tools.sh` so the blocker works with no
network access and no dependency on any other repository, and they are
refreshed by `.github/workflows/sync-isp.yml` (weekly) and by
`st isp update` on a server.

File names: `mci`, `mtn`, `tci`, `rightel`, `shatel`, `asiatech`, `pishgaman`,
`mobinnet`, `parsonline` (upstream calls the last one `parsan`).

## Layout

- `upstream/<id>.ipv4` — the Kiya6955/IR-ISP-Blocker lists, as published.
- `asn/<id>.ipv4` — IPv4 prefixes announced in BGP by the ISP's autonomous
  system (see `asn.map`; currently MCI = AS197207, Irancell = AS44244), from RIPEstat.
- `extra/<id>.ipv4` — ranges added by hand or taken from the RIPE database (one per line, `#` comments allowed). The sync never touches them.
- `<id>.ipv4` — the union of the two, produced by `tools/merge-isp.sh`. This is
  what the build embeds and what `st isp update` downloads. Do not edit it by hand.
- `<id>.ipv6` — IPv6 ranges for the ISPs that have them (currently MCI
  2a02:4540::/29 and Irancell 2a01:5ec0::/29, the RIR allocations, plus their
  BGP-announced prefixes).

## What counts as "MCI" or "Irancell"

A range is listed when the operator owns it (RIPE database: organisations
`ORG-MCCo2-RIPE` / `ORG-ICSa1-RIPE`, maintainers `MCCI-MNT` / `IRANCELL-MNT`) or
announces it in BGP (AS197207, AS44244). Space the operator owns but that
another listed ISP announces in BGP is left out of `extra/` on purpose, so that
blocking MCI does not also block that ISP's customers: Mobinnet (AS50810)
announces parts of 178.131.0.0/16, 37.98.112.0/21, 188.211.0.0/20,
188.212.240.0/21 and 188.213.192.0/22; TCI (AS58224) announces 185.115.76.0/23
and 185.115.78.0/24. Block those ISPs separately to cut them off too.
Unannounced (reserved, unused) space is kept.
