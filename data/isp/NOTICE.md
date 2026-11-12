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
  system (see `asn.map`; currently MCI = AS197207), from RIPEstat.
- `extra/<id>.ipv4` — ranges added by hand (one per line). The sync never touches them.
- `<id>.ipv4` — the union of the two, produced by `tools/merge-isp.sh`. This is
  what the build embeds and what `st isp update` downloads. Do not edit it by hand.
