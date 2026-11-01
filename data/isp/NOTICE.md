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
