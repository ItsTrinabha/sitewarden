# Bundled data

| File | Source | Licence |
|---|---|---|
| `sitewarden/data/hsts-preload.txt.gz` | Chromium `transport_security_state_static.json` (force-https entries only) | BSD-3-Clause (The Chromium Authors) |
| `sitewarden/data/public_suffix_list.dat.gz` | https://publicsuffix.org/list/ | MPL-2.0 |
| `sitewarden/data/mozilla-guidelines.json` | mozilla/ssl-config-generator, `guidelines/latest.json` (v6.0) | MPL-2.0 |
| `sitewarden/data/retirejs-repository.json` | RetireJS/retire.js `repository/jsrepository-v4.json` | Apache-2.0 |
| Root certificates | `certifi` (Mozilla CA store), installed as a dependency | MPL-2.0 |

`sitewarden update` refreshes all four data files into `~/.cache/sitewarden`, which takes precedence over the bundled copies.
