# geo test fixtures

`GeoIP2-City-Test.mmdb` and `GeoLite2-Country-Test.mmdb` are the **fake, sample**
MaxMind DB test databases from the upstream
[`maxmind/MaxMind-DB`](https://github.com/maxmind/MaxMind-DB) repository
(`test-data/`). They contain *no real geolocation data* — only a handful of
synthetic records for example/test purposes.

They are vendored here so cadish's MaxMind `geo.Source` tests run hermetically
with no network and no operator-supplied database (cadish bundles no real DB; see
D11/D56 — the operator brings their own `.mmdb`).

**License:** the MaxMind-DB repository (including these test databases) is
Copyright (c) 2013-2026 MaxMind, Inc. and is dual-licensed under the
**Apache License, Version 2.0** OR the **MIT License**, at the user's option.
cadish is Apache-2.0 (D2), so these fixtures are carried under Apache-2.0 —
fully compatible. See https://github.com/maxmind/MaxMind-DB (LICENSE-APACHE /
LICENSE-MIT).

These are TEST DATA ONLY and are never compiled into or shipped with the cadish
binary.

## Records used by the tests (synthetic)

City edition (`GeoIP2-City-Test.mmdb`):

| IP | country | subdivision[0] | region token |
|---|---|---|---|
| `81.2.69.142` | GB | ENG | GB-ENG |
| `89.160.20.112` | SE | E | SE-E |
| `216.160.83.56` | US | WA | US-WA |
| `67.43.156.0` | BT | (none) | unknown |

Country edition (`GeoLite2-Country-Test.mmdb`): same countries, **no
subdivisions** (region always unknown); `175.16.199.0` (CN in the City DB) is
**absent** in the Country DB.
