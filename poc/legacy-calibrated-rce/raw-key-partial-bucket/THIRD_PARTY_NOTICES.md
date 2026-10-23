# Third-party notices

The PHP request-lifecycle research and heap-layout work in this lab was
informed in part by:

- **PHP2Shell Full-Chain Exploit**, 78ResearchLab
- Repository: <https://github.com/78ResearchLab/PHP2Shell-Full-Chain-Exploit>
- Reviewed commit: `167085410a9342fafbd1bd64f5006920dbc83b8e`
- Reviewed `exploit.py` SHA-256:
  `6aadf7bc93b3f4f93b755fed727d3f017e806419c96853290cf2250e567c1323`
- License: MIT
- Copyright: Copyright (c) 2026 78ResearchLab

This PHP 7.3/7.4/8.0 partial-Bucket implementation is a separately written,
fixed-purpose local calibration harness. It does not copy an upstream source
file wholesale. The upstream MIT permission notice is retained in
`THIRD_PARTY_LICENSES/78ResearchLab-MIT.txt` so that any adapted portions
remain properly attributed.

Additional technical references used to understand the affected source path:

- Calif, **PHP2Shell**: <https://calif.io/php2shell/>
- PHP source commit introducing the raw-string optimization:
  <https://github.com/php/php-src/commit/6de54703f055231603816495c55e6e1924cb5e71>
- PHP 7.4 EOL-branch mitigation:
  <https://github.com/php/php-src/commit/712e60f9edfd03f0960fc4fc3c2c375f42b90aa2>
- PHP 8.0 EOL-branch mitigation:
  <https://github.com/php/php-src/commit/82f8f31b16a035c1b67cc253e79f7cc288f4cc20>

No source from the Calif article or the PHP commits is redistributed here.
The Docker runner references official container images by immutable digest and
does not redistribute their files in this repository.
