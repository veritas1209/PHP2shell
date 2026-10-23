# Third-party notices

The request lifecycle, leak sequence, and packed `r0` spray in `exploit.py`
are adapted in part from:

- **PHP2Shell Full-Chain Exploit**, 78ResearchLab
- Repository: <https://github.com/78ResearchLab/PHP2Shell-Full-Chain-Exploit>
- Reviewed commit: `167085410a9342fafbd1bd64f5006920dbc83b8e`
- Reviewed `exploit.py` SHA-256:
  `6aadf7bc93b3f4f93b755fed727d3f017e806419c96853290cf2250e567c1323`
- License: MIT
- Copyright: Copyright (c) 2026 78ResearchLab

The complete permission notice is retained in
`THIRD_PARTY_LICENSES/78ResearchLab-MIT.txt` and `LICENSE`.

The A1/B1/A2/B2 algorithm used by the pure-HTTP variant follows prior art in
the following no-license repository, reviewed at the listed commit:

- **php2shell-bypass-aslr-exp**, 9bie
- Repository: <https://github.com/9bie/php2shell-bypass-aslr-exp>
- Reviewed commit: `17e98ee81025cccfd94b4f9c9a17bf269c65ff75`
- License detected at review time: none

Its source files are not included in this release. The PHP 8.2 profile records
locally measured geometry, and a generic declarative renderer is checked
against the locally reproduced A1 request length and SHA-256.

