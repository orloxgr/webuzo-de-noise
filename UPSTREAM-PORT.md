# Hestia changes included in Webuzo 0.5.0

Compared the complete range from the previously recorded upstream base
`c8cc463f3f55d2f21e866b05b755c1193b41613d` (0.17.2) through
`25436f5ea919a625ebe626d8937eae8b8f79852b` (0.21.0), including the restored
manual append behavior in 0.20.3. Source: https://github.com/orloxgr/hestia-de-noise.

| Upstream change | Webuzo result |
| --- | --- |
| 0.18.0: five agent categories, bot descriptions, complete agent/PHP inventories, contextual findings, review notes/filters, pagination/All and complete CSV | Already present in Webuzo 0.4.3. Compared reusable implementations, including the catalog, descriptions, inventories, PHP findings and listing controls. Retained Webuzo webmail/log handling. |
| 0.18.1: Domains in General, Fail2ban navigation, PHP analyzer beside its list | Already present. Retained the requested removal of delegated domain automatic bans. |
| 0.18.2: toolbar descriptions and collapsible IP-ban sections | Added descriptions matching Webuzo actions and collapsible direct-probe, general-404, exceptions and status sections. |
| 0.18.3: standalone Hestia CLI installer progress/pretty output | Platform-specific. Webuzo installs through its native plugin manager and JSON lifecycle bridge, which remain unchanged. No standalone Hestia installer or deadline was introduced. |
| 0.19.0: custom endpoints and optional first-match IP bans | Added exact/native-PCRE rules, domain scope, Observe/Enforce, duration units, evidence and Activity labels. Uses the existing Webuzo website-ban backend and native Nginx validation/rollback. |
| 0.20.0: full non-image endpoint analysis and selected final-404 bans | Added inventories, actual-status counting, scope, grouped advice, filters/notes, complete CSV and fresh activation periods. Removed the path-search length cutoff. |
| 0.20.1: careful advice, individual exact-rule suggestions and responsive actions | Added advice distinct from manual actions and separate domain-scoped exact rules instead of an oversized generated regex. |
| 0.20.2: five Endpoints accordions, visible chevrons and keyboard behavior | Added with existing Webuzo form ownership and local styling. Append opens its destination section. |
| 0.20.3: restore manual append for every exact finding | Included. Recommendations never gate manual append. Mixed-status paths with a recorded 404 remain selectable for the 404 list. |
| 0.21.0: attempts/window, source reconciliation and explicit grouped selection | Included with Webuzo schema transitions, old-form preservation, selected-options-only append, no mutation for empty selections, and Ctrl help for every native multi-select. |

## Webuzo integration

- Discovery, account/domain ownership, include points, log formats and paths
  remain Webuzo-native. No Hestia CLI, directory dependency or firewall command
  is installed.
- Website bans remain in the owned, persisted Webuzo Nginx map, for IPv4 and
  IPv6. Hestia's volatile firewall-chain reboot repair is not applicable to this
  backend. Existing unban, expiry and ownership checks remain in use.
- Where discovery confirms a complete native access log, that log supplies the
  final status and structured 404 duplicates are discarded. Otherwise the shared
  reconciliation tracks multiplicities per source and counts their maximum.
  Without a common request ID, different requests that coincide in the same
  second/IP/domain/path/method bucket but exist only in different incomplete
  sources can be undercounted; the reconciliation does not claim perfect unique
  request identification.
- Webuzo schema 11 has no delegated domain bans or custom endpoints. Schema 12
  adds custom endpoints; schema 13 adds the complete selected-404 settings.
  Existing old panels preserve fields they did not render. New controls start
  disabled/empty, without adding protection rules automatically.
- De-Noise remains independent of the Varnish addon. Only native plugin extension
  points and owned configuration files are used; Webuzo core files are unchanged.

Validation and its scope are recorded in [FEATURES.md](FEATURES.md).
