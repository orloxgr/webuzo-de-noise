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

Webuzo 0.5.1 additionally introduces the independently requested per-site
**Disable XML-RPC** control. Its schema 14 preserves the schema 13 endpoint
settings and old-panel submissions; this addition is not attributed to the
Hestia 0.21.0 upstream commit.

## Webuzo 0.5.2

Compared the subsequent upstream changes through
`a0542c3c360a5e22d180e0f3565d199520d94343` (Hestia 0.23.1).
Hestia 0.22.0 contains the per-site XML-RPC block already present in Webuzo 0.5.1.
Ported 0.23.0's per-site IPv4/IPv6/CIDR exceptions and 0.23.1's on-demand
**Allow Jetpack** action. Nginx maps use Webuzo's canonical `$hdn_site` identity,
including aliases hosted in separate native virtual hosts, and its existing
authenticated panel/CSRF/wexec transport. Native website bans remain in force.

Additionally, the requested **Global** row has its own scope checkbox, IP/CIDR
editor and **Allow Jetpack** button. It covers newly discovered sites without
adding their names to the saved selection. Global exceptions and each site's
additional exceptions affect only XML-RPC blocking. Schema 15 preserves existing
site selections and settings; older open panels retain the global and exception
fields they did not render. Hestia's delegated domain-ban feature remains absent.

## Webuzo 0.5.3

Compared all subsequent upstream commits through
`431eca09a79c425b32075aeaaf1c979e5a26c9c9` (Hestia 0.25.1).
Hestia 0.24.0's global XML-RPC exception box is already present in Webuzo 0.5.2,
including the explicitly requested Global scope checkbox and future-site support;
that Webuzo behavior is retained without importing Hestia's policy migration.

Ported 0.25.0's expanded crawler catalog, descriptions and two optional Search
append groups, together with 0.25.1's purpose corrections. Bytespider,
ElevenlabsCrawler, CCBot and VelenPublicWebCrawler are suggested under AI Training;
YisouSpider and ZoominfoBot under additional search. The fifth editor is called
Data Collection / Monitoring. Unconfirmed names and generic clients are recognized
for individual review but excluded from bulk suggestions.

The Webuzo snapshot keeps its native nested presets structure and administrator
visibility. Existing list values, independent enable switches and effective
blocking are preserved; this release adds no policy schema or migration.

## Webuzo 0.6.0

Compared both subsequent commits from `431eca09a79c425b32075aeaaf1c979e5a26c9c9`
through `30129e9c21955c82886d8330bfe10659be04ab60` (Hestia 0.26.1):
`42066603bd9b0b06485acad6c32edc5d26ed5c81` adds server-wide agent limits;
`30129e9c21955c82886d8330bfe10659be04ab60` refines suggestions and Various review.

- Reused the portable rate validation/maps, catalog, purpose descriptions and
  destination-specific editor behavior. Individual > group > blocklist applies
  across all categories; longest substring and stable lexical ties select one
  rate budget. Observe/Enforce counters are separate and Off has an empty key.
- Webuzo schema 15 upgrades to schema 16 with empty, disabled rate settings.
  Existing settings and old open form submissions retain saved choices. The
  existing administrator-only native PHP/CSRF/wexec bridge, Nginx candidate test,
  confirmed reload and journaled rollback/recovery remain in use.
- Five full-width category accordions include block/group editors and individual
  tables. The analyzer accordion preserves its form/report. Data Collection and
  Monitoring append separately; Various is a finite unchecked per-name selector.
  The stored `agents` category and its one group budget remain unchanged.
- Activity records and complete filtered CSV retain the overall native limiter
  result, without attributing an independent rejection to a particular zone.
  Previous reports display Not recorded for unavailable rate results.
- Website budgets span Webuzo's website Nginx instance, including aliases and
  client IPs. Shared webmail uses a separate native EMPS Nginx instance, so its
  existing optional blocklists/private-file protection remain independent.
  No extra service, cross-instance counter helper or Hestia integration is added.
- No Hestia CLI, paths, firewall/domain-ban backend, vendor source, generated
  virtual host or distributed template is imported or edited.

Validation and its limits are recorded in [FEATURES.md](FEATURES.md).
