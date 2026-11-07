# Presets

## Scanner tools

**User-Agents → Add scanner tools** inserts these literal names into the
Scanner tools box, which has its own enable switch:

```text
TLM-Audit-Scanner
sqlmap
Nikto
Nuclei
zgrab
masscan
ZmEu
DirBuster
gobuster
ffuf
WPScan
CensysInspect
Expanse
Palo Alto Networks
```

These are scanning tools; authorized scans can use them too. The list matches
declared names and is not identity verification.

## AI training, search, SEO and other crawlers

Each **User-Agents** box has its own enable switch and **Add suggested agents**
button. The buttons append suggestions to unsaved text; Save & Apply is required.

| List | Suggested names |
| --- | --- |
| AI Training Crawlers | meta-externalagent, ClaudeBot, GPTBot, Reflectionbot, Amazonbot |
| Search Indexers | LinkupBot, meta-webindexer, PetalBot, Baiduspider, ibou-search |
| SEO & Backlink Crawlers | MJ12bot, AhrefsBot, SemrushBot, DotBot, BLEXBot, SERankingBacklinksBot |
| Other Crawlers / Data Collection | GoogleOther, Bytespider, YisouSpider, ElevenlabsCrawler, CCBot |

These names describe declared purposes, not maliciousness or verified identity.
Some crawlers serve several products. AhrefsBot also supplies Yep, and Amazonbot
has mixed product and potential AI-training uses. GoogleOther is a generic
research/product crawler and is kept outside the AI training group.

**Analyze current agents** additionally recognizes Baiduspider render/image/mobile/video,
Googlebot image/news/video, PerplexityBot, ExaSearchBot and DuckAssistBot as search
crawlers. CensysInspect and Palo Alto Networks declarations are classified as scanners.
Versions of each product combine; image/render products remain separate so appending
one does not silently select the parent crawler. Social previews, user-requested
fetchers, application clients and unrecognized browser strings stay under Other.
That placement is not a recommendation to block them.

Googlebot, Bingbot, Applebot, PerplexityBot, ExaSearchBot, DuckAssistBot, social-preview
and user-requested retrieval agents are recognized without being added to default
block suggestions. Existing saved lists and switches are not updated automatically.
Run a new analysis after upgrading to apply the current catalog to new results.

Crawler documentation: [Exa](https://crawler.exa.ai/),
[Perplexity](https://docs.perplexity.ai/docs/resources/perplexity-crawlers),
[DuckAssistBot](https://duckduckgo.com/duckduckgo-help-pages/results/duckassistbot),
[Censys](https://docs.censys.com/docs/opt-out-of-data-collection),
[Palo Alto Networks](https://cortex-docs.paloaltonetworks.com/cortex-xpanse/reference/scanning-activity.md).

**Add optional search crawlers** separately suggests `LinkupBot`,
`meta-webindexer`, `PetalBot`, `Baiduspider` and `ibou-search`. Review before saving: blocking
these names can reduce visibility in their services. Suggestions do not change
existing blocklists automatically.

For a narrower policy, use **Filtered URLs → Add optional search crawlers to
this rule**. This adds the same names to that rule only and preserves its
domains, action, rate, switch and other names. It does not create a global
User-Agent block. Review and Save & Apply.

## Paths and request budgets

The optional **IP bans** module has separate switches for secret/config-file
and repository probes. It defaults to one matching request and permanent duration
when enabled. Its two separate 404 groups default to 2 strikes in 60 seconds
and a 3-day ban. PHP strikes require distinct selected nonexistent paths;
query strikes require selected parameters and explicit secret-target matches.
The complete editable PHP list is [src/php-probes.txt](src/php-probes.txt).
It contains 265 literal paths. Version 0.11.0 adds 46 missing-file probe
suggestions; exact prior bundled lists expand automatically, while edited lists
stay unchanged. Existing files, domain exceptions and configured ban thresholds
retain their behavior.
The separate optional general 404 rule defaults to 10 responses within 300
seconds and a 3-day ban. Missing images, CSS, JS, maps, fonts, media and PDF files
are excluded by default, and at least 3 different URL paths must be requested.
Both controls are editable. Repeated URLs count toward the request threshold;
query strings do not create different paths. Explicit security probes use their
own counter. User-Agent blocks and exceeded crawler/login budgets do not count
as 404s. The counting window, duration,
trigger domains and never-ban networks are editable in the panel.

| Module | Match | Action in Enforce |
| --- | --- | --- |
| WordPress login | POST `/wp-login.php`, including normalized trailing slash | 5/minute/client/domain, burst 3 by default; editable |
| XML-RPC | POST `/xmlrpc.php`, including normalized trailing slash | 10/minute/client/domain, burst 3 by default; editable |
| Private files | `.env`, `.git`, `.svn`, `.hg`, selected `wp-config.php` backup extensions, `.htpasswd`, `.DS_Store` | 403 |
| Credentials | Selected `.aws`, `.docker`, `.kube`, `.terraform`, `/var/run/secrets/kubernetes.io/serviceaccount/` paths | 403 |
| Operating-system probes | `/proc/self/environ`, numeric-process equivalents, `cmdline`, `/etc/passwd`, `/etc/shadow`, `/etc/gshadow` | 403 |
| Filtered URL crawling | Selected path + any selected parameter name + selected crawler name + domain scope | Editable limit per crawler/domain across IPs, or explicit 403 |
| Missing static files | Selected directory + extension, GET/HEAD, file does not exist | 404; existing files retain their routing |

Private paths are matched against Nginx's normalized URI, independently of the
declared User-Agent. Ordinary `/api`, `/config`, `/.well-known`, AJAX, REST and
public pages are not generally blocked. There is no blanket browser/bot rule.

## Filtered URL examples

Filtered-URL suggestions now come from **Analyze logs** for selected domains,
not application-specific insertion presets. Older saved rules remain unchanged.
The following are examples, not recommended universal rules or thresholds:

| Listing type | Path | Parameter names |
| --- | --- | --- |
| Product listing | `/shop/` | `min_price`, `max_price`, `orderby`, `filter_color`, `filter_size` |
| Directory listing | `/directory/` | `listing_tag`, `listing_category`, `listing_distance` |
| Localized listings using the same parameters | `/` on selected domains | The exact parameter names used by that application |

The add-rule form starts disabled with no preselected parameter names, crawler
names or rate. Choose these deliberately after reviewing the site and log sample.
An enabled rule limits only the configured filter combinations; ordinary indexable pages
remain outside that rule. No query values or URLs are rewritten, and no
`robots.txt`, sitemap or canonical setting is changed.

Each filter rule also has **Preview robots.txt suggestions** and a copy control.
These generate Disallow directives from its path prefix and parameter names,
with the selected domain scope shown beside the preview. Use them only if those
filtered URLs should stay out of search. Merge into the appropriate existing
User-agent groups, including any more-specific crawler groups; these directives
are not a complete robots.txt file. The preview neither saves a rule nor writes
any domain file. Fix malformed internal language links in the originating site
rather than applying a global URL rewrite across unrelated domains.

Google's [faceted navigation guidance](https://developers.google.com/crawling/docs/faceted-navigation)
explains when preventing crawling can save resources and when filtered URLs
should remain discoverable. Do not disallow filters needed for indexing.

Aliases use the canonical domain's budget. Different crawlers and domains have
independent budgets. Multiple rules can apply; all applicable limits must pass.

## Missing static files

| Panel preset | Directories | Extensions |
| --- | --- | --- |
| WordPress source maps | `/wp-content/` | `map` |
| WordPress JS / CSS | `/wp-content/plugins/`, `/wp-content/themes/`, `/wp-includes/` | `js css map` |

The JS/CSS button inserts three editable rules. **Add rule** creates a custom
rule, initially `/wp-content/` with extension `map`. Nothing is saved until
**Save & Apply**. Repeated preset clicks preserve matching existing rules,
including their switches and domain selection. Observe records candidates and
allows them; Off disables them.

**File exceptions by domain** accepts one exact URL path per line. A listed
file follows normal routing on that domain and its aliases, regardless of query
string, across every static rule. It does not bypass other De-Noise modules.

All rules are bundled and editable. There is no automatic external deny-list
import or application/plugin detection.
