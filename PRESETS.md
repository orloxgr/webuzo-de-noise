# Presets — Webuzo 0.6.0

Suggestions are optional. Each purpose category has an independent blocklist,
a shared group-rate list and individual rate rules. Append buttons target their
own editor and preserve live manual edits and enable switches. Review the result,
then Save & Apply; no button saves settings or enables protection automatically.

Individual rules override group limits, which override blocklists across all
categories. Website budgets span all protected sites, aliases and client IPs;
Observe uses separate counters and Off does not count. Rate fields start empty
and inactive. Shared EMPS webmail keeps its existing separate block/private-file
protection and does not participate in website rate budgets.

Names are literal case-insensitive substrings and never verified identities.
The following are the complete optional bulk suggestions in `src/agent_catalog.py`.

## Scanner tools

Security scanners and testing tools, including tools used for authorized audits.

**Add suggested agents**:

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
l9scan
ModatScanner
```

## AI Training Crawlers

Content collection for AI model development and training, including general-purpose datasets used for AI. Common Crawl and Velen also support research or business uses; this category does not imply exclusive AI use.

**Add suggested agents**:

```text
meta-externalagent
ClaudeBot
GPTBot
Reflectionbot
Amazonbot
Bytespider
ElevenlabsCrawler
CCBot
VelenPublicWebCrawler
RiverBot
PostHogImageFetcherBot
```

## Search Indexers

Search and AI search indexing. Blocking these crawlers can reduce visibility in their services.

**Add additional search bots**:

```text
PetalBot
Baiduspider
ibou-search
Owler
SeekportBot
YandexBot
MojeekBot
IbouBot
360Spider
YisouSpider
ZoominfoBot
ShapBot
KeenableBot
SeznamBot
SofyaBot
Qwantbot
Sogou web spider
Sogou Pic Spider
```

**Add major search & AI bots**:

```text
Googlebot
Googlebot-Image
Googlebot-News
Googlebot-Video
bingbot
Applebot
DuckDuckBot
DuckAssistBot
meta-webindexer
OAI-SearchBot
Claude-SearchBot
Amzn-SearchBot
PerplexityBot
ExaSearchBot
ExaSearchBot-Images
LinkupBot
```

## SEO & Backlink Crawlers

SEO analysis and backlink indexes. Some also feed search engines; AhrefsBot powers Yep as well as Ahrefs tools.

**Add suggested agents**:

```text
MJ12bot
AhrefsBot
SemrushBot
DotBot
BLEXBot
SERankingBacklinksBot
DataForSeoBot
Barkrowler
serpstatbot
SearchAtlasBot
LinkpadBot
Screaming Frog SEO Spider
MegaIndex.ru
SeobilityBot
SEOkicks-Robot
rogerbot
```

## Data Collection / Monitoring / Various

Research, image collection, brand monitoring and threat intelligence. Various contains generic automation and unconfirmed declarations for individual selection; these names do not establish malicious use.

**Add Data Collection**:

```text
GoogleOther
ImagesiftBot
webXtrendBot
KStandBot
```

**Add Monitoring**:

```text
AwarioBot
Magpie-Crawler
RecordedFuture
```

**Add Various…** opens a finite per-name selector with descriptions and available
source links. Initially no choices are checked; there is no select-all action.
Only checked names append to the chosen block/group editor. Closing retains the
selection. These names are absent from every bulk preset:

Generic automation: HeadlessChrome, Python-urllib, python-requests, curl, httpx, Go-http-client, quic-go, Amazon Web Services.

Unconfirmed purpose/operator: BacklinksExtendedBot, Timpibot, CMS-Checker, AionBot, Epochal-Search, BasegrowBot, FontScanBot, EchoGreyBot, CrolBot, SeltzSitemapFetcher, Bravebot, YouBot, cohere-ai, DeepSeekBot, Kimi-SearchBot, KimiBot, MoonshotBot, GrokBot, AzureAI-SearchBot, Qwenbot.

WP-Safe-Scanner and wp-cve-2026-87902-validator are recognized declarations for
individual scanner review, without a verified operator, claimed checks or CVE.
Named fetch clients, ad checks and social previews remain outside bulk/Various.
HeadlessChrome is generic automation; Bravebot is not confirmed as Brave Search.

**Append analyzed agents** reads recognized names actually present in the entire
completed report, including recognized generic/unconfirmed clients. Unknown
browser/application declarations stay individually selectable in the results.
Specific recognized bot tokens precede generic libraries/renderers when grouping
new observations; image/news/fetch products remain separate. Saved literal
matching, lists and switches are unchanged by catalog updates.

Purpose documentation: [River](https://river.ai/bot),
[PostHog](https://posthog.com/docs/ai-research/image-fetcher-bot),
[Keenable](https://app.keenable.ai/bot), [Sofya](https://sofya.co/bot),
[Seznam](https://o-seznam.cz/napoveda/vyhledavani/en/seznambot-crawler/),
[Qwant](https://help.qwant.com/bot), [Sogou](https://www.sogou.com/docs/help/webmasters.htm),
[LeakIX](https://docs.leakix.net/docs/api/domain/), [Modat](https://scanner.modat.io/),
[webXtrend](https://webxtrend.com/crawler),
[KStand](https://url-classification.io/wiki/index.php/Website_classification_crawler),
[Chrome automation](https://developer.chrome.com/docs/automation-and-testing/headless)
and [Brave's crawler declaration](https://search.brave.com/help/brave-search-crawler).

**Analyze current agents** counts retained log requests. Append individual rows
or recognized names from the completed report to the chosen unsaved list, then review
and **Save & Apply**. Appending never enables a category. The current complete suggestion catalog is
`src/agent_catalog.py`; lists below illustrate the purposes. ShapBot belongs to
Search Indexers (additional search), as documented by
[Parallel](https://parallel.ai/parallel-web-systems-bots). Unknown/browser-like
declarations are not automatically classified as malicious.

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
