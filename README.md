# Webuzo De-Noise

Request filtering in Nginx before requests reach Apache or PHP, with per-domain
controls and traffic analysis inside the Webuzo panel.

This project ports [Hestia De-Noise](https://github.com/orloxgr/hestia-de-noise)
to Webuzo.

## Features

- Five independent User-Agent lists: scanner tools, AI training crawlers, search
  indexers, SEO/backlink crawlers and Data Collection / Monitoring / Various.
  Search has separate **Add additional search bots** and **Add major search & AI
  bots** buttons. Both append to the same blocklist, preserve manual entries and
  skip duplicates; they do not save settings or enable a list. Blocking major
  search and AI crawlers can reduce search visibility and citations.
  The catalog explains operator, purpose and usefulness. Generic HTTP libraries
  and names with an unconfirmed purpose remain individually reviewable rather
  than becoming bulk suggestions.
- Private-file protection, login/XML-RPC limits, filtered-URL budgets and
  missing-static-file rules.
- Global or per-site XML-RPC blocking, IP/CIDR exceptions and Allow Jetpack.
- Custom exact-path or native PCRE endpoint rules, with optional website IP bans.
- Selected-path bans after a configurable number of real final HTTP 404s.
- Endpoint log analysis with grouped advice, individual path selection and CSV.
- On-demand agent hit counts and PHP-path 404 counts by domain and time window,
  with selectable append to the editable lists.
- Global website IP bans, with editable thresholds,
  durations, exclusions, evidence, history and unban controls.
- Optional WordPress user-enumeration protection and failed-login bans.
- HTTP webmail protection, on-demand activity/log analysis, crawler verification
  and robots.txt previews.
- Native cron schedule preview/apply/restore, bulk domain modes and account views
  restricted to the account's own domains.

Global website IP bans reject HTTP/HTTPS requests across hosted websites.
WordPress failed-login bans use Fail2ban on the web ports. Optional service jails
protect SSH, mailbox authentication, SMTP authentication and FTP on their detected ports.

## Install

1. Download the `webuzo-de-noise` ZIP from [Releases](https://github.com/orloxgr/webuzo-de-noise/releases).
2. In the Webuzo administrator panel, open **Plugins → Installed Plugins**, upload
   the ZIP and activate **Webuzo De-Noise**.
3. Open **De-Noise**. New installations start in **Observe**, with empty blocklists.
   To start blocking, select **Enforce**, enable **Private-file protection**, add
   the desired scanner/crawler names and choose **Save & Apply**.

Use **Analyze current agents** in User-Agents or **Analyze PHP 404s** under
selected PHP file bans to inspect recorded traffic. Select results and choose
**Append selected to lists**, then **Save & Apply**. **Download CSV** downloads all
results in the selected list and current site filter, across every result page.
Every data list offers **20 / 50 / 100 / 500 / All** records per page. Changing
pages keeps unsaved settings; it does not start a new log review. Agent CSV keeps
its two columns: agent and hits.

PHP 404 analysis explains bundled probe signatures, application/WordPress routes,
unknown paths and repeated directory patterns. Repeated directories share an
expandable group with exact paths, source domains, requesting agents, distinct
client counts and first/last-seen times. Grouping changes the presentation only:
select individual exact paths to append, and review the rules before saving.
PHP CSV includes every exact path and its hits, domains, interpretation and times.
The **Bot information** column shows the operator or tool project, its purpose,
practical uses for your site (such as search discovery, link previews or SEO
audits), and a source link. Unidentified declarations stay marked as unconfirmed.
This bundled reference also appears on existing completed reports; no new scan
or external lookup is needed to display it.

Each User-Agent list also has **Append analyzed agents**. It adds recognized
names in that category from the entire completed analysis, across every result
page. Existing names are deduplicated case-insensitively and unsaved edits are
preserved. Under Other, unknown declarations and browser/application strings
remain available only for individual selection. List switches are unchanged;
choose **Save & Apply** when ready to save your edits.

Agent analysis recognizes Baidu rendering/image crawlers, Google image/news/video
crawlers, Perplexity, Exa and DuckAssist as search crawlers, and Censys/Palo Alto
as scanners. Versions of the same product share a row; separate image/render
products keep separate append rules. Browser strings and application clients
under Other are not automatic block suggestions. After upgrading, run a new
analysis to use the updated catalog; completed reports retain their saved results.
Appending preserves existing
entries, list switches, thresholds and exceptions. The analyses run in the
background, support cancellation and resume, and paginate the complete results.

Enable the other protections as needed. Domain owners open **Security → De-Noise**
in their account panel to view their domains and activity. All protection settings
are managed by the hosting administrator.

Upload a newer ZIP through the same plugin manager to update. Settings are
preserved. Saving CAPTCHA protection installs any missing companion systemd
units automatically; reactivation is not required. Deactivate the plugin before removing its source directory; deactivation
removes its filtering rules and scheduled maintenance while retaining settings
and history for reactivation.

## User-Agent blocklists and server-wide rate limits

Each of the five purpose categories has its own full-width accordion. Blocklist
is on the left, Group rate limit list on the right, and the editable Individual
rate limit rules table below. On small screens the two lists stack. Preset and
analyzed-agent buttons append only to the indicated list, preserving current
edits and switches. Add individual rule accepts any printable literal substring;
new rows are inactive with an empty name/rate. Review and Save & Apply explicitly.

**Analyze current agents** also has its own accordion. Closing it keeps the
current selection and report; it does not cancel a running analysis.
**Data Collection / Monitoring / Various** keeps the same saved category key,
switches and single server-wide group budget. **Add Data Collection** and
**Add Monitoring** append separate optional purpose-based suggestions to their
own editor. **Add Various…** opens an initially unchecked selection of generic
automation and unconfirmed names, with descriptions and available sources.
Only checked names are appended; closing the picker preserves selections.
Generic clients such as HeadlessChrome, curl and Python libraries may belong to
legitimate rendering, testing or integrations. They are not bulk suggestions or
verified malicious bots. Manual entries and selected analysis rows remain usable.
**Append analyzed agents** remains available and may include recognized generic
or unconfirmed names actually present in the report; review before appending.
Specific named bots take precedence over generic renderer/library declarations
when grouping new analysis results; this does not alter saved literal rules.

For each request, enabled individual rules take priority over every group limit,
which takes priority over every blocklist, across category boundaries. Disabled
rules do not override anything. Removing/disabling an individual rule can expose
the next group limit or a blocklist again. Within the individual or group level,
the longest literal substring wins; equal-length matches use case-insensitive
lexical name order, then category key. Matching remains case-insensitive against
the full declared User-Agent, without treating that declaration as verified identity.
Conflicting individual budgets for the same literal name, or an identical name
in multiple enabled groups, must be resolved before saving. The effective-action
preview uses unsaved editor values and shows the action for each configured name.

**All budgets are shared across all supported server websites and all client IPs.**
Every bot in a category's group list spends the same group budget. A bot selected
by an individual rule spends only its own budget, not the group budget. Neither
changing IP nor moving to another website or alias grants another budget. Heavy
crawling on one website can exhaust the budget for the others.

Webuzo shared webmail runs in its separate EMPS Nginx instance. Its existing
optional User-Agent blocklists and private-file protection remain independent;
it does not share these website budgets or gain a User-Agent rate limiter.

Set a positive average rate per minute or second and a nonnegative burst. All
matching methods and paths count, including images, CSS and JavaScript. [Native
Nginx](https://nginx.org/en/docs/http/ngx_http_limit_req_module.html) uses a leaky
bucket rather than a fixed calendar-minute quota. Burst permits
short spikes without delaying requests; excess requests receive **429** in Enforce,
without an automatic IP ban. Observe permits requests and records excesses using
separate counters, so it cannot consume Enforce's budget; Off does not count.
Other endpoint/private-file/URL/login/access/firewall protections still apply.

Activity identifies the selected group or individual policy when it is the match
label; higher-priority independent protection matches retain their own labels.
Individual records and complete CSV include the native overall rate result:
REJECTED is a real limiter rejection, REJECTED_DRY_RUN an Observe overrun.
Multiple independent URL/login limiters can apply, so this status does not prove
which limiter rejected a request. Older saved reports say Not recorded for the
new rate-result field; refresh Activity to collect it.

Updates retain every saved blocklist, switch, override and other policy setting.
New group lists are empty, disabled and have no preselected rate; individual
lists are empty. Saving from an older already-open panel preserves saved rate
settings. New controls use the existing journaled candidate validation, confirmed
reload and rollback path, and remain administrator-only in the backend.

ShapBot is an optional Search Indexers / additional search suggestion. Parallel
[documents it as its search-index crawler](https://parallel.ai/parallel-web-systems-bots),
separate from user-triggered Shap-User. Adding this catalog entry never inserts it
into a saved blocklist or enables a rule on upgrade.

## Domains and Fail2ban

**General** contains the server defaults and **Save & Apply**, followed by
**Domains** with its separate **Apply to selected** control. Domains inherit the
server mode unless the administrator selects an override. Central rules apply
according to their configured targets; domain owners cannot change them.

Open **Fail2ban** and choose **Refresh service status** to detect the installation,
existing jails, listening ports and authentication log sources. SSH, Dovecot,
Exim and PureFTPd have separate opt-in controls for attempts, counting windows,
ban durations and never-ban networks. Existing matching jails are reported and
left under their existing management; De-Noise does not create duplicates.
When CSF or LFD is detected, De-Noise blocks enabling its SSH, mail and FTP
protections in both the panel and backend. Existing De-Noise service jails can
still be disabled; no existing jail or CSF/LFD setting is changed automatically.
WordPress login protection and Fail2ban installation remain available with
CSF/LFD. Installation keeps Fail2ban stopped until the package is configured and
validated. New installations start with authentication jails off; enable the
WordPress jail separately. SSH, mail, FTP and CSF/LFD settings are unchanged.
Existing Fail2ban configuration is preserved. If that configuration already enables
other jails, the installer leaves the service stopped rather than rewriting them.
Starting an existing Fail2ban service through De-Noise checks the enabled jails;
with CSF/LFD installed, only an empty or De-Noise WordPress-only configuration
is accepted. Existing jails and configuration files are never disabled or edited
by these checks. Other active BFD protection is reported for review. After changing service ports
or logging elsewhere, refresh status and Save & Apply again to update the owned
jails.

If Fail2ban is missing, **Preview Fail2ban installation** shows the package plan.
**Install Fail2ban & start service** installs the reviewed package and dependencies
from authenticated Debian or Ubuntu repositories and enables the system service.
The automatic installer also requires the distribution `python3-apt` package
for repository verification. No repository is added. Other distributions require manual installation of their
OS Fail2ban package. Installation progress runs in the background and can be
checked after returning to the page. Distribution defaults can already enable
SSH protection; De-Noise service jails stay off until explicitly saved.

**Test filter against recent logs** checks a bounded recent sample using the
installed native Fail2ban filter. Saving enabled service protection repeats this
test, validates the configuration, reloads Fail2ban and verifies the requested
jails are active. Failed changes restore the previous configuration. Zero sample
matches can mean no failed logins have been recorded; generate a controlled
failed login to verify a new log source. Exim and Dovecot use normal authentication
filters, excluding aggressive connection/spam-rejection rules. A plugin-owned
Dovecot filter extends the native filter for explicit Dovecot 2.4 `auth_failed`
messages; distribution filters are preserved.

Only the detected TCP service ports are blocked. Loopback and inherited Fail2ban
exclusions remain exempt. Add administrator IPs to the SSH exemptions before
enabling a new SSH jail. **Disable website protection** leaves authentication
jails active; disable those separately in **Fail2ban**. Deactivation removes only
De-Noise-owned jails, leaving the Fail2ban package, service and unrelated jails.

The former additional domain-only automatic-ban feature has been removed.
Upgrading drops its rules and stored bans; central website protections remain.

## WordPress administration access and countries

Open **WP access** to choose an extra **HTTP username / password** or a local
image **CAPTCHA** for direct requests to `wp-login.php` and `wp-admin`, including
WordPress installations in subdirectories. These checks run before WordPress;
they require no WordPress plugin or external CAPTCHA service. Shop account,
checkout, AJAX and public form-handler routes remain outside the gate.

The administrator sets **Central defaults**. Each hosting account and domain can
**Inherit parent settings** or choose a custom profile, including explicit Off.
HTTP passwords can inherit separately; only salted hashes are stored. Hosting
users can change only their own account and domain profiles. De-Noise domain
modes still apply: **Enforce** activates the checks, **Observe** records candidates
and **Off** bypasses them. New installations leave these checks disabled.

**Bypass for internal requests** allows requests declaring the exact same origin
through browser Fetch Metadata or, if absent, an exact-origin Referer. This is a
compatibility option, not proof of a trusted client: WordPress authentication
remains necessary. Turn it off to require the extra check for every protected
request. Existing administrator HTTP authentication is reported as a conflict
before enabling a gate.

CAPTCHA verification is remembered for **six hours by default**, configurable in
seconds. Its signed cookie is tied to the exact hostname and protocol. Incorrect
answers do not create IP bans. Submitted WordPress forms are never replayed;
visitors submit them again after verification. A socket-activated service handles
only the local challenge; Nginx validates subsequent cookies directly with its
[secure_link module](https://nginx.org/en/docs/http/ngx_http_secure_link_module.html).
The service uses a restricted dynamic system user and a private Unix socket,
with no public listener. It starts only when CAPTCHA protection is configured.

Country filtering is independent of the password/CAPTCHA choice. Select countries
to block or allow, choose administration paths or the entire site, and decide how
unknown locations are handled. Unknown locations are allowed by default; ACME
certificate validation is exempt. Rejections return HTTP 403 without a firewall
ban. Whole-site filtering also affects customers, APIs and payment callbacks.

The administrator configures a MaxMind account ID and GeoLite2 license key in
**Countries**, then downloads the country database once for the server. Visitor
requests use local IPv4/IPv6 data and send no visitor information to MaxMind.
Automatic weekly updates use the existing maintenance job when a country filter
is active; a failed download retains the previous working database. No GeoIP
Nginx module or WordPress plugin is installed. The license key remains in
root-only state and is not returned to the panel.

## WordPress user-enumeration protection

- **Enable user-enumeration protection** is the main switch for the selected
  protections. Domains in Enforce reject matching public requests with HTTP 403;
  Observe records matches and Off disables protection for that domain.
- **Protect public REST user lists and profiles** restricts anonymous access to
  the API user list and numeric user profiles. Authenticated requests keep their
  normal WordPress permissions. Public features that fetch these profiles may be
  affected; other API routes, such as posts and pages, keep their normal behavior.
- **Protect author-ID discovery** blocks requests such as `/?author=1` that can
  reveal an author slug through a redirect. Author archive URLs stay public
  unless the archive option is also enabled.
- **Also protect public author archive pages** restricts pages such as
  `/author/name/` to authenticated users. Visitors and search crawlers receive
  HTTP 403 there; individual articles remain available. Leave it off when public
  author pages are needed.

No manual WordPress plugin installation is required for these options. After
**Save & Apply**, De-Noise automatically installs its User Enumeration Guard as a
[Must-Use plugin](https://developer.wordpress.org/advanced-administration/plugins/mu-plugins/)
for selected domains in Enforce. It loads automatically and appears in
**Plugins > Must-Use**. Observe does not install the helper for that domain.
Disable the main switch and Save & Apply to remove the helper when no protected
domain sharing that WordPress installation needs it. All three protections use
this same helper; WP fail2ban is only needed for the separate login-ban feature.

The managed file is `wp-content/mu-plugins/webuzo-de-noise-user-enumeration.php`.
The integration requires the standard WordPress content/MU plugin directories;
custom directory settings report an error and require separate integration.

## Integration

- Uses Webuzo's plugin lifecycle, panel sessions and privilege separation.
- Uses the documented custom Nginx configuration extension points.
- Does not patch Webuzo source, distributed templates, generated virtual hosts,
  or the panel's main Nginx configuration.
- Existing custom configuration is preserved; conflicting configuration is
  reported instead of overwritten.
- Account and domain settings are discovered on each server. No server address,
  account name or website is built into the plugin.

Feature coverage and validation are tracked in [FEATURES.md](FEATURES.md).

Optional webmail protection applies the selected User-Agent lists and private-file
rules to Webuzo's native mail route, including its custom webmail ports. It uses
the documented [EMPS custom configuration](https://www.webuzo.com/docs/how-tos/how-to-add-custom-conf-in-webuzo-emps-binary/)
extension. The shared webmail service and its activity are visible to administrators;
hosting accounts retain access only to their own website activity.

## Requirements

- Webuzo with its native website Nginx running and custom domain includes enabled.
- Python 3.9 or later with SQLite support, available as `/usr/bin/python3`.
- CAPTCHA additionally uses SQLite 3.35 or later and Nginx `secure_link` support.
- Administrator access to install the plugin through Webuzo's plugin manager.

Validated on Webuzo 4.9.1 with Ubuntu 24.04 and native Nginx. The
[feature coverage](FEATURES.md) lists the runtime and compatibility checks.

WordPress failed-login bans additionally require Fail2ban and an active WP fail2ban
plugin on each protected WordPress site. Its authentication events must reach the
host's journal or authentication log with the visitor's real IP. Logging permissions
and trusted proxy settings belong to the hosting setup; the plugin does not change
them. The journal backend includes hosting-user events and avoids syslog's repeated
message reduction. File-based logging must preserve individual authentication events.

## License

GPL-3.0-or-later. Author: Byron Iniotakis — https://www.iniotakis.com.

This project is an independent third-party integration. It is not affiliated
with, endorsed, sponsored, or supported by Webuzo or Softaculous. The Webuzo name
is used only to describe compatibility with the hosting platform.

### Reviewing findings

PHP 404 inventories separate URL characteristics from review priority. A repeated directory, diagnostic filename or application-shaped URL can carry several characteristics. Client/path and cross-domain correlations explain why an item deserves attention; they never create a ban automatically. Original URLs remain separate when selecting exact file rules.

Log and PHP reviews have domain, priority, characteristic, review-state, path and minimum-hit filters. PHP reviews also filter by minimum domain count. Filters apply before pagination; CSV exports every matching exact result across all pages. Already rejected secret-file probes can be grouped by domain and expanded without losing their individual URLs.

Mark reviewed, Ignore in findings and Reopen apply to one exact path on one domain, including future reviews. These root-private notes do not change protection settings or create allowlist exceptions. Ignored entries remain accessible through the review-state filter. Agents, request methods, parameter names and event times provide context in the log-review CSV. Known cron/cache transport parameters do not inflate content-filter diversity. WooCommerce, Complianz and UltraCache endpoints identify the work being performed.

### Endpoints

**Disable XML-RPC** has an enable switch, a **Global** checkbox and a checkbox
for each site. Global covers every current and future site; individual selections
cover only those sites. Choose the scope, then **Save & Apply**. In Enforce,
Nginx rejects XML-RPC with 403 before
WordPress runs, including aliases, subfolder installations and every HTTP method.
Observe records matches without blocking; Off keeps normal routing. With Global
off, an empty site selection affects no sites. The list has pagination, Select all / Clear
selection and CSV. New installations start with this option off and no selected
sites. Upgrades retain the existing switch and site selections.

Global and each site have their own **Allowed IPs / CIDRs** and **Allow Jetpack**
button. Enter IPv4/IPv6 addresses or CIDRs, one per line. When Global is checked,
its exceptions apply across protected sites; a site's exceptions add access only
on that site and its aliases. Other De-Noise rules,
website bans and the XML-RPC request rate limit still apply. Behind a proxy,
Nginx must already obtain the real client address from that trusted proxy;
declared User-Agent names and arbitrary forwarded headers do not grant access.

**Allow Jetpack** downloads the current [official Jetpack IP list](https://jetpack.com/ips-v4.txt)
and appends missing ranges to that box's unsaved exceptions. It retains manual
entries and edits made during the download, does not change any switch or site
selection, and requires **Save & Apply**. Click it again to add newly published
ranges; updates are on demand and obsolete entries can be removed manually.
See [Jetpack's allowlist instructions](https://jetpack.com/support/how-to-add-jetpack-ips-allowlist/).

Normal wp-admin access is unchanged. This control does not ban IPs. Activity
identifies rejected requests as **XML-RPC disabled**.

**Custom endpoint rules** match exact paths or native Nginx PCRE expressions on
selected domains, or all web domains. Enforce returns 403 before the application,
including when a file exists. Observe records matches; Off leaves requests alone.
The first matching rule determines its optional **Also ban IP** action. Ban
durations accept seconds, minutes, hours or days; 0 means permanent. These
website bans use the existing De-Noise backend and its Never-ban/server-IP
exceptions, independently of the global probe-ban switch.

**Ban after repeated HTTP 404s for selected paths** counts actual final 404
responses from one IP across the selected paths and domains. Choose attempts,
counting window and ban duration independently. Repeating one selected path
counts. Existing routes returning 200, redirects or other statuses keep normal
routing. Enabling or changing the selections/threshold/window starts a fresh
counting period, without retroactively banning requests from retained history.

**Analyze endpoint logs** reviews all retained non-image paths, including JS,
CSS, PHP, backups and application routes, across all recorded response statuses.
It shows methods, declared agents, distinct client counts, cross-domain 404
context and coverage. Filtering, review notes, pagination and CSV use the saved
report; they do not enable protection.

Every exact finding supports manual append as a disabled domain-scoped 403 rule
with IP banning off. Every path with a recorded 404 can be appended to the 404
list, even if other responses for that path succeeded. Recommendations do not
restrict these manual actions. In grouped results, select the paths to append;
an empty selection changes nothing. Existing list switches, thresholds,
durations and domains are preserved. Review the result, then **Save & Apply**.

New endpoint rules and the new 404 list start disabled and empty. They are
managed by the hosting administrator. Existing settings remain in place after
an upgrade, including when an older open settings form is submitted.
