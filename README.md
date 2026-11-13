# Webuzo De-Noise

Request filtering in Nginx before requests reach Apache or PHP, with per-domain
controls and traffic analysis inside the Webuzo panel.

This project ports [Hestia De-Noise](https://github.com/orloxgr/hestia-de-noise)
to Webuzo.

## Features

- Five independent User-Agent lists: scanner tools, AI training crawlers, search
  indexers, SEO/backlink crawlers and other data collection.
- Private-file protection, login/XML-RPC limits, filtered-URL budgets and
  missing-static-file rules.
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
WordPress login protection remains available. Automatic Fail2ban package installation is blocked while
CSF/LFD is installed because distribution package scripts may activate an SSH
jail. Install and configure Fail2ban manually for WordPress-only use in that case.
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
