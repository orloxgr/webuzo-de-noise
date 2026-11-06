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
- Global website IP bans and domain-only bans, with editable thresholds,
  durations, exclusions, evidence, history and unban controls.
- Optional WordPress user-enumeration protection and failed-login bans.
- HTTP webmail protection, on-demand activity/log analysis, crawler verification
  and robots.txt previews.
- Native cron schedule preview/apply/restore, bulk domain modes and account views
  restricted to the account's own domains.

Global website IP bans reject HTTP/HTTPS requests across hosted websites.
WordPress failed-login bans use Fail2ban on the web ports.

## Install

1. Download `webuzo-de-noise-0.2.1.zip` from [Releases](https://github.com/orloxgr/webuzo-de-noise/releases).
2. In the Webuzo administrator panel, open **Plugins → Installed Plugins**, upload
   the ZIP and activate **Webuzo De-Noise**.
3. Open **De-Noise**. New installations start in **Observe**, with empty blocklists.
   To start blocking, select **Enforce**, enable **Private-file protection**, add
   the desired scanner/crawler names and choose **Save & Apply**.

Use **Analyze current agents** in User-Agents or **Analyze PHP 404s** under
selected PHP file bans to inspect recorded traffic. Select results and choose
**Append selected to lists**, then **Save & Apply**. **Export CSV** downloads all
agent names and hit counts from the completed analysis, across every result page.
Appending preserves existing
entries, list switches, thresholds and exceptions. The analyses run in the
background, support cancellation and resume, and paginate the complete results.

Enable the other protections as needed. Domain owners open **Security → De-Noise**
in their account panel for their domain bans, domains and activity.

Upload a newer ZIP through the same plugin manager to update. Settings are
preserved. Deactivate the plugin before removing its source directory; deactivation
removes its filtering rules and scheduled maintenance while retaining settings
and history for reactivation.

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
