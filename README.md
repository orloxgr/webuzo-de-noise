# Webuzo De-Noise

Request filtering in Nginx before requests reach Apache or PHP, with per-domain
controls and traffic analysis inside the Webuzo panel.

This project ports [Hestia De-Noise](https://github.com/orloxgr/hestia-de-noise)
to Webuzo. Development and compatibility testing are in progress. Installation
packages will be published after the Webuzo integration passes its runtime tests.

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
