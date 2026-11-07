# Feature coverage

The source feature set is Hestia De-Noise at the commit recorded in `UPSTREAM`.
The Webuzo integration was validated on Webuzo 4.9.1, Ubuntu 24.04, native website
Nginx 1.30.5 and PHP 8.3. Panel PHP syntax is also checked with EMPS PHP 7.4;
Python source syntax is checked for Python 3.9 compatibility. The automated suite
covers native Nginx, WordPress, Fail2ban, panel access, rollback and browser behavior.

| Feature | Webuzo integration | Validation |
| --- | --- | --- |
| Five independent User-Agent categories | Native Nginx custom includes; existing selections migrate without new blocks | Real native Nginx requests verify each switch independently; website and webmail compilers, case-insensitive literal matching and configuration escaping |
| Full agent CSV export | Completed, administrator-owned report; no new scan | Complete multi-chunk export, CSV quoting and formula neutralization, empty reports, failure handling and account/job access checks |
| Current agent and PHP 404 inventories | Administrator-only background analysis of native web logs | Native panel AJAX: exact five-request counts split across two domains; domain/time selection, compressed rotations, complete pagination, job ownership and CSRF. Browser append/save preserves existing entries and switches |
| Private-file and repository protection | Native Nginx custom includes | HTTP runtime before PHP; isolated mail compiler tests |
| Observe / Enforce / Off | Per-domain Nginx rules | HTTP runtime including independent account override |
| Login and XML-RPC rate limits | Native Nginx request limiting | Native login HTTP 429; XML-RPC compiler and isolated Nginx tests |
| Filtered URLs and per-crawler budgets | Native Nginx maps and zones | Native HTTP: shared crawler/domain budget, independent second domain and shared alias budget |
| Robots.txt suggestions | Panel preview only | Browser runtime: add rule, path/parameter preview and reload without saving; no website file written |
| Missing static files | Server rewrite phase, existing routing retained | Native Off/Observe/Enforce requests correlated with Apache logs: enforced matches stop before Apache/PHP; isolated Nginx tests preserve existing files and exceptions |
| Selected PHP probes and suspicious queries | Native Nginx rules and counters | Native Off/Observe/Enforce requests and Apache-log correlation; enforced requests stop before Apache/PHP. Global counter/evidence tests |
| General 404 counters | Completed native access logs | Native runtime: one local 404 request gives one strike; exact three-request threshold. Global regression fixtures exclude duplicate fallback records |
| Global IP bans | Shared website Nginx geo map, HTTP 403 | Native IPv4 HTTP runtime on two accounts; SSH remains accessible. Isolated native Nginx sockets verify IPv4/IPv6 across two accounts and aliases. Ban/unban preserves shared webmail protection |
| Never-ban networks and server addresses | Native address discovery and plugin policy | Native one-request thresholds: ignored client CIDR and requests from the discovered server address remain unbanned; IPv4/IPv6 unit coverage |
| Ban evidence, history, pagination and retention | Plugin-owned SQLite state | Native automatic global ban evidence; pagination, retention and scope unit tests |
| Selected/all unban | Owning scope only | Native global all-unban and WordPress selected unban; large-selection unit tests |
| Service authentication bans | Opt-in SSH, Dovecot, Exim and PureFTPd jails; discovered ports and logs | Native Dovecot/Exim authentication samples and applied mail jails; IPv4/IPv6 ban/unban, separate port sets, existing SSH preservation and exact configuration restoration. PureFTPd native filter fixture; FTP service was not installed in the test environment |
| Fail2ban installation | Previewed, authenticated Debian/Ubuntu package-manager installation | Native browser preview/install/progress completion on Ubuntu 24.04; original SSH jail restored and 182 original Fail2ban/SSH/mail configuration files byte-identical. Repository, plan, dependency, ownership and failure tests |
| General and account layout | Domains follow the first Save & Apply; additional domain-ban feature removed | Native panel and PHP rendering tests: separate forms, admin-only Fail2ban actions, accounts retain only their own Domains and Activity; obsolete domain-ban state removed without changing global bans |
| WordPress failed-login bans and escalation | Namespaced native Fail2ban jail; requires WordPress syslog events | Real WordPress HTTP logins: three native ban stages, exact permanent sentinel, automatic expiry, web-port blocking, SSH accessibility and unban; requires working logging and client-IP setup |
| User enumeration and author archives | Nginx and scoped WordPress companion | Real WordPress tests: anonymous, forged credentials, authenticated REST, editor and reset flows |
| HTTP webmail protection | Documented EMPS custom include; native proxy routes and custom webmail ports | Native Enforce/Observe/Off, private-file and agent blocks; real Roundcube mailbox login and assets remain functional. Native custom HTTP/HTTPS webmail ports, invalid-candidate rollback, deactivation/reactivation and administrator-only activity verified |
| Activity and declared User-Agent details | Plugin-owned logs | Native activity preserves full declared agents; complete pagination and owner-context tests |
| On-demand log analysis and crawler verification | Native domain logs | Native administrator AJAX job completes across two domains; published Google ranges checked, 35 declared Googlebot requests from an unverified address remain unconfirmed; policy unchanged |
| Cron schedule preview/apply/restore | Native Webuzo cron API | Native runtime: preview unchanged, apply, exact restore and rejection of stale preview |
| Administrator and account views | Native panel authentication and CSRF | Two account sessions: own domains, cross-account and global-action rejection, scoped AJAX. Browser checks cover native menu navigation, working tabs, owner-only domains and completed Activity review |
| Bulk changes and domain overrides | Account ownership validation | Native form POSTs: independent Off/Observe/Inherit, multi-domain changes, invalid/empty selections rejected, exact policy restoration |
| New/deleted/suspended accounts and aliases | Official admin users/domains APIs | Native create/suspend/unsuspend/delete and separate alias hosts verified; aliases share policies/budgets/log scope |
| Transaction rollback and interrupted recovery | Plugin-owned journal | Failure/recovery and custom-include preservation tests; native invalid EMPS candidate restores both website and panel configurations, clears the journal and preserves policy/history |
| Confirmed Nginx reload | Native configured PID and new-worker verification | Native runtime on rules, account synchronization and unban |
| Log rotation | Plugin-owned logrotate entry | Native forced rotations, including compressed records: activity and exact three-probe automatic-ban threshold preserved; worker-owned log fixtures |
| Disable, deactivate, uninstall and upgrade | Native plugin lifecycle | Cold install with source/state/configuration/logs/queue absent starts with empty Observe defaults. Native activation, enforcement, deactivation and original-installation restoration pass 15 HTTP/state/configuration checks. Deactivation removes website/webmail rules, both custom blocks and maintenance. Native ZIP update preserves the exact active policy and normal requests. Stale-bytecode regression verified |
| Core/template integrity and rebuild persistence | Hash comparison and native rebuild | Original 598 PHP sources unchanged. Native virtual-host rebuild and reboot preserve website and shared webmail rules; ordinary Roundcube login remains available. Official Webuzo updater ran on current 4.9.1; no newer-version transition was available |
| Cross-account isolation and hostile input | Runtime security tests | Native settings hashes remain unchanged after forbidden requests; each completed account report excludes the other account; foreign job status/cancellation rejected. Direct PHP template access denied |
