# Feature coverage

The source feature set is Hestia De-Noise at the commit recorded in `UPSTREAM`.
The Webuzo port must verify each feature separately before release.

| Feature | Webuzo integration | Validation |
| --- | --- | --- |
| Scanner and crawler User-Agent lists | Native Nginx custom includes | HTTP runtime: blocked, case insensitive, configuration injection escaped |
| Private-file and repository protection | Native Nginx custom includes | HTTP runtime before PHP; isolated mail compiler tests |
| Observe / Enforce / Off | Per-domain Nginx rules | HTTP runtime including independent account override |
| Login and XML-RPC rate limits | Native Nginx request limiting | Native login HTTP 429; XML-RPC compiler and isolated Nginx tests |
| Filtered URLs and per-crawler budgets | Native Nginx maps and zones | Pending |
| Robots.txt suggestions | Panel preview only | Pending |
| Missing static files | Server rewrite phase, existing routing retained | Pending |
| Selected PHP probes and suspicious queries | Native Nginx rules and counters | Pending |
| General 404 counters | Completed-response logs | Pending |
| Global IP bans | Shared website Nginx geo map, HTTP 403 | IPv4 HTTP runtime on two accounts; SSH remains accessible; IPv6 configuration validated |
| Domain-only IPv4/IPv6 bans | Native Nginx maps | Pending |
| Never-ban networks and server addresses | Native address discovery and plugin policy | Unit coverage; automatic threshold runtime pending |
| Ban evidence, history, pagination and retention | Plugin-owned SQLite state | Pending |
| Selected/all unban | Owning scope only | Pending |
| WordPress failed-login bans and escalation | Namespaced native Fail2ban jail; requires WordPress syslog events | Real WordPress HTTP logins: three native ban stages, exact permanent sentinel, automatic expiry, web-port blocking, SSH accessibility and unban; requires working logging and client-IP setup |
| User enumeration and author archives | Nginx and scoped WordPress companion | Real WordPress tests: anonymous, forged credentials, authenticated REST, editor and reset flows |
| HTTP webmail protection | Website mail aliases inherit their website policy | Separate panel-hosted webmail integration under investigation; not yet supported |
| Activity and declared User-Agent details | Plugin-owned logs | Pending |
| On-demand log analysis and crawler verification | Native domain logs | Pending |
| Cron schedule preview/apply/restore | Native Webuzo cron API | Native runtime: preview unchanged, apply, exact restore and rejection of stale preview |
| Administrator and account views | Native panel authentication and CSRF | Two account sessions: own settings, cross-account and global-action rejection, scoped AJAX |
| Bulk changes and domain overrides | Account ownership validation | Pending |
| New/deleted/suspended accounts and aliases | Official admin users/domains APIs | Native create/suspend/unsuspend/delete verified; alias ordering unit test, native alias runtime pending |
| Transaction rollback and interrupted recovery | Plugin-owned journal | Failure/recovery unit tests and custom-include preservation tests |
| Confirmed Nginx reload | Native configured PID and new-worker verification | Native runtime on rules, account synchronization and unban |
| Log rotation | Plugin-owned logrotate entry | Worker-owned log fixtures passed; native logrotate runtime pending |
| Disable, deactivate, uninstall and upgrade | Native plugin lifecycle | Pending |
| Core/template integrity and rebuild persistence | Hash comparison and native rebuild | Baseline source integrity verified; native virtual-host rebuild and reboot preserve filtering. Webuzo upgrade testing pending |
| Cross-account isolation and hostile input | Runtime security tests | Native panel scope/CSRF checks and hostile request-file fixtures; further runtime cases pending |
