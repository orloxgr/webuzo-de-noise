# Feature coverage

The source feature set is Hestia De-Noise at the commit recorded in `UPSTREAM`.
The Webuzo port must verify each feature separately before release.

| Feature | Webuzo integration | Validation |
| --- | --- | --- |
| Scanner and crawler User-Agent lists | Native Nginx custom includes | HTTP runtime: blocked, case insensitive, configuration injection escaped |
| Private-file and repository protection | Native Nginx custom includes | HTTP runtime before PHP; isolated mail compiler tests |
| Observe / Enforce / Off | Per-domain Nginx rules | HTTP runtime including independent account override |
| Login and XML-RPC rate limits | Native Nginx request limiting | Native login HTTP 429; XML-RPC compiler and isolated Nginx tests |
| Filtered URLs and per-crawler budgets | Native Nginx maps and zones | Native HTTP: shared crawler/domain budget, independent second domain and shared alias budget |
| Robots.txt suggestions | Panel preview only | Pending |
| Missing static files | Server rewrite phase, existing routing retained | Pending |
| Selected PHP probes and suspicious queries | Native Nginx rules and counters | Pending |
| General 404 counters | Completed native access logs | Native runtime: one local 404 request gives one strike; exact three-request threshold. Global/domain regression fixtures exclude duplicate fallback records |
| Global IP bans | Shared website Nginx geo map, HTTP 403 | IPv4 HTTP runtime on two accounts; SSH remains accessible; IPv6 configuration validated |
| Domain-only IPv4/IPv6 bans | Native Nginx maps | Native automatic domain ban runtime; isolated real Nginx sockets verify IPv4/IPv6 and alias blocking while a second domain remains accessible |
| Never-ban networks and server addresses | Native address discovery and plugin policy | Unit coverage; automatic threshold runtime pending |
| Ban evidence, history, pagination and retention | Plugin-owned SQLite state | Native automatic global/domain ban evidence; pagination, retention and scope unit tests |
| Selected/all unban | Owning scope only | Native global all-unban and WordPress selected unban; large-selection unit tests |
| WordPress failed-login bans and escalation | Namespaced native Fail2ban jail; requires WordPress syslog events | Real WordPress HTTP logins: three native ban stages, exact permanent sentinel, automatic expiry, web-port blocking, SSH accessibility and unban; requires working logging and client-IP setup |
| User enumeration and author archives | Nginx and scoped WordPress companion | Real WordPress tests: anonymous, forged credentials, authenticated REST, editor and reset flows |
| HTTP webmail protection | Documented EMPS custom include; native proxy routes and custom webmail ports | Native Enforce/Observe/Off, private-file and agent blocks; real Roundcube mailbox login and assets remain functional. Native custom HTTP/HTTPS webmail ports, invalid-candidate rollback, deactivation/reactivation and administrator-only activity verified |
| Activity and declared User-Agent details | Plugin-owned logs | Native activity preserves full declared agents; complete pagination and owner-context tests |
| On-demand log analysis and crawler verification | Native domain logs | Pending |
| Cron schedule preview/apply/restore | Native Webuzo cron API | Native runtime: preview unchanged, apply, exact restore and rejection of stale preview |
| Administrator and account views | Native panel authentication and CSRF | Two account sessions: own settings, cross-account and global-action rejection, scoped AJAX |
| Bulk changes and domain overrides | Account ownership validation | Pending |
| New/deleted/suspended accounts and aliases | Official admin users/domains APIs | Native create/suspend/unsuspend/delete and separate alias hosts verified; aliases share policies/budgets/log scope |
| Transaction rollback and interrupted recovery | Plugin-owned journal | Failure/recovery and custom-include preservation tests; native invalid EMPS candidate restores both website and panel configurations, clears the journal and preserves policy/history |
| Confirmed Nginx reload | Native configured PID and new-worker verification | Native runtime on rules, account synchronization and unban |
| Log rotation | Plugin-owned logrotate entry | Worker-owned log fixtures passed; native logrotate runtime pending |
| Disable, deactivate, uninstall and upgrade | Native plugin lifecycle | Native manager deactivation removes website/webmail rules, both documented custom blocks and cron; reactivation restores saved protection. Upgrade cases pending |
| Core/template integrity and rebuild persistence | Hash comparison and native rebuild | Baseline source integrity verified; native virtual-host rebuild and reboot preserve filtering. Webuzo upgrade testing pending |
| Cross-account isolation and hostile input | Runtime security tests | Native settings hashes remain unchanged after forbidden requests; each completed account report excludes the other account; foreign job status/cancellation rejected. Direct PHP template access denied |
