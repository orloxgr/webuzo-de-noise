(() => {
    'use strict';
    const csvAgent = value => {
        // Agent declarations are untrusted input, including spreadsheet formulas.
        if (/^[\s\uFEFF]*[=+\-@]/.test(value) || /^[\t\r\n]/.test(value)) value = "'" + value;
        return '"' + value.replace(/"/g, '""') + '"';
    };
    const initializeReview = (formId, prefix, actionPrefix, tab, label) => {
      const scanForm = document.getElementById(formId);
      if (scanForm) {
        const button = scanForm.querySelector('button[type="submit"]');
        const cancel = document.getElementById(prefix + '-cancel');
        const progress = document.getElementById(prefix + '-progress');
        const output = document.getElementById(prefix + '-output');
        const domainFilter = actionPrefix === 'activity' ? scanForm.querySelector('[name="activity_domain"]') : null;
        const storageKey = 'hdn-review:' + location.pathname + ':' + actionPrefix + ':' + (scanForm.dataset?.hdnContext || '');
        let job = null, active = false, generation = 0;
        let completedJob = null, appending = false;
        const supportsFilters = ['log_scan','php_files'].includes(actionPrefix);
        const filterDefaults = {domain:'all',priority:'all',feature:'all',review:'visible',query:'',min_hits:0,min_domains:0,group_rejected:true};
        let findingFilters = {...filterDefaults}, viewGeneration = 0;
        let perPage = '20';
        try { const saved = localStorage.getItem(storageKey + ':size'); if (['20','50','100','500','all'].includes(saved)) perPage = saved; } catch (_) {}
        if (supportsFilters) {
            try {
                const saved = JSON.parse(localStorage.getItem(storageKey + ':filters') || 'null');
                if (saved && typeof saved === 'object' && !Array.isArray(saved)) {
                    for (const key of Object.keys(filterDefaults)) if (typeof saved[key] === typeof filterDefaults[key]) findingFilters[key] = saved[key];
                }
            } catch (_) {}
            const choices = {priority:['all','high','normal','low'],review:['visible','all','open','reviewed','ignored'],
                feature:['all','probe','configuration','repeated','application','unexpected','cross_domain','client_sweep','encoded','unknown','security','errors','rejected','technical','frontend','crawl','asset','activity']};
            for (const [key, allowed] of Object.entries(choices)) if (!allowed.includes(findingFilters[key])) findingFilters[key] = filterDefaults[key];
            for (const key of ['min_hits','min_domains']) if (!Number.isSafeInteger(findingFilters[key]) || findingFilters[key] < 0) findingFilters[key] = 0;
            if (findingFilters.query.length > 2048 || /[\x00-\x1f]/.test(findingFilters.query)) findingFilters.query = '';
            if (!/^[a-zA-Z0-9.-]+$/.test(findingFilters.domain)) findingFilters.domain = 'all';
        }
        const appendButtons = actionPrefix === 'agents' ? [...document.querySelectorAll('[data-hdn-append-analyzed]')] : [];
        const updateAppendButtons = () => appendButtons.forEach(item => { item.disabled = !completedJob || appending; });
        let restoreSelection = true;
        const selectionEdited = () => { restoreSelection = false; };
        scanForm.addEventListener('input', selectionEdited);
        scanForm.addEventListener('change', selectionEdited);
        try { job = sessionStorage.getItem(storageKey); } catch (_) { /* Storage is optional. */ }
        const remember = id => { job = id; try { sessionStorage.setItem(storageKey, id); } catch (_) {} };
        const request = async (action, page = 1, initial = false, exportOffset = null, requestedJob = job, category = null, extra = null) => {
            const body = initial ? new FormData(scanForm) : new FormData();
            body.set('action', action);
            body.set('token', scanForm.querySelector('input[name="token"]').value);
            body.set('tab', tab);
            if (requestedJob) body.set('analysis_job', requestedJob);
            body.set('analysis_page', page);
            body.set('analysis_per_page', perPage);
            if (action === 'review_export') body.set('review_kind', actionPrefix === 'log_scan' ? 'scan' : actionPrefix);
            if (domainFilter) body.set('activity_domain', domainFilter.value);
            if (supportsFilters && (action.endsWith('_status') || action === 'review_export')) body.set('review_filters', JSON.stringify(findingFilters));
            if (extra) for (const [key,value] of Object.entries(extra)) body.set(key,value);
            const filterKey = JSON.stringify([findingFilters,perPage]);
            if (exportOffset !== null) body.set('export_offset', exportOffset);
            if (category !== null) body.set('analysis_category', category);
            // Named input "action" must never shadow the form's URL attribute.
            const response = await fetch(scanForm.getAttribute('action') || location.href, {
                method: 'POST', body, credentials: 'same-origin', headers: {'X-HDN-Analysis': '1'}
            });
            const text = await response.text();
            let value;
            try { value = JSON.parse(text); } catch (_) {
                const login = response.redirected && /\/login(?:\/|$)/.test(new URL(response.url).pathname);
                throw new Error(login ? 'Your Webuzo session has expired. Sign in again to resume the review.' : `Review response was not JSON (HTTP ${response.status}). The background job can be resumed.`);
            }
            if (!response.ok || !value.ok) throw new Error(value.error || `Review failed: HTTP ${response.status}.`);
            value.filterKey = filterKey;
            return value;
        };
        const display = value => {
            if (supportsFilters && value.filterKey !== JSON.stringify([findingFilters,perPage])) return active;
            const current = value.job;
            if (restoreSelection && current.selection) {
                const fields = [
                    ['[name="analysis_minutes"]', 'value', String(current.selection.minutes)],
                    ['[name="analysis_target"]', 'value', current.selection.target],
                    ['[name="analysis_verify_google"]', 'checked', current.selection.verify_google]
                ];
                fields.forEach(([selector, property, setting]) => {
                    const field = scanForm.querySelector(selector);
                    if (field) field[property] = setting;
                });
                restoreSelection = false;
            }
            if (current.id) remember(current.id);
            active = ['queued', 'running'].includes(current.state);
            completedJob = current.state === 'complete' ? current.id : null;
            updateAppendButtons();
            cancel.hidden = !active;
            if (value.report && (!domainFilter || !current.analysis || current.analysis.selected_domain === domainFilter.value)) {
                const page = new DOMParser().parseFromString(value.report, 'text/html');
                const report = page.getElementById(prefix + '-output');
                if (!report) throw new Error('The panel returned an unexpected report.');
                output.replaceChildren(...[...report.childNodes].map(node => document.importNode(node, true)));
                if (domainFilter) output.querySelectorAll('time[data-hdn-time]').forEach(node => {
                    const date = new Date(node.getAttribute('datetime'));
                    if (!Number.isNaN(date.getTime())) node.textContent = date.toLocaleString(undefined, {timeZoneName:'short'});
                });
            }
            if (current.state === 'idle') progress.textContent = '';
            else if (current.state === 'complete') progress.textContent = actionPrefix === 'activity'
                ? 'Showing a saved Activity review. Its exact time range is shown below. Refresh activity reads a new window.'
                : 'Review completed. All available retained logs were processed; see coverage for missing or unreadable data. Unsaved rule edits are unchanged.';
            else if (current.state === 'cancelled') progress.textContent = 'Review cancelled. Protection settings and unsaved edits are unchanged.';
            else if (current.state === 'failed') throw new Error(current.error || 'Review process failed.');
            else {
                const p = current.progress || {};
                progress.textContent = `${p.stage || (current.state === 'queued' ? 'Review queued' : 'Review running')} · ${p.records || 0} records · ${((p.bytes || 0) / 1048576).toFixed(2)} MiB · ${p.files_done || 0}/${p.files_total || '?'} files${p.domain ? ' · ' + p.domain : ''}`;
            }
            return active;
        };
        const observe = async (start = false) => {
            const turn = ++generation;
            completedJob = null;
            updateAppendButtons();
            button.disabled = true;
            try {
                if (start) {
                    const value = await request(actionPrefix + '_start', 1, true);
                    remember(value.job.id);
                    display(value);
                }
                while (turn === generation) {
                    const value = await request(actionPrefix + '_status');
                    if (turn !== generation || !display(value)) break;
                    await new Promise(resolve => setTimeout(resolve, 1000));
                }
            } catch (error) {
                progress.textContent = error.message;
            } finally {
                if (turn === generation) {
                    button.disabled = false;
                    button.textContent = active ? 'Resume review' : label;
                }
            }
        };
        scanForm.addEventListener('submit', event => {
            event.preventDefault();
            restoreSelection = false;
            return observe(!job || !active);
        });
        cancel.addEventListener('click', async () => {
            ++generation;
            try { display(await request(actionPrefix + '_cancel')); }
            catch (error) { progress.textContent = error.message; }
            button.disabled = false;
            button.textContent = active ? 'Resume review' : label;
        });
        appendButtons.forEach(item => item.addEventListener('click', async () => {
            const category = item.dataset.hdnAppendAnalyzed;
            const allowed = ['tool_agents', 'ai_agents', 'search_agents', 'seo_agents', 'agents'];
            if (!completedJob || appending || !allowed.includes(category)) return;
            const sourceJob = completedJob;
            const field = document.getElementById(category);
            const status = document.getElementById('hdn-analyzed-' + category);
            appending = true;
            updateAppendButtons();
            status.textContent = 'Reading analyzed agents…';
            try {
                const names = new Map();
                let offset = 0, total = null;
                do {
                    const value = (await request('agents_candidates', 1, false, offset, sourceJob, category)).candidates;
                    if (!value || value.category !== category || !Array.isArray(value.names) ||
                        !Number.isSafeInteger(value.total) || value.total < 0 ||
                        !Number.isSafeInteger(value.scanned) || value.scanned < 0 || value.scanned > 500 ||
                        value.names.length > value.scanned || (total !== null && total !== value.total)) {
                        throw new Error('The panel returned invalid agent candidates. Try again.');
                    }
                    total = value.total;
                    const end = offset + value.scanned;
                    if (end > total || (value.next_offset === null ? end !== total :
                        value.next_offset !== end || end <= offset || end >= total)) {
                        throw new Error('The agent report is incomplete. Try again.');
                    }
                    for (const name of value.names) {
                        if (typeof name !== 'string' || !name || name !== name.trim() || /[^\x20-\x7e]/.test(name)) {
                            throw new Error('The panel returned an invalid agent name.');
                        }
                        names.set(name.toLowerCase(), name);
                    }
                    offset = value.next_offset;
                } while (offset !== null);
                // Merge into the latest unsaved text only after every chunk succeeds.
                const added = appendLines(field, [...names.values()], true);
                status.textContent = names.size ?
                    `${added} new agents appended; ${names.size - added} already present. Save & Apply to save your changes.` :
                    'No recognized agents in this category were found in this analysis.';
            } catch (error) {
                status.textContent = error.message;
            } finally {
                appending = false;
                updateAppendButtons();
            }
        }));
        const refreshView = async (page = 1) => {
            const turn = ++viewGeneration;
            const value = await request(actionPrefix + '_status', page);
            if (turn === viewGeneration) display(value);
        };
        const applyFilters = async reset => {
            const next = reset ? {...filterDefaults} : {...findingFilters};
            if (!reset) for (const field of output.querySelectorAll('[data-hdn-filter]')) {
                const name = field.dataset.hdnFilter;
                if (!(name in filterDefaults)) continue;
                if (name === 'min_hits' || name === 'min_domains') {
                    if (!/^[0-9]+$/.test(field.value) || !Number.isSafeInteger(Number(field.value))) throw new Error('Choose nonnegative whole-number filters.');
                    next[name] = Number(field.value);
                } else next[name] = field.type === 'checkbox' ? field.checked : field.value;
            }
            findingFilters = next;
            try { localStorage.setItem(storageKey + ':filters', JSON.stringify(next)); } catch (_) {}
            await refreshView(1);
        };
        output.addEventListener('keydown', async event => {
            if (event.key !== 'Enter' || !event.target.matches('[data-hdn-filter]')) return;
            event.preventDefault();
            try { await applyFilters(false); } catch (error) { progress.textContent = error.message; }
        });
        output.addEventListener('change', async event => {
            if (!event.target.matches('[data-hdn-review-size]') || !job) return;
            perPage = event.target.value;
            try { localStorage.setItem(storageKey + ':size', perPage); } catch (_) {}
            try { await refreshView(1); }
            catch (error) { progress.textContent = error.message; }
        });
        output.addEventListener('click', async event => {
            const apply = event.target.closest('[data-hdn-apply-filters]');
            const reset = event.target.closest('[data-hdn-reset-filters]');
            if (supportsFilters && (apply || reset)) {
                try { await applyFilters(Boolean(reset)); } catch (error) { progress.textContent = error.message; }
                return;
            }
            const mark = event.target.closest('[data-hdn-review-mark]');
            if (supportsFilters && mark && completedJob) {
                const item = mark.closest('[data-hdn-review-item]');
                const domain = item.querySelector('[data-hdn-note-domain]').value;
                const status = output.querySelector('[data-hdn-review-note-status]');
                if (!domain) { status.textContent = 'Choose the domain for this exact path.'; return; }
                mark.disabled = true;
                try {
                    await request('review_mark', 1, false, null, completedJob, null, {
                        review_kind:actionPrefix === 'log_scan' ? 'scan' : actionPrefix,
                        review_domain:domain,review_item:item.dataset.hdnReviewItem,review_mark:mark.dataset.hdnReviewMark
                    });
                    await refreshView(1);
                    output.querySelector('[data-hdn-review-note-status]').textContent = 'Review note saved. Protection settings are unchanged.';
                } catch (error) { status.textContent = error.message; }
                finally { mark.disabled = false; }
                return;
            }
            const reviewExport = event.target.closest('[data-hdn-export-review]');
            if (reviewExport && completedJob) {
                const sourceJob = completedJob, sourceDomain = domainFilter?.value, sourceFilters = JSON.stringify(findingFilters);
                const status = output.querySelector('[data-hdn-export-status]');
                reviewExport.disabled = true;
                try {
                    const lines = ['\uFEFF']; let offset = 0, total = null, columns = null, count = 0, revision = null;
                    do {
                        if (domainFilter && sourceDomain !== domainFilter.value) throw new Error('The site filter changed. Download again.');
                        if (sourceFilters !== JSON.stringify(findingFilters)) throw new Error('The filters changed. Download again.');
                        const value = (await request('review_export', 1, false, offset, sourceJob)).export;
                        if (sourceFilters !== JSON.stringify(findingFilters)) throw new Error('The filters changed. Download again.');
                        if (offset === 0) revision = value?.view_revision;
                        else if (revision !== value?.view_revision) throw new Error('The review notes changed during export. Download again.');
                        if (!value || !Array.isArray(value.rows) || !Array.isArray(value.columns) ||
                            !Number.isSafeInteger(value.total) || value.total < 0 || !Number.isSafeInteger(value.scanned) || value.scanned < 0 || value.scanned > 500 ||
                            total !== null && total !== value.total) throw new Error('Invalid CSV export response.');
                        if (columns === null) { columns = value.columns; lines.push(columns.map(csvAgent).join(',') + '\r\n'); }
                        else if (JSON.stringify(columns) !== JSON.stringify(value.columns)) throw new Error('The CSV columns changed. Download again.');
                        total = value.total;
                        const end = offset + value.scanned;
                        if (end > total || (value.next_offset === null ? end !== total : value.next_offset !== end || end <= offset || end >= total)) throw new Error('The CSV export is incomplete.');
                        value.rows.forEach(row => {
                            if (!Array.isArray(row) || row.length !== columns.length) throw new Error('Invalid CSV record.');
                            lines.push(row.map(cell => csvAgent(String(cell ?? ''))).join(',') + '\r\n'); count++;
                        });
                        status.textContent = `Exporting ${end} / ${total} records…`; offset = value.next_offset;
                    } while (offset !== null);
                    const url = URL.createObjectURL(new Blob(lines, {type:'text/csv;charset=utf-8'}));
                    const link = document.createElement('a'); link.href = url;
                    link.download = 'webuzo-de-noise-' + actionPrefix + '-' + new Date().toISOString().replace(/[:.]/g, '-') + '.csv';
                    document.body.appendChild(link);
                    try { link.click(); } finally { link.remove(); setTimeout(() => URL.revokeObjectURL(url), 10000); }
                    status.textContent = `CSV downloaded: ${count} records.`;
                } catch (error) { status.textContent = error.message; }
                finally { reviewExport.disabled = false; }
                return;
            }
            const exportButton = actionPrefix === 'agents' ? event.target.closest('[data-hdn-export-agents]') : null;
            if (exportButton && job) {
                const exportJob = job;
                const status = output.querySelector('[data-hdn-export-status]');
                exportButton.disabled = true;
                status.textContent = 'Preparing CSV…';
                try {
                    const lines = ['\uFEFFagent,hits\r\n'];
                    let offset = 0, count = 0;
                    do {
                        const value = (await request('agents_export', 1, false, offset, exportJob)).export;
                        if (!value || !Array.isArray(value.rows) || !Number.isSafeInteger(value.total) || value.total < 0) {
                            throw new Error('The panel returned an invalid CSV export.');
                        }
                        for (const row of value.rows) {
                            if (!Array.isArray(row) || row.length !== 2 || typeof row[0] !== 'string' || !Number.isSafeInteger(row[1]) || row[1] < 0) {
                                throw new Error('The panel returned an invalid agent row.');
                            }
                            lines.push(csvAgent(row[0]) + ',' + row[1] + '\r\n');
                        }
                        count += value.rows.length;
                        if (value.next_offset !== null && (value.next_offset !== count || count <= offset)) {
                            throw new Error('The CSV export did not advance. Try again.');
                        }
                        offset = value.next_offset;
                        status.textContent = `Exporting ${count} / ${value.total} agents…`;
                        if (offset === null && count !== value.total) throw new Error('The CSV export is incomplete. Try again.');
                    } while (offset !== null);
                    const url = URL.createObjectURL(new Blob(lines, {type:'text/csv;charset=utf-8'}));
                    const link = document.createElement('a');
                    link.href = url;
                    link.download = 'webuzo-de-noise-agents-' + new Date().toISOString().replace(/[:.]/g, '-') + '.csv';
                    document.body.appendChild(link);
                    try { link.click(); } finally {
                        link.remove();
                        setTimeout(() => URL.revokeObjectURL(url), 10000);
                    }
                    status.textContent = `CSV downloaded: ${count} agents.`;
                } catch (error) {
                    status.textContent = error.message;
                } finally { exportButton.disabled = false; }
                return;
            }
            const page = event.target.closest('[data-hdn-analysis-page]');
            if (!page || !job) return;
            try { await refreshView(Number(page.dataset.hdnAnalysisPage)); }
            catch (error) { progress.textContent = error.message; }
        });
        if (domainFilter) domainFilter.addEventListener('change', async () => {
            if (!job) return;
            try { display(await request(actionPrefix + '_status', 1)); }
            catch (error) { progress.textContent = error.message; }
        });
        // Ask once for the last server-side job too: its start response may have
        // been lost, or this may be a new browser tab. This does not start work.
        observe();
      }
    };
    initializeReview('hdn-log-scan', 'hdn-analysis', 'log_scan', 'filters', 'Analyze logs');
    initializeReview('hdn-activity-scan', 'hdn-activity', 'activity', 'activity', 'Refresh activity');
    initializeReview('hdn-agents-scan', 'hdn-agents', 'agents', 'agents', 'Analyze current agents');
    initializeReview('hdn-php_files-scan', 'hdn-php_files', 'php_files', 'bans', 'Analyze PHP 404s');
    const appendLines = (field, values, insensitive = false) => {
        const lines = field.value.split(/\r?\n/).map(value => value.trim()).filter(Boolean);
        const key = value => insensitive ? value.toLowerCase() : value;
        const seen = new Set(lines.map(key));
        let added = 0;
        values.forEach(value => {
            value = value.trim();
            if (value && !/[\r\n]/.test(value) && !seen.has(key(value))) {
                seen.add(key(value)); lines.push(value); added++;
            }
        });
        field.value = lines.join('\n');
        if (added) field.dispatchEvent(new Event('input', {bubbles: true}));
        return added;
    };
    // Delegation also handles restored reports and newly loaded result pages.
    document.addEventListener('change', event => {
        if (!event.target.matches('[data-hdn-select-inventory]')) return;
        event.target.closest('[data-hdn-inventory]').querySelectorAll('[data-hdn-inventory-value]:not(:disabled)')
            .forEach(box => { if (!box.closest('[hidden]')) box.checked = event.target.checked; });
    });
    document.addEventListener('click', event => {
        const button = event.target.closest('[data-hdn-append-selected]');
        if (!button) return;
        const report = button.closest('[data-hdn-inventory]');
        const allowed = report.dataset.hdnInventory === 'agents' ?
            ['tool_agents', 'ai_agents', 'search_agents', 'seo_agents', 'agents'] : ['bans-missing_files-list'];
        let added = 0, selected = 0;
        report.querySelectorAll('[data-hdn-inventory-value]:checked:not(:disabled)').forEach(box => {
            const destination = box.closest('[data-hdn-inventory-row]').querySelector('[data-hdn-inventory-field]').value;
            if (!allowed.includes(destination)) return;
            const field = document.getElementById(destination);
            if (!field) return;
            selected++;
            added += appendLines(field, [box.dataset.hdnInventoryValue], report.dataset.hdnInventory === 'agents');
            const collapsed = field.closest('details');
            if (collapsed) collapsed.open = true;
            box.checked = false;
        });
        const all = report.querySelector('[data-hdn-select-inventory]');
        if (all) all.checked = false;
        report.querySelector('[data-hdn-append-status]').textContent = selected ?
            `${added} new entries appended; ${selected - added} already present. Review your lists, then Save & Apply.` : 'Select entries to append first.';
    });
    const presets = JSON.parse(document.getElementById('hdn-agent-presets').textContent);
    const probePresets = JSON.parse(document.getElementById('hdn-probe-presets').textContent);
    document.querySelectorAll('[data-hdn-probe-preset]').forEach(button => button.addEventListener('click', () => {
        const field = document.getElementById(button.dataset.hdnProbeField);
        appendLines(field, probePresets[button.dataset.hdnProbePreset] || []);
    }));
    document.getElementById('hdn-probe-domain')?.addEventListener('change', event => {
        document.querySelectorAll('[data-hdn-probe-domain]').forEach(panel => { panel.hidden = panel.dataset.hdnProbeDomain !== event.target.value; });
    });
    document.querySelectorAll('[data-hdn-preset]').forEach(button => button.addEventListener('click', () => {
        const field = document.getElementById(button.dataset.hdnAgentField);
        appendLines(field, presets[button.dataset.hdnPreset] || [], true);
    }));
    document.querySelectorAll('[data-hdn-access-method]').forEach(select => {
        const form = select.closest('form');
        const update = () => {
            form.querySelector('[data-hdn-basic-controls]').hidden = select.value !== 'basic';
            form.querySelector('[data-hdn-captcha-controls]').hidden = select.value !== 'captcha';
            form.querySelector('[name="access_username"]').required = select.value === 'basic';
            form.querySelector('[name="captcha_seconds"]').required = select.value === 'captcha';
        };
        select.addEventListener('change', update);
        update();
    });
    document.querySelectorAll('[data-hdn-access-source]').forEach(select => {
        const controls = select.closest('form').querySelector('[data-hdn-access-controls]');
        select.addEventListener('change', () => { controls.disabled = select.value === 'inherit'; });
    });
    const tabs = [...document.querySelectorAll('[data-hdn-tab]')];
    tabs.forEach(button => {
        button.addEventListener('click', () => {
            tabs.forEach(tab => {
                const selected = tab === button;
                tab.setAttribute('aria-selected', String(selected));
                tab.tabIndex = selected ? 0 : -1;
                document.getElementById(tab.getAttribute('aria-controls')).hidden = !selected;
            });
            const save = document.getElementById('hdn-save');
            if (save) save.hidden = ['general', 'cron', 'fail2ban', 'activity', 'access', 'countries'].includes(button.dataset.hdnTab);
            document.querySelectorAll('input[name="tab"]').forEach(input => { input.value = button.dataset.hdnTab; });
            if (button.dataset.hdnTab === 'fail2ban' && document.getElementById('hdn-fail2ban-status')?.dataset.loaded === 'false') {
                document.getElementById('hdn-fail2ban-refresh')?.requestSubmit();
            }
        });
        button.addEventListener('keydown', event => {
            if (!['ArrowLeft', 'ArrowRight', 'ArrowUp', 'ArrowDown', 'Home', 'End'].includes(event.key)) return;
            event.preventDefault();
            const columns = getComputedStyle(button.parentElement).gridTemplateColumns.split(' ').length;
            const step = event.key === 'ArrowUp' ? -columns : event.key === 'ArrowDown' ? columns :
                event.key === 'ArrowLeft' ? -1 : 1;
            const index = event.key === 'Home' ? 0 : event.key === 'End' ? tabs.length - 1 :
                (tabs.indexOf(button) + step + tabs.length) % tabs.length;
            tabs[index].click();
            tabs[index].focus();
        });
    });
    document.addEventListener('invalid', event => {
        const panel = event.target.closest('[role="tabpanel"]');
        if (panel?.hidden) document.getElementById(panel.getAttribute('aria-labelledby'))?.click();
    }, true);
    document.getElementById('hdn-select')?.addEventListener('click', () => {
        const boxes = [...document.querySelectorAll('.hdn-target')];
        const next = boxes.some(box => !box.checked);
        boxes.forEach(box => { box.checked = next; });
    });
})();
