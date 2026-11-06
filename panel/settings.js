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
        const storageKey = 'hdn-review:' + location.pathname + ':' + actionPrefix + ':' + (scanForm.dataset?.hdnContext || '');
        let job = null, active = false, generation = 0;
        let restoreSelection = true;
        const selectionEdited = () => { restoreSelection = false; };
        scanForm.addEventListener('input', selectionEdited);
        scanForm.addEventListener('change', selectionEdited);
        try { job = sessionStorage.getItem(storageKey); } catch (_) { /* Storage is optional. */ }
        const remember = id => { job = id; try { sessionStorage.setItem(storageKey, id); } catch (_) {} };
        const request = async (action, page = 1, initial = false, exportOffset = null, requestedJob = job) => {
            const body = initial ? new FormData(scanForm) : new FormData();
            body.set('action', action);
            body.set('token', scanForm.querySelector('input[name="token"]').value);
            body.set('tab', tab);
            if (requestedJob) body.set('analysis_job', requestedJob);
            body.set('analysis_page', page);
            if (exportOffset !== null) body.set('export_offset', exportOffset);
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
            return value;
        };
        const display = value => {
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
            cancel.hidden = !active;
            if (value.report) {
                const page = new DOMParser().parseFromString(value.report, 'text/html');
                const report = page.getElementById(prefix + '-output');
                if (!report) throw new Error('The panel returned an unexpected report.');
                output.replaceChildren(...[...report.childNodes].map(node => document.importNode(node, true)));
            }
            if (current.state === 'idle') progress.textContent = '';
            else if (current.state === 'complete') progress.textContent = 'Review completed. All available retained logs were processed; see coverage for missing or unreadable data. Unsaved rule edits are unchanged.';
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
        output.addEventListener('click', async event => {
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
            try { display(await request(actionPrefix + '_status', Number(page.dataset.hdnAnalysisPage))); }
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
            .forEach(box => { box.checked = event.target.checked; });
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
            if (save) save.hidden = ['cron', 'domain-bans', 'wordpress'].includes(button.dataset.hdnTab);
            document.querySelectorAll('input[name="tab"]').forEach(input => { input.value = button.dataset.hdnTab; });
            if (button.dataset.hdnTab === 'wordpress' && document.getElementById('hdn-wordpress-status')?.dataset.loaded === 'false') {
                document.getElementById('hdn-wordpress-refresh')?.requestSubmit();
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
