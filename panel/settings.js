(() => {
    'use strict';
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
        const request = async (action, page = 1, initial = false) => {
            const body = initial ? new FormData(scanForm) : new FormData();
            body.set('action', action);
            body.set('token', scanForm.querySelector('input[name="token"]').value);
            body.set('tab', tab);
            if (job) body.set('analysis_job', job);
            body.set('analysis_page', page);
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
    const presets = JSON.parse(document.getElementById('hdn-agent-presets').textContent);
    const probePresets = JSON.parse(document.getElementById('hdn-probe-presets').textContent);
    document.querySelectorAll('[data-hdn-probe-preset]').forEach(button => button.addEventListener('click', () => {
        const field = document.getElementById(button.dataset.hdnProbeField);
        const lines = field.value.split(/\r?\n/).map(value => value.trim()).filter(Boolean);
        (probePresets[button.dataset.hdnProbePreset] || []).forEach(value => { if (!lines.includes(value)) lines.push(value); });
        field.value = lines.join('\n');
    }));
    document.getElementById('hdn-probe-domain')?.addEventListener('change', event => {
        document.querySelectorAll('[data-hdn-probe-domain]').forEach(panel => { panel.hidden = panel.dataset.hdnProbeDomain !== event.target.value; });
    });
    document.querySelectorAll('[data-hdn-preset]').forEach(button => button.addEventListener('click', () => {
        const field = document.getElementById(button.dataset.hdnAgentField);
        const lines = field.value.split(/\r?\n/).map(value => value.trim()).filter(Boolean);
        (presets[button.dataset.hdnPreset] || []).forEach(agent => {
            if (!lines.some(line => line.toLowerCase() === agent.toLowerCase())) lines.push(agent);
        });
        field.value = lines.join('\n');
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
