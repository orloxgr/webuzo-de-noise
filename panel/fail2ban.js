(() => {
    'use strict';
    let refreshing = false, polling = false;
    const request = async form => {
        const response = await fetch(form.getAttribute('action') || location.href, {
            method: 'POST', body: new FormData(form), credentials: 'same-origin',
            headers: {'X-HDN-Analysis': '1'}
        });
        let result;
        try { result = await response.json(); }
        catch (_) { throw new Error('The panel session may have expired. Sign in again and refresh status.'); }
        if (!response.ok || !result.ok) throw new Error(result.error || 'Fail2ban request failed.');
        return result;
    };
    const displayError = (form, error) => {
        let output = document.getElementById('hdn-fail2ban-request-error');
        if (!output) {
            output = document.createElement('p');
            output.id = 'hdn-fail2ban-request-error';
            output.className = 'alert alert-danger u-mb20';
            output.setAttribute('role', 'alert');
            form.before(output);
        }
        output.textContent = error.message;
    };
    const refresh = async form => {
        if (refreshing) return;
        refreshing = true;
        const button = form.querySelector('button');
        button.disabled = true;
        try {
            const result = await request(form);
            if (typeof result.report !== 'string') throw new Error('The panel returned an incomplete service report.');
            const template = new DOMParser().parseFromString(result.report, 'text/html');
            document.getElementById('hdn-panel-fail2ban').replaceChildren(
                ...[...template.body.childNodes].map(node => document.importNode(node, true)));
            poll();
        } catch (error) { displayError(form, error); }
        finally { refreshing = false; button.disabled = false; }
    };
    const poll = async (manual = false) => {
        if (polling) return;
        const form = document.getElementById('hdn-install-poll');
        const output = document.getElementById('hdn-install-progress');
        if (!form || !output || (!manual && !['queued', 'running'].includes(output.dataset.state))) return;
        polling = true;
        try {
            do {
                const value = await request(form);
                const job = value.install_job;
                if (!job || typeof job.state !== 'string') throw new Error('The panel returned an invalid installation status.');
                output.dataset.state = job.state;
                output.textContent = job.error || job.message || 'Fail2ban installation is in progress…';
                output.className = 'alert u-mb20 ' + (job.state === 'failed' ? 'alert-danger' : 'alert-info');
                if (!['queued', 'running'].includes(job.state)) {
                    if (job.state === 'complete') await refresh(document.getElementById('hdn-fail2ban-refresh'));
                    break;
                }
                await new Promise(resolve => setTimeout(resolve, 2000));
            } while (document.contains(form));
        } catch (error) { displayError(form, error); }
        finally {
            polling = false;
            const current = document.getElementById('hdn-install-poll');
            if (current && current !== form && ['queued', 'running'].includes(document.getElementById('hdn-install-progress')?.dataset.state)) {
                setTimeout(() => poll(), 0);
            }
        }
    };
    document.addEventListener('submit', event => {
        if (event.target.id === 'hdn-fail2ban-refresh') {
            event.preventDefault(); refresh(event.target);
        } else if (event.target.id === 'hdn-install-poll') {
            event.preventDefault(); poll(true);
        }
    });
    poll();
    const tab = document.querySelector('[data-hdn-tab="fail2ban"]');
    const status = document.getElementById('hdn-fail2ban-status');
    if (tab?.getAttribute('aria-selected') === 'true' && status?.dataset.loaded === 'false' && status.dataset.installing !== 'true') {
        document.getElementById('hdn-fail2ban-refresh')?.requestSubmit();
    }
})();
