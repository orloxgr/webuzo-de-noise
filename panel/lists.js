(() => {
    'use strict';
    const sizes = ['20', '50', '100', '500', 'all'];
    const csvCell = value => {
        let text = String(value ?? '');
        if (/^[\s\uFEFF]*[=+@-]|^[\t\r\n]/.test(text)) text = "'" + text;
        return '"' + text.replace(/"/g, '""') + '"';
    };
    const csv = rows => '\uFEFF' + rows.map(row => row.map(csvCell).join(',')).join('\r\n') + '\r\n';
    const pageRows = (rows, size, page) => {
        if (!sizes.includes(String(size))) throw new Error('Invalid list size');
        const pages = size === 'all' ? 1 : Math.max(1, Math.ceil(rows.length / Number(size)));
        page = Math.max(1, Math.min(page, pages));
        const start = size === 'all' ? 0 : (page - 1) * Number(size);
        return {page, pages, visible: rows.slice(start, size === 'all' ? undefined : start + Number(size))};
    };
    const ruleData = fields => {
        const value = key => fields.find(field => field.name.endsWith('[' + key + ']'))?.value || '';
        const setting = field => field.type === 'checkbox' ? (field.checked ? 'Yes' : 'No') :
            field.multiple ? [...field.selectedOptions].map(option => option.textContent).join('; ') : field.value;
        return [value('id'), value('path'), fields.filter(field => !/\[(id|path)\]$/.test(field.name))
            .map(field => field.name.replace(/^[^[]+\[\d+\]/, '') + ': ' + setting(field)).join(' | ')];
    };
    if (typeof module !== 'undefined') module.exports = {csv, csvCell, pageRows, ruleData};
    if (typeof document === 'undefined') return;
    const download = (rows, name) => {
        const url = URL.createObjectURL(new Blob([csv(rows)], {type: 'text/csv;charset=utf-8'}));
        const link = document.createElement('a');
        link.href = url;
        link.download = 'webuzo-de-noise-' + name.replace(/[^a-z0-9_-]/gi, '-').toLowerCase() + '-' + new Date().toISOString().replace(/[:.]/g, '-') + '.csv';
        document.body.appendChild(link);
        try { link.click(); } finally { link.remove(); setTimeout(() => URL.revokeObjectURL(url), 10000); }
    };
    const controllers = new WeakMap();
    const create = list => {
        const table = list.tagName === 'TABLE';
        const records = () => table ? [...list.tBodies[0].rows] : [...list.children].filter(row => row.hasAttribute('data-hdn-list-row'));
        const header = () => list.dataset.hdnColumns ? JSON.parse(list.dataset.hdnColumns) : table ? [...list.tHead.rows[0].cells].filter(cell => cell.textContent.trim() !== 'Select').map(cell => cell.textContent.trim()) : JSON.parse(list.dataset.hdnColumns || '["Entry"]');
        const data = row => {
            if (row.dataset.hdnCsv) return JSON.parse(row.dataset.hdnCsv);
            if (list.hasAttribute('data-hdn-rule-list')) {
                return ruleData([...row.querySelectorAll('input[name],select[name],textarea[name]')]);
            }
            if (!table) return [(row.querySelector(':scope > summary') || row).textContent.trim()];
            const cells = [...row.cells];
            const headings = [...list.tHead.rows[0].cells];
            return cells.filter((_, i) => headings[i]?.textContent.trim() !== 'Select').map(cell => cell.textContent.trim());
        };
        const controls = document.createElement('nav');
        controls.className = 'hdn-list-controls u-mb10 u-mt10';
        controls.setAttribute('aria-label', list.dataset.hdnList + ' pages and download');
        const label = document.createElement('label'); label.append('Show per page ');
        const select = document.createElement('select'); select.className = 'form-select';
        sizes.forEach(size => { const option = document.createElement('option'); option.value = size; option.textContent = size === 'all' ? 'All' : size; select.appendChild(option); });
        label.appendChild(select); controls.appendChild(label);
        const counter = document.createElement('span'); counter.setAttribute('role', 'status');
        const button = text => { const b = document.createElement('button'); b.type = 'button'; b.className = 'button button-secondary'; b.textContent = text; return b; };
        const previous = button('Previous'), next = button('Next'), exportButton = button('Download CSV');
        exportButton.title = 'Download every record in this list, across all pages.';
        controls.append(counter, previous, next, exportButton);
        list.before(controls);
        const key = 'hdn-list-size:' + list.dataset.hdnList;
        try { const saved = localStorage.getItem(key); if (sizes.includes(saved)) select.value = saved; } catch (_) {}
        let page = 1;
        const refresh = (added = false) => {
            const all = records();
            if (added && list.hasAttribute('data-hdn-rule-list') && select.value !== 'all') page = Math.max(1, Math.ceil(all.length / Number(select.value)));
            const result = pageRows(all, select.value, page); page = result.page;
            const shown = new Set(result.visible); all.forEach(row => { row.hidden = !shown.has(row); });
            counter.textContent = `Page ${page} / ${result.pages} · ${all.length} records`;
            previous.disabled = page === 1; next.disabled = page === result.pages;
        };
        select.addEventListener('change', () => { page = 1; try { localStorage.setItem(key, select.value); } catch (_) {} refresh(); });
        previous.addEventListener('click', () => { page--; refresh(); });
        next.addEventListener('click', () => { page++; refresh(); });
        exportButton.addEventListener('click', () => download([header(), ...records().map(data)], list.dataset.hdnList));
        controllers.set(list, {refresh}); refresh();
    };
    const initialize = () => document.querySelectorAll('[data-hdn-list]').forEach(list => { if (!controllers.has(list)) create(list); });
    initialize();
    new MutationObserver(changes => {
        initialize();
        const changed = new Map();
        changes.forEach(change => {
            const target = change.target.tagName === 'TBODY' ? change.target.parentElement : change.target;
            if (controllers.has(target)) changed.set(target, changed.get(target) || [...change.addedNodes].some(node => node.nodeType === 1 && node.hasAttribute('data-hdn-list-row')));
        });
        changed.forEach((added, list) => controllers.get(list).refresh(added));
    }).observe(document.getElementById('hdn-container'), {childList: true, subtree: true});
    // Remote lists change only their own fragment, preserving unsaved settings.
    document.addEventListener('change', event => {
        const select = event.target.closest('[data-hdn-remote-size]');
        if (!select) return;
        const url = new URL(location.href); const scope = select.dataset.hdnRemoteSize;
        url.searchParams.set(scope + '_per_page', select.value); url.searchParams.set(scope + '_page', '1');
        const wrapper = select.closest('[data-hdn-remote-list]');
        url.searchParams.set('tab', scope === 'wordpress' ? 'fail2ban' : 'bans');
        if (scope === 'wordpress') url.searchParams.set('wordpress_read', '1');
        if (wrapper.dataset.hdnView) url.searchParams.set(scope + '_view', wrapper.dataset.hdnView);
        load(url, wrapper);
    });
    const load = async (url, wrapper) => {
        try {
            wrapper.setAttribute('aria-busy', 'true');
            const response = await fetch(url, {credentials: 'same-origin'});
            if (!response.ok) throw new Error('Could not read this page.');
            const page = new DOMParser().parseFromString(await response.text(), 'text/html');
            const replacement = page.querySelector('[data-hdn-remote-list="' + wrapper.dataset.hdnRemoteList + '"]');
            if (!replacement) throw new Error('Your panel session may have expired. Sign in again.');
            wrapper.replaceWith(document.importNode(replacement, true));
        } catch (error) { wrapper.removeAttribute('aria-busy'); alert(error.message); }
    };
    document.addEventListener('click', event => {
        const link = event.target.closest('[data-hdn-remote-page]');
        if (link) { event.preventDefault(); load(new URL(link.href), link.closest('[data-hdn-remote-list]')); }
    });
})();
