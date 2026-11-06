(() => {
    'use strict';
    const presets = JSON.parse(document.getElementById('hdn-rule-presets').textContent);
    const names = value => value.toLowerCase().split(/[\s,]+/).filter(Boolean).sort().join(',');
    const path = value => value.replace(/\/+$/, '') || '/';
    const domainSelect = document.getElementById('hdn-exception-domain');
    domainSelect?.addEventListener('change', () => {
        document.querySelectorAll('[data-hdn-exception-domain]').forEach(row => {
            row.hidden = row.dataset.hdnExceptionDomain !== domainSelect.value;
        });
    });
    document.querySelectorAll('[data-hdn-add]').forEach(button => button.addEventListener('click', () => {
        const module = button.dataset.hdnAdd;
        const list = document.getElementById('hdn-' + module + '-rows');
        const preset = (presets[module] || []).find(item => item.key === button.dataset.hdnRulePreset);
        const existing = [...list.querySelectorAll('.hdn-rule')];
        const field = (row, key) => row.querySelector('[name$="[' + key + ']"]');
        const match = (row, rule) => path(field(row, 'path').value) === path(rule.path) &&
            names(field(row, module === 'static' ? 'extensions' : 'parameters').value) ===
            names(rule[module === 'static' ? 'extensions' : 'parameters'].join(' '));
        const rules = preset ? preset.rules.filter(rule => !existing.some(row => match(row, rule))) : [null];
        const message = document.getElementById('hdn-' + module + '-message');
        if (!rules.length) { message.textContent = 'These rules already exist. Your settings were kept.'; return; }
        const template = document.getElementById('hdn-' + module + '-template');
        rules.forEach(rule => {
            const used = new Set([...document.querySelectorAll('.hdn-rule input[name$="[id]"]')].map(input => input.value));
            const base = rule ? rule.id : module;
            let number = 1, ident = rule ? base : base + '_1';
            while (used.has(ident)) ident = base + '_' + (++number);
            const indices = [...list.querySelectorAll('input[name$="[id]"]')].map(input => Number(input.name.match(/\[(\d+)\]/)?.[1] ?? -1));
            const next = indices.reduce((largest, value) => Math.max(largest, value), -1) + 1;
            const fragment = template.content.cloneNode(true);
            fragment.querySelectorAll('[name]').forEach(input => { input.name = input.name.replace('__INDEX__', String(next)); });
            const row = fragment.querySelector('.hdn-rule');
            field(row, 'id').value = ident;
            if (rule) {
                for (const [key, value] of Object.entries(rule)) {
                    if (key === 'id' || key === 'targets') continue;
                    const input = field(row, key === 'action' ? 'rule_action' : key);
                    if (input.type === 'checkbox') input.checked = value;
                    else input.value = Array.isArray(value) ? value.join(input.tagName === 'TEXTAREA' ? '\n' : ' ') : value;
                }
            }
            list.appendChild(fragment);
        });
        message.textContent = 'Added ' + rules.length + ' rule(s). Review domains, then Save & Apply.';
    }));
    document.addEventListener('click', event => {
        const addAgents = event.target.closest('[data-hdn-filter-agents]');
        if (addAgents) {
            const field = addAgents.closest('.hdn-rule').querySelector('[name$="[agents]"]');
            const agents = JSON.parse(document.getElementById('hdn-agent-presets').textContent).search_crawlers || [];
            const lines = field.value.split(/\r?\n/).map(value => value.trim()).filter(Boolean);
            agents.forEach(agent => { if (!lines.some(line => line.toLowerCase() === agent.toLowerCase())) lines.push(agent); });
            field.value = lines.join('\n');
            document.getElementById('hdn-filters-message').textContent = 'Added crawler names to this rule only. Review domains, action and rate, then Save & Apply.';
        }
        const robots = event.target.closest('[data-hdn-robots]');
        if (robots) {
            const row = robots.closest('.hdn-rule');
            const prefix = row.querySelector('[name$="[path]"]').value.trim();
            const parameters = [...new Set(row.querySelector('[name$="[parameters]"]').value.split(/\r?\n/).map(value => value.trim()).filter(Boolean))];
            const message = document.getElementById('hdn-filters-message');
            const preview = document.getElementById('hdn-robots-preview');
            // Only render literal path prefixes and valid parameter names.
            if (!/^\/[A-Za-z0-9_./~-]*$/.test(prefix) || prefix.split('/').includes('..') || prefix.includes('//') ||
                !parameters.length || parameters.some(name => !/^[A-Za-z][A-Za-z0-9_.-]*$/.test(name))) {
                preview.hidden = true;
                message.textContent = 'Use a literal URL path and valid parameter names before generating robots.txt suggestions.';
                return;
            }
            const selected = [...row.querySelector('select[name$="[targets][]"]').selectedOptions].map(option => option.textContent.trim());
            document.getElementById('hdn-robots-scope').textContent = selected.length ? 'Selected domains: ' + selected.join(', ') : 'Scope: all domains. Apply these suggestions only to sites that actually use these parameters.';
            document.getElementById('hdn-robots-text').value = '# Merge into the appropriate existing User-agent groups.\n' +
                parameters.map(name => 'Disallow: ' + prefix + '*?*' + name + '=').join('\n') + '\n';
            document.getElementById('hdn-robots-message').textContent = 'Preview generated. No robots.txt file was changed.';
            message.textContent = '';
            preview.hidden = false;
        }
        const button = event.target.closest('[data-hdn-remove]');
        if (button) button.closest('.hdn-rule').remove();
    });
    document.getElementById('hdn-robots-copy')?.addEventListener('click', async () => {
        const field = document.getElementById('hdn-robots-text');
        const message = document.getElementById('hdn-robots-message');
        try {
            await navigator.clipboard.writeText(field.value);
            message.textContent = 'Copied. Merge into the appropriate existing User-agent groups after review.';
        } catch (_) {
            field.focus(); field.select();
            message.textContent = 'Text selected. Press Ctrl+C to copy.';
        }
    });
})();
