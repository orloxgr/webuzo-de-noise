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
        if (module === 'custom_endpoints') document.getElementById('hdn-custom-endpoints-box').open = true;
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
    const findingSelection = (button, only404=false) => {
        const select = button.closest('.hdn-endpoint-card')?.querySelector('[data-hdn-finding-paths]');
        return select ? [...select.selectedOptions].filter(o=>!only404 || o.dataset.hdnHas404==='1').map(o=>o.value) : null;
    };
    document.addEventListener('click', event => {
        const chooseFindings=event.target.closest('[data-hdn-select-findings]');
        if (chooseFindings) {
            const select=chooseFindings.closest('.hdn-endpoint-card').querySelector('[data-hdn-finding-paths]');
            [...select.options].forEach(option=>{option.selected=chooseFindings.dataset.hdnSelectFindings==='all';});
            return;
        }
        const bulk404 = event.target.closest('[data-hdn-append-endpoint404], [data-hdn-endpoint404-group]');
        if (bulk404) {
            const field=document.getElementById('hdn-endpoint404-paths');
            const domainSelect=document.getElementById('hdn-endpoint404-targets');
            const wasEmpty=!field.value.trim();
            const selected = bulk404.hasAttribute('data-hdn-endpoint404-group') ?
                (findingSelection(bulk404,true) ?? JSON.parse(bulk404.dataset.hdnEndpoint404Group)).map(path=>({path,site:bulk404.dataset.hdnEndpointSite})) :
                [...document.querySelectorAll('[data-hdn-endpoint404-path]:checked')].map(box=>({path:box.dataset.hdnEndpoint404Path,site:box.dataset.hdnEndpointSite}));
            if (!selected.length) { document.getElementById('hdn-endpoint-append-status').textContent='Select one or more paths with recorded 404 responses to append.'; return; }
            const paths=new Set(field.value.split(/\r?\n/).map(p=>p.trim()).filter(Boolean));
            const before=paths.size;
            selected.forEach(item=>{ if (item.path.startsWith('/') && !/[\r\n?#]/.test(item.path)) paths.add(item.path); });
            field.value=[...paths].join('\n');
            if (wasEmpty && !domainSelect.selectedOptions.length) {
                const sites=new Set(selected.map(item=>item.site));
                sites.forEach(site=>{ if (![...domainSelect.options].some(o=>o.value===site)) domainSelect.appendChild(new Option(site,site)); });
                [...domainSelect.options].forEach(option=>{option.selected=sites.has(option.value);});
            }
            document.getElementById('hdn-endpoint404-box').open=true;
            document.getElementById('hdn-endpoint404-message').textContent=`${paths.size-before} new exact paths appended. Enabled switch, attempt threshold, counting window and duration kept. Review domains, then Save & Apply.`;
            return;
        }
        const suggestion = event.target.closest('[data-hdn-append-endpoint], [data-hdn-endpoint-group]');
        if (suggestion) {
            const list = document.getElementById('hdn-custom_endpoints-rows');
            const field = (row,key) => row.querySelector('[name$="[' + key + ']"]');
            const target = suggestion.dataset.hdnEndpointSite;
            const grouped = suggestion.hasAttribute('data-hdn-endpoint-group');
            const patterns = grouped ? (findingSelection(suggestion) ?? JSON.parse(suggestion.dataset.hdnEndpointGroup)) : [suggestion.dataset.hdnAppendEndpoint];
            if (!patterns.length) { document.getElementById('hdn-endpoint-append-status').textContent='Select one or more exact paths to append.'; return; }
            const type = grouped ? 'exact' : (suggestion.dataset.hdnEndpointType || 'exact');
            let added = 0;
            for (const pattern of patterns) {
                const duplicate = [...list.querySelectorAll('.hdn-rule')].some(row => field(row,'type').value === type &&
                    field(row,'pattern').value === pattern && [...row.querySelector('[name$="[targets][]"]').selectedOptions].some(o => o.value === target));
                if (duplicate) continue;
                document.querySelector('[data-hdn-add="custom_endpoints"]').click();
                const row = list.querySelector('.hdn-rule:last-child');
                field(row,'name').value = suggestion.dataset.hdnEndpointName || pattern;
                field(row,'type').value = type;
                field(row,'pattern').value = pattern;
                const domains = row.querySelector('[name$="[targets][]"]');
                let option = [...domains.options].find(o => o.value === target);
                if (!option) { option = new Option(target, target); domains.appendChild(option); }
                option.selected = true;
                added++;
            }
            document.getElementById('hdn-endpoint-append-status').textContent = added ?
                `Added ${added} disabled endpoint rule(s) for this domain, with Also ban IP off. Review, enable if appropriate, then Save & Apply.` :
                'These domain/path rules already exist. Your settings were kept.';
            return;
        }
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
    document.addEventListener('change', event=>{
        if (event.target.matches('[data-hdn-select-endpoint404]')) {
            document.querySelectorAll('[data-hdn-endpoint404-path]').forEach(box=>{box.checked=event.target.checked;});
        }
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
