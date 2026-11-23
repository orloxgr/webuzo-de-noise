(() => {
    'use strict';
    const cards = [...document.querySelectorAll('[data-hdn-agent-category]')];
    if (!cards.length) return;
    const lines = value => [...new Map(value.split(/\r?\n/).map(x => x.trim()).filter(Boolean).map(x => [x.toLowerCase(), x])).values()];
    const control = (row, suffix) => row.querySelector(`[name$="[${suffix}]"]`);
    const rateText = row => `${control(row, 'rate').value || '?'} requests/${control(row, 'unit').value === 's' ? 'second' : 'minute'}; burst ${control(row, 'burst').value}`;
    const refresh = () => {
        const individual = [], groups = [], blocks = [], ownNames = new Map(), conflicts = new Map();
        const namesSeen = new Map(), groupSeen = new Map();
        cards.forEach(card => {
            const field = card.dataset.hdnAgentCategory;
            const block = document.getElementById(field), group = document.getElementById(field + '_rate');
            const scope = card.querySelectorAll('.hdn-agent-list')[1];
            const nameSet = new Set([...lines(block.value), ...lines(group.value)]);
            group.setCustomValidity('');
            control(scope, 'rate').required = control(scope, 'enabled').checked;
            if (control(scope, 'enabled').checked) {
                if (!lines(group.value).length) group.setCustomValidity('Enter at least one agent for an enabled group.');
                lines(group.value).forEach(name => {
                    const key = name.toLowerCase();
                    if (groupSeen.has(key)) {
                        const message = `Agent appears in multiple enabled groups: ${name}`;
                        group.setCustomValidity(message); groupSeen.get(key).setCustomValidity(message);
                        conflicts.set(field, message);
                    }
                    groupSeen.set(key, group);
                    groups.push({name, field, label:`Group rate limit (${card.querySelector('summary').textContent.trim()}): ${rateText(scope)}; overrides blocklist`});
                });
            }
            if (card.querySelector(`[name="${field}_enabled"]`).checked) lines(block.value).forEach(name => blocks.push({name, field}));
            card.querySelectorAll('[data-hdn-agent-rate-row]').forEach(row => {
                const agent = control(row, 'agent'), rate = control(row, 'rate');
                const enabled = control(row, 'enabled').checked;
                agent.setCustomValidity(''); rate.required = enabled;
                if (agent.value.trim()) nameSet.add(agent.value.trim());
                if (!enabled || !agent.value.trim()) return;
                const key = agent.value.trim().toLowerCase();
                const budget = JSON.stringify([Number(rate.value) * (control(row, 'unit').value === 's' ? 60 : 1), Number(control(row, 'burst').value)]);
                if (namesSeen.has(key) && namesSeen.get(key).budget !== budget) {
                    const message = `Conflicting individual limits for ${agent.value.trim()}`;
                    agent.setCustomValidity(message); namesSeen.get(key).agent.setCustomValidity(message);
                    conflicts.set(field, message);
                }
                namesSeen.set(key, {budget, agent});
                individual.push({name:agent.value.trim(), field, label:`Individual rate limit: ${rateText(row)} (match: ${agent.value.trim()}); overrides group and blocklist`});
            });
            ownNames.set(card, nameSet);
        });
        const order = (a, b) => b.name.length - a.name.length ||
            (a.name.toLowerCase() < b.name.toLowerCase() ? -1 : a.name.toLowerCase() > b.name.toLowerCase() ? 1 : 0) ||
            (a.field < b.field ? -1 : a.field > b.field ? 1 : 0);
        individual.sort(order); groups.sort(order);
        cards.forEach(card => {
            const body = card.querySelector('[data-hdn-agent-effective]');
            body.replaceChildren();
            [...ownNames.get(card)].sort().forEach(name => {
                const matches = item => name.toLowerCase().includes(item.name.toLowerCase());
                const chosen = individual.find(matches) || groups.find(matches);
                const action = chosen ? chosen.label : blocks.some(matches) ? 'Blocklist: 403 in Enforce' : 'No active User-Agent action';
                const row = document.createElement('tr');
                [name, action].forEach(value => { const cell = document.createElement('td'); cell.textContent = value; row.appendChild(cell); });
                body.appendChild(row);
            });
            card.querySelector('[data-hdn-agent-conflicts]').textContent = conflicts.get(card.dataset.hdnAgentCategory) ||
                'Preview for configured names using current edits. Actual requests match their full User-Agent; other security rules remain independent.';
        });
    };
    cards.forEach(card => {
        const body = card.querySelector('[data-hdn-agent-rate-body]');
        let next = body.querySelectorAll('[data-hdn-agent-rate-row]').length;
        card.querySelector('[data-hdn-agent-add]').addEventListener('click', () => {
            const fragment = card.querySelector('[data-hdn-agent-rate-template]').content.cloneNode(true);
            fragment.querySelectorAll('[name]').forEach(input => { input.name = input.name.replace('__INDEX__', String(next)); });
            next++;
            body.appendChild(fragment); card.open = true;
            body.lastElementChild.querySelector('[name$="[agent]"]').focus();
            refresh();
        });
        card.addEventListener('click', event => {
            const button = event.target.closest('[data-hdn-agent-remove]');
            if (!button) return;
            button.closest('[data-hdn-agent-rate-row]').remove(); refresh();
        });
        card.addEventListener('input', refresh);
        card.addEventListener('change', refresh);
    });
    // A conflicting hidden row must be made visible before native validation.
    document.addEventListener('invalid', event => {
        if (event.target.form?.id !== 'hdn-settings') return;
        let parent = event.target.parentElement;
        while (parent) { if (parent.tagName === 'DETAILS') parent.open = true; parent = parent.parentElement; }
    }, true);
    refresh();
})();
