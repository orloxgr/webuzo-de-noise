(() => {
    'use strict';
    document.querySelectorAll('[data-hdn-various-toggle]').forEach(toggle => {
        const picker = document.getElementById(toggle.getAttribute('aria-controls'));
        if (!picker) return;
        const append = picker.querySelector('[data-hdn-various-append]');
        const status = picker.querySelector('[data-hdn-various-status]');
        const checked = () => [...picker.querySelectorAll('[data-hdn-various-name]:checked')];
        const show = open => {
            picker.hidden = !open;
            toggle.setAttribute('aria-expanded', String(open));
        };
        toggle.addEventListener('click', () => show(picker.hidden));
        picker.querySelector('[data-hdn-various-close]').addEventListener('click', () => {
            show(false); toggle.focus();
        });
        picker.addEventListener('change', () => {
            const count = checked().length;
            append.disabled = count === 0;
            status.textContent = count ? `${count} names selected. Append adds them to this editor only; Save & Apply is separate.` : 'No names selected.';
        });
        append.addEventListener('click', () => {
            const destination = picker.dataset.hdnAgentField;
            if (!['agents', 'agents_rate'].includes(destination)) return;
            const field = document.getElementById(destination);
            if (!field) return;
            const selected = checked();
            const seen = new Set(field.value.split(/\r?\n/).map(name => name.trim().toLowerCase()));
            const added = [];
            selected.forEach(box => {
                const name = box.value.trim(), key = name.toLowerCase();
                if (name && !/[\r\n]/.test(name) && !seen.has(key)) {
                    seen.add(key); added.push(name);
                }
            });
            if (added.length) {
                field.value += (field.value && !/\n$/.test(field.value) ? '\n' : '') + added.join('\n');
                field.dispatchEvent(new Event('input', {bubbles:true}));
            }
            selected.forEach(box => {box.checked = false;});
            append.disabled = true;
            status.textContent = `${added.length} new entries appended; ${selected.length - added.length} already present. Review this list, then Save & Apply. Settings were not saved or enabled.`;
        });
        append.disabled = checked().length === 0;
    });
})();
