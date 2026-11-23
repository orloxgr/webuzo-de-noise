'use strict';
// Run against the rendered PHP fixture with actual exported catalog metadata.
const assert = require('node:assert/strict');
const puppeteer = require(process.env.HDN_PUPPETEER || 'puppeteer-core');
(async () => {
    const browser = await puppeteer.launch({executablePath:process.env.HDN_BROWSER,headless:true});
    try {
        const page = await browser.newPage(), errors = [], requests = [];
        page.on('pageerror', error => errors.push(error.message));
        await page.goto(require('node:url').pathToFileURL(process.argv[2]).href);
        page.on('request', request => {if (['fetch','xhr'].includes(request.resourceType()) || request.method() !== 'GET') requests.push(request.url());});
        await page.evaluate(() => {
            window.submissions = 0;
            document.getElementById('hdn-settings').addEventListener('submit', event => {
                event.preventDefault(); window.submissions++;
            });
        });
        const initial = await page.$$eval('textarea', nodes => Object.fromEntries(nodes.map(e => [e.id, e.value])));
        assert.equal(await page.$$eval('[data-hdn-agent-category]', nodes => nodes.length), 5);
        assert.equal(await page.$eval('#hdn-agents-analysis', e => e.open), false);
        await page.click('#hdn-agents-analysis > summary');
        await page.$eval('#hdn-agents-scan [name="analysis_minutes"]', e => {e.value='45';});
        await page.click('#hdn-agents-analysis > summary');
        await page.focus('#hdn-agents-analysis > summary');
        await page.keyboard.press('Enter');
        assert.equal(await page.$eval('#hdn-agents-scan [name="analysis_minutes"]', e => e.value), '45');
        await page.click('#hdn-agents-analysis > summary');
        await page.$eval('[data-hdn-agent-category="search_agents"]', e => {e.open = true;});
        const switches = await page.$$eval('input[type="checkbox"]', nodes => nodes.map(e => [e.name, e.checked]));
        for (const group of ['search_additional', 'search_major']) {
            const selector = `[data-hdn-preset="${group}"][data-hdn-agent-field="search_agents"]`;
            assert.match(await page.$eval(selector, e => e.title), /blocklist/);
            assert.equal(await page.$eval(selector, e => e.type), 'button');
            const expected = await page.$eval('#hdn-agent-presets', (e, key) => JSON.parse(e.textContent)[key], group);
            assert.ok(expected.length > 0);
            const before = await page.$eval('#search_agents', e => e.value.split('\n'));
            await page.click(selector);
            const after = await page.$eval('#search_agents', e => e.value.split('\n'));
            assert.deepEqual(after, before.concat(expected.filter(name => !before.some(old => old.toLowerCase() === name.toLowerCase()))));
            await page.click(selector);
            assert.deepEqual(await page.$eval('#search_agents', e => e.value.split('\n')), after);
            if (group === 'search_additional') {
                assert.ok(!after.includes('Googlebot') && !after.includes('OAI-SearchBot'));
                // Preserve an edit made between the two independent preset actions.
                await page.$eval('#search_agents', e => {e.value += '\nAnother manual agent';});
            }
        }
        assert.deepEqual(await page.$$eval('input[type="checkbox"]', nodes => nodes.map(e => [e.name, e.checked])), switches);
        for (const [field, value] of Object.entries(initial)) {
            if (field !== 'search_agents') assert.equal(await page.$eval('#' + field, e => e.value), value);
        }
        const submitted = await page.$eval('#hdn-settings', form => Object.fromEntries(new FormData(form)));
        assert.match(submitted.search_agents, /^My custom agent\ngOoGlEbOt-ImAgE\n/);
        assert.match(submitted.search_agents, /Another manual agent/);
        assert.ok(!('search_agents_enabled' in submitted));
        // Right-hand presets append only to their own unsaved group list.
        const blockBefore = await page.$eval('#search_agents', e => e.value);
        await page.click('[data-hdn-preset="search_additional"][data-hdn-agent-field="search_agents_rate"]');
        assert.match(await page.$eval('#search_agents_rate', e => e.value), /ShapBot/);
        assert.equal(await page.$eval('#search_agents', e => e.value), blockBefore);
        assert.equal(await page.$$eval('[data-hdn-agent-rate-row]', nodes => nodes.length), 0);
        await page.click('[data-hdn-agent-category="search_agents"] [data-hdn-agent-add]');
        const row = '[data-hdn-agent-category="search_agents"] [data-hdn-agent-rate-row]';
        await page.$eval(row, e => {
            const set = (suffix, value) => {const input=e.querySelector(`[name$="[${suffix}]"]`); input.value=value;};
            set('agent','ShapBot'); set('rate','7'); set('burst','2');
            e.querySelector('[name$="[enabled]"]').checked=true;
            e.dispatchEvent(new Event('input',{bubbles:true}));
        });
        assert.match(await page.$eval('[data-hdn-agent-category="search_agents"] [data-hdn-agent-effective]', e => e.textContent), /ShapBotIndividual rate limit: 7/);
        const budget = await page.$eval('#hdn-settings', form => Object.fromEntries(new FormData(form)));
        assert.equal(budget['agent_individual[search_agents][0][agent]'], 'ShapBot');
        assert.equal(budget['agent_individual[search_agents][0][rate]'], '7');
        // Removing then adding must not reuse a name that is still in the form.
        await page.click('[data-hdn-agent-category="search_agents"] [data-hdn-agent-add]');
        await page.click(row + ' [data-hdn-agent-remove]');
        await page.click('[data-hdn-agent-category="search_agents"] [data-hdn-agent-add]');
        const names = await page.$$eval(row + ' [name$="[agent]"]', nodes => nodes.map(e=>e.name));
        assert.equal(new Set(names).size, 2);
        // A second category sees the same effective individual rule.
        await page.$eval('#agents', e => {e.value='ShapBot'; e.dispatchEvent(new Event('input',{bubbles:true}));});
        await page.$eval(row + ' [name$="[agent]"]', e => {e.value='ShapBot';});
        await page.$eval(row + ' [name$="[rate]"]', e => {e.value='9';});
        await page.$eval(row + ' [name$="[enabled]"]', e => {e.checked=true; e.dispatchEvent(new Event('change',{bubbles:true}));});
        assert.match(await page.$eval('[data-hdn-agent-category="agents"] [data-hdn-agent-effective]', e => e.textContent), /ShapBotIndividual/);
        // Constraint validation opens collapsed controls before focusing errors.
        await page.$eval('[data-hdn-agent-category="search_agents"]', e => {e.open=false;});
        assert.equal(await page.$eval('#hdn-settings', e=>e.checkValidity()),false);
        assert.equal(await page.$eval('[data-hdn-agent-category="search_agents"]', e=>e.open),true);
        // Conflicts are detected across categories, not just within one table.
        await page.$eval('[data-hdn-agent-category="agents"]', e=>{e.open=true;});
        await page.click('[data-hdn-agent-category="agents"] [data-hdn-agent-add]');
        await page.$eval('[data-hdn-agent-category="agents"] [data-hdn-agent-rate-row]', row=>{
            row.querySelector('[name$="[agent]"]').value='shapbot';
            row.querySelector('[name$="[rate]"]').value='99';
            row.querySelector('[name$="[enabled]"]').checked=true;
            row.dispatchEvent(new Event('input',{bubbles:true}));
        });
        assert.match(await page.$eval('[data-hdn-agent-category="agents"] [data-hdn-agent-rate-row] [name$="[agent]"]', e=>e.validationMessage), /Conflicting/);
        await page.click('[data-hdn-agent-category="agents"] [data-hdn-agent-remove]');
        await page.$eval('[data-hdn-agent-category="agents"]', e=>{e.open=false;});
        // Collection/monitoring buttons and review-only Various target each editor separately.
        const beforeVariousSwitches = await page.$$eval('input[type="checkbox"][name]',nodes=>nodes.map(e=>[e.name,e.checked]));
        await page.$eval('[data-hdn-agent-category="agents"]', e=>{e.open=true;});
        const general = '[data-hdn-agent-category="agents"]';
        assert.match(await page.$eval(general+' > summary', e=>e.textContent), /Monitoring \/ Various/);
        assert.equal(await page.$$eval('[data-hdn-various-name]:checked', nodes=>nodes.length),0);
        assert.equal(await page.$eval('#hdn-various-agents [data-hdn-various-append]', e=>e.disabled),true);
        assert.equal(await page.$eval('#hdn-various-agents [data-hdn-various-name]', e=>e.form),null);
        await page.click('[data-hdn-preset="data_collection"][data-hdn-agent-field="agents"]');
        const collection = await page.$eval('#agents',e=>e.value);
        assert.match(collection,/webXtrendBot/);
        assert.doesNotMatch(collection,/AwarioBot|HeadlessChrome|Bravebot/);
        const blockToggle = general+' [aria-controls="hdn-various-agents"]';
        await page.click(blockToggle);
        assert.equal(await page.$eval(blockToggle,e=>e.getAttribute('aria-expanded')),'true');
        await page.click('#hdn-various-agents [value="HeadlessChrome"]');
        assert.match(await page.$eval('#hdn-various-agents [value="HeadlessChrome"]',e=>e.closest('.hdn-various-choice').textContent), /not a specific crawler or security scanner/);
        await page.click('#hdn-various-agents [data-hdn-various-close]');
        assert.equal(await page.$eval(blockToggle,e=>e.getAttribute('aria-expanded')),'false');
        await page.click(blockToggle);
        assert.equal(await page.$eval('#hdn-various-agents [value="HeadlessChrome"]',e=>e.checked),true);
        await page.$eval('#agents',e=>{e.value+='\n  Keep my current edit  ';});
        await page.click('#hdn-various-agents [data-hdn-various-append]');
        assert.match(await page.$eval('#agents',e=>e.value),/\n  Keep my current edit  \nHeadlessChrome$/);
        assert.equal(await page.$$eval('#hdn-various-agents [data-hdn-various-name]:checked',nodes=>nodes.length),0);
        const variousBlock = await page.$eval('#agents',e=>e.value);
        await page.click('[data-hdn-preset="monitoring"][data-hdn-agent-field="agents_rate"]');
        assert.match(await page.$eval('#agents_rate',e=>e.value),/AwarioBot/);
        assert.doesNotMatch(await page.$eval('#agents_rate',e=>e.value),/HeadlessChrome|webXtrendBot/);
        await page.click(general+' [aria-controls="hdn-various-agents_rate"]');
        await page.click('#hdn-various-agents_rate [value="HeadlessChrome"]');
        await page.click('#hdn-various-agents_rate [value="Bravebot"]');
        assert.match(await page.$eval('#hdn-various-agents_rate [value="Bravebot"]',e=>e.closest('.hdn-various-choice').textContent), /not confirmed as Brave Search/);
        await page.$eval('#agents_rate',e=>{e.value+='\nheadlesschrome';});
        await page.click('#hdn-various-agents_rate [data-hdn-various-append]');
        assert.match(await page.$eval('#agents_rate',e=>e.value),/headlesschrome\nBravebot$/);
        assert.match(await page.$eval('#hdn-various-agents_rate [data-hdn-various-status]',e=>e.textContent), /1 new entries appended; 1 already present/);
        assert.equal(await page.$eval('#agents',e=>e.value),variousBlock);
        const switchValues = await page.$$eval('input[type="checkbox"][name]',nodes=>nodes.map(e=>[e.name,e.checked]));
        assert.deepEqual(switchValues,beforeVariousSwitches);
        for (const width of [1280,390]) {
            await page.setViewport({width,height:1000});
            assert.ok(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth), `Page overflow at ${width}`);
            const columns = await page.$eval('.hdn-agent-columns', e => getComputedStyle(e).gridTemplateColumns.split(' ').length);
            assert.equal(columns, width===1280 ? 2 : 1);
            if (process.env.HDN_SCREENSHOT_DIR) {
                require('node:fs').mkdirSync(process.env.HDN_SCREENSHOT_DIR,{recursive:true});
                await page.screenshot({path:require('node:path').join(process.env.HDN_SCREENSHOT_DIR,`agents-${width}.png`),fullPage:true});
            }
        }
        assert.equal(await page.evaluate(() => window.submissions), 0);
        assert.deepEqual(requests, []);
        assert.deepEqual(errors, []);
        console.log('Category/analyzer accordions; collection/monitoring and Various selection isolation; edits, deduplication, descriptions, no implicit save/enable; individual priorities; desktop/mobile. Status lookup is stubbed; no native analysis or network requests.');
    } finally { await browser.close(); }
})().catch(error => {console.error(error); process.exitCode=1;});
