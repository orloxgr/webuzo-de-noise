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
        page.on('request', request => requests.push(request.url()));
        await page.evaluate(() => {
            window.submissions = 0;
            document.getElementById('hdn-settings').addEventListener('submit', event => {
                event.preventDefault(); window.submissions++;
            });
        });
        const initial = await page.$$eval('textarea', nodes => Object.fromEntries(nodes.map(e => [e.id, e.value])));
        const switches = await page.$$eval('input[type="checkbox"]', nodes => nodes.map(e => [e.name, e.checked]));
        for (const group of ['search_additional', 'search_major']) {
            const selector = `[data-hdn-preset="${group}"]`;
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
        assert.equal(await page.evaluate(() => window.submissions), 0);
        assert.deepEqual(requests, []);
        assert.deepEqual(errors, []);
        console.log('Search preset groups preserve edits, deduplicate, keep switches and form association, and do not save or make requests.');
    } finally { await browser.close(); }
})().catch(error => {console.error(error); process.exitCode=1;});
