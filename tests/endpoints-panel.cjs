'use strict';
// Optional rendered-browser check: PHP fixture output as argv[2].
const assert = require('node:assert/strict');
const fs = require('node:fs');
const puppeteer = require(process.env.HDN_PUPPETEER || 'puppeteer-core');
(async () => {
    const browser = await puppeteer.launch({executablePath:process.env.HDN_BROWSER,headless:true});
    try {
        const page=await browser.newPage(), errors=[];
        page.on('pageerror',error=>errors.push(error.message));
        await page.goto(require('node:url').pathToFileURL(process.argv[2]).href);
        const categories=['hdn-xmlrpc-block-box','hdn-endpoint404-box','hdn-custom-endpoints-box','hdn-endpoint-analysis-box','hdn-endpoint-rate-login','hdn-endpoint-rate-xmlrpc'];
        for (const id of categories) assert.ok(await page.$('#'+id+' > summary.box-collapse-header'));
        await page.$eval('#hdn-xmlrpc-block-box', e=>e.open=true);
        assert.equal(await page.$eval('[name="xmlrpc_block_enabled"]',e=>e.checked),true);
        assert.deepEqual(await page.$$eval('[name="xmlrpc_block_targets[]"]:checked',nodes=>nodes.map(e=>e.value)),['alice/one.test']);
        await page.click('[data-hdn-xmlrpc-select="all"]');
        assert.deepEqual(await page.$$eval('[name="xmlrpc_block_targets[]"]:checked',nodes=>nodes.map(e=>e.value)),['alice/one.test','bob/two.test']);
        await page.click('[data-hdn-xmlrpc-select="none"]');
        assert.equal(await page.$$eval('[name="xmlrpc_block_targets[]"]:checked',nodes=>nodes.length),0);
        assert.equal(await page.$eval('[name="xmlrpc_block_enabled"]',e=>e.checked),true);
        assert.ok(await page.$eval('[name="xmlrpc_block_targets[]"]',e=>e.form.id==='hdn-settings'));
        await page.click('[name="xmlrpc_block_targets[]"][value="alice/one.test"]');
        const beforeToggle=await page.$eval('#hdn-settings',e=>new URLSearchParams(new FormData(e)).toString());
        assert.equal(await page.$eval('#hdn-endpoint404-box',e=>e.open),false);
        const closedChevron=await page.$eval('#hdn-endpoint404-box > summary',e=>getComputedStyle(e,'::after').transform);
        await page.click('#hdn-endpoint404-box > summary');
        assert.equal(await page.$eval('#hdn-endpoint404-box',e=>e.open),true);
        const openChevron=await page.$eval('#hdn-endpoint404-box > summary',e=>getComputedStyle(e,'::after').transform);
        assert.notEqual(openChevron,closedChevron);
        await page.focus('#hdn-endpoint404-box > summary');
        await page.keyboard.press('Enter');
        assert.equal(await page.$eval('#hdn-endpoint404-box',e=>e.open),false);
        assert.equal(await page.$eval('#hdn-settings',e=>new URLSearchParams(new FormData(e)).toString()),beforeToggle);
        assert.equal(await page.$eval('[name="custom_endpoints[0][duration]"]',e=>e.value),'2');
        assert.equal(await page.$eval('[name="custom_endpoints[0][duration_unit]"]',e=>e.value),'hours');
        await page.$eval('[data-hdn-append-endpoint="/wp-config.old"]',e=>e.closest('details').open=true);
        await page.click('[data-hdn-append-endpoint="/wp-config.old"]');
        await page.click('[data-hdn-append-endpoint="/wp-config.old"]');
        const result=await page.evaluate(()=>{
            const rows=[...document.querySelectorAll('#hdn-custom_endpoints-rows .hdn-rule')];
            const field=(row,key)=>row.querySelector('[name$="['+key+']"]');
            const appended=rows[1];
            const domains=appended.querySelector('[name$="[targets][]"]');
            const saved=rows[0];
            return {count:rows.length,appended:{name:field(appended,'name').value,pattern:field(appended,'pattern').value,
                enabled:field(appended,'enabled').checked,ban:field(appended,'also_ban').checked,
                domains:[...domains.selectedOptions].map(o=>o.value)},
                saved:{enabled:field(saved,'enabled').checked,ban:field(saved,'also_ban').checked,pattern:field(saved,'pattern').value},
                valid:document.getElementById('hdn-settings').checkValidity(),
                encoded:new URLSearchParams(new FormData(document.getElementById('hdn-settings'))).toString()};
        });
        assert.equal(result.count,2);
        assert.equal(await page.$eval('#hdn-custom-endpoints-box',e=>e.open),true);
        assert.deepEqual(result.appended,{name:'/wp-config.old',pattern:'/wp-config.old',enabled:false,ban:false,domains:['alice/one.test']});
        assert.deepEqual(result.saved,{enabled:true,ban:true,pattern:'^/saved\\.sql$'});
        assert.equal(result.valid,true);
        assert.equal((await page.$$('[data-hdn-append-endpoint="/wp-blog-header.php"], [data-hdn-endpoint404-path="/wp-blog-header.php"]')).length,2);
        assert.ok(await page.$eval('[data-hdn-endpoint-group]',e=>e.title.includes('existing files')));
        assert.ok(await page.$eval('[data-hdn-endpoint404-group]',e=>e.title.includes('configured 404 threshold')));
        await page.click('[data-hdn-select-endpoint404]');
        await page.click('[data-hdn-append-endpoint404]');
        assert.deepEqual(await page.$eval('#hdn-endpoint404-paths',e=>e.value.split('\n')),['/kept.php','/wp-config.old','/wp-blog-header.php','/missing.js','/missing.css','/application/route']);
        assert.equal(await page.$eval('#hdn-endpoint404-box',e=>e.open),true);
        assert.equal(await page.$eval('[name="endpoint404_enabled"]',e=>e.checked),false);
        assert.equal(await page.$eval('[name="endpoint404_maxretry"]',e=>e.value),'3');
        assert.equal(await page.$eval('[name="endpoint404_findtime"]',e=>e.value),'600');
        assert.equal(await page.$eval('[name="endpoint404_duration"]',e=>e.value),'2');
        assert.equal(await page.$eval('[name="endpoint404_unit"]',e=>e.value),'hours');
        await page.$eval('[data-hdn-endpoint-group]',e=>e.closest('details').open=true);
        await page.click('[data-hdn-endpoint-group]');
        assert.equal((await page.$$('#hdn-custom_endpoints-rows .hdn-rule')).length,2);
        await page.select('[data-hdn-finding-paths]','/wp-config.bak');
        await page.click('[data-hdn-endpoint-group]');
        await page.click('[data-hdn-endpoint-group]');
        assert.equal((await page.$$('#hdn-custom_endpoints-rows .hdn-rule')).length,3);
        assert.equal(await page.$eval('#hdn-custom_endpoints-rows .hdn-rule:last-child [name$="[type]"]',e=>e.value),'exact');
        await page.click('[data-hdn-endpoint404-group]');
        assert.deepEqual(await page.$eval('#hdn-endpoint404-paths',e=>e.value.split('\n')),['/kept.php','/wp-config.old','/wp-blog-header.php','/missing.js','/missing.css','/application/route','/wp-config.bak']);
        await page.click('[data-hdn-add="custom_endpoints"]');
        await page.$eval('#hdn-custom_endpoints-rows .hdn-rule:last-child [data-hdn-remove]',e=>e.click());
        assert.equal((await page.$$('#hdn-custom_endpoints-rows .hdn-rule')).length,3);
        assert.equal((await page.$$('[data-hdn-endpoint404-path="/working.js"]')).length,0);
        await page.$eval('[data-hdn-append-endpoint="/working.js"]',e=>e.closest('details').open=true);
        await page.click('[data-hdn-append-endpoint="/working.js"]');
        assert.equal(await page.$eval('#hdn-custom_endpoints-rows .hdn-rule:last-child [name$="[pattern]"]',e=>e.value),'/working.js');
        assert.equal(await page.$eval('#hdn-custom_endpoints-rows .hdn-rule:last-child [name$="[enabled]"]',e=>e.checked),false);
        assert.equal(await page.$eval('#hdn-custom_endpoints-rows .hdn-rule:last-child [name$="[also_ban]"]',e=>e.checked),false);
        const groupIndex=await page.$$eval('[data-hdn-endpoint-group]',nodes=>nodes.findIndex(e=>JSON.parse(e.dataset.hdnEndpointGroup).includes('/missing.js')));
        assert.ok(groupIndex>=0);
        await page.$$eval('[data-hdn-endpoint-group]',(nodes,i)=>{nodes[i].closest('details').open=true;const select=nodes[i].closest('.hdn-endpoint-card').querySelector('[data-hdn-finding-paths]');[...select.options].forEach(o=>o.selected=o.value==='/missing.js');nodes[i].click();},groupIndex);
        assert.equal((await page.$$('#hdn-custom_endpoints-rows .hdn-rule')).length,5);
        await page.$$eval('[data-hdn-endpoint-group]',(nodes,i)=>{
            const card=nodes[i].closest('.hdn-endpoint-card');
            const select=card.querySelector('[data-hdn-finding-paths]');
            [...select.options].forEach(o=>o.selected=o.value==='/working.js');
            card.querySelector('[data-hdn-endpoint404-group]').click();
        },groupIndex);
        assert.ok(!(await page.$eval('#hdn-endpoint404-paths',e=>e.value.split('\n'))).includes('/working.js'));
        await page.$$eval('[data-hdn-endpoint-group]',(nodes,i)=>nodes[i].closest('.hdn-endpoint-card').querySelector('[data-hdn-select-findings="all"]').click(),groupIndex);
        assert.deepEqual(await page.$$eval('[data-hdn-finding-paths]',(nodes,i)=>[...nodes[i].selectedOptions].map(o=>o.value),groupIndex),['/missing.js','/working.js']);
        await page.$$eval('[data-hdn-endpoint-group]',(nodes,i)=>nodes[i].closest('.hdn-endpoint-card').querySelector('[data-hdn-select-findings="none"]').click(),groupIndex);
        assert.equal(await page.$$eval('[data-hdn-finding-paths]',(nodes,i)=>nodes[i].selectedOptions.length,groupIndex),0);
        assert.ok(await page.$$eval('select[multiple]',nodes=>nodes.every(e=>e.nextElementSibling?.textContent.includes('Press CTRL to select/deselect'))));
        for (const width of [1280,390]) {
            await page.setViewport({width,height:1200});
            const layout=await page.$eval('.hdn-endpoint-card',card=>{
                const field=card.querySelector('[data-hdn-finding-paths]').getBoundingClientRect();
                const buttons=[...card.querySelectorAll('.hdn-endpoint-actions button')].map(e=>e.getBoundingClientRect());
                return {overflow:document.documentElement.scrollWidth>window.innerWidth,
                    below:buttons.every(b=>b.top>=field.bottom),
                    contained:buttons.every(b=>b.left>=0 && b.right<=window.innerWidth)};
            });
            assert.deepEqual(layout,{overflow:false,below:true,contained:true});
        }
        if (process.env.HDN_SCREENSHOT) await page.screenshot({path:process.env.HDN_SCREENSHOT,fullPage:true});
        assert.deepEqual(errors,[]);
        if (process.argv[3]) fs.writeFileSync(process.argv[3],await page.$eval('#hdn-settings',e=>new URLSearchParams(new FormData(e)).toString()));
        console.log('Rendered endpoint append, deduplication, saved-state preservation, duration units, form association and remove: OK');
    } finally { await browser.close(); }
})().catch(error=>{console.error(error);process.exitCode=1;});
