const {test} = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const source = fs.readFileSync(path.join(__dirname, '../panel/settings.js'), 'utf8');

function fixture(replies, {action = null, remembered = null, activity = false, inventory = null} = {}) {
    if (!remembered) replies.unshift({ok:true,job:{id:null,state:'idle'}});
    const handlers = {}, requests = [], downloads = [];
    let filterControls = [];
    const exportStatus = {}, exportButton = {disabled:false};
    let exportedBlob;
    let updated = false, updates = 0, stored = remembered;
    const button = {textContent: 'Analyze logs', disabled: false};
    const progress = {textContent: ''};
    const cancel = {hidden: true, addEventListener: (_, fn) => {handlers.cancel = fn;}};
    const output = {querySelector:()=>exportStatus, querySelectorAll:selector=>selector === '[data-hdn-filter]' ? filterControls : [], replaceChildren: (...nodes) => {updated = nodes[0] === 'report'; updates++;}, addEventListener: (event, fn) => {handlers[event === 'click' ? 'page' : 'reviewSize'] = fn;}};
    const fields = {
        '[name="analysis_minutes"]': {value:'30'},
        '[name="analysis_target"]': {value:'all'},
        '[name="analysis_verify_google"]': {checked:false},
        '[name="activity_domain"]': {value:'all', addEventListener: (_, fn) => {handlers.domain = fn;}}
    };
    const form = {action: {toString: () => '[object HTMLInputElement]'},
        getAttribute: () => action,
        querySelector: selector => selector.startsWith('button') ? button : (fields[selector] || {value: 'csrf-token'}),
        addEventListener: (event, fn) => {handlers[event] = fn;}};
    const reviewPrefix = inventory ? 'hdn-' + inventory : activity ? 'hdn-activity' : 'hdn-analysis';
    const nodes = {[inventory ? 'hdn-' + inventory + '-scan' : activity ? 'hdn-activity-scan' : 'hdn-log-scan']: form,
        [reviewPrefix + '-progress']: progress,
        [reviewPrefix + '-cancel']: cancel,
        [reviewPrefix + '-output']: output,
        'hdn-agent-presets': {textContent: '{}'}, 'hdn-probe-presets': {textContent: '{}'}};
    const appendButtons = inventory === 'agents' ? ['tool_agents','ai_agents','search_agents','seo_agents','agents'].map(category => {
        nodes[category] = {value:'Existing custom agent', dispatchEvent(){this.edited=true;}};
        nodes['hdn-analyzed-' + category] = {textContent:''};
        const item = {dataset:{hdnAppendAnalyzed:category},disabled:true,
            addEventListener:(_, fn)=>{item.click=fn;}};
        return item;
    }) : [];
    vm.runInNewContext(source, {
        Event:class{},
        document: {getElementById: id => nodes[id], querySelectorAll: selector => selector === '[data-hdn-append-analyzed]' ? appendButtons : [], addEventListener() {}, importNode: node => node,
            body:{appendChild(){}}, createElement:()=>({click(){downloads.push({blob:exportedBlob,name:this.download});},remove(){}})},
        location: {pathname: '/plugins/de-noise/', href: 'https://panel.test/plugins/de-noise/?tab=filters'},
        sessionStorage: {getItem: () => stored, setItem: (_, value) => {stored = value;}},
        FormData: class {constructor(input) {this.fields = new Map(input ? [['action', 'log_scan_start'], ['token', 'csrf-token'], ['analysis_target', 'all']] : []);} set(k,v) {this.fields.set(k,String(v));}},
        Blob, URL:class extends URL {static createObjectURL(blob){exportedBlob=blob;return 'blob:csv-test';} static revokeObjectURL(){}}, setTimeout: fn => fn(),
        fetch: async (target, options) => {
            requests.push({target, options}); assert.ok(replies.length, 'Unexpected request');
            const value = replies.shift();
            return {ok: !value.http || value.http < 400, status: value.http || 200,
                redirected: value.redirected || false, url: value.url || 'https://panel.test/plugins/de-noise/',
                text: async () => value.text === undefined ? JSON.stringify(value) : value.text};
        },
        DOMParser: class {parseFromString() {return {getElementById: () => ({childNodes: ['report']})};}}
    });
    if (!remembered) requests.shift(); // Initial status lookup is not a new scan.
    return {handlers, requests, button, progress, fields, downloads, exportStatus, appendButtons, nodes,
        setFilters:values=>{filterControls=Object.entries(values).map(([name,value])=>({dataset:{hdnFilter:name},value:String(value),type:typeof value==='boolean'?'checkbox':'text',checked:value}));},
        applyFilters:()=>handlers.page({target:{closest:selector=>selector==='[data-hdn-apply-filters]'?{}:null}}),
        resetFilters:()=>handlers.page({target:{closest:selector=>selector==='[data-hdn-reset-filters]'?{}:null}}),
        exportReview:()=>handlers.page({target:{closest:selector=>selector === '[data-hdn-export-review]' ? exportButton : null}}),
        exportCSV:()=>handlers.page({target:{closest:selector=>selector === '[data-hdn-export-agents]' ? exportButton : null}}), updated: () => updated, updates: () => updates,
        submit: () => handlers.submit({preventDefault() {}})};
}
const queued = {ok: true, job: {id: 'one', state: 'queued'}};
const done = {ok: true, job: {id: 'one', state: 'complete'}, report: 'HTML'};

test('per-category append reads all chunks, merges current edits and never saves or enables rules', async () => {
    const f=fixture([queued,done,
        {ok:true,candidates:{category:'search_agents',names:['Googlebot-Image'],scanned:500,total:502,next_offset:500}},
        {ok:true,candidates:{category:'search_agents',names:['googlebot-image','PerplexityBot'],scanned:2,total:502,next_offset:null}}
    ],{inventory:'agents'});
    assert.ok(f.appendButtons.every(item=>item.disabled));
    await f.submit();
    f.nodes.search_agents.value='gOoGlEbOt-ImAgE\nMy unsaved rule';
    await f.appendButtons[2].click();
    assert.equal(f.nodes.search_agents.value,'gOoGlEbOt-ImAgE\nMy unsaved rule\nPerplexityBot');
    assert.equal(f.nodes.ai_agents.value,'Existing custom agent');
    assert.match(f.nodes['hdn-analyzed-search_agents'].textContent,/1 new agents appended; 1 already present/);
    for (const request of f.requests.slice(2)) {
        const fields=request.options.body.fields;
        assert.equal(fields.get('action'),'agents_candidates');
        assert.equal(fields.get('analysis_job'),'one');
        assert.equal(fields.get('analysis_category'),'search_agents');
        assert.equal(fields.get('token'),'csrf-token');
        assert.equal(fields.has('policy'),false);
    }
    assert.deepEqual(f.requests.slice(2).map(r=>r.options.body.fields.get('export_offset')),['0','500']);
    assert.ok(f.appendButtons.every(item=>!item.disabled));
});

test('failed or malformed candidate transfers leave every unsaved list untouched', async () => {
    const bad=[{http:503,error:'Read failed'},
        {ok:true,candidates:{category:'agents',names:['GPTBot'],scanned:1,total:501,next_offset:null}},
        {ok:true,candidates:{category:'ai_agents',names:['Bad\nRule'],scanned:1,total:501,next_offset:null}},
        {ok:true,candidates:{category:'ai_agents',names:[],scanned:0,total:501,next_offset:500}},
        {ok:true,candidates:{category:'ai_agents',names:['ClaudeBot'],scanned:1,total:502,next_offset:null}}];
    for (const failure of bad) {
        const f=fixture([queued,done,
            {ok:true,candidates:{category:'ai_agents',names:['GPTBot'],scanned:500,total:501,next_offset:500}},failure
        ],{inventory:'agents'});
        await f.submit(); await f.appendButtons[1].click();
        assert.equal(f.nodes.ai_agents.value,'Existing custom agent');
        assert.ok(f.appendButtons.every(item=>!item.disabled));
        assert.doesNotMatch(f.nodes['hdn-analyzed-ai_agents'].textContent,/appended/);
    }
});

test('empty category is a no-op and unavailable reports cannot append', async () => {
    const f=fixture([queued,done,{ok:true,candidates:{category:'agents',names:[],scanned:0,total:0,next_offset:null}}],{inventory:'agents'});
    await new Promise(resolve=>setImmediate(resolve));
    await f.appendButtons[4].click(); assert.equal(f.requests.length,0);
    await f.submit(); await f.appendButtons[4].click();
    assert.equal(f.nodes.agents.value,'Existing custom agent');
    assert.match(f.nodes['hdn-analyzed-agents'].textContent,/No recognized agents/);
});

test('named action input cannot clobber the URL; review POST retains CSRF and scope', async () => {
    const f = fixture([queued, done]); await f.submit();
    for (const r of f.requests) {
        assert.equal(r.target, 'https://panel.test/plugins/de-noise/?tab=filters');
        assert.equal(r.options.credentials, 'same-origin');
        assert.equal(r.options.body.fields.get('token'), 'csrf-token');
        assert.equal(r.options.headers['X-HDN-Analysis'], '1');
        assert.equal(r.options.body.fields.has('policy'), false);
    }
    assert.equal(f.requests[0].options.body.fields.get('action'), 'log_scan_start');
    assert.equal(f.requests[1].options.body.fields.get('action'), 'log_scan_status');
    assert.equal(f.updated(), true); assert.equal(f.button.disabled, false);
});
test('explicit form action is used', async () => {
    const f = fixture([queued, done], {action: '/review'}); await f.submit(); assert.equal(f.requests[0].target, '/review');
});
test('observation continues past the former overall browser timeout', async () => {
    const running = {ok: true, job: {id: 'one', state: 'running', progress: {records: 900}}};
    const f = fixture([queued, ...Array(25).fill(running), done]); await f.submit();
    assert.equal(f.requests.length, 27); assert.equal(f.updated(), true); assert.doesNotMatch(source, /AbortController|20000/);
});
test('HTTP failures do not incorrectly blame the session', async () => {
    const f = fixture([{http: 503, text: '<html>Failed</html>'}]); await f.submit();
    assert.match(f.progress.textContent, /HTTP 503/); assert.doesNotMatch(f.progress.textContent, /session/i); assert.equal(f.button.disabled, false);
});
test('actual login redirect identifies expiry and resumption', async () => {
    const f = fixture([{text: 'login', redirected: true, url: 'https://panel.test/login/'}]); await f.submit(); assert.match(f.progress.textContent, /session has expired/);
});
test('failed worker is not presented as a completed review', async () => {
    const f = fixture([queued, {ok:true, job:{id:'one',state:'failed',error:'Read failed'}}]); await f.submit(); assert.equal(f.progress.textContent,'Read failed'); assert.equal(f.updated(),false);
});
test('reload resumes the existing job without starting a second one', async () => {
    const f = fixture([done],{remembered:'one'}); await new Promise(resolve=>setImmediate(resolve));
    assert.equal(f.requests.length,1); assert.equal(f.requests[0].options.body.fields.get('action'),'log_scan_status'); assert.equal(f.updated(),true);
});

test('restoring a review also restores its time window, domain and verification selection', async () => {
    const value = {...done, job:{...done.job, selection:{minutes:360,target:'alice/one.test',verify_google:true}}};
    const f = fixture([value], {remembered:'one'}); await new Promise(resolve=>setImmediate(resolve));
    assert.equal(f.fields['[name="analysis_minutes"]'].value, '360');
    assert.equal(f.fields['[name="analysis_target"]'].value, 'alice/one.test');
    assert.equal(f.fields['[name="analysis_verify_google"]'].checked, true);
});

test('restored report and pagination never overwrite a newly edited review selection', async () => {
    const value = {...done, job:{...done.job, selection:{minutes:360,target:'alice/one.test',verify_google:true}}};
    const f = fixture([value,value], {remembered:'one'});
    f.fields['[name="analysis_minutes"]'].value='1440'; f.handlers.input();
    await new Promise(resolve=>setImmediate(resolve));
    await f.handlers.page({target:{closest:selector=>selector === '[data-hdn-analysis-page]' ? {dataset:{hdnAnalysisPage:'2'}} : null}});
    assert.equal(f.fields['[name="analysis_minutes"]'].value,'1440');
    assert.equal(f.fields['[name="analysis_target"]'].value,'all');
});
test('pagination exposes remaining findings without policy changes', async () => {
    const f = fixture([queued,done,done]); await f.submit(); await f.handlers.page({target:{closest:selector=>selector === '[data-hdn-analysis-page]' ? {dataset:{hdnAnalysisPage:'2'}} : null}});
    assert.equal(f.requests[2].options.body.fields.get('analysis_page'),'2'); assert.equal(f.requests[2].options.body.fields.has('analysis_target'),false);
});
test('cancellation uses the authenticated job endpoint', async () => {
    const f = fixture([queued,done,{ok:true,job:{id:'one',state:'cancelled'}}]); await f.submit(); await f.handlers.cancel();
    assert.equal(f.requests[2].options.body.fields.get('action'),'log_scan_cancel'); assert.match(f.progress.textContent,/Review cancelled/);
});

test('activity loads metadata without scanning and uses its own start/status endpoints', async () => {
    const f = fixture([queued,done], {activity:true}); await f.submit();
    assert.equal(f.requests[0].options.body.fields.get('action'),'activity_start');
    assert.equal(f.requests[1].options.body.fields.get('action'),'activity_status');
    assert.equal(f.requests[0].options.body.fields.get('tab'),'activity');
    assert.equal(f.updated(),true);
    assert.equal(f.updates(),1);
});

test('tabs switch panels and keyboard focus without depending on the panel theme', () => {
    const panels = {}, inputs = [{value:'general'}], save = {hidden:false};
    const tabs = ['general','filters','cron'].map(name => {
        const handlers = {}, attributes = {'aria-controls':'panel-'+name};
        panels['panel-'+name] = {hidden:name !== 'general'};
        return {dataset:{hdnTab:name}, parentElement:{}, tabIndex:name === 'general' ? 0 : -1,
            setAttribute:(key,value)=>{attributes[key]=value;}, getAttribute:key=>attributes[key],
            addEventListener:(event,fn)=>{handlers[event]=fn;}, click:()=>handlers.click(),
            focus(){this.focused=true;}, key:key=>handlers.keydown({key,preventDefault(){}}), attributes};
    });
    const nodes = {...panels, 'hdn-save':save,
        'hdn-agent-presets':{textContent:'{}'}, 'hdn-probe-presets':{textContent:'{}'}};
    vm.runInNewContext(source, {
        document:{getElementById:id=>nodes[id], addEventListener(){},
            querySelectorAll:selector=>selector === '[data-hdn-tab]' ? tabs : selector === 'input[name="tab"]' ? inputs : []},
        getComputedStyle:()=>({gridTemplateColumns:'100px 100px'})
    });
    tabs[1].click();
    assert.equal(panels['panel-filters'].hidden,false);
    assert.equal(panels['panel-general'].hidden,true);
    assert.equal(tabs[1].attributes['aria-selected'],'true');
    assert.equal(tabs[0].tabIndex,-1); assert.equal(tabs[1].tabIndex,0);
    assert.equal(inputs[0].value,'filters'); assert.equal(save.hidden,false);
    tabs[1].key('End');
    assert.equal(panels['panel-cron'].hidden,false); assert.equal(save.hidden,true);
    assert.equal(tabs[2].focused,true); assert.equal(inputs[0].value,'cron');
    tabs[2].key('ArrowDown');
    assert.equal(panels['panel-filters'].hidden,false); assert.equal(save.hidden,false);
    assert.equal(tabs[1].focused,true);
});

for (const kind of ['agents', 'php_files']) {
    test(kind + ' inventory uses independent authenticated resumable endpoints', async () => {
        const f = fixture([queued, done], {inventory:kind}); await f.submit();
        assert.equal(f.requests[0].options.body.fields.get('action'), kind+'_start');
        assert.equal(f.requests[1].options.body.fields.get('action'), kind+'_status');
        assert.equal(f.requests[0].options.body.fields.get('tab'), kind === 'agents' ? 'agents' : 'bans');
        assert.equal(f.requests[0].options.body.fields.has('policy'), false);
        assert.equal(f.updated(), true);
    });
}

test('append merges selected rows, deduplicates and preserves switches and unrelated edits', () => {
    const handlers = {}, status = {}, collapsed = {open:false}, all = {checked:true};
    const fields = {
        ai_agents:{value:'GPTBot\nExistingTraining', dispatchEvent(){this.edited=true;},closest:()=>null},
        agents:{value:'MyCustomAgent',dispatchEvent(){this.edited=true;},closest:()=>collapsed},
        'bans-missing_files-list':{value:'/keep.php',dispatchEvent(){this.edited=true;},closest:()=>null},
        'hdn-agent-presets':{textContent:'{}'}, 'hdn-probe-presets':{textContent:'{}'}
    };
    const switches = {ai_agents_enabled:false, agents_enabled:false};
    const row = (value, destination) => ({checked:true,dataset:{hdnInventoryValue:value},
        closest:()=>({querySelector:()=>({value:destination})})});
    const boxes = [row('gptbot','ai_agents'),row('NewAgent','agents'),row('NewAgent','agents'),row('other','invalid')];
    const report = {dataset:{hdnInventory:'agents'},querySelectorAll:()=>boxes,
        querySelector:selector=>selector.includes('status') ? status : all};
    const button={closest:()=>report};
    vm.runInNewContext(source, {Event:class{}, document:{getElementById:id=>fields[id],querySelectorAll:()=>[],
        addEventListener:(name,fn)=>{handlers[name]=fn;}}});
    handlers.click({target:{closest:()=>button}});
    assert.equal(fields.ai_agents.value,'GPTBot\nExistingTraining');
    assert.equal(fields.agents.value,'MyCustomAgent\nNewAgent');
    assert.equal(fields['bans-missing_files-list'].value,'/keep.php');
    assert.deepEqual(switches,{ai_agents_enabled:false,agents_enabled:false});
    assert.match(status.textContent,/1 new entries appended; 2 already present/);
    assert.equal(collapsed.open,true); assert.equal(all.checked,false);
    assert.equal(boxes[0].checked,false); assert.equal(boxes[3].checked,true);
    assert.equal(fields.agents.edited,true);
});

test('PHP inventory appends exact paths and keeps case-sensitive URL distinctions', () => {
    const handlers={},status={},field={value:'/Keep.php',closest:()=>null,dispatchEvent(){}};
    const boxes=['/Keep.php','/keep.php','/new.php'].map(value=>({checked:true,dataset:{hdnInventoryValue:value},
        closest:()=>({querySelector:()=>({value:'bans-missing_files-list'})})}));
    const report={dataset:{hdnInventory:'php_files'},querySelectorAll:()=>boxes,
        querySelector:selector=>selector.includes('status') ? status : {checked:true}};
    const nodes={'bans-missing_files-list':field,'hdn-agent-presets':{textContent:'{}'},'hdn-probe-presets':{textContent:'{}'}};
    vm.runInNewContext(source,{Event:class{},document:{getElementById:id=>nodes[id],querySelectorAll:()=>[],addEventListener:(name,fn)=>{handlers[name]=fn;}}});
    handlers.click({target:{closest:()=>({closest:()=>report})}});
    assert.equal(field.value,'/Keep.php\n/keep.php\n/new.php');
    assert.match(status.textContent,/2 new entries/);
});


test('CSV exports the complete saved inventory across chunks and safely quotes agent declarations', async () => {
    const rows=[['GPTBot',23],['Comma, "quote"',7],['=HYPERLINK("https://example.test")',3],['  +SUM(1,2)',2],['\tformula',1],['Ελληνικά',1],['',1]];
    const f=fixture([queued,done,{ok:true,export:{rows:rows.slice(0,2),total:7,next_offset:2}},
        {ok:true,export:{rows:rows.slice(2),total:7,next_offset:null}}],{inventory:'agents'});
    await f.submit(); await f.exportCSV();
    assert.equal(f.downloads.length,1);
    const csv=await f.downloads[0].blob.text();
    assert.ok(csv.startsWith('agent,hits\r\n"GPTBot",23\r\n'));
    assert.ok(csv.includes('"Comma, ""quote""",7\r\n'));
    assert.ok(csv.includes('"\'=HYPERLINK(""https://example.test"")",3'));
    assert.ok(csv.includes('"\'  +SUM(1,2)",2'));
    assert.ok(csv.includes('"\'\tformula",1'));
    assert.ok(csv.includes('"Ελληνικά",1')); assert.ok(csv.endsWith('"",1\r\n'));
    assert.match(f.downloads[0].name,/^webuzo-de-noise-agents-.*\.csv$/);
    const requests=f.requests.filter(r=>r.options.body.fields.get('action')==='agents_export');
    assert.deepEqual(requests.map(r=>r.options.body.fields.get('export_offset')),['0','2']);
    requests.forEach(r=>{
        assert.equal(r.options.body.fields.get('analysis_job'),'one');
        assert.equal(r.options.body.fields.get('token'),'csrf-token');
        assert.equal(r.options.body.fields.has('policy'),false);
    });
    assert.equal(f.exportStatus.textContent,'CSV downloaded: 7 agents.');
});

test('a failed export chunk never downloads a partial CSV or restarts analysis', async () => {
    const f=fixture([queued,done,{ok:true,export:{rows:[['First',1]],total:2,next_offset:1}},
        {ok:false,error:'Report unavailable',http:400}],{inventory:'agents'});
    await f.submit(); await f.exportCSV();
    assert.equal(f.downloads.length,0); assert.equal(f.exportStatus.textContent,'Report unavailable');
    assert.equal(f.requests.filter(r=>r.options.body.fields.get('action')==='agents_start').length,1);
});

test('an empty completed inventory exports the two-column header', async () => {
    const f=fixture([queued,done,{ok:true,export:{rows:[],total:0,next_offset:null}}],{inventory:'agents'});
    await f.submit(); await f.exportCSV();
    assert.equal(await f.downloads[0].blob.text(),'agent,hits\r\n');
    assert.equal(f.exportStatus.textContent,'CSV downloaded: 0 agents.');
});

test('Activity filters the saved report without launching a new scan and ignores stale selections', async () => {
    const f=fixture([queued,{...done,job:{...done.job,analysis:{selected_domain:'all'}}},
        {...done,job:{...done.job,analysis:{selected_domain:'one.test'}}},
        {...done,job:{...done.job,analysis:{selected_domain:'one.test'}}}],{activity:true});
    await f.submit();
    assert.match(f.progress.textContent,/saved Activity review/);
    f.fields['[name="activity_domain"]'].value='one.test';
    await f.handlers.domain();
    assert.equal(f.updates(),2);
    assert.equal(f.updated(),true);
    assert.equal(f.requests.at(-1).options.body.fields.get('activity_domain'),'one.test');
    f.fields['[name="activity_domain"]'].value='two.test';
    await f.handlers.domain();
    assert.equal(f.updates(),2);
    assert.equal(f.requests.filter(r=>r.options.body.fields.get('action')==='activity_start').length,1);
    assert.equal(f.requests.at(-1).options.body.fields.get('activity_domain'),'two.test');
});

test('Access method and inheritance controls enable only relevant required fields', () => {
    const controls={disabled:true},basic={},captcha={},username={},seconds={};
    const nodes={'hdn-agent-presets':{textContent:'{}'},'hdn-probe-presets':{textContent:'{}'}};
    const form={querySelector:s=>({'[data-hdn-basic-controls]':basic,'[data-hdn-captcha-controls]':captcha,
        '[name="access_username"]':username,'[name="captcha_seconds"]':seconds,'[data-hdn-access-controls]':controls})[s]};
    const method={value:'off',closest:()=>form,addEventListener:(_,fn)=>{method.change=fn;}};
    const inherit={value:'inherit',closest:()=>form,addEventListener:(_,fn)=>{inherit.change=fn;}};
    vm.runInNewContext(source,{document:{getElementById:id=>nodes[id],querySelectorAll:s=>
        s==='[data-hdn-access-method]'?[method]:s==='[data-hdn-access-source]'?[inherit]:[],addEventListener(){}}});
    assert.equal(username.required,false);assert.equal(seconds.required,false);
    method.value='captcha';method.change();
    assert.equal(basic.hidden,true);assert.equal(captcha.hidden,false);assert.equal(seconds.required,true);
    method.value='basic';method.change();
    assert.equal(basic.hidden,false);assert.equal(captcha.hidden,true);assert.equal(username.required,true);
    inherit.value='custom';inherit.change();assert.equal(controls.disabled,false);
    inherit.value='inherit';inherit.change();assert.equal(controls.disabled,true);
});


test('review size changes only the saved report page, with all supported choices', async () => {
    const f=fixture([queued,done,...Array.from({length:5},()=>done)]); await f.submit();
    for (const size of ['20','50','100','500','all']) {
        await f.handlers.reviewSize({target:{matches:selector=>selector==='[data-hdn-review-size]',value:size}});
        const fields=f.requests.at(-1).options.body.fields;
        assert.equal(fields.get('analysis_per_page'),size);
        assert.equal(fields.get('analysis_page'),'1');
        assert.equal(fields.get('action'),'log_scan_status');
        assert.equal(fields.has('policy'),false);
    }
});

test('PHP CSV expands grouped exact paths and waits for every chunk before downloading', async () => {
    const f=fixture([queued,done,
        {ok:true,export:{columns:['Path','Hits'],rows:[['/a.php',3],['/a/a.php',2]],scanned:500,total:501,next_offset:500}},
        {ok:true,export:{columns:['Path','Hits'],rows:[['=bad',1]],scanned:1,total:501,next_offset:null}}
    ],{inventory:'php_files'}); await f.submit(); await f.exportReview();
    assert.equal(f.downloads.length,1);
    const text=await f.downloads[0].blob.text();
    assert.match(text,/"\/a\/a.php","2"/); assert.ok(text.includes('"\'=bad","1"'));
    assert.deepEqual(f.requests.slice(2).map(r=>r.options.body.fields.get('export_offset')),['0','500']);
    assert.ok(f.requests.slice(2).every(r=>r.options.body.fields.get('review_kind')==='php_files'));
});

test('review CSV refuses incomplete or failed transfers without a partial download', async () => {
    for (const reply of [{http:503,error:'Read failed'}, {ok:true,export:{columns:['Path'],rows:[],scanned:0,total:1,next_offset:null}}]) {
        const f=fixture([queued,done,reply],{inventory:'php_files'}); await f.submit(); await f.exportReview();
        assert.equal(f.downloads.length,0);
        assert.match(f.exportStatus.textContent,/Read failed|incomplete/);
    }
});


test('finding filters apply to saved results, pagination and every CSV chunk without starting another scan', async () => {
    const f=fixture([queued,done,done,done,{ok:true,export:{columns:['Path'],rows:[['/probe.php']],scanned:1,total:1,next_offset:null,view_revision:'stable'}}],{inventory:'php_files'});
    await f.submit();
    f.setFilters({domain:'one.test',priority:'high',query:'/probe',min_hits:2,min_domains:1,review:'all'});
    await f.applyFilters();
    await f.handlers.page({target:{closest:selector=>selector==='[data-hdn-analysis-page]'?{dataset:{hdnAnalysisPage:'2'}}:null}});
    await f.exportReview();
    for(const r of f.requests.slice(2)) {
        const b=r.options.body.fields,filters=JSON.parse(b.get('review_filters'));
        assert.equal(filters.domain,'one.test');assert.equal(filters.priority,'high');assert.equal(filters.min_hits,2);
        assert.equal(filters.query,'/probe');assert.equal(b.get('token'),'csrf-token');assert.equal(b.has('policy'),false);
    }
    assert.equal(f.requests.filter(r=>r.options.body.fields.get('action')==='php_files_start').length,1);
    assert.equal(f.downloads.length,1);
});

test('review notes post only the exact domain/path, then refresh the saved view', async () => {
    const f=fixture([queued,done,{ok:true,mark:{state:'ignored'}},done],{inventory:'php_files'});
    await f.submit();
    const item={dataset:{hdnReviewItem:'/images/images/probe.php'},querySelector:()=>({value:'one.test'})};
    const button={dataset:{hdnReviewMark:'ignored'},closest:()=>item,disabled:false};
    await f.handlers.page({target:{closest:selector=>selector==='[data-hdn-review-mark]'?button:null}});
    const body=f.requests[2].options.body.fields;
    assert.equal(body.get('action'),'review_mark');assert.equal(body.get('review_domain'),'one.test');
    assert.equal(body.get('review_item'),'/images/images/probe.php');assert.equal(body.get('review_kind'),'php_files');
    assert.equal(body.get('review_mark'),'ignored');assert.equal(body.get('token'),'csrf-token');assert.equal(body.has('policy'),false);
    assert.equal(f.requests[3].options.body.fields.get('action'),'php_files_status');
    assert.match(f.exportStatus.textContent,/Protection settings are unchanged/);
});

test('CSV refuses changing review revisions instead of downloading mixed results', async () => {
    const f=fixture([queued,done,
      {ok:true,export:{columns:['Path'],rows:[['/one.php']],scanned:1,total:2,next_offset:1,view_revision:'before'}},
      {ok:true,export:{columns:['Path'],rows:[['/two.php']],scanned:1,total:2,next_offset:null,view_revision:'after'}}],{inventory:'php_files'});
    await f.submit();await f.exportReview();
    assert.equal(f.downloads.length,0);assert.match(f.exportStatus.textContent,/notes changed/);
});

test('invalid numeric filters never submit partial settings or launch work', async () => {
    const f=fixture([queued,done],{inventory:'php_files'});await f.submit();
    f.setFilters({min_hits:'-1'});await f.applyFilters();
    assert.equal(f.requests.length,2);assert.match(f.progress.textContent,/nonnegative/);
});
