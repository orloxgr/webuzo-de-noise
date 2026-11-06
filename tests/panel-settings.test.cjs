const {test} = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const source = fs.readFileSync(path.join(__dirname, '../panel/settings.js'), 'utf8');

function fixture(replies, {action = null, remembered = null, activity = false} = {}) {
    if (!remembered) replies.unshift({ok:true,job:{id:null,state:'idle'}});
    const handlers = {}, requests = [];
    let updated = false, stored = remembered;
    const button = {textContent: 'Analyze logs', disabled: false};
    const progress = {textContent: ''};
    const cancel = {hidden: true, addEventListener: (_, fn) => {handlers.cancel = fn;}};
    const output = {replaceChildren: (...nodes) => {updated = nodes[0] === 'report';}, addEventListener: (_, fn) => {handlers.page = fn;}};
    const fields = {
        '[name="analysis_minutes"]': {value:'30'},
        '[name="analysis_target"]': {value:'all'},
        '[name="analysis_verify_google"]': {checked:false}
    };
    const form = {action: {toString: () => '[object HTMLInputElement]'},
        getAttribute: () => action,
        querySelector: selector => selector.startsWith('button') ? button : (fields[selector] || {value: 'csrf-token'}),
        addEventListener: (event, fn) => {handlers[event] = fn;}};
    const nodes = {[activity ? 'hdn-activity-scan' : 'hdn-log-scan']: form,
        [activity ? 'hdn-activity-progress' : 'hdn-analysis-progress']: progress,
        [activity ? 'hdn-activity-cancel' : 'hdn-analysis-cancel']: cancel,
        [activity ? 'hdn-activity-output' : 'hdn-analysis-output']: output,
        'hdn-agent-presets': {textContent: '{}'}, 'hdn-probe-presets': {textContent: '{}'}};
    vm.runInNewContext(source, {
        document: {getElementById: id => nodes[id], querySelectorAll: () => [], addEventListener() {}, importNode: node => node},
        location: {pathname: '/plugins/de-noise/', href: 'https://panel.test/plugins/de-noise/?tab=filters'},
        sessionStorage: {getItem: () => stored, setItem: (_, value) => {stored = value;}},
        FormData: class {constructor(input) {this.fields = new Map(input ? [['action', 'log_scan_start'], ['token', 'csrf-token'], ['analysis_target', 'all']] : []);} set(k,v) {this.fields.set(k,String(v));}},
        URL, setTimeout: fn => fn(),
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
    return {handlers, requests, button, progress, fields, updated: () => updated,
        submit: () => handlers.submit({preventDefault() {}})};
}
const queued = {ok: true, job: {id: 'one', state: 'queued'}};
const done = {ok: true, job: {id: 'one', state: 'complete'}, report: 'HTML'};

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
    await f.handlers.page({target:{closest:()=>({dataset:{hdnAnalysisPage:'2'}})}});
    assert.equal(f.fields['[name="analysis_minutes"]'].value,'1440');
    assert.equal(f.fields['[name="analysis_target"]'].value,'all');
});
test('pagination exposes remaining findings without policy changes', async () => {
    const f = fixture([queued,done,done]); await f.submit(); await f.handlers.page({target:{closest:()=>({dataset:{hdnAnalysisPage:'2'}})}});
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
});
