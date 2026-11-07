const {test} = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const source = fs.readFileSync(path.join(__dirname, '../panel/fail2ban.js'), 'utf8');

function fixture(replies, installation = null) {
    const handlers = {}, requests = [], errors = [];
    let replaced = false;
    const unchangedRule = {value:'unsaved crawler rule'};
    const form = action => ({id:action === 'fail2ban_status' ? 'hdn-fail2ban-refresh' : 'hdn-install-poll',
        action:{toString:()=> '[object HTMLInputElement]'}, fields:{action,token:'csrf-test',tab:'fail2ban'},
        getAttribute:()=>null, querySelector:()=>({disabled:false}), before:node=>errors.push(node)});
    const refreshForm = form('fail2ban_status'), pollForm = form('fail2ban_install_status');
    const output = installation && {dataset:{state:installation},textContent:''};
    const nodes = {'hdn-fail2ban-refresh':refreshForm, 'hdn-install-poll':installation ? pollForm : null,
        'hdn-install-progress':output, 'hdn-fail2ban-status':{dataset:{loaded:'true'}},
        'hdn-panel-fail2ban':{replaceChildren:()=>{replaced = true;}}, 'rule':unchangedRule};
    vm.runInNewContext(source, {
        document:{getElementById:id=>nodes[id],querySelector:()=>null,addEventListener:(event,fn)=>{handlers[event]=fn;},
            createElement:()=>({setAttribute(){}}),importNode:node=>node,contains:()=>true},
        FormData:class {constructor(form){this.fields = new Map(Object.entries(form.fields));}},
        location:{href:'https://panel.example.test/index.php?act=webuzo-de-noise'},
        DOMParser:class {parseFromString(){return {body:{childNodes:['new service report']}};}},
        setTimeout:fn=>fn(),
        fetch:async (url, options)=>{
            requests.push({url,options});assert.ok(replies.length, 'Unexpected request');
            const reply = replies.shift();
            return {ok:reply.http !== 403,json:async()=>reply};
        }
    });
    return {requests, errors, nodes, replaced:()=>replaced,
        submit:()=>handlers.submit({target:refreshForm,preventDefault(){}}),
        flush:()=>new Promise(resolve=>setImmediate(resolve))};
}

test('service status uses authenticated read-only AJAX and preserves unsaved website rules', async()=>{
    const f = fixture([{ok:true,report:'<p>services</p>'}]);f.submit();await f.flush();
    assert.equal(f.requests.length,1);assert.equal(f.replaced(),true);
    const request = f.requests[0];
    assert.equal(request.url,'https://panel.example.test/index.php?act=webuzo-de-noise');
    assert.equal(request.options.credentials,'same-origin');
    assert.equal(request.options.headers['X-HDN-Analysis'],'1');
    assert.equal(request.options.body.fields.get('token'),'csrf-test');
    assert.equal(request.options.body.fields.get('action'),'fail2ban_status');
    assert.equal(f.nodes.rule.value,'unsaved crawler rule');
});

test('an expired or forbidden status request does not replace the panel', async()=>{
    const f = fixture([{ok:false,http:403,error:'Request token expired'}]);f.submit();await f.flush();
    assert.equal(f.replaced(),false);assert.equal(f.errors[0].textContent,'Request token expired');
});

test('installation polling resumes the existing job and refreshes only on completion',async()=>{
    const f = fixture([{ok:true,install_job:{state:'running'}},
        {ok:true,install_job:{state:'complete',message:'Installed'}},
        {ok:true,report:'<p>installed</p>'}], 'running');
    await f.flush();
    assert.equal(f.replaced(),true);
    assert.deepEqual(f.requests.map(r=>r.options.body.fields.get('action')),
        ['fail2ban_install_status','fail2ban_install_status','fail2ban_status']);
    assert.equal(f.nodes['hdn-install-progress'].textContent,'Installed');
});

test('a failed package job stops polling and shows its actual diagnostic',async()=>{
    const f = fixture([{ok:true,install_job:{state:'failed',error:'Repository authentication failed'}}], 'queued');
    await f.flush();
    assert.equal(f.requests.length,1);assert.equal(f.replaced(),false);
    assert.equal(f.nodes['hdn-install-progress'].textContent,'Repository authentication failed');
});

test('viewing a page with no installation job does not install or start anything',async()=>{
    const f = fixture([]);await f.flush();assert.equal(f.requests.length,0);
});
