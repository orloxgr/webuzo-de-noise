const {test} = require('node:test');
const assert = require('node:assert/strict');
const {csv, pageRows, ruleData} = require('../panel/lists.js');

test('all supported sizes expose disjoint complete pages, including All above 500 records', () => {
    const rows = Array.from({length: 1508}, (_, i) => ({id:i, checked:i === 1499}));
    for (const size of ['20','50','100','500']) {
        const visited = [];
        for (let page = 1; page <= Math.ceil(rows.length / Number(size)); page++) visited.push(...pageRows(rows, size, page).visible);
        assert.deepEqual(visited, rows);
    }
    const all = pageRows(rows, 'all', 400);
    assert.equal(all.pages, 1); assert.equal(all.page, 1);
    assert.equal(all.visible.length, 1508);
    assert.equal(all.visible[1499], rows[1499]); // Keep edited controls and selections.
    assert.equal(pageRows([], '20', 1).pages, 1);
    assert.throws(() => pageRows(rows, '1000', 1));
});

test('CSV includes every supplied row and neutralizes formulas without losing quoted Unicode/newlines', () => {
    const rows = [['Agent','Hits'], ['=HYPERLINK("bad")', 4], [' \t+SUM(1)', 3], ['@x', 2], ['-2+3', 1], ['Μια "τιμή"\nεδώ', 0], ...Array.from({length: 1508}, (_, i) => ['Agent' + i, i])];
    const text = csv(rows);
    assert.ok(text.startsWith('\uFEFF"Agent","Hits"\r\n'));
    assert.ok(text.includes('"\'=HYPERLINK(""bad"")","4"'));
    assert.ok(text.includes('"\' \t+SUM(1)"'));
    assert.ok(text.includes('"Μια ""τιμή""\nεδώ","0"'));
    assert.ok(text.includes('"Agent1507","1507"\r\n'));
});

test('rule CSV includes live edits, textarea patterns, selected domains and actual enabled state', () => {
    const field = (key, value, more = {}) => ({name:'filters[3][' + key + ']',value,...more});
    const row = ruleData([field('id','my_rule'),field('path','/shop/'),field('enabled','on',{type:'checkbox',checked:false}),
        field('agents','CrawlerOne\nCrawlerTwo'),field('parameters','sort\ncolor'),
        field('targets','',{multiple:true,selectedOptions:[{textContent:'a.test'},{textContent:'b.test'}]})]);
    assert.deepEqual(row.slice(0,2),['my_rule','/shop/']);
    assert.ok(row[2].includes('[enabled]: No'));
    assert.ok(row[2].includes('CrawlerOne\nCrawlerTwo'));
    assert.ok(row[2].includes('sort\ncolor'));
    assert.ok(row[2].includes('a.test; b.test'));
});
