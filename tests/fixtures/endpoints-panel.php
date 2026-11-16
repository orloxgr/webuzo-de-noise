<?php
define('SOFTACULOUS', true);
$install = $argv[1];
$escape = static fn($v) => htmlspecialchars((string)$v, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
$actor = 'admin';
$fields = static function ($action) use ($escape) {
    echo '<input type="hidden" name="action" value="' . $escape($action) . '"><input type="hidden" name="token" value="fixture-token">';
};
$policy = ['custom_endpoints'=>[['id'=>'saved_rule','name'=>'Saved rule','enabled'=>true,'type'=>'regex',
    'pattern'=>'^/saved\.sql$','targets'=>[],'also_ban'=>true,'duration_seconds'=>7200]]];
$policy['endpoint_404']=['enabled'=>false,'paths'=>['/kept.php'],'targets'=>['alice/one.test'],'duration_seconds'=>7200,'maxretry'=>3,'findtime'=>600];
$policy['xmlrpc_block']=['enabled'=>true,'targets'=>['alice/one.test']];
$data = ['sites'=>[['key'=>'alice/one.test','domain'=>'one.test','owner'=>'alice'],['key'=>'bob/two.test','domain'=>'two.test','owner'=>'bob']],
    'analysis'=>['inventory_kind'=>'endpoints','minutes'=>1440,'totals'=>['requests'=>2],'findings_total'=>1,
        'bytes_read'=>1024,'partial'=>false,'note'=>'Fixture only','page'=>1,'pages'=>1,'per_page'=>20,
        'findings'=>[['domain'=>'one.test','site'=>'alice/one.test','path'=>'/wp-config.old','candidate'=>'/wp-config.old',
            'count'=>2,'successful'=>0,'missing'=>2,'eligible_404'=>true,'eligible_block'=>true,'can_append'=>true,'can_append_404'=>true,'category'=>'Backup / database filename','advice'=>'Review first',
            'statuses'=>['404'=>2],'methods'=>['GET'=>2],'clients'=>1,'first'=>1000,'last'=>1001,
            'agents'=>['Scanner <script>bad()</script>'=>2]]]]];
$data['analysis']['suggestions']=[['site'=>'alice/one.test','domain'=>'one.test','category'=>'Backup archives','action'=>'block',
    'title'=>'Proposed filename rule','detail'=>'Exactly the observed filenames','paths'=>['/wp-config.old','/wp-config.bak'],
    'missing_paths'=>['/wp-config.old','/wp-config.bak'],'block_paths'=>['/wp-config.old','/wp-config.bak'],'count'=>3,'statuses'=>['404'=>3],
    'pattern'=>null,'type'=>'exact']];
$data['analysis']['findings'][]=array_replace($data['analysis']['findings'][0],
    ['path'=>'/wp-blog-header.php','candidate'=>'/wp-blog-header.php','category'=>'PHP path',
     'eligible_404'=>false,'eligible_block'=>false,'advice'=>'Inspect application routing. No block or ban suggested.']);
foreach (['/missing.js','/missing.css','/application/route','/working.js'] as $path) {
    $success=$path==='/working.js';
    $mixed=$path==='/missing.js';
    $data['analysis']['findings'][]=array_replace($data['analysis']['findings'][0],
        ['path'=>$path,'candidate'=>$path,'eligible_block'=>false,'eligible_404'=>false,
         'can_append'=>true,'can_append_404'=>!$success,'successful'=>($success||$mixed)?1:0,
         'missing'=>$success?0:1,'statuses'=>$success?['200'=>1]:($mixed?['200'=>1,'404'=>1]:['404'=>1])]);
}
$data['analysis']['findings_total']=count($data['analysis']['findings']);
$data['analysis']['suggestions'][]=['site'=>'alice/one.test','domain'=>'one.test','category'=>'JavaScript','action'=>'review',
    'title'=>'Review requests','detail'=>'Manual actions are independent of this recommendation.',
    'paths'=>['/missing.js','/working.js'],'missing_paths'=>['/missing.js'],'block_paths'=>[],
    'count'=>3,'statuses'=>['404'=>1,'200'=>2],'pattern'=>null,'type'=>'exact'];
?>
<!doctype html><html><head><meta charset="utf-8"><style><?php readfile($install.'/panel/ui.css'); ?></style></head><body>
<div id="hdn-container"><form id="hdn-settings" method="post"><?php $fields('save'); ?></form>
<?php require $install.'/panel/endpoints.php'; ?></div>
<script id="hdn-agent-presets" type="application/json">{}</script>
<script id="hdn-probe-presets" type="application/json">{}</script>
<script id="hdn-rule-presets" type="application/json">{}</script>
<script><?php readfile($install.'/panel/rules.js'); ?></script>
<script><?php readfile($install.'/panel/lists.js'); ?></script>
</body></html>
