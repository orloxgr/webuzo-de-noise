"""Community declarations and optional search groups preserve policy choices."""
import copy
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
import agent_catalog as catalog
import policy


class AgentPresets(unittest.TestCase):
    def test_all_community_names_are_recognized_under_their_purpose(self):
        groups = {
            'ai_agents': 'Amazonbot|ClaudeBot|GPTBot|Reflectionbot|Bytespider|VelenPublicWebCrawler|CCBot',
            'search_agents': 'Owler|SeekportBot|YandexBot|OAI-SearchBot|PetalBot|MojeekBot|IbouBot|360Spider|PerplexityBot|BaiduSpider|Claude-SearchBot|ExaSearchBot|ZoominfoBot',
            'seo_agents': 'DataForSeoBot|SemrushBot|DotBot|MJ12bot|Barkrowler|serpstatbot|BLEXBot|AhrefsBot|SearchAtlasBot|LinkpadBot|Screaming Frog SEO Spider|SERankingBacklinksBot|MegaIndex.ru|SeobilityBot|SEOkicks-Robot|rogerbot',
            'agents': 'Amazon Web Services|AwarioBot|ImagesiftBot|GoogleOther|BacklinksExtendedBot|Timpibot|Magpie-Crawler|Go-http-client|RecordedFuture|quic-go|CMS-Checker|AionBot|Epochal-Search|BasegrowBot',
        }
        self.assertEqual(sum(len(names.split('|')) for names in groups.values()), 50)
        for field, names in groups.items():
            for name in names.split('|'):
                with self.subTest(name=name):
                    canonical, observed_field = catalog.observed('Mozilla/5.0 (compatible; ' + name.lower() + '/1.0)')
                    self.assertEqual(canonical.casefold(), name.casefold())
                    self.assertEqual(observed_field, field)
                    self.assertEqual(catalog.classify(name), field)

    def test_search_groups_separate_main_search_and_ai_without_changing_categories(self):
        additional = set(catalog.SEARCH_PRESETS['search_additional'])
        major = set(catalog.SEARCH_PRESETS['search_major'])
        self.assertFalse(additional & major)
        self.assertEqual(additional | major, set(catalog.CATEGORIES['search_agents']['entries']))
        self.assertTrue({'Googlebot', 'bingbot', 'meta-webindexer', 'OAI-SearchBot',
                         'Claude-SearchBot', 'PerplexityBot'} <= major)
        self.assertTrue({'MojeekBot', 'YandexBot', 'SeekportBot', 'Owler', 'IbouBot', 'YisouSpider', 'ZoominfoBot'} <= additional)
        for name in major | additional:
            self.assertEqual(catalog.classify(name), 'search_agents')
        self.assertEqual(len(catalog.CATEGORIES), 5)
        self.assertEqual(catalog.classify('Screaming Frog SEO Spider'), 'seo_agents')

    def test_general_clients_and_unconfirmed_names_are_reviewable_without_bulk_suggestions(self):
        suggestions = {name for category in catalog.CATEGORIES.values() for name in category['entries']}
        for name in ('Amazon Web Services', 'Go-http-client', 'quic-go', 'BacklinksExtendedBot',
                     'Timpibot', 'CMS-Checker', 'AionBot', 'Epochal-Search', 'BasegrowBot'):
            self.assertIn(name, catalog.EXTRA['agents'])
            self.assertNotIn(name, suggestions)
            self.assertEqual(policy.validate_agents([name]), [name])
        for name in ('BacklinksExtendedBot', 'Timpibot', 'CMS-Checker', 'AionBot', 'Epochal-Search', 'BasegrowBot'):
            self.assertEqual(catalog.describe(name)['operator'], 'Not confirmed')
        self.assertIn('OpenWeb', catalog.describe('Owler')['operator'])
        self.assertEqual(catalog.describe('Magpie-Crawler')['operator'], 'Brandwatch')

    def test_upgrade_keeps_saved_entries_and_switches_exactly(self):
        saved = copy.deepcopy(policy.DEFAULT)
        saved.update(search_agents=['My custom search', 'meta-webindexer'],
                     search_agents_enabled=False, seo_agents=['AhrefsBot'],
                     agents=['CMS-Checker'], agents_enabled=False)
        upgraded = policy.validate(copy.deepcopy(saved))
        self.assertEqual(upgraded, saved)
        self.assertEqual(policy.validate(copy.deepcopy(policy.DEFAULT)), policy.DEFAULT)
        compiled = policy.global_config(upgraded, [])
        for name in catalog.SEARCH_MAJOR:
            self.assertNotIn(policy.literal_regex(name), compiled)

    def test_reclassified_presets_do_not_move_saved_rules_between_switches(self):
        moved = ['Bytespider', 'ElevenlabsCrawler', 'CCBot', 'VelenPublicWebCrawler',
                 'YisouSpider', 'ZoominfoBot']
        for enabled in (True, False):
            saved = copy.deepcopy(policy.DEFAULT)
            saved.update(agents=moved, agents_enabled=enabled,
                         ai_agents_enabled=not enabled, search_agents_enabled=not enabled)
            upgraded = policy.validate(copy.deepcopy(saved))
            self.assertEqual(upgraded, saved)
            self.assertEqual(catalog.enabled(upgraded), moved if enabled else [])
        self.assertEqual(catalog.classify('ElevenlabsCrawler'), 'ai_agents')
        self.assertIn('research', catalog.describe('CCBot')['purpose'])

    def test_new_declared_products_are_separate_from_generic_and_unconfirmed_clients(self):
        groups = {
            'ai_agents': ['RiverBot', 'PostHogImageFetcherBot'],
            'search_agents': ['KeenableBot', 'SeznamBot', 'SofyaBot', 'Qwantbot',
                              'Sogou web spider', 'Sogou Pic Spider', 'Qwantbot-news'],
            'tool_agents': ['l9scan', 'ModatScanner', 'WP-Safe-Scanner', 'wp-cve-2026-87902-validator'],
            'agents': ['webXtrendBot', 'KStandBot', 'Keenable-User', 'Sofya-User'] + catalog.VARIOUS,
        }
        for field, names in groups.items():
            for name in names:
                with self.subTest(name=name):
                    self.assertEqual(catalog.observed('Mozilla/5.0 (' + name.lower() + '/1.0)'), (name, field))
        for name in ('HeadlessChrome', 'Bravebot', 'WP-Safe-Scanner', 'wp-cve-2026-87902-validator'):
            self.assertNotIn(name, {n for c in catalog.CATEGORIES.values() for n in c['entries']})
        self.assertEqual(catalog.describe('Bravebot')['operator'], 'Not confirmed')
        self.assertIn('does not establish', catalog.describe('wp-cve-2026-87902-validator')['usefulness'])

    def test_specific_products_override_generic_renderers_and_libraries_in_analysis_only(self):
        for name, field in [('RiverBot', 'ai_agents'), ('ShapBot', 'search_agents'),
                            ('Sogou Pic Spider', 'search_agents'), ('Sofya-User', 'agents')]:
            self.assertEqual(catalog.observed('HeadlessChrome/145.0 curl/8.0 ' + name + '/1.0'), (name, field))
        for name in ('HeadlessChrome', 'curl', 'FontScanBot'):
            raw = 'Not' + name + '/1.0'
            self.assertEqual(catalog.observed(raw), (raw, 'agents'))
        self.assertEqual(catalog.observed('Qwantbot-news/2.0'), ('Qwantbot-news', 'search_agents'))

    def test_collection_monitoring_bulk_and_various_selection_are_disjoint(self):
        self.assertEqual(set(catalog.DATA_COLLECTION) | set(catalog.MONITORING), set(catalog.OTHER))
        self.assertFalse(set(catalog.DATA_COLLECTION) & set(catalog.MONITORING))
        bulk = {name for category in catalog.CATEGORIES.values() for name in category['entries']}
        self.assertFalse(bulk & set(catalog.VARIOUS))
        choices = catalog.review_choices()
        self.assertEqual([row['name'] for row in choices], catalog.VARIOUS)
        for row in choices:
            self.assertTrue(row['purpose'] and row['usefulness'] and row['kind'])
            self.assertNotIn('checked', row)
        for name in ('ChatGPT-User', 'facebookcatalog', 'AdsBot-Google-Mobile', 'Pinterestbot'):
            self.assertNotIn(name, bulk | set(catalog.VARIOUS))

    def test_catalog_update_preserves_saved_block_and_rate_rules_and_schema16(self):
        saved = copy.deepcopy(policy.DEFAULT)
        saved.update(agents=['RiverBot', 'HeadlessChrome', 'My manual name'], agents_enabled=False,
                     search_agents=['KStandBot'], search_agents_enabled=True)
        saved['agent_limits']['agents']['group'].update(enabled=True, agents=['curl'], rate=7)
        saved['agent_limits']['agents']['individual'] = [dict(enabled=True, agent='HeadlessChrome', rate=3, unit='m', burst=0)]
        self.assertEqual(policy.validate(copy.deepcopy(saved)), saved)
        old = copy.deepcopy(saved); old.pop('agent_limits'); old['schema'] = 15
        migrated = policy.validate(old)
        for field in catalog.CATEGORIES:
            self.assertEqual(migrated[field], saved[field])
            self.assertEqual(migrated[field + '_enabled'], saved[field + '_enabled'])
        self.assertEqual(migrated['agent_limits'], policy.DEFAULT['agent_limits'])
        compiled = policy.global_config(policy.DEFAULT, [])
        for name in ('HeadlessChrome', 'RiverBot', 'ModatScanner', 'webXtrendBot'):
            self.assertNotIn(policy.literal_regex(name), compiled)


if __name__ == '__main__':
    unittest.main()
