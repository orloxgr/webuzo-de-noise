"""Purpose-based suggestions; names are declarations, never identity proof."""
import re

SCANNERS = ['TLM-Audit-Scanner', 'sqlmap', 'Nikto', 'Nuclei', 'zgrab',
            'masscan', 'ZmEu', 'DirBuster', 'gobuster', 'ffuf', 'WPScan',
            'CensysInspect', 'Expanse', 'Palo Alto Networks']
AI = ['meta-externalagent', 'ClaudeBot', 'GPTBot', 'Reflectionbot', 'Amazonbot',
      'Bytespider', 'ElevenlabsCrawler', 'CCBot', 'VelenPublicWebCrawler']
SEARCH_ADDITIONAL = ['PetalBot', 'Baiduspider', 'ibou-search', 'Owler', 'SeekportBot',
                     'YandexBot', 'MojeekBot', 'IbouBot', '360Spider', 'YisouSpider', 'ZoominfoBot']
SEARCH_MAJOR = ['Googlebot', 'Googlebot-Image', 'Googlebot-News', 'Googlebot-Video',
                'bingbot', 'Applebot', 'DuckDuckBot', 'DuckAssistBot', 'meta-webindexer',
                'OAI-SearchBot', 'Claude-SearchBot', 'Amzn-SearchBot', 'PerplexityBot',
                'ExaSearchBot', 'ExaSearchBot-Images', 'LinkupBot']
SEARCH = SEARCH_ADDITIONAL + SEARCH_MAJOR
# Optional append groups in the same Search editor, never saved policy defaults.
SEARCH_PRESETS = {'search_additional': SEARCH_ADDITIONAL, 'search_major': SEARCH_MAJOR}
SEO = ['MJ12bot', 'AhrefsBot', 'SemrushBot', 'DotBot', 'BLEXBot', 'SERankingBacklinksBot',
       'DataForSeoBot', 'Barkrowler', 'serpstatbot', 'SearchAtlasBot', 'LinkpadBot',
       'Screaming Frog SEO Spider', 'MegaIndex.ru', 'SeobilityBot', 'SEOkicks-Robot', 'rogerbot']
OTHER = ['GoogleOther', 'AwarioBot', 'ImagesiftBot', 'Magpie-Crawler', 'RecordedFuture']

CATEGORIES = {
    'tool_agents': dict(title='Scanner tools', entries=SCANNERS,
        description='Security scanners and testing tools, including tools used for authorized audits.'),
    'ai_agents': dict(title='AI Training Crawlers', entries=AI,
        description='Content collection for AI model development and training, including general-purpose datasets used for AI. Common Crawl and Velen also support research or business uses; this category does not imply exclusive AI use.'),
    'search_agents': dict(title='Search Indexers', entries=SEARCH,
        description='Search and AI search indexing. Blocking these crawlers can reduce visibility in their services.'),
    'seo_agents': dict(title='SEO & Backlink Crawlers', entries=SEO,
        description='SEO analysis and backlink indexes. Some also feed search engines; AhrefsBot powers Yep as well as Ahrefs tools.'),
    'agents': dict(title='Data Collection / Monitoring', entries=OTHER,
        description='General research, image collection, brand monitoring and threat intelligence. Recognized fetch clients and unclassified declarations also appear here for individual review.')}

# Recognize fetch clients, variants and uncertain/generic declarations separately.
# Generic libraries and names with no confirmed purpose are not bulk suggestions.
EXTRA = {
    'search_agents': ['Baiduspider-render', 'Baiduspider-image', 'Baiduspider-mobile', 'Baiduspider-video'],
    'seo_agents': ['AhrefsSiteAudit', 'SiteAuditBot'],
    'agents': ['ChatGPT-User', 'Claude-User', 'Amzn-User', 'meta-externalfetcher',
               'Perplexity-User', 'ExaUser', 'Google-InspectionTool', 'AdsBot-Google',
               'OAI-AdsBot', 'meta-externalads', 'facebookcatalog',
               'facebookexternalhit', 'Twitterbot', 'Slackbot', 'Discordbot', 'WhatsApp', 'TelegramBot',
               'BacklinksExtendedBot', 'Timpibot', 'CMS-Checker', 'AionBot', 'Epochal-Search',
               'BasegrowBot', 'Amazon Web Services', 'Go-http-client', 'quic-go']}

# Keep distinct products (including image/render crawlers) separate so appending
# a selected row never broadens an image-only rule to an entire crawler family.
_NAMES = [(name, field) for field, category in CATEGORIES.items()
          for name in category['entries'] + EXTRA.get(field, [])]
_OBSERVED = tuple((re.compile(r'(?<![A-Za-z0-9_-])' + re.escape(name) + r'(?![A-Za-z0-9_-])', re.I), name, field)
                  for name, field in sorted(_NAMES, key=lambda row: -len(row[0])))


def classify(value):
    """Classify a complete declared name, not an arbitrary matching substring."""
    for field, category in CATEGORIES.items():
        for name in category['entries'] + EXTRA.get(field, []):
            if value.strip().casefold() == name.casefold():
                return field
    return 'agents'


def observed(value):
    # Longest product names first; e.g. AhrefsSiteAudit is not AhrefsBot.
    for pattern, name, field in _OBSERVED:
        if pattern.search(value):
            return name, field
    # Keep unknown declarations separate instead of combining all of them as
    # "Other". No automatic block, heuristic malicious label or network lookup.
    return value, 'agents'


def enabled(policy):
    return list(dict.fromkeys(entry for field in CATEGORIES if policy[field + '_enabled']
                             for entry in policy[field]))


def describe(value):
    """Explain a declared product without changing classification or rules."""
    import agent_details
    name, _ = observed(value)
    return agent_details.describe(name)
