"""Purpose-based suggestions; names are declarations, never identity proof."""
import re

SCANNERS = ['TLM-Audit-Scanner', 'sqlmap', 'Nikto', 'Nuclei', 'zgrab',
            'masscan', 'ZmEu', 'DirBuster', 'gobuster', 'ffuf', 'WPScan']
AI = ['meta-externalagent', 'ClaudeBot', 'GPTBot', 'Reflectionbot', 'Amazonbot']
SEARCH = ['LinkupBot', 'meta-webindexer', 'PetalBot', 'Baiduspider', 'ibou-search']
SEO = ['MJ12bot', 'AhrefsBot', 'SemrushBot', 'DotBot', 'BLEXBot']
OTHER = ['GoogleOther', 'Bytespider', 'YisouSpider', 'ElevenlabsCrawler', 'CCBot']

CATEGORIES = {
    'tool_agents': dict(title='Scanner tools', entries=SCANNERS,
        description='Security scanners and testing tools, including tools used for authorized audits.'),
    'ai_agents': dict(title='AI Training Crawlers', entries=AI,
        description='Content collection for AI model development and training. Some operators also use the data for other products.'),
    'search_agents': dict(title='Search Indexers', entries=SEARCH,
        description='Search and AI search indexing. Blocking these crawlers can reduce visibility in their services.'),
    'seo_agents': dict(title='SEO & Backlink Crawlers', entries=SEO,
        description='SEO analysis and backlink indexes. Some also feed search engines; AhrefsBot powers Yep as well as Ahrefs tools.'),
    'agents': dict(title='Other Crawlers / Data Collection', entries=OTHER,
        description='General collection, research and agents with mixed or unclassified purposes. Review individual names before blocking.')}

# Recognize useful search/fetch clients without adding them to block suggestions.
EXTRA = {
    'search_agents': ['OAI-SearchBot', 'Claude-SearchBot', 'Amzn-SearchBot',
                      'Googlebot', 'bingbot', 'Applebot', 'DuckDuckBot'],
    'seo_agents': ['AhrefsSiteAudit', 'SiteAuditBot', 'SERankingBacklinksBot'],
    'agents': ['ChatGPT-User', 'Claude-User', 'Amzn-User', 'meta-externalfetcher',
               'facebookexternalhit', 'Twitterbot', 'Slackbot', 'Discordbot', 'WhatsApp', 'TelegramBot']}


def classify(value):
    """Classify a complete declared name, not an arbitrary matching substring."""
    for field, category in CATEGORIES.items():
        for name in category['entries'] + EXTRA.get(field, []):
            if value.strip().casefold() == name.casefold():
                return field
    return 'agents'


def observed(value):
    # Longest product names first; e.g. AhrefsSiteAudit is not AhrefsBot.
    names = [(name, field) for field, category in CATEGORIES.items()
             for name in category['entries'] + EXTRA.get(field, [])]
    for name, field in sorted(names, key=lambda row: -len(row[0])):
        if re.search(r'(?<![A-Za-z0-9_-])' + re.escape(name) + r'(?![A-Za-z0-9_-])', value, re.I):
            return name, field
    # Keep unknown declarations separate instead of combining all of them as
    # "Other". No automatic block, heuristic malicious label or network lookup.
    return value, 'agents'


def enabled(policy):
    return list(dict.fromkeys(entry for field in CATEGORIES if policy[field + '_enabled']
                             for entry in policy[field]))
