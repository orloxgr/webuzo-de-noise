"""Bundled bot descriptions. No network lookups or policy recommendations.

Purpose and attribution follow the linked operator/project documentation.
Usefulness describes practical applications, not measured traffic or rankings.
For user-run tools, the project is the developer, not the requester identity.
"""

DETAILS = {}


def add(names, operator, purpose, usefulness, url):
    for name in names.split('|'):
        DETAILS[name.casefold()] = dict(operator=operator, purpose=purpose,
            usefulness=usefulness, url=url)


OPENAI = 'https://developers.openai.com/api/docs/bots'
ANTHROPIC = 'https://support.anthropic.com/en/articles/8896518-does-anthropic-crawl-data-from-the-web-and-how-can-site-owners-block-the-crawler'
META = 'https://developers.facebook.com/docs/sharing/webmasters/web-crawlers/'
AMAZON = 'https://developer.amazon.com/docs/amazonbot/amazonbot.html'
GOOGLE = 'https://developers.google.com/crawling/docs/crawlers-fetchers/google-common-crawlers'
PERPLEXITY = 'https://docs.perplexity.ai/docs/resources/perplexity-crawlers'
EXA = 'https://crawler.exa.ai/'
AUDITS = 'Security tests you or your hosting provider requested; the tool can also be run by unrelated parties.'
TRAINING = 'Contributing content to AI model development; this is separate from search indexing and referrals.'

add('GPTBot', 'OpenAI', 'Collects web content that may be used to train generative AI models.', TRAINING, OPENAI)
add('OAI-SearchBot', 'OpenAI', 'Indexes pages for search in ChatGPT.', 'Discovery of your articles, services and shop pages in ChatGPT search.', OPENAI)
add('ChatGPT-User', 'OpenAI', 'Retrieves a page when a ChatGPT user or custom GPT requests it.', 'Letting ChatGPT users read and cite your pages during a conversation.', OPENAI)
add('OAI-AdsBot', 'OpenAI', 'Checks landing pages submitted as ads on ChatGPT.', 'Validating your campaigns and ad landing pages on ChatGPT.', OPENAI)
add('ClaudeBot', 'Anthropic', 'Collects web content that may contribute to Claude model training.', TRAINING, ANTHROPIC)
add('Claude-SearchBot', 'Anthropic', 'Collects content to improve search responses in Claude.', 'Discovery and citations of your pages in Claude search answers.', ANTHROPIC)
add('Claude-User', 'Anthropic', 'Retrieves pages in response to Claude user requests.', 'Letting Claude users access your articles, services and products.', ANTHROPIC)
add('meta-externalagent', 'Meta', 'Collects web content for uses including AI model training.', TRAINING, META)
add('meta-webindexer', 'Meta', 'Indexes web content for Meta AI search.', 'Discovery and citations of your pages in Meta AI search.', META)
add('meta-externalfetcher', 'Meta', 'Retrieves links at a user request in Meta products.', 'Letting users access your content through Meta AI features.', META)
add('meta-externalads', 'Meta', 'Collects information for ads and other business products.', 'Meta advertising and business-product workflows.', META)
add('facebookexternalhit', 'Meta', 'Fetches page metadata and images for shared-link previews.', 'Article and product previews when links are shared on Facebook and other Meta apps.', META)
add('facebookcatalog', 'Meta', 'Retrieves information associated with product catalogs.', 'Product catalog and commerce integrations in Meta products.', 'https://www.facebook.com/business/help/120325381656392')
add('Amazonbot', 'Amazon', 'Collects content to improve Amazon services and may train Amazon AI models.', 'Amazon product and AI development; use Amzn-SearchBot for the separate search use case.', AMAZON)
add('Amzn-SearchBot', 'Amazon', 'Indexes content for search experiences in Amazon products, including Alexa.', 'Discovery of your pages through Amazon and Alexa search experiences.', AMAZON)
add('Amzn-User', 'Amazon', 'Fetches live pages to answer user requests, including Alexa questions.', 'Helping Alexa users access current information from your site.', AMAZON)
add('Reflectionbot', 'Reflection AI', 'Collects public web pages to build and improve AI models.', TRAINING, 'https://reflection.ai/legal/reflectionbot')
add('ElevenlabsCrawler', 'ElevenLabs', 'Collects web content that may train ElevenLabs generative AI models.', TRAINING, 'https://elevenlabs.io/docs/bots')
add('Googlebot', 'Google', 'Crawls web pages for Google Search.', 'Organic search visibility for articles, services and e-shop product pages.', GOOGLE)
add('Googlebot-Image', 'Google', 'Crawls images for Google image search.', 'Discovery of product photos and other images in Google Images.', GOOGLE)
add('Googlebot-News', 'Google', 'Identifies Google News crawling preferences.', 'News content visibility in Google News; most relevant to publishers.', GOOGLE)
add('Googlebot-Video', 'Google', 'Crawls video content for Google video search.', 'Discovery of videos and product demonstrations in Google search.', GOOGLE)
add('GoogleOther', 'Google', 'General-purpose crawling for Google research and product teams.', 'Google research and product development; distinct from Google Search indexing.', GOOGLE)
add('Google-InspectionTool', 'Google', 'Supports Search Console URL inspection and Google testing tools.', 'Checking indexing, rendering and structured data on your own pages.', GOOGLE)
add('AdsBot-Google', 'Google', 'Checks the quality of Google Ads landing pages.', 'Google Ads campaigns, including e-shop advertising landing pages.', 'https://developers.google.com/crawling/docs/crawlers-fetchers/google-special-case-crawlers')
add('bingbot', 'Microsoft / Bing', 'Crawls web pages for the Bing search index.', 'Organic discovery of your articles, services and products through Bing.', 'https://www.bing.com/webmasters/help/which-crawlers-does-bing-use-8c184ec0')
add('Applebot', 'Apple', 'Crawls public web content for Apple search and related product features.', 'Discovery of your content through Apple features such as Siri and Spotlight.', 'https://support.apple.com/en-us/119829')
add('DuckDuckBot', 'DuckDuckGo', 'Crawls web pages to improve DuckDuckGo search.', 'Discovery of your pages in DuckDuckGo search.', 'https://duckduckgo.com/duckduckgo-help-pages/results/duckduckbot')
add('DuckAssistBot', 'DuckDuckGo', 'Retrieves web content for AI-assisted search answers.', 'Citations and discovery of your content in DuckDuckGo Search Assist.', 'https://duckduckgo.com/duckduckgo-help-pages/results/duckassistbot')
add('PerplexityBot', 'Perplexity', 'Indexes pages for Perplexity search, rather than foundation-model training.', 'Discovery and citations of your articles, services and product pages in Perplexity.', PERPLEXITY)
add('Perplexity-User', 'Perplexity', 'Retrieves pages in response to Perplexity user requests.', 'Letting Perplexity users read and cite your current content.', PERPLEXITY)
add('ExaSearchBot', 'Exa', 'Indexes public web pages for Exa search and retrieval.', 'Discovery and citations of your pages through applications using Exa search.', EXA)
add('ExaSearchBot-Images', 'Exa', 'Fetches images on pages crawled by Exa.', 'Image content accompanying your pages in Exa-powered search and retrieval.', EXA)
add('ExaUser', 'Exa', 'Retrieves a page in response to a user request.', 'Letting applications using Exa retrieve your current pages for their users.', EXA)
add('LinkupBot', 'Linkup', 'Builds the Linkup web search index for AI applications.', 'Discovery and citations through applications using Linkup search.', 'https://www.linkup.so/bot')
add('PetalBot', 'Huawei / Petal Search', 'Crawls web content for Petal Search.', 'Discovery of your pages through Petal Search.', 'https://webmaster.petalsearch.com/site/petalbot')
add('ibou-search', 'IBOU', 'Crawls pages for the IBOU search engine.', 'Discovery of your content in IBOU search.', 'https://ibou.io/manifeste-fr.html')
add('Baiduspider|Baiduspider-mobile', 'Baidu', 'Crawls web pages for Baidu search.', 'Search visibility when your audience includes users of Baidu.', 'https://help.baidu.com/question?class=476&id=2996&prod_id=99')
add('Baiduspider-render', 'Baidu', 'Renders pages for Baidu search crawling.', 'Helping Baidu understand pages that rely on rendered content.', 'https://help.baidu.com/question?class=476&id=2996&prod_id=99')
add('Baiduspider-image', 'Baidu', 'Crawls images for Baidu search.', 'Image and product-photo discovery for audiences using Baidu.', 'https://help.baidu.com/question?class=476&id=2996&prod_id=99')
add('Baiduspider-video', 'Baidu', 'Crawls video content for Baidu search.', 'Video discovery for audiences using Baidu.', 'https://help.baidu.com/question?class=476&id=2996&prod_id=99')
add('AhrefsBot', 'Ahrefs', 'Builds backlink and web data for Ahrefs tools and the Yep search engine.', 'Backlink research in Ahrefs and discovery through Yep.', 'https://ahrefs.com/robot')
add('AhrefsSiteAudit', 'Ahrefs', 'Audits websites for technical and on-page SEO issues.', 'Your own or your SEO agency\'s Ahrefs Site Audit checks.', 'https://ahrefs.com/robot')
add('SemrushBot', 'Semrush', 'Collects web and backlink information for Semrush tools.', 'SEO and backlink research when you or your agency use Semrush.', 'https://www.semrush.com/bot/')
add('SiteAuditBot', 'Semrush', 'Checks a website for technical SEO problems.', 'Your own or your agency\'s Semrush Site Audit checks.', 'https://www.semrush.com/bot/')
add('MJ12bot', 'Majestic', 'Maps links between websites for the Majestic backlink index.', 'Backlink analysis and link research in Majestic.', 'https://mj12bot.com/')
add('DotBot', 'Moz', 'Collects data for the Moz Link Index.', 'Link Explorer, backlink analysis and SEO reporting in Moz.', 'https://moz.com/help/moz-procedures/crawlers/dotbot')
add('BLEXBot', 'WebMeUp / SEO PowerSuite', 'Collects links for a backlink index and SEO tools.', 'Backlink research in WebMeUp and SEO PowerSuite tools.', 'https://webmeup-crawler.com/')
add('SERankingBacklinksBot', 'SE Ranking', 'Collects information about website links and their relationships.', 'Backlink analysis and competitor research in SE Ranking.', 'https://help.seranking.com/hc/en-us/articles/23020353159964-SERankingBacklinksBot-Crawler')
add('CCBot', 'Common Crawl', 'Builds an open repository of web crawl data used for research and AI model training.', 'General-purpose open datasets; AI training is one use, not the sole purpose.', 'https://www.commoncrawl.org/about')
add('CensysInspect', 'Censys', 'Maps publicly exposed internet services and their configurations.', 'Security research and finding exposed services; not product or article indexing.', 'https://docs.censys.com/docs/internet-scanning')
add('Expanse|Palo Alto Networks', 'Palo Alto Networks / Cortex Xpanse', 'Scans publicly exposed assets for attack-surface management.', 'Security and exposure monitoring; not search or e-shop indexing.', 'https://www.paloaltonetworks.com/company/press/2020/palo-alto-networks-completes-acquisition-of-expanse')
add('sqlmap', 'sqlmap project (user-run tool)', 'Tests for and can exploit SQL injection vulnerabilities.', AUDITS, 'https://sqlmap.org/')
add('Nikto', 'CIRT / Nikto project (user-run tool)', 'Checks web servers for vulnerable software, files and misconfigurations.', AUDITS, 'https://cirt.net/nikto/')
add('Nuclei', 'ProjectDiscovery (user-run tool)', 'Runs template-based vulnerability and exposure checks.', AUDITS, 'https://github.com/projectdiscovery/nuclei')
add('zgrab', 'ZMap project (user-run tool)', 'Collects application-layer service responses during internet scans.', AUDITS, 'https://github.com/zmap/zgrab2')
add('masscan', 'Masscan project (user-run tool)', 'Performs high-speed network port scanning and service discovery.', AUDITS, 'https://github.com/robertdavidgraham/masscan')
add('DirBuster', 'OWASP DirBuster project (user-run tool)', 'Searches for web directories and files using wordlists.', AUDITS, 'https://sourceforge.net/projects/dirbuster/')
add('gobuster', 'Gobuster project (user-run tool)', 'Enumerates paths, DNS names and virtual hosts.', AUDITS, 'https://github.com/OJ/gobuster')
add('ffuf', 'ffuf project (user-run tool)', 'Fuzzes web requests to discover paths, parameters and virtual hosts.', AUDITS, 'https://github.com/ffuf/ffuf')
add('WPScan', 'WPScan (user-run tool)', 'Checks WordPress core, plugins and themes for security issues.', 'WordPress security audits you or your provider requested.', 'https://wpscan.com/wordpress-cli-scanner/')
add('Slackbot', 'Slack', 'Fetches metadata and media for links shared in Slack.', 'Article and product-link previews in Slack conversations.', 'https://api.slack.com/robots')
add('Twitterbot', 'X / Twitter', 'Fetches metadata and images for shared-link cards.', 'Article and product previews when links are shared on X.', 'https://docs.x.com/x-for-websites/cards/overview/abouts-cards')
add('Discordbot', 'Discord', 'Fetches metadata for shared-link embeds.', 'Article and product-link previews in Discord conversations.', 'https://discord.com/developers/docs/resources/message#embed-object')
add('WhatsApp', 'Meta / WhatsApp', 'Retrieves page information for shared-link previews.', 'Article and product-link previews in WhatsApp conversations.', 'https://faq.whatsapp.com/1082723438217439')
add('TelegramBot', 'Telegram', 'Retrieves page information for shared-link previews.', 'Article and product-link previews in Telegram conversations.', 'https://telegram.org/blog/link-preview-options')


add('DataForSeoBot', 'DataForSEO', 'Collects links for a backlink index.', 'Backlink data and SEO analysis through DataForSEO products.', 'https://dataforseo.com/dataforseo-bot')
add('Barkrowler', 'Babbar', 'Collects links and page metadata to build a web graph.', 'Link research and SEO analysis with Babbar.', 'https://www.babbar.tech/crawler')
add('serpstatbot', 'Serpstat', 'Collects links for backlink analysis.', 'Backlink research and competitor analysis in Serpstat.', 'https://serpstatbot.com/')
add('SearchAtlasBot', 'Search Atlas', 'Crawls websites for Search Atlas and OTTO SEO checks.', 'SEO audits and OTTO workflows you or your agency use.', 'https://chat.labs.searchatlas.com/hc/searchatlas-help/articles/1786754770-update-otto-sitemap-and-robots-txt-after-deleting-ur_ls')
add('LinkpadBot', 'Linkpad', 'Collects website links for a backlink index.', 'Linkpad backlink analysis and SEO research.', 'https://www.linkpad.ru/help/')
add('Screaming Frog SEO Spider', 'Screaming Frog (user-run tool)', 'Crawls websites for technical SEO audits.', 'Audits you or your SEO agency run; the tool can also be run by unrelated parties.', 'https://www.screamingfrog.co.uk/seo-spider/')
add('MegaIndex.ru', 'MegaIndex (historical crawler name)', 'Historically associated with MegaIndex SEO and backlink crawling; current documentation of this exact name is unavailable.', 'Review your SEO services and requested URLs; the declared name does not verify the requester.', 'https://www.megaindex.ru/')
add('SeobilityBot', 'Seobility', 'Crawls websites for SEO analysis.', 'Technical SEO checks and monitoring through Seobility.', 'https://www.seobility.net/en/bot/')
add('SEOkicks-Robot', 'SEOkicks', 'Collects links for a backlink index.', 'Backlink research and SEO analysis in SEOkicks.', 'https://www.seokicks.de/robot.html')
add('rogerbot', 'Moz', 'Crawls websites for Moz campaign site audits.', 'Moz SEO audits you or your agency requested.', 'https://moz.com/help/moz-procedures/crawlers/rogerbot')
add('Owler', 'OpenWebSearch / OpenWebIndex', 'Crawls web pages for an open search index.', 'Discovery through services using the open web index; distinct from the similarly named business-information service.', 'https://openwebsearch.eu/owler/')
add('SeekportBot', 'Seekport / SISTRIX', 'Crawls web pages for Seekport search.', 'Search discovery for audiences using Seekport.', 'https://bot.seekport.com/')
add('YandexBot', 'Yandex', 'Crawls web pages for Yandex search.', 'Search visibility when your audience uses Yandex.', 'https://yandex.com/support/webmaster/en/robot-workings/check-yandex-robots.html')
add('MojeekBot', 'Mojeek', 'Crawls pages for the independent Mojeek search index.', 'Discovery through Mojeek search and services using its index.', 'https://www2.mojeek.com/bot.html')
add('IbouBot', 'IBOU', 'Crawls web pages for IBOU search.', 'Discovery through IBOU search; kept separate from the ibou-search declaration.', 'https://ibou.io/iboubot.html')
add('360Spider', '360 Search', 'Crawls web pages for 360 Search.', 'Search visibility for audiences using 360 Search.', 'https://www.so.com/help/help_3_2.html')
add('AwarioBot', 'Awario', 'Collects web mentions for brand and social listening.', 'Monitoring mentions of your brand and products through Awario.', 'https://awario.com/bots.html')
add('ImagesiftBot', 'Hive / Imagesift', 'Collects public images and related text for web intelligence and image search.', 'Image discovery and web intelligence; this is not a general web search indexer.', 'https://imagesift.com/about')
add('VelenPublicWebCrawler', 'Velen / Hunter', 'Collects public web data for business datasets and machine-learning models.', 'Business data and research datasets; review whether these uses benefit your site.', 'https://velen.io/')
add('ZoominfoBot', 'ZoomInfo (as listed by Cloudflare)', 'Indexes company and professional information for specialized business search.', 'Discovery of businesses and professionals through ZoomInfo; a specialized search index rather than a general consumer engine.', 'https://radar.cloudflare.com/bots/directory/zoominfobot')
add('Magpie-Crawler', 'Brandwatch', 'Collects public web content for social listening.', 'Brand monitoring and consumer research through Brandwatch.', 'https://www.brandwatch.com/legal/magpie-crawler/')
add('RecordedFuture', 'Recorded Future (declared name; requester not verified)', 'The named service collects public information for threat intelligence; its privacy policy does not confirm this exact User-Agent.', 'Threat intelligence and security research; review requested URLs before blocking.', 'https://www.recordedfuture.com/legal/privacy-policy/4-0')
add('Go-http-client', 'Go net/http library (user-run client)', 'Default client declaration used by programs making HTTP requests with Go.', 'May be a legitimate integration, monitor or crawler; this name alone identifies no particular bot.', 'https://go.dev/src/net/http/request.go')
add('quic-go', 'quic-go project (client library)', 'QUIC and HTTP/3 library used by multiple applications.', 'May be a legitimate client or integration; this name alone identifies no particular bot.', 'https://github.com/quic-go/quic-go')
add('Bytespider', 'ByteDance', 'Collects public content, including data for AI model training, testing and validation.', 'Contributing data to ByteDance AI development; the cited training-data summary documents this use, not every use of the crawler.', 'https://aial.ie/research/gpai-training-transparency/archive/ByteDance_Seedeam_5_0_2026_09_08.pdf')
add('YisouSpider', 'Shenma Search', 'Crawls web pages for Shenma mobile search.', 'Search visibility for audiences using Shenma in China.', 'https://zhanzhang.sm.cn/open/optimizaGuide')

add('ShapBot', 'Parallel', 'Collects public web pages to build and maintain the Parallel search index.', 'Discovery through Parallel web search APIs and search features. Separate from user-triggered Shap-User requests.', 'https://parallel.ai/parallel-web-systems-bots')


add('RiverBot', 'River', 'Collects public web pages for AI model training and evaluation.', TRAINING, 'https://river.ai/bot')
add('PostHogImageFetcherBot', 'PostHog', 'Downloads images referenced by session recordings for AI training; not a search crawler.', 'AI training image retrieval. Blocking this fetcher does not disable ordinary PostHog session recording or replay.', 'https://posthog.com/docs/ai-research/image-fetcher-bot')
add('KeenableBot', 'Keenable', 'Builds and maintains a search index for AI agents and applications.', 'Discovery and citations through Keenable search; separate from user-triggered Keenable-User fetches.', 'https://app.keenable.ai/bot')
add('Keenable-User', 'Keenable', 'Fetches specific pages requested by a person or an agent acting for one.', 'User-requested retrieval through Keenable; separate from its search-index crawler.', 'https://app.keenable.ai/bot')
add('SofyaBot', 'Sofya', 'Builds an independent web search index.', 'Discovery through Sofya search; separate from user-triggered Sofya-User fetches.', 'https://sofya.co/bot')
add('Sofya-User', 'Sofya', 'Fetches individual pages requested by users of Sofya.', 'User-requested access to your current pages through Sofya.', 'https://sofya.co/bot')
add('SeznamBot', 'Seznam', 'Crawls web pages for Seznam search.', 'Search visibility for audiences using Seznam.', 'https://o-seznam.cz/napoveda/vyhledavani/en/seznambot-crawler/')
add('Qwantbot', 'Qwant', 'Builds and refreshes the Qwant web search index.', 'Discovery of pages through Qwant search.', 'https://help.qwant.com/bot')
add('Qwantbot-news', 'Qwant', 'Crawls content for Qwant News.', 'News discovery through Qwant; kept separate from the general web crawler in analysis.', 'https://help.qwant.com/bot')
add('Sogou web spider', 'Sogou (declared crawler name)', 'Declares Sogou web search crawling.', 'Search visibility for audiences using Sogou; the declaration does not verify the requester.', 'https://www.sogou.com/docs/help/webmasters.htm')
add('Sogou Pic Spider', 'Sogou (declared image crawler name)', 'Declares image crawling for Sogou; kept separate from the web spider.', 'Image discovery for audiences using Sogou; the declaration does not verify the requester.', 'https://www.sogou.com/docs/help/webmasters.htm')
add('l9scan', 'LeakIX scanning project (declared name)', 'Declares internet-service scanning; l9scan is named in LeakIX event pipelines.', 'Exposure and security research; the name alone does not establish who ran a scan.', 'https://docs.leakix.net/docs/api/domain/')
add('ModatScanner', 'Modat', 'Scans and indexes publicly exposed hosts and services at machine level.', 'Internet exposure and security research rather than ordinary web search indexing.', 'https://scanner.modat.io/')
add('webXtrendBot', 'webXtrend', 'Collects domain, DNS, redirect and start-page information, with periodic revisits.', 'Market research, competitive analysis, security and brand protection; collection and monitoring overlap.', 'https://webxtrend.com/crawler')
add('KStandBot', 'URL Classification / Komodia', 'Crawls websites to classify their content, with periodic revisits.', 'Website categorization and filtering services.', 'https://url-classification.io/wiki/index.php/Website_classification_crawler')
add('HeadlessChrome', 'Chrome automation (requester not identified)', 'Chrome running without a visible browser window; not a specific crawler or security scanner.', 'Rendering, screenshots, tests and other automation, including scraping. Review your own services before blocking this broad name.', 'https://developer.chrome.com/docs/automation-and-testing/headless')
add('Python-urllib', 'Python urllib library (user-run client)', 'HTTP client declaration used by programs using Python urllib.', 'May be a legitimate integration, monitor or script; the name alone does not identify a particular bot.', 'https://docs.python.org/3/library/urllib.request.html')
add('python-requests', 'Requests project (user-run client)', 'HTTP client library used by many Python programs.', 'May be an API integration, monitor or script; review your own services before restricting it.', 'https://requests.readthedocs.io/en/latest/')
add('curl', 'curl project (user-run client)', 'Command-line HTTP client and transfer tool used by many scripts.', 'May be a legitimate health check, scheduled task or integration; not a specific bot.', 'https://curl.se/docs/manpage.html')
add('httpx', 'HTTPX declaration (requester not identified)', 'A shared client name that does not establish which HTTP client or tool made a request.', 'May be a legitimate HTTP client, integration or testing tool; inspect requested URLs before restricting it.', None)
add('Bravebot', 'Not confirmed', 'This declaration is not confirmed as Brave Search. Brave documents that its crawler does not advertise a differentiated User-Agent.', 'Review the requester independently; do not infer official Brave identity or maliciousness from this name.', 'https://search.brave.com/help/brave-search-crawler')
add('WP-Safe-Scanner|wp-cve-2026-87902-validator', 'Not confirmed', 'The name declares WordPress security testing; the operator and claimed checks are unverified.', 'Could be an authorized audit or an unrelated scan. The declaration does not establish a vulnerability or validate a CVE identifier.', None)


def describe(name):
    known = DETAILS.get(name.casefold())
    if known:
        return dict(known)
    return dict(operator='Not confirmed', purpose='No documented bot purpose identified for this name.',
                usefulness='Review the requested URLs and your integrations before blocking.', url=None)
