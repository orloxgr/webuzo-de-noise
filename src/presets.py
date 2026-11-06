"""Operator-selected rule suggestions, independent of installed applications."""
def static(ident, path, extensions):
    return {'id': ident, 'enabled': True, 'path': path, 'targets': [], 'extensions': extensions}


RULES = {
    'static': [
        {'key': 'wp_maps', 'title': 'WordPress source maps',
         'description': '/wp-content/ · map',
         'rules': [static('wp_source_maps', '/wp-content/', ['map'])]},
        {'key': 'wp_assets', 'title': 'WordPress JS / CSS',
         'description': '/wp-content/plugins/, /wp-content/themes/, /wp-includes/ · js css map',
         'rules': [static('wp_plugin_assets', '/wp-content/plugins/', ['js', 'css', 'map']),
                   static('wp_theme_assets', '/wp-content/themes/', ['js', 'css', 'map']),
                   static('wp_core_assets', '/wp-includes/', ['js', 'css', 'map'])]},
    ],
    'filters': [],  # Application-specific suggestions now come from log review.
}
