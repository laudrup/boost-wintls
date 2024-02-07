import sphinx_bootstrap_theme
import os
import sys

sys.path.append(os.path.abspath("./extensions"))

project = 'wintls'
copyright = '2021, Kasper Laudrup'
author = 'Kasper Laudrup'

master_doc = 'index'

extensions = ['sphinx.ext.autosectionlabel',
              'breathe',
              'toctree_elements',
              'remove_inline_specifier',
              'sphinx_jinja',
              ]

highlight_language = 'c++'

primary_domain = 'cpp'

templates_path = ['templates']

html_static_path = ['static']

html_title = 'asio.wintls'

html_css_files = [
  project + '.css',
]

html_theme = 'bootstrap'
html_theme_path = sphinx_bootstrap_theme.get_html_theme_path()

html_theme_options = {
    'bootswatch_theme': 'flatly',
    'navbar_title': html_title
}

# Hack to get the version passed from the command line. There ought to
# be a cleaner way to do this
version_from_cmdline = [s for s in sys.argv if s.startswith('version=')][0].split('=')[1]

html_last_updated_fmt = ''

jinja_contexts = {
    'version_uris': {
        'examples_uri': f'https://github.com/laudrup/boost-wintls/tree/v{version_from_cmdline}/examples',
    }
}

breathe_default_project = 'wintls'
