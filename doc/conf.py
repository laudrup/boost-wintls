import sphinx_bootstrap_theme
import os
import sys

sys.path.append(os.path.abspath("./extensions"))

project = 'boost-wintls'
copyright = '2021, Kasper Laudrup'
author = 'Kasper Laudrup'

master_doc = 'index'

rst_prolog = """
.. figure:: logo.jpg
   :alt: Boost.Wintls logo

"""

extensions = ['breathe', 'toctree_elements']

highlight_language = 'c++'

primary_domain = 'cpp'

templates_path = ['templates']

html_static_path = ['static']

html_title = 'boost::wintls'

html_css_files = [
  project + '.css',
]

html_theme = 'bootstrap'
html_theme_path = sphinx_bootstrap_theme.get_html_theme_path()

html_theme_options = {
  'bootswatch_theme': 'flatly'
}

breathe_default_project = 'boost-wintls'
