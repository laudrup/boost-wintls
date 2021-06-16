project = 'boost-wintls'
copyright = '2020, Kasper Laudrup'
author = 'Kasper Laudrup'

master_doc = 'index'

rst_prolog = """
.. figure:: logo.jpg
   :alt: Boost.Wintls logo

"""

extensions = ['breathe', 'sphinxcontrib.fulltoc']

highlight_language = 'c++'

primary_domain = 'cpp'

templates_path = ['templates']

html_static_path = ['static']

html_title = 'boost::wintls'

html_css_files = [
  project + '.css',
]

html_theme_options = {
  "fixed_sidebar": True,
  "page_width": "95em",
  "font_family": "times-new-roman",
}

breathe_default_project = 'boost-wintls'

html_sidebars = {
  '**': ['localtoc.html'],
}
