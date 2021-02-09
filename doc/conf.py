project = 'boost-wintls'
copyright = '2020, Kasper Laudrup'
author = 'Kasper Laudrup'

master_doc = 'index'

extensions = ['breathe']

highlight_language = 'c++'

primary_domain = 'cpp'

templates_path = ['_templates']

html_title = 'boost::wintls'

html_theme_options = {
  "fixed_sidebar": True,
  "page_width": "95em",
  "font_family": "times-new-roman",
}

breathe_default_project = 'boost-wintls'

html_sidebars = {
  '**': ['localtoc.html'],
}
