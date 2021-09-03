import subprocess


def get_git_hash():
    return subprocess.check_output(['git', 'rev-parse', '--short', 'HEAD'])


def get_git_tag():
    return subprocess.check_output(['git', 'tag', '--points-at', 'HEAD'])


def get_git_revision():
    tag = get_git_tag()
    if not tag:
        return get_git_hash().decode('utf-8')
    return tag.decode('utf-8')


def html_page_context(app, pagename, templatename, context, doctree):
    context['git_revision'] = get_git_revision()


def setup(app):
    app.connect('html-page-context', html_page_context)
