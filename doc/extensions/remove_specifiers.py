specifiers = ['enumerator', 'inline']


def doctree_resolved(app, doctree, docname):
    for node in doctree.traverse():
        if node.astext() in specifiers and node.parent.tagname == 'desc_signature_line':
            node.parent.remove(node)


def setup(app):
    app.connect('doctree-resolved', doctree_resolved)
