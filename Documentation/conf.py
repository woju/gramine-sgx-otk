import os
import sys
sys.path.insert(0, os.path.abspath('..'))

project = 'gramine-sgx-otk'
copyright = '2023, Wojtek Porczyk'
author = 'Wojtek Porczyk'

extensions = [
    'sphinx.ext.autodoc',
    'sphinx.ext.napoleon',
]

exclude_patterns = ['_build', '.gitignore']

html_theme = 'alabaster'

man_pages = [
    ('manpages/gramine-sgx-otk', 'gramine-sgx-otk', 'One-Time-Key signer for SGX', '', 1),
]
