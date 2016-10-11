#!/bin/sh

export SPHINX_APIDOC_OPTIONS='members,special-members,private-members,undoc-members,show-inheritance'
sphinx-apidoc -f -o docs/source/dev/api/ lama/ -H "LAMA API"
cd docs
make html
