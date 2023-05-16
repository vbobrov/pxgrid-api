Posting to pypi and readthedocs
===============================

I created this document mainly to remind myself how to run these processes

pypi
----

The following modules are needed for building and posting to pypi

.. code-block:: console

  $ pip install build twine


**build** tool uses **pyproject.toml** file that describes how the pypi package needs to be built. The resulting pypi package is save to dist/ folder. 

Any time the package is uploaded to pypi, its name must be different than the priviously uploaded one. The simplest way to do that is to bump up the version number is **pyproject.toml** as well as **pxapi/__init__.py**

Start by deleting existing packages from dist/ folder

.. code-block:: console

  $ rm dist/*

Run **built** module

.. code-block:: console

  $ python -m build
  --- snip ---
  Successfully built pxgrid-api-0.1.2.tar.gz and pxgrid_api-0.1.2-py3-none-any.whl

  $ ls -l dist
  total 112
  -rw-r--r--  1 user  staff  29189 May 15 15:49 pxgrid-api-0.1.2.tar.gz
  -rw-r--r--  1 user  staff  24484 May 15 15:49 pxgrid_api-0.1.2-py3-none-any.whl

Next, we use twine utility to upload the package to pypi. As of this writing, pypi allows basic authentication with password even when MFA is enabled on the account. This might be blocked in the future and API key will be required for uploads.

.. code-block:: console
  
  $ twine upload dist/*
  Uploading distributions to https://upload.pypi.org/legacy/
  Enter your username: user
  Enter your password: 
  Uploading pxgrid_api-0.1.2-py3-none-any.whl
  100% ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 53.8/53.8 kB • 00:00 • 70.5 MB/s
  Uploading pxgrid-api-0.1.2.tar.gz
  100% ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 58.1/58.1 kB • 00:00 • 76.1 MB/s

  View at:
  https://pypi.org/project/pxgrid-api/0.1.2/

Readthedocs
===========

I loosely followed the tutorial here: https://sphinx-rtd-tutorial.readthedocs.io/en/latest/

First, we need to install **sphinx** and **sphinx-rtd-theme**

.. code-block:: console

  $ pip install sphinx
  $ pip install sphinx-rtd-theme

Next, we initialize with quick start

.. code-block:: console

  $ mkdir docs
  $ cd docs
  $ sphinx-quickstart


**docs/source/conf.py** needs to be edited to include the following

.. code-block:: python

  import os
  import sys
  sys.path.insert(0,"../../src/pxapi")
  html_theme = 'sphinx_rtd_theme'
  extensions = ['sphinx.ext.autodoc']

The following command can be used to generate .rst files for each python file

.. code-block:: console
  
  sphinx-apidoc -o ./source/ ../src/pxapi/

See **docs/source/pxapi.rst** for the final version. Additionally, **intro.rst**, **api.rst** and **pxshell.rst** were created

**index.rst** now needs to be updated with those additional files without .rst extension

To build local html files, run the following from docs/folder

.. code-block:: console

  make html

This will output documentation to **docs/build/html**

readthedocs will automatically build documentation from GitHub source. There is no need to include html files when uploading to GitHub