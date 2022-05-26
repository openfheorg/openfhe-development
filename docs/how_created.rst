How this Version of ExhaleCompanion was Created
========================================================================================

For convenience, I'm going to inline the code used in this configuration from
``conf.py`` here.  The three main things you need to do here are

1. The ``requirements.txt`` used on read the docs.
2. Setup the ``breathe`` and ``exhale`` extensions.
3. Choose your ``html_theme``, which affects what you choose for the ``exhale`` side.

Refer to the `Start to finish for Read the Docs <stffrtd_>`_ tutorial for getting
everything setup on RTD.

.. _stffrtd: http://exhale.readthedocs.io/en/latest/usage.html#start-to-finish-for-read-the-docs

``requirements.txt``
----------------------------------------------------------------------------------------

.. include:: the_requirements.rst

.. _extension_setup:

Extension Setup
----------------------------------------------------------------------------------------

.. include:: conf_extensions.rst

.. _html_theme_setup:

HTML Theme Setup
----------------------------------------------------------------------------------------

.. include:: conf_theme.rst
