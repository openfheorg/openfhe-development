Contributing to OpenFHE
=======================

We are using git for version management and control. We use github for
issue and milestone tracking.

We classify contributions as *Major* or *Minor*.

- **Major** contributions include adding a new scheme, or capability to the library.

  - These contributions would require users to change existing
    OpenFHE API code

  - Major contributions would not be scheduled
    for inclusion except for a Major release.

  - We usually require such contributions to be done in
    their own fork of the repository to minimize disruption to the ongoing
    release schedule.

- **Minor** contributions are less broad in scope, and usually are limited to
  a few files at a time.

  - These are usually done on a branch in the
    development repository, and are usuall incorporated into the next minor
    release cycle.

.. attention::

   Sometimes a seemingly minor improvement may affect a large number of
   files. Formatting changes are an example of this. Changes to a large
   number of files can be disruptive if done in the wrong point of a
   release cycle.

.. note::
   If you discover a problem or identify a useful enhancement, do feel free
   to create a new issue in github. Major enhancements should be discussed
   with the OpenFHE team ahead of time before undertaking any work (see
   below).

Workflow for Minor Contributions
----------------------------------

Our workflow for Minor contributions is that developers work in feature
branches they create and then submit merge requests. All contributions –
be they bug fixes or enhancements – must be documented in a gitlab
issue, before the merge request.

We require that the code work correctly in all environments before it
will be accepted for merging. We are working on bringing up a CI
pipeline environment where branches can be tested on multiple platforms
automatically. Unfortunately our Windows and MacOS build tests are
currently done manually. If you do not have all the required systems to
test, please coordinate with the team to schedule testing.

Pre-requisites
^^^^^^^^^^^^^^^

Before contributing an improvement, install Python3 if it is not already
installed. Then install the following dependencies:

-  ``clang-format``
-  ``pre-commit``
-  ``cpplint``

On linux systems you will need to

-  ``pip3 install clang-format``
-  ``pip3 install pre-commit``
-  ``pip3 install cpplint``

On macOS install using

-  ``brew install clang-format``
-  ``brew install pre-commit``
-  ``pip install cpplint``

On Windows systems, install clang-format using an executable for Clang
v9.0.0 or later. Then using ``git bash`` run

-  ``pip3 install pre-commit``
-  ``pip3 install cpplint``


.. note:: ``clang-format`` is not backwards compatible; the current format has
   been tested using ``clang-format`` version 9.0.0.

Setup
^^^^^^^^^^^^^^^

.. code:: bash

   pre-commit install

Now, ``pre-commit`` will run automatically on ``git commit``.

By default, ``pre-commit`` will only run on changed files. To run on all
the files (recommended when adding new hooks), call

.. code:: bash

   pre-commit run --all-files

Making the code changes and checking in the result
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

We request that you conform to the following workflow:

1. Start in main, or whichever branch you want to start from using the
   following command: ``git checkout main``
2. Pull down the latest in this branch from the git repo:
   ``git pull origin main``
3. Create a new branch with the a unique name:
   ``git checkout -b <your new branch name>``.

  -  Note that we recommend naming feature branches by appending your name
     with an issue number. If your last name is Rohloff and you’re fixing
     a bug documented in issue 233, then one would create a branch named
     ``Rohloff_issue233``.

  -  This command will create the branch and move you into it.

4. Make any changes you want to in the branch.
5. Commit your changes to the local repo:
   ``git commit -am "commit message"``

  -  Note the commit message should be succinct yet meaningful and
     indicate the issue you’re addressing, and discussion of things you
     weren’t able to address.
  -  Be sure the ``pre-commit`` hooks run, to ensure the code meets the
     style guidelines. As a check, running
     ``./scripts/maint/apply-code-format.sh`` to apply clang-format should not
     result in any additional formatting changes in the code.
  -  For a more granular control, you can first add files using
     ``git add`` and then run ``git commit -m "commit message"``. In this
     case, the changes made by pre-commit will not automatically be added
     to the commit. Review the changes using ``git diff``. If all looks
     well, run ``git add``, and then retry
     ``git commit -m "commit message"``.

6.  Push your local commit to the server in your branch:
    ``git push origin <your local branch name>``

7.  After you finished inserting your new code you wanted to address,
    make sure the code builds and runs correctly and that you have not
    introduced any additional bugs.

8.  Make sure all unit tests pass and add additional unit tests as
    needed for features you’ve added.

9.  Before creating merge requests, developers should rebase their
    branch from main and test that their code works properly. :ref:`This page
    describes a workflow to rebase a branch from a main
    branch. <rebasing>`

10. Submit a merge request so project owners can review your commits
    here. You should include the text ``Fixes #issue`` in your merge
    request.

11. You may get feedback on your merge request, especially if there are
    problems or issues.

12. When your merge request is accepted, your changes will be merged
    into main and your branch will be deleted.

  -  All additions to the released versions of OpenFHE are subject to approval
     by the OpenFHE governance team as outlined in the :ref:`OpenFHE Governance
     document. <governance>`

Workflow for Major Contributions
----------------------------------

If you plan major modifications of OpenFHE, please consult with the
OpenFHE team first by contacting us at contact@openfhe.org to plan your
modifications so that they can be implemented efficiently and in a way
that doesn’t conflict with any other planned future development. OpenFHE
is a work in progress, and major release revisions can deprecate large
amounts of existing code. This way you can make sure your additions will
be consistent with the planned release schedule of OpenFHE. It will also
ensure that you base your changes on the most recent version of the
development library.

In addition to the workflow for Minor contributions the following is the
requested procedure or a Major change.

-  Fork the ``openfhe-development`` repository on GitLab

-  Clone your new repository or add it as a remote to an existing
   repository

-  Check out the existing ``main`` branch, then start a new feature
   branch for your work

-  When making changes, write code that is consistent with the
   surrounding code (see the `style guidelines <#style-guidelines>`__
   below)

-  Add tests for any new features that you are implementing to either
   the GoogleTest-based test suite or the Python test suite.

-  Add examples that highlight new capabilities, or update existing
   examples to make use of new features.

-  As you make changes, commit them to your feature branch

   -  Configure Git with your name and e-mail address before making any
      commits
   -  Use descriptive commit messages (summary line of no more than 72
      characters, followed by a blank line and a more detailed summary,
      if any)
   -  Make related changes in a single commit, and unrelated changes in
      separate commits
   -  Make sure that your commits do not include any undesired files,
      e.g., files produced as part of the build process or other
      temporary files.
   -  Use Git’s history-rewriting features (i.e., ``git rebase -i``; see
      https://help.github.com/articles/about-git-rebase/) to organize
      your commits and squash “fixup” commits and reversions.
   -  Do not merge your branch with ``main``. If needed, you should
      occasionally rebase your branch onto the most recent ``HEAD``
      commit of ``main``.
   -  Periodically run the test suite (``make testall``) to make sure
      that your changes are not causing any test failures.

-  Major additions may require changes to the OpenFHE CMAKE files. Refer
   to the
   :ref:`Use-of-CMake-in-OpenFHE <cmake_in_openfhe>`
   page for details.

-  Submit a Pull Request on GitLab. Check the results of the continuous-
   integration tests pipelines and resolve any issues that arise.

-  Additional discussion of good Git & GitLab workflow is provided at
   `matplotlib <http://matplotlib.org/devel/gitwash/development_workflow.html>`_
   `scipy <https://docs.scipy.org/doc/numpy-1.15.0/dev/gitwash/development_workflow.html>`_

-  OpenFHE is licensed under a `BSD
   license <https://github.com/openfheorg/openfhe-development/blob/main/LICENSE>`__
   which allows others to freely modify the code, and if your Pull
   Request is accepted, then that code will be release under this
   license as well. The copyright for OpenFHE is held collectively by
   the contributors. If you have made a significant contribution, please
   add your name to the ``AUTHORS.md`` file.

-  All additions to the released versions of OpenFHE are subject to
   approval by the OpenFHE governance team as outlined in the :ref:`OpenFHE
   Governance document. <governance>`

Acknowlegement
--------------

We would like to acknowlege the Cantera Project. We have modeled this
document on their examples.
