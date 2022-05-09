.. _rebasing:

Rebasing
====================================

When working on the library one should be working on a feature branch, and submit merge requests to move one's code onto the main branch.

Periodically the main branch will evolve and improve before a feature branch, and the feature branch should updated with changes in the main to test that this code works well together before a merge request is submitted.

There are multiple ways to move code updates from a main to a feature, but I'm going to describe the method that works for me.
As an example, suppose one is working on the branch ``issue-123``, and there have been improvements to the main branch. Generally one can rebase by doing the following:

1) Pull the latest code from both the ``issue-123`` and ``main`` branches with the following commands:

::

    git checkout main

    git pull origin main
    git checkout issue-123

    git pull origin issue-123

Make sure both of branches build properly before going any further.  Correct any bugs on the feature branch and commit that branch.  Also check the main branch and notify the OpenFHE team if there is an error in the main branch.

2) Run the following rebase operation: ``git rebase main issue-123``

- The changes are rebased into the feature branch one-by-one.  Often there are conflicts.  Suppose there is a conflict in `nbtheory.h`.  In this example, manually inspect `nbtheory.h` and resolve the conflict.

3) When you are done working on the conflict, you would add the file back to the branch as follows: ``git add src/core/include/math/nbtheory.h``

4) As soon as you resolve conflicts, continue the rebase: ``git rebase --continue``

5) Repeat the process of conflict resolution and continue until the rebase is finished.  Then build one final time as a sanity check, commit code, and push to the feature branch:

::

    git commit -m "finalized rebase"

    git push --force-with-lease origin issue-123


.. note:: The ``--force-with-lease`` (force) flag is needed to overwrite the git commit history
   If ``--force-with-lease`` is not supplied, the push will be declined.

You can then create a merge request here:

`OpenFHE Development Pull Requests <https://github.com/openfheorg/openfhe-development/pulls>`_


