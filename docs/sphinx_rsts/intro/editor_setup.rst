Setting up your Editor
====================================


**Table of Contents**
---------------------

Visual Studio Code
^^^^^^^^^^^^^^^^^^^^^^^

- :ref:`editor-vs-general-configuration`

  - :ref:`editor-vs-decrease-memory-cpu`
  - :ref:`editor-vs-openfhe-path`
  - :ref:`editor-vs-markdown`
  - :ref:`editor-vs-code-formatting`
  - :ref:`editor-vs-git`

- :ref:`editor-vs-debugger`

  - :ref:`editor-vs-debugger-build-debug`
  - :ref:`editor-vs-debugger-multi-target`

Eclipse
^^^^^^^^^^^^^^^^^^^^^^^

- :ref:`editor-eclipse-cmake`


Visual Studio Code
-----------------------

.. _editor-vs-general-configuration:

General Configuration
^^^^^^^^^^^^^^^^^^^^^

This section includes setting snippets to include in the to work with OpenFHE in a friendly manor. In addition we have some recommended extensions for developers to use:

- [Clang-Format]
- [GitLens]
- [C/C++]
- [Markdown All in One]


.. _editor-vs-decrease-memory-cpu:

Decrease Memory & CPU usage
^^^^^^^^^^^^^^^^^^^^^^^^^^^

Code uses inotify to monitor file changes, use the following to tell Code to ignore the build outputs.

::

    // Ignore build directory, saves a lot of memory and CPU!
    "files.watcherExclude": {
        "**/build/**": true
    },


.. _editor-vs-openfhe-path:

Setup OpenFHE Install Path
^^^^^^^^^^^^^^^^^^^^^^^^^^^

If developing external to the OpenFHE repository the following are great to add to the local `.vscode/settings.json`. This is normally intended for users or working with independent example repositories.

::

    // Include installed OpenFHE for library references
    "C_Cpp.default.includePath": [
        "/usr/local/include/openfhe/core",
        "/usr/local/include/openfhe/pke",
        "/usr/local/include/openfhe/cereal",
        // "/usr/local/include/openfhe/binfhe", // (optional) only needed if working with circuits
    ],

.. warning:: Using this inside OpenFHE-Development repository will create duplicate references


.. _editor-vs-markdown:

Markdown
^^^^^^^^

OpenFHE uses markdown documents inside the repository to document details about the code. To get the most from code use the extension [Markdown All in One].

.. _editor-vs-code-formatting:

Setup Code Formatting
^^^^^^^^^^^^^^^^^^^^^

Install the `Clang Format <https://marketplace.visualstudio.com/items?itemName=xaver.clang-format/>`__ Extensions

There are `.clang-format` files in the repository, the following setting will enable the formatter and point it to the configuration files.

::

    // Code Formatting
    "[cpp]": {
        "editor.defaultFormatter": "xaver.clang-format"
    },
    "clang-format.language.cpp.enable": true,
    "clang-format.assumeFilename": ".clang-format",


.. _editor-vs-git:

Setup code for Git
^^^^^^^^^^^^^^^^^^

You can use code for git diffs, merges, and rebasing (rebasing works best with the [GitLens] extension installed)

::

    [core]
        editor = code --wait
    [diff]
        tool = vscode
    [difftool "vscode"]
        cmd = code --wait --diff $LOCAL $REMOTE
    [merge]
        tool = vscode
    [mergetool "vscode"]
        cmd = code --wait $MERGED



.. _editor-vs-debugger:

Setup Debugger
--------------

To set up the debugger for examples that uses OpenFHE, the examples need to be compiled with cmake with the debug mode ON. This is done by using the command:

.. code-block:: bash

    cmake -DCMAKE_BUILD_TYPE=Debug ..

Then, add configuration to launch.json file in vscode. This file is created in the .vscode folder of the project by using the menu option Run -> Add Configuration. Then choose 'C/C++ (gdb) Launch' from the dropdown. The option '(gdb) Attach' allows to attach the debugger to an already running process. More on the other options are available in the
`vscode tutorial <https://code.visualstudio.com/docs/editor/debugging/>`_.

A sample configuration looks as below for a target 'example':

.. code-block:: json

    {
        "version": "0.2.0",
        "configurations": [

            {
                "name": "Server",
                "type": "cppdbg",
                "request": "launch",
                "program": "${workspaceFolder}/build/bin/example",
                "args": [],
                "stopAtEntry": false,
                "cwd": "${workspaceFolder}",
                "environment": [],
                "MIMode": "gdb",
                "setupCommands": [
                    {
                        "description": "Enable pretty-printing for gdb",
                        "text": "-enable-pretty-printing",
                        "ignoreFailures": true
                    }
                ]
            },
        ]

The main arguments in the configuration are "name", "type", "request", "program" and "args". The "args"
argument is to pass arguments to the target example (such as port number if the example is a server application). After saving the file with this configuration, the debug options that are available with vscode can be accessed (from the Run menu and Debug view) for the example.


.. _editor-vs-debugger-multi-target:

Multiple Targets
^^^^^^^^^^^^^^^^

In case of examples with multiple targets (such as a client and server), we can add multiple configurations for the targets in the same launch.json file. A sample configuration looks as below for targets 'client' and 'server':

.. code-block:: json

    {
        "version": "0.2.0",
        "configurations": [


            {
                "name": "Server",
                "type": "cppdbg",
                "request": "launch",
                "program": "${workspaceFolder}/build/bin/server",
                "args": [],
                "stopAtEntry": false,
                "cwd": "${workspaceFolder}",
                "environment": [],
                "MIMode": "gdb",
                "setupCommands": [
                    {
                        "description": "Enable pretty-printing for gdb",
                        "text": "-enable-pretty-printing",
                        "ignoreFailures": true
                    }
                ]
            },

            {
                "name": "Client",
                "type": "cppdbg",
                "request": "launch",
                "program": "${workspaceFolder}/build/bin/client",
                "args": [],
                "stopAtEntry": false,
                "cwd": "${workspaceFolder}",
                "environment": [],
                "MIMode": "gdb",
                "setupCommands": [
                    {
                        "description": "Enable pretty-printing for gdb",
                        "text": "-enable-pretty-printing",
                        "ignoreFailures": true
                    }
                ]
            }

        ]

    }

After saving this file with the configuration for the multiple targets, the debug view (from the side bar) can be used to choose the target (from a dropdown list of the configuration "names") that we want to debug and we can run multiple debuggers for different targets.

.. _editor-vs-debugger-build-debug:

Build and Debug
^^^^^^^^^^^^^^^^

To enable rebuilding with cmake options before debugging use the ``task.json``. This file is stored in ``.vscode`` directory.

``task.json``

.. code-block:: json

    {
        "label": "buildCmake",
        "type": "shell",
        "command": "cd build && rm CMakeCache.txt && cmake .. -DCMAKE_BUILD_TYPE=Debug && make"
    },

and add it to your launch options in ``launch.json``

``launch.json``

.. code-block:: json

            "preLaunchTask": "buildCmake32",

.. note:: this goes at the same level as ``name``, ``type``, etc.


References
--------------------

- `GitLens <https://marketplace.visualstudio.com/items?itemName=eamodio.gitlens/>`_.

- `Clang-Format <https://marketplace.visualstudio.com/items?itemName=xaver.clang-format/>`_.

- `C/C++ <https://marketplace.visualstudio.com/items?itemName=ms-vscode.cpptools/>`_.

- `Markdown All In One <https://marketplace.visualstudio.com/items?itemName=yzhang.markdown-all-in-one/>`_.


.. _editor-eclipse:

Eclipse
--------

.. _editor-eclipse-cmake:

CMAKE
^^^^^^^^^^^^

Developers that wish to use Eclipse for building OpenFHE can use the shell script ``configure/setup-eclipse-cmake.sh``.
This script should be run in the users build tree. All command line arguments are passed to CMake. The shell configures the build tree so that it can be imported into Eclipse, and built directly from Eclipse.

