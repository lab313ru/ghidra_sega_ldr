# ghidra_sega_ldr
Sega Mega Drive / Genesis ROMs loader for GHIDRA

# Building
- Clone the repo and navigate to the directory
- Set the GHIDRA_INSTALL_DIR environment variable to the correct path. ``export GHIDRA_INSTALL_DIR=<absolute path to ghidra install>``
- Simply run the command ``gradle`` from within the repo directory to build the project

# Installing
- After building, the resulting .zip should be located in the ``dist/`` directory. Move it into your Ghidra extensions folder.
- Start ghidra and go to ``File -> Install Extensions`` and you should see the ghidraSegaLdr plugin there. Install it and restart ghidra
- Now you can use the loader when importing a sega genesis rom into Ghidra.
