=========================
WSL Nested Virtualization
=========================

This is a short helper guide for anyone wanting to use libvirt under WSL in
Windows using nested virtualization. It is recommended that the user has the
Windows Terminal emulator installed, or something similar.


1. Open 'Turn Windows features on or off' and turn on the following:
        * Hyper-V
        * Virtual Machine Platform
        * WindowsSubsystem for Linux


2. Restart machine.


3. Open PowerShell in the Terminal and install WSL Ubuntu::

        wsl --update
        wsl --install -d Ubuntu
        wsl -v

**NOTE:** After the above, make sure the output says WSL version 2.


4. Open WSL Ubuntu and updated the user and password. Afterwards, make sure that
   all the packages are up-to-date::

        sudo apt update
        sudo apt upgrade


5. To configure WSL to use nested virtualization, add the file ``.wslconfig`` in
   the Windows current user directory. Edit the file and add the following::

        [wsl2]
        nestedVirtualization=true


6. Shutdown WSL in PowerShell::

        wsl.exe --shutdown


Nested virtualization and WSL should now be fully enabled and installed, and the
user is now ready to install and use libvirt. If you have not see the article,
check out :doc:`vm-setup`.
