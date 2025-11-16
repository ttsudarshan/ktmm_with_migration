=========================
Testing Environment Setup
=========================

This is a guide discussing how to setup the appropriate virtual machine for
testing. If you are using WSL Ubuntu and need help with setting up nested
virtualization, see :doc:`wsl-nested-vm`.

Required Packages
-----------------

WSL Ubuntu::

        qemu-system virtiofsd bridge-utils virt-manager

Debian/Ubuntu::

        qemu-system libvirt-daemon-system bridge-utils virt-manager

Arch::

        qemu-full virt-manager


Download Testing Distribution
-----------------------------

Debian 12::

        wget "https://cdimage.debian.org/debian-cd/current/amd64/iso-cd/debian-12.10.0-amd64-netinst.iso"


Install Virtual Machine
-----------------------

The instructions below use example instructions used on a host machine with
32GiB of memory and 24 logical CPUs. In the each user's case, these 
instructions may need to be modified slightly. Please read notes attached to
each step.

1. Install the VM::

        sudo virt-install \
                --name debian12-numa \
                --memory=16384 \
                --vcpus=16,maxvcpus=16 \
                --cpu host-model \
                --disk path=/home/user/vm/disk/debian12-numa.qcow2,size=80 \
                --cdrom /home/user/vm/iso/debian12.10.0-amd64-netinst.iso \
                --os-variant=linux2022
                --graphics vnc \
                --network network=default \
                --check disk_size=off

**NOTE:**
        * Recommended to adjust memory to about half of available from host
        * The 'maxvcpus' is necessary for vCPU hotplug

2. If not automatic, view the newly created VM::

        sudo virsh --connect qemu:///session debian12-numa

3. Recommended settings for Debian 12 installation
        a. Do not create a root password (access root via user using sudo).
        b. Partition disk file as one partition without encryption.
        c. Setup partitioning to use 4+ GB of swap space.
        d. Install only standard system utilities.

4. Modify virtual hardware configuration::

        sudo virsh --connect qemu:///system edit debian12-numa

**NOTE:** Hardware configuration can also be accessed in the virtual machine's
settings via virt-manager's XML editor.

5. Modify CPU settings:

.. code-block:: xml

        <cpu mode='host-model'>
          <numa>
            <cell id='0' cpus='0-7' memory='8192' unit='MiB'/>
            <cell id='1' cpus='8-15' memory='8192' unit='MiB'/>
          </numa>
        </cpu>

**NOTE:** Adjust memory for each cell to half of total allocated memory.

6. Confirm the setup inside the VM using::

        sudo apt install numactl
        numactl --hardware
