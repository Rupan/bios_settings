BIOS Settings tools for UEFI and Python
---------------------------------------


This repository will eventually contain two components related to BIOS settings:

* An EDK2-based exporter for the HII database (a UEFI application)
* A Python program to decode (and possibly modify) the BIOS settings

The exporter has been completed, based upon the sample EDk2 application code as well
as a [gist](https://gist.github.com/apage43/bf15f62266159d8c3016e691e44f338c) from
Aaron Miller.

Building the EFI application under the EDK2 is fairly straightforward.  Start by editing
the file ```AppPkg/AppPkg.dsc```, adding ```AppPkg/Applications/hiidb/hiidb.inf``` under
the ```[Components]``` section.  Then copy the entire ```hiidb/``` directory into
```AppPkg/Applications```.  Now build it the same way you would the sample applications.

A prebuilt ```hiidb.efi``` binary is available in the releases.
