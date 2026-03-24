This script is designed to **dynamically extract Configuration for a CVE based on the files that are patched in the CVE fix.**

If you are working on a kernel CVE triage and need to know the affected configuration to decide if you are affected or not, this script will help you identify the configuration looking at the Makefile.

It looks at the CVE.org to get the affected files and then checks the **makefile** to get the configuration that needs to be checked for a CVE.

`Note: this scripts tries to covers many use-cases but there may be use-cases that are not covered as part of this script. If you identified any use-case that is not covered, please feel free to contribute.`


### How to Run

``python3 kernelConfig.py --cve <CVENumber>``
