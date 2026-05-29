
## kernelCVEConfig
A Python-based utility to identify Linux kernel configuration options that influence whether a given kernel CVE may be relevant to a system.

This project is intended to help security engineers, kernel developers, distro maintainers, DevSecOps teams, and researchers quickly map a kernel vulnerability to the CONFIG_* options that control the affected code paths.

This script is designed to **dynamically extract Configuration for a CVE based on the files that are patched in the CVE fix.**

If you are working on a kernel CVE triage and need to know the affected configuration to decide if you are affected or not, this script will help you identify the configuration looking at the Makefile.

It looks at the CVE.org to get the affected files and then checks the **makefile** to get the configuration that needs to be checked for a CVE.

`Note: this scripts tries to covers many use-cases but there may be use-cases that are not covered as part of this script. If you identified any use-case that is not covered, please feel free to contribute.`

### Why this project exists
Linux kernel CVEs are often tied to code that is only compiled when specific kernel configuration options are enabled. In practice, this means:

a CVE may affect one kernel build but not another
the same kernel version can have different exposure depending on .config
determining impact often requires checking both the vulnerability details and the relevant kernel config symbols
kernelCVEConfig aims to simplify that process by providing the configuration options associated with a kernel CVE so you can make faster and more informed triage decisions.

### Goals
The main goals of this repository are:

map a kernel CVE to relevant Linux kernel config options
reduce manual effort during vulnerability triage
improve understanding of why a CVE does or does not apply to a given build
provide a simple Python workflow that can be extended over time


### Example problem this helps solve
Suppose you are evaluating whether CVE-YYYY-NNNN affects a production kernel.

Knowing only the CVE ID is often not enough. You may also need to know:

Is the vulnerable subsystem compiled in?
Is the required driver or feature enabled?
Is the issue architecture-specific?
Is the code path disabled by config in this kernel build?
This tool helps answer the config-related part of that analysis.



### How to Run


#### Installation
Clone the repository:

git clone https://github.com/amitu314/kernelCVEConfig.git
cd kernelCVEConfig
If dependencies are added in the future, install them with:

pip install -r requirements.txt
If the project is packaged later, installation may look like:

pip install .

#### Usage
The exact command depends on the script filename and implemented arguments.

Typical usage may look like one of the following:

python kernelCVEConfig.py --cve CVE-2024-12345
or

python kernelCVEConfig.py CVE-2024-12345

``python3 kernelConfig.py --cve <CVENumber>``



