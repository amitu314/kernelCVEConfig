import subprocess
import json
import os
from pip._vendor import requests
from prettytable import PrettyTable
import re
import argparse
from bs4 import BeautifulSoup
from git import Repo, GitCommandError
 
def kernelLocal():
    repo_url = 'https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git' 
    repo_dir = 'linux-stable'
 
 
    if os.path.exists(repo_dir):
        try:
 
            subprocess.run(['git', '-C', repo_dir, 'fetch'], check=True, stdout=subprocess.DEVNULL)
            subprocess.run(['git', '-C', repo_dir, 'reset', '--hard', 'origin/master'], check=True, stdout=subprocess.DEVNULL)
        except subprocess.CalledProcessError as e:
            print(f"Error: {e}")
            return
    else:
        try:
            subprocess.run(['git', 'clone', repo_url, repo_dir], check=True)
        except subprocess.CalledProcessError as e:
            print(f"Error: {e}")
            return
 
 
def configMakefile(cve):
    url = 'https://cveawg.mitre.org/api/cve/' + str(cve)
    response = requests.get(url)
    uniqFile = []
    allMtches = []
    if response.status_code == 200:
        data = response.json()
        affectedEntries = data.get('containers', {}).get('cna', {}).get('affected', [])
        for affectedEntry in affectedEntries:
            programFiles = affectedEntry.get('programFiles', [])
            for item in programFiles:
                if item not in uniqFile:
                    uniqFile.append(item)

        for filePath in uniqFile:
            if not filePath:
                continue

            dirPath = os.path.dirname(filePath)
            if not dirPath:
                continue

            repoDir = 'linux-stable'
            makefilePath = os.path.join(repoDir, dirPath, 'Makefile')
            try:
                if not os.path.exists(makefilePath):
                    if not os.path.exists(repoDir):
                        repoUrl = 'https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git'
                        subprocess.run(['git', 'clone', repoUrl, repoDir], check=True)

                    if not os.path.exists(makefilePath):
                        continue

                with open(makefilePath, 'r', encoding='utf-8', errors='ignore') as f:
                    makefileContent = f.read()

                baseName = os.path.basename(filePath)
                fileNameWithoutExt = os.path.splitext(baseName)[0]
                print("FileName without extension::", fileNameWithoutExt )

                pattern = re.compile(
                    r'obj-\$\(CONFIG_([A-Z0-9_]+)\)\s*\+=.*\b' + re.escape(fileNameWithoutExt) + r'\.[a-zA-Z0-9_]+\b'
                )
                
                matches = []
                for line in makefileContent.splitlines():
                    match = pattern.search(line)
                    #print(("Line:", line, "Match:", match))
                    if match:
                        configName = f"CONFIG_{match.group(1)}"
                        if configName not in matches:
                            matches.append(configName)
                

                # Enhanced pattern: Look for obj-$(CONFIG_X) += module.o, then module-y += file.o
                objPattern = re.compile(r'obj-\$\(CONFIG_([A-Z0-9_]+)\)\s*\+=\s*([a-zA-Z0-9_]+)\.o')
                for line in makefileContent.splitlines():
                    objMatch = objPattern.search(line)
                    if objMatch:
                        configName = f"CONFIG_{objMatch.group(1)}"
                        moduleName = objMatch.group(2)
                        
                        # Look for module-y patterns that include our file (handle multiline with \)
                        # First, join continuation lines
                        joinedContent = re.sub(r'\\\s*\n\s*', ' ', makefileContent)
                        
                        modulePattern1 = re.compile(rf'^{re.escape(moduleName)}-y\s*[:+]?=.*\b{re.escape(fileNameWithoutExt)}\.o\b', re.MULTILINE)
                        modulePattern2 = re.compile(rf'^{re.escape(moduleName)}-y\s*[:+]?=.*\b{re.escape(fileNameWithoutExt)}\b', re.MULTILINE)
                        
                        if modulePattern1.search(joinedContent) or modulePattern2.search(joinedContent):
                            if configName not in matches:
                                matches.append(configName)


                groupPattern = re.compile(r'^([a-zA-Z0-9_]+)-y\s*[:+]?=\s*' + re.escape(fileNameWithoutExt) + r'\.[a-zA-Z0-9_]+\b')
                #groupPattern = re.compile(r'^([a-zA-Z0-9_]+)-y\s*[:+]?=.*\b' + re.escape(fileNameWithoutExt) + r'\.[a-zA-Z0-9_]+\b')

                for line in makefileContent.splitlines():
                    wordMatch = groupPattern.search(line)
                    
                    
                    if wordMatch:
                        someword = wordMatch.group(1)
                        print(f"Word Match: {someword}")
                        # Now search for obj-$(CONFIG_...) += ... someword.<ext>
                        altPattern = re.compile(
                            r'obj-\$\(CONFIG_([A-Z0-9_]+)\)\s*[:+]?=.*\b' + re.escape(someword) + r'\.[a-zA-Z0-9_]+\b'
                        )
                        for objline in makefileContent.splitlines():
                            altMatch = altPattern.search(objline)
                            if altMatch:
                                configName = f"CONFIG_{altMatch.group(1)}"
                                if configName not in matches:
                                    matches.append(configName)
                                #print(f"Makefile matches for {filePath}: {matches}")
                                #allMtches.extend(matches)

                groupPattern2 = re.compile(
                    r'^([a-zA-Z0-9_]+)-objs\s*[:+]?=\s*(?:.*\\\s*\n)*?.*' + re.escape(fileNameWithoutExt) + r'\.[a-zA-Z0-9_]+\b',
                    re.MULTILINE
                )
                for wordMatch2 in groupPattern2.finditer(makefileContent):
                    #print(f"Word Match 2: {wordMatch2.group(1)}")
                    someword2 = wordMatch2.group(1)
                    altPattern2 = re.compile(
                        r'obj-\$\(CONFIG_([A-Z0-9_]+)\)\s*[:+]?=\s*' + re.escape(someword2) + r'\.o\b'
                    )
                    for altMatch2 in altPattern2.finditer(makefileContent):
                        configName2 = f"CONFIG_{altMatch2.group(1)}"
                        if configName2 not in matches:
                            matches.append(configName2)
                                    #print(f"Makefile matches for {filePath}: {matches}")
                                    #allMtches.extend(matches)

                groupPattern3 = re.compile(r'^([a-zA-Z0-9_]+)-y\s*[:+]?=.*\b' + re.escape(fileNameWithoutExt) + r'\.[a-zA-Z0-9_]+\b')

                for line in makefileContent.splitlines():
                    wordMatch3 = groupPattern3.search(line)
                    #print(wordMatch3)
                    if wordMatch3:
                        someword3 = wordMatch3.group(1)
                        print(f"Word Match 3: {someword3}")
                        
                        altPattern3 = re.compile(
                            r'obj-\$\(CONFIG_([A-Z0-9_]+)\)\s*[:+]?=.*\b' + re.escape(someword3) + r'\.[a-zA-Z0-9_]+\b'
                        )
                        for objline2 in makefileContent.splitlines():
                            altMatch3 = altPattern3.search(objline2)
                            if altMatch3:
                                configName3 = f"CONFIG_{altMatch3.group(1)}"
                                if configName3 not in matches:
                                    matches.append(configName3)
                                #print(f"Makefile matches for {filePath}: {matches}")
                                #allMtches.extend(matches)

                groupPattern4 = re.compile(
                    r'^([a-zA-Z0-9_-]+)-(?:y|objs)\s*[:+]?=.*?\b' + re.escape(fileNameWithoutExt) + r'\.o\b',
                    re.MULTILINE
                )
                for wordMatch4 in groupPattern4.finditer(makefileContent):
                    someword4 = wordMatch4.group(1)
                    print(f"Word Match 4: {someword4}")
                    
                    altPattern4 = re.compile(
                        r'obj-\$\(CONFIG_([A-Z0-9_]+)\)\s*[:+]?=.*?\b' + re.escape(someword4) + r'\.o\b',
                        re.MULTILINE
                    )
                    for altMatch4 in altPattern4.finditer(makefileContent):
                        configName4 = f"CONFIG_{altMatch4.group(1)}"
                        if configName4 not in matches:
                            matches.append(configName4)


                groupPattern5 = re.compile(
                    r'^([a-zA-Z0-9_]+)-y\s*[:+]?=\s*(?:.*\\\s*\n)*?.*' + re.escape(fileNameWithoutExt) + r'\.[a-zA-Z0-9_]+\b',
                    re.MULTILINE
                )
                for wordMatch5 in groupPattern5.finditer(makefileContent):
                    #print(f"Word Match 2: {wordMatch5.group(1)}")
                    someword5 = wordMatch5.group(1)
                    print(f"Word Match 5: {someword5}")
                    altPattern5 = re.compile(
                        r'obj-\$\(CONFIG_([A-Z0-9_]+)\)\s*[:+]?=\s*' + re.escape(someword5) + r'\.[a-zA-Z0-9_]\b'
                    )
                    for altMatch5 in altPattern5.finditer(makefileContent):
                        #print(f"Alt Match 5: {altMatch5.group(1)}")
                        configName5 = f"CONFIG_{altMatch5.group(1)}"
                        if configName5 not in matches:
                            matches.append(configName5)
                                    #print(f"Makefile matches for {filePath}: {matches}")
                                    #allMtches.extend(matches)

                groupPattern6 = re.compile(r'^([a-zA-Z0-9_]+)-\$\(CONFIG_([A-Z0-9_]+)\)\s*[:+]?=.*\b' + re.escape(fileNameWithoutExt) + r'\.[a-zA-Z0-9_]+\b')

                
                for line in makefileContent.splitlines():
                    match6 = groupPattern6.search(line)
                    #print(match6)
                    if match6:
                        configName = f"CONFIG_{match6.group(2)}"
                        if configName not in matches:
                            matches.append(configName)

                groupPattern7 = re.compile(
                    r'^([a-zA-Z0-9_-]+)-y\s*[:+]?=\s*(?:.*\\\s*\n)*?.*?\b' + re.escape(fileNameWithoutExt) + r'\.o\b',
                    re.MULTILINE
                )
                for wordMatch7 in groupPattern7.finditer(makefileContent):
                    #print(f"Word Match 5: {wordMatch5.group(1)}")
                    someword7 = wordMatch7.group(1)
                    #print(f"Word Match 5: {someword5}")
                    altPattern7 = re.compile(
                        r'obj-\$\(CONFIG_([A-Z0-9_]+)\)\s*[:+]?=\s*.*?\b' + re.escape(someword7) + r'\.o\b',
                        re.MULTILINE
                    )
                    for altMatch7 in altPattern7.finditer(makefileContent):
                        #print(f"Alt Match 5: {altMatch5.group(1)}")
                        configName7 = f"CONFIG_{altMatch7.group(1)}"
                        if configName7 not in matches:
                            matches.append(configName7)
                                    #print(f"Makefile matches for {filePath}: {matches}")
                                    #allMtches.extend(matches)
               
               # file pointing to a word that points to obj-y
                groupPattern8 = re.compile(
                    r'^([a-zA-Z0-9_]+)-y\s*[:+]?=\s*(?:.*\\\s*\n)*?.*' + re.escape(fileNameWithoutExt) + r'\.[a-zA-Z0-9_]+\b',
                    re.MULTILINE
                )
                for wordMatch8 in groupPattern8.finditer(makefileContent):
                    #print(f"Word Match 2: {wordMatch5.group(1)}")
                    someword8 = wordMatch8.group(1)
                    print(f"Word Match 8: {someword8}")
                    altPattern8 = re.compile(
                        r'(obj-y)\s*(:=|=|:|:+|\+=)\s*' + re.escape(someword8) + r'\.[a-zA-Z0-9_]\b'
                    )
                    
                    for altMatch8 in altPattern8.finditer(makefileContent):
                        print(f"Alt Match 8: {altMatch8.group(1)}")
                        if altMatch8.group(1) == "obj-y":
                            print(f""" 
                                  There is no CONFIG_* option for {someword8} in the snippet. {someword8} appears in the unconditional `obj-y` list, so it is built into the kernel image (built-in) rather than controlled by a Kconfig symbol. Built-in kernel config match found for {someword8}
                                  """)
                
                builtInKernelConfig = re.compile(
                    r'^(obj-y)\s*(:=|=|:|:+)\s*(?:.*\\\s*\n)*?.*?\b' + re.escape(fileNameWithoutExt) + r'\.o\b',
                    re.MULTILINE
                )
                for wordMatch7 in builtInKernelConfig.finditer(makefileContent):
                    #print(f"Word Match 5: {wordMatch5.group(1)}")
                    someword7 = wordMatch7.group(1)
                    #print(f"Word Match 5: {someword5}")
                    if someword7 == "obj-y":
                        print(f""" 
                              There is no CONFIG_* option for {fileNameWithoutExt} in the snippet. {fileNameWithoutExt} appears in the unconditional `obj-y` list, so it is built into the kernel image (built-in) rather than controlled by a Kconfig symbol. Built-in kernel config match found for {fileNameWithoutExt}

""")


                #Note to self Addignthis for https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/tree/drivers/usb/dwc3/Makefile?id=5a1a847d841505dba2bd85602daf5c218e1d85b8
                ifneqPattern2 = re.compile(
                    r'ifneq\s*\(\$\(filter\s+y,\s*\$\(CONFIG_([A-Z0-9_]+)\)\s*\$\(CONFIG_([A-Z0-9_]+)\)\s*\)\s*,\s*\)\s*(.*?)(?:else|endif)',
                    re.DOTALL
                )
                for ifneqMatch in ifneqPattern2.finditer(makefileContent):
                    configName1 = f"CONFIG_{ifneqMatch.group(1)}"
                    configName2 = f"CONFIG_{ifneqMatch.group(2)}"
                    blockContent = ifneqMatch.group(3)

                    if re.search(r'\b' + re.escape(fileNameWithoutExt) + r'\.o\b', blockContent):
                        if configName1 not in matches:
                            matches.append(configName1)
                        if configName2 not in matches:
                            matches.append(configName2)

                #Note to self Addignthis for https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/tree/drivers/usb/dwc3/Makefile?id=5a1a847d841505dba2bd85602daf5c218e1d85b8
                ifneqPattern3 = re.compile(
                    r'ifneq\s*\(\$\(CONFIG_([A-Z0-9_]+)\)\s*,\s*\)\s*(.*?)(?:else|endif)',
                    re.DOTALL
                )
                for ifneqMatch in ifneqPattern3.finditer(makefileContent):
                    configName = f"CONFIG_{ifneqMatch.group(1)}"
                    blockContent = ifneqMatch.group(2)

                    if re.search(r'\b' + re.escape(fileNameWithoutExt) + r'\.o\b', blockContent):
                        if configName not in matches:
                            matches.append(configName)
                

                ifeqPattern = re.compile(
                    r'ifeq\s*\(\s*\$\(CONFIG_([A-Z0-9_]+)\)\s*,\s*y\s*\)(.*?)(?:else|endif)',
                    re.DOTALL
                )
                for ifeqMatch in ifeqPattern.finditer(makefileContent):
                    configName = f"CONFIG_{ifeqMatch.group(1)}"
                    blockContent = ifeqMatch.group(2)
                    
                    if re.search(r'\b' + re.escape(fileNameWithoutExt) + r'\.o\b', blockContent):
                        if configName not in matches:
                            matches.append(configName)
               
                



                print(f"Makefile matches for {filePath}: {matches}")
                allMtches.extend(matches)
            except (subprocess.CalledProcessError, IOError) as e:
                continue
    return allMtches

 
if __name__ == '__main__':
    
    parser = argparse.ArgumentParser(description='get kernel config')
    parser.add_argument("--cve", required=True, type=str, help='CVE to check')
    
    args = parser.parse_args()
 
    kernelLocal()
    configMakefile(args.cve)
