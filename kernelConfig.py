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
    if response.status_code == 200:
        data = response.json()
        affectedEntries = data.get('containers', {}).get('cna', {}).get('affected', [])
        for affectedEntry in affectedEntries:
            programFiles = affectedEntry.get('programFiles', [])
            for item in programFiles:
                if item not in uniqFile:
                    uniqFile.append(item)
 
        for filePath in uniqFile:
            #print(f"Processing file: {filePath}")
            dirPath = os.path.dirname(filePath)
            #print(f"Directory path: {dirPath}")
            repoDir = 'linux-stable'
            makefilePath = os.path.join(repoDir, dirPath, 'Makefile')
            try:
                if not os.path.exists(makefilePath):
                    if not os.path.exists(repoDir):
                        repoUrl = 'https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git' 
                        subprocess.run(['git', 'clone', repoUrl, repoDir], check=True)
 
                    if not os.path.exists(makefilePath):
                        return None
 
                with open(makefilePath, 'r', encoding='utf-8', errors='ignore') as f:
                    makefileContent = f.read()
 
                baseName = os.path.basename(filePath)
                fileNameWithoutExt = os.path.splitext(baseName)[0]
 
                pattern = re.compile(
                    r'obj-\$\(CONFIG_([A-Z0-9_]+)\)\s*\+=.*\b' + re.escape(fileNameWithoutExt) + r'\.[a-zA-Z0-9_]+\b'
                )
 
                matches = []
                for line in makefileContent.splitlines():
                    match = pattern.search(line)
                    if match:
                        configName = f"CONFIG_{match.group(1)}"
                        if configName not in matches:
                            matches.append(configName)
                
                groupPattern = re.compile(r'^([a-zA-Z0-9_]+)-y\s*[:+]?=\s*' + re.escape(fileNameWithoutExt) + r'\.[a-zA-Z0-9_]+\b')
                for line in makefileContent.splitlines():
                    wordMatch = groupPattern.search(line)
                    if wordMatch:
                        someword = wordMatch.group(1)
                        # Now search for obj-$(CONFIG_...) += ... someword.<ext>
                        altPattern = re.compile(
                            r'obj-\$\(CONFIG_([A-Z0-9_]+)\)\s*\+=.*\b' + re.escape(someword) + r'\.[a-zA-Z0-9_]+\b'
                        )
                        for objline in makefileContent.splitlines():
                            altMatch = altPattern.search(objline)
                            if altMatch:
                                configName = f"CONFIG_{altMatch.group(1)}"
                                if configName not in matches:
                                    matches.append(configName)
                                #print(f"Makefile matches for {filePath}: {matches}")
                                

                groupPattern2 = re.compile(
                    r'^([a-zA-Z0-9_]+)-objs\s*[:+]?=\s*(?:.*\\\s*\n)*?.*' + re.escape(fileNameWithoutExt) + r'\.[a-zA-Z0-9_]+\b',
                    re.MULTILINE
                )
                for wordMatch2 in groupPattern2.finditer(makefileContent):
                    print(f"Word Match 2: {wordMatch2.group(1)}")
                    someword2 = wordMatch2.group(1)
                    altPattern2 = re.compile(
                        r'obj-\$\(CONFIG_([A-Z0-9_]+)\)\s*\+=\s*' + re.escape(someword2) + r'\.o\b'
                    )
                    for altMatch2 in altPattern2.finditer(makefileContent):
                        configName2 = f"CONFIG_{altMatch2.group(1)}"
                        if configName2 not in matches:
                            matches.append(configName2)
                                    #print(f"Makefile matches for {filePath}: {matches}")
                                    
                
                groupPattern3 = re.compile(r'^([a-zA-Z0-9_]+)-y\s*[:+]?=\s*(?:.*\s)?' + re.escape(fileNameWithoutExt) + r'\.[a-zA-Z0-9_]+\b')
                for line in makefileContent.splitlines():
                    wordMatch = groupPattern3.search(line)
                    if wordMatch:
                        someword3 = wordMatch.group(1)
                        # Now search for obj-$(CONFIG_...) += ... someword.<ext>
                        altPattern3 = re.compile(
                            r'obj-\$\(CONFIG_([A-Z0-9_]+)\)\s*\+=.*\b' + re.escape(someword3) + r'\.[a-zA-Z0-9_]+\b'
                        )
                        for objline in makefileContent.splitlines():
                            altMatch2 = altPattern3.search(objline)
                            if altMatch2:
                                configName3 = f"CONFIG_{altMatch2.group(1)}"
                                if configName3 not in matches:
                                    matches.append(configName3)
                                #print(f"Makefile matches for {filePath}: {matches}")
                                


                print(f"""Makefile matches: 
{matches}""")
 
 
if __name__ == '__main__':
    
    parser = argparse.ArgumentParser(description='get kernel config')
    parser.add_argument("--cve", required=True, type=str, help='CVE to check')
    
    args = parser.parse_args()
 
    kernelLocal()
    configMakefile(args.cve)
