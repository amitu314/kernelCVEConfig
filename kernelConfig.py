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
                print(f"""Makefile matches: 
{matches}""")
 
 
if __name__ == '__main__':
    
    parser = argparse.ArgumentParser(description='get kernel config')
    parser.add_argument("--cve", required=True, type=str, help='CVE to check')
    
    args = parser.parse_args()
 
    kernelLocal()
    configMakefile(args.cve)
