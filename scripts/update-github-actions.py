#!/usr/bin/env python3
"""
Update GitHub Actions dependencies to latest commit SHA.

This script scans GitHub Actions workflow files in .github/workflows/
and updates action references to their latest commit SHA.

Usage:
    python scripts/update-github-actions.py

Environment Variables:
    GITHUB_TOKEN: Optional GitHub personal access token to avoid rate limits
"""

import os
import re
import json
import urllib.request
import time
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock
from urllib.error import URLError, HTTPError
import difflib

# To avoid API rate limits, set GITHUB_TOKEN environment variable
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")

# Rate limiting: wait between API calls to avoid DDoS-ing GitHub API
API_DELAY_SECONDS = 0.5

# Request timeout to prevent hanging
REQUEST_TIMEOUT_SECONDS = 30

# Check mode: show changes without modifying files
CHECK_MODE = "--check" in sys.argv

# Debug mode: show detailed repository checking information
DEBUG_MODE = "--debug" in sys.argv

# Thread-safe cache for release information
release_cache = {}
cache_lock = Lock()

# Validate repo name pattern (owner/repo format)
REPO_PATTERN = re.compile(r'^[a-zA-Z0-9-._]+/[a-zA-Z0-9-._]+$')

def validate_repo(repo):
    """Validate repository name format."""
    if not REPO_PATTERN.match(repo):
        raise ValueError(f"Invalid repository name: {repo}")
    return repo

def validate_directory(directory):
    """Validate directory path to prevent directory traversal."""
    abs_path = os.path.abspath(directory)
    # Ensure directory is within current working directory or absolute path
    if not os.path.exists(abs_path):
        raise ValueError(f"Directory does not exist: {abs_path}")
    if not os.path.isdir(abs_path):
        raise ValueError(f"Path is not a directory: {abs_path}")
    return abs_path

def generate_diff(old_content, new_content, filepath, directory):
    """Generate unified diff between old and new content with color formatting."""
    old_lines = old_content.splitlines(keepends=True)
    new_lines = new_content.splitlines(keepends=True)
    
    # Use relative path from directory for cleaner diff output
    try:
        rel_path = os.path.relpath(filepath, directory)
    except ValueError:
        rel_path = filepath
    
    diff = difflib.unified_diff(
        old_lines,
        new_lines,
        fromfile=f"a/{rel_path}",
        tofile=f"b/{rel_path}",
        lineterm=''
    )
    
    # ANSI color codes
    RED = '\033[31m'
    GREEN = '\033[32m'
    YELLOW = '\033[33m'
    CYAN = '\033[36m'
    GRAY = '\033[90m'
    RESET = '\033[0m'
    
    colored_diff = []
    for line in diff:
        if line.startswith('---') or line.startswith('+++'):
            colored_diff.append(f"{CYAN}{line}{RESET}")
        elif line.startswith('@@'):
            colored_diff.append(f"{YELLOW}{line}{RESET}")
        elif line.startswith('-'):
            colored_diff.append(f"{RED}{line}{RESET}")
        elif line.startswith('+'):
            colored_diff.append(f"{GREEN}{line}{RESET}")
        elif line.startswith(' '):
            colored_diff.append(f"{GRAY}{line}{RESET}")
        else:
            colored_diff.append(line)
    
    return ''.join(colored_diff)

def get_sha_for_release(repo, tag):
    """Get the SHA for a specific release tag."""
    validate_repo(repo)
    url = f"https://api.github.com/repos/{repo}/git/refs/tags/{tag}"
    headers = {"Accept": "application/vnd.github.v3+json"}
    if GITHUB_TOKEN:
        headers["Authorization"] = f"token {GITHUB_TOKEN}"
    
    try:
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT_SECONDS) as response:
            data = json.loads(response.read().decode())
            return data['object']['sha']
    except HTTPError as e:
        print(f"HTTP error getting SHA for {repo} tag {tag}: {e.code}")
        return None
    except URLError as e:
        print(f"URL error getting SHA for {repo} tag {tag}: {e.reason}")
        return None
    except (json.JSONDecodeError, KeyError) as e:
        print(f"Error parsing response for {repo} tag {tag}: {e}")
        return None
    except Exception as e:
        print(f"Unexpected error getting SHA for {repo} tag {tag}: {e}")
        return None

def get_latest_release(repo):
    """Get the latest release tag for the repository."""
    validate_repo(repo)
    url = f"https://api.github.com/repos/{repo}/releases/latest"
    headers = {"Accept": "application/vnd.github.v3+json"}
    if GITHUB_TOKEN:
        headers["Authorization"] = f"token {GITHUB_TOKEN}"
    
    try:
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT_SECONDS) as response:
            data = json.loads(response.read().decode())
            return data['tag_name']
    except HTTPError as e:
        if e.code == 404:
            # No releases found
            return None
        print(f"HTTP error getting latest release for {repo}: {e.code}")
        return None
    except URLError as e:
        print(f"URL error getting latest release for {repo}: {e.reason}")
        return None
    except (json.JSONDecodeError, KeyError) as e:
        print(f"Error parsing response for {repo}: {e}")
        return None
    except Exception as e:
        print(f"Unexpected error getting latest release for {repo}: {e}")
        return None

def get_action_info(repo):
    """Get latest release and SHA for a repo, with caching."""
    validate_repo(repo)
    
    # Thread-safe cache access
    with cache_lock:
        if repo in release_cache:
            return release_cache[repo]
    
    time.sleep(API_DELAY_SECONDS)
    
    latest_release = get_latest_release(repo)
    if not latest_release:
        with cache_lock:
            release_cache[repo] = None
        return None
    
    time.sleep(API_DELAY_SECONDS)
    
    release_sha = get_sha_for_release(repo, latest_release)
    if not release_sha:
        with cache_lock:
            release_cache[repo] = None
        return None
    
    info = {
        'release': latest_release,
        'sha': release_sha
    }
    
    # Thread-safe cache update
    with cache_lock:
        release_cache[repo] = info
    
    return info


def update_workflows(directory=".github/workflows"):
    """Update GitHub Actions workflow files with latest commit SHAs and version tags."""
    try:
        directory = validate_directory(directory)
    except ValueError as e:
        print(f"Error: {e}")
        return

    if CHECK_MODE:
        print("CHECK MODE: Showing changes without modifying files\n")

    # Regex to find 'uses: owner/repo@ref # version'
    # Ignores local paths starting with './'
    action_pattern = re.compile(r'(uses:\s*)([a-zA-Z0-9-._]+/[a-zA-Z0-9-._]+)@([a-zA-Z0-9-._/]+)(\s*#\s*[vV]?[0-9]+\.[0-9]+\.[0-9]+.*)?')

    # Collect all unique repos to check
    repos_to_check = set()
    file_actions = {}  # filepath -> list of (prefix, repo, current_ref, current_version_comment)

    try:
        for filename in os.listdir(directory):
            if filename.endswith((".yml", ".yaml")):
                filepath = os.path.join(directory, filename)
                # Validate file is within the directory
                if not os.path.abspath(filepath).startswith(os.path.abspath(directory)):
                    print(f"Warning: Skipping file outside directory: {filepath}")
                    continue
                
                with open(filepath, 'r', encoding='utf-8') as f:
                    content = f.read()

                matches = action_pattern.findall(content)
                if matches:
                    file_actions[filepath] = matches
                    for _, repo, _, _ in matches:
                        try:
                            validate_repo(repo)
                            repos_to_check.add(repo)
                        except ValueError as e:
                            print(f"Warning: Skipping invalid repo {repo}: {e}")
    except PermissionError as e:
        print(f"Error: Permission denied accessing directory: {e}")
        return
    except Exception as e:
        print(f"Error reading directory: {e}")
        return

    # Get info for all repos in parallel
    print(f"Checking {len(repos_to_check)} unique repositories...")
    with ThreadPoolExecutor(max_workers=5) as executor:
        future_to_repo = {executor.submit(get_action_info, repo): repo for repo in repos_to_check}
        
        for future in as_completed(future_to_repo):
            repo = future_to_repo[future]
            try:
                info = future.result()
                if DEBUG_MODE and info:
                    print(f"  {repo}: {info['release']}")
            except Exception as e:
                if DEBUG_MODE:
                    print(f"  Error checking {repo}: {e}")

    # Now update files with the cached info
    for filepath, matches in file_actions.items():
        # Validate file is still within the directory
        if not os.path.abspath(filepath).startswith(os.path.abspath(directory)):
            print(f"Warning: Skipping file outside directory: {filepath}")
            continue
        
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                content = f.read()
        except PermissionError as e:
            print(f"Error: Permission denied reading {filepath}: {e}")
            continue
        except Exception as e:
            print(f"Error reading {filepath}: {e}")
            continue

        new_content = content
        file_updated = False
        
        for prefix, repo, current_ref, current_version_comment in matches:
            # Extract current version from comment if available
            current_version = None
            if current_version_comment:
                version_match = re.search(r'[vV]?([0-9]+\.[0-9]+\.[0-9]+.*)', current_version_comment)
                if version_match:
                    current_version = version_match.group(1)

            info = release_cache.get(repo)
            if not info:
                continue

            latest_release = info['release']
            release_sha = info['sha']

            # Skip if already using the correct SHA for the latest release
            if release_sha == current_ref:
                continue

            # Update the uses: line with release SHA
            old_line = f"{prefix}{repo}@{current_ref}{current_version_comment}"
            
            # Fix duplicate v in version tag - remove v if release already has it
            version_comment = f" # {latest_release}" if latest_release else ""
            
            new_line = f"{prefix}{repo}@{release_sha}{version_comment}"
            
            if not CHECK_MODE:
                print(f"Updating {repo}: {current_ref[:12]}... -> {release_sha[:12]}... ({latest_release})")
            new_content = new_content.replace(old_line, new_line)
            file_updated = True

        if file_updated and not CHECK_MODE:
            try:
                # Create backup before writing
                backup_path = filepath + '.bak'
                with open(backup_path, 'w', encoding='utf-8') as f:
                    f.write(content)
                
                # Write new content
                with open(filepath, 'w', encoding='utf-8') as f:
                    f.write(new_content)
                
                # Remove backup on success
                os.remove(backup_path)
                print(f"Updated {os.path.basename(filepath)}\n")
            except PermissionError as e:
                print(f"Error: Permission denied writing {filepath}: {e}")
                # Restore backup if it exists
                if os.path.exists(backup_path):
                    with open(backup_path, 'r', encoding='utf-8') as f:
                        content = f.read()
                    with open(filepath, 'w', encoding='utf-8') as f:
                        f.write(content)
                    os.remove(backup_path)
            except Exception as e:
                print(f"Error writing {filepath}: {e}")
                # Restore backup if it exists
                if os.path.exists(backup_path):
                    with open(backup_path, 'r', encoding='utf-8') as f:
                        content = f.read()
                    with open(filepath, 'w', encoding='utf-8') as f:
                        f.write(content)
                    os.remove(backup_path)
        elif file_updated and CHECK_MODE:
            # Generate and print diff
            diff = generate_diff(content, new_content, filepath, directory)
            print(diff)
            print()


if __name__ == "__main__":
    update_workflows()
