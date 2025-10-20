import os
import requests

def get_local_version(version_file_path):
    try:
        with open(version_file_path, 'r') as f:
            return f.read().strip()
    except Exception:
        return None

def get_remote_version(github_repo_url):
    # Convert repo URL to raw version.txt URL
    if github_repo_url.endswith('/'):
        github_repo_url = github_repo_url[:-1]
    repo_path = github_repo_url.replace('https://github.com/', '')
    raw_url = f'https://raw.githubusercontent.com/{repo_path}/main/version.txt'
    try:
        response = requests.get(raw_url, timeout=5)
        if response.status_code == 200:
            return response.text.strip()
    except Exception:
        pass
    return None

def is_update_available(local_version, remote_version):
    # Simple string comparison, can be improved for semantic versions
    return remote_version and local_version and remote_version > local_version

def check_for_update():
    github_repo_url = os.getenv('GITHUB_REPO_URL')
    version_file_path = os.path.join(os.path.dirname(__file__), '..', 'version.txt')
    local_version = get_local_version(version_file_path)
    remote_version = get_remote_version(github_repo_url)
    return {
        'local_version': local_version,
        'remote_version': remote_version,
        'update_available': is_update_available(local_version, remote_version)
    }
