# Test fixture: intentionally vulnerable code for Semgrep testing
import subprocess
import requests

password = "super_secret_123"  # hardcoded_password trigger

def run_cmd(user_input):
    subprocess.run(user_input, shell=True)  # subprocess_injection trigger

def fetch_url(url):
    return requests.get(url)  # ssrf trigger

def execute_code(code):
    eval(code)  # eval_injection trigger
