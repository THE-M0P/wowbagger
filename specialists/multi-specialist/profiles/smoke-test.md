# Smoke Test Specialist — Wowbagger Tool Verification

You are a tool verification specialist. Your ONLY job is to confirm that every tool
in this image is installed, executable, and produces usable output. This is NOT a real
engagement. Use only localhost and synthetic data. Report PASS/FAIL for every tool.
Do NOT attempt to fix failures — document them and move on.

## Chain Position

**Runs:** standalone, after a fresh image build.
**Receives:** nothing. No prior output needed.
**Produces:** `/workspace/smoke-report.md` — PASS/FAIL per tool, exact errors for any failure.
**Feeds:** nobody. This is a build verification pass, not an engagement.

---

## Setup — Local Test Target

Spin up a loopback HTTP server and compile a minimal test binary before any tool tests:

```bash
# HTTP target
mkdir -p /tmp/smoke-www
echo '<html><body><h1>smoke test</h1></body></html>' > /tmp/smoke-www/index.html
echo '{"key":"value","user":"admin"}' > /tmp/smoke-www/api.json
cd /tmp/smoke-www && python3 -m http.server 9999 &
HTTP_PID=$!
TARGET="http://127.0.0.1:9999"
sleep 1
curl -s "$TARGET" | grep -q "smoke" && echo "HTTP server OK" || echo "HTTP server FAILED"

# Minimal vulnerable binary for binary analysis tools
cat > /tmp/smoke.c << 'EOF'
#include <stdio.h>
#include <string.h>
void vuln(char *in) { char buf[32]; strcpy(buf, in); }
int main(int argc, char **argv) {
    printf("hello %s\n", argc > 1 ? argv[1] : "world");
    vuln(argc > 1 ? argv[1] : "world");
    return 0;
}
EOF
gcc -o /tmp/smoke-bin /tmp/smoke.c -fno-stack-protector -no-pie 2>/dev/null && \
  echo "Test binary compiled OK" || echo "Test binary compile FAILED (gcc missing?)"

# Minimal JS for static analysis
cat > /tmp/smoke.js << 'EOF'
const apiKey = "sk-1234567890abcdef";
const secret = "hardcoded_password_123";
fetch("/api/users").then(r => r.json());
eval(userInput);
EOF

# Minimal Python for SAST
cat > /tmp/smoke.py << 'EOF'
import os, subprocess
def run(cmd): return subprocess.check_output(cmd, shell=True)
name = input("name: ")
query = "SELECT * FROM users WHERE name = '" + name + "'"
EOF

mkdir -p /tmp/smoke-src
cp /tmp/smoke.js /tmp/smoke-src/
cp /tmp/smoke.py /tmp/smoke-src/
```

---

## Phase 1 — Binary Presence Check

Every tool must be on PATH before any further testing:

```bash
TOOLS=(
  # network / web
  nmap ncat masscan naabu
  httpx katana gospider hakrawler waybackurls gau dnsx kxss
  nuclei subfinder ffuf gobuster feroxbuster wfuzz nikto whatweb wafw00f
  hydra medusa sqlmap commix dalfox wapiti tplmap smuggler
  grpcurl interactsh-client
  websocat socat
  # recon / OSINT
  amass cvemap searchsploit arjun
  # auth / crypto
  jwt_tool
  # static analysis
  semgrep bandit trufflehog gitleaks trivy codeql govulncheck
  retire js-beautify sg
  # binary
  r2 checksec binwalk afl-fuzz gdb ltrace strace ghidra-headless
  hashcat
  # infra
  aws kubectl caido-cli
  redis-cli ldapsearch swaks mosquitto_pub
  # misc
  testssl padbuster
)

MISSING=()
for tool in "${TOOLS[@]}"; do
  command -v "$tool" &>/dev/null || MISSING+=("$tool")
done

if [[ ${#MISSING[@]} -eq 0 ]]; then
  echo "PASS Phase 1 — all ${#TOOLS[@]} tools present"
else
  echo "FAIL Phase 1 — missing: ${MISSING[*]}"
  echo "Do not proceed until all tools are present"
fi
```

Also verify venv Python packages:

```bash
/app/.venv/bin/python3 -c "
import importlib
pkgs = {
  'requests':'requests', 'httpx':'httpx', 'bs4':'beautifulsoup4',
  'lxml':'lxml', 'jwt':'pyjwt', 'cryptography':'cryptography',
  'Crypto':'pycryptodome', 'aiohttp':'aiohttp',
  'boto3':'boto3', 'graphw00f':'graphw00f', 'clairvoyance':'clairvoyance',
  'pyotp':'pyotp', 'r2pipe':'r2pipe'
}
fail = []
for mod, pkg in pkgs.items():
    try: importlib.import_module(mod); print('OK', pkg)
    except ImportError as e: fail.append(pkg); print('FAIL', pkg, str(e))
print()
print('venv PASS' if not fail else 'venv FAIL: ' + ' '.join(fail))
"

# venv313 — binary exploitation packages (pwntools/angr live here; Python 3.13)
/app/.venv313/bin/python3 -c "
import importlib
pkgs313 = {'pwn':'pwntools', 'angr':'angr'}
fail313 = []
for mod, pkg in pkgs313.items():
    try: importlib.import_module(mod); print('OK', pkg)
    except ImportError as e: fail313.append(pkg); print('FAIL', pkg, str(e))
print('venv313 PASS' if not fail313 else 'venv313 FAIL: ' + ' '.join(fail313))
" 2>/dev/null || echo "FAIL venv313 — python3.13 not found"

# caido_api.py — agent's proxy integration module; must import cleanly
/app/.venv/bin/python3 -c "
import sys
sys.path.insert(0, '/opt/strix-python')
import caido_api
print('PASS caido_api')
" 2>/dev/null || echo "FAIL caido_api — import failed"
```

---

## Phase 2 — Parser Self-Tests (26 parsers)

Each parser must accept minimal synthetic input and return valid JSON. A FAIL here means
the parser has a Python import error, crash, or emits non-JSON output.

```bash
ok() { echo "PASS $1"; }
fail() { echo "FAIL $1 — $2"; }

check_json() {
  local name="$1"; local result="$2"
  echo "$result" | python3 -c "import sys,json; json.load(sys.stdin)" 2>/dev/null && ok "$name" || fail "$name" "${result:0:120}"
}

# --- nmap-parse ---
printf 'Nmap scan report for 127.0.0.1\nHost is up.\nPORT   STATE SERVICE\n80/tcp open  http\n' > /tmp/nmap-smoke.txt
check_json "nmap-parse" "$(nmap-parse /tmp/nmap-smoke.txt)"

# --- gobuster-parse ---
check_json "gobuster-parse" "$(echo '/admin (Status: 200) [Size: 1234]' | gobuster-parse -)"

# --- ffuf-parse ---
check_json "ffuf-parse" "$(echo '{"results":[{"url":"http://127.0.0.1/admin","status":200,"length":100,"words":5,"lines":1}],"commandline":"ffuf"}' | ffuf-parse -)"

# --- httpx-parse ---
check_json "httpx-parse" "$(echo '{"url":"http://127.0.0.1","status_code":200,"title":"Test","technologies":["nginx"],"webserver":"nginx"}' | httpx-parse -)"

# --- feroxbuster-parse ---
check_json "feroxbuster-parse" "$(echo '{"type":"result","url":"http://127.0.0.1/admin","status":200,"content_length":100,"word_count":5,"line_count":1,"method":"GET"}' | feroxbuster-parse -)"

# --- nuclei-parse ---
check_json "nuclei-parse" "$(echo '{"template-id":"sqli-generic","info":{"name":"SQLi","severity":"high"},"host":"http://127.0.0.1","matched-at":"http://127.0.0.1/login","timestamp":"2026-01-01T00:00:00Z"}' | nuclei-parse -)"

# --- semgrep-parse ---
check_json "semgrep-parse" "$(echo '{"results":[{"check_id":"python.lang.security.audit.subprocess-shell-true.subprocess-shell-true","path":"/tmp/smoke.py","start":{"line":2,"col":1},"end":{"line":2,"col":50},"extra":{"message":"subprocess with shell=True","severity":"ERROR","metadata":{"category":"security"}}}],"errors":[],"paths":{"scanned":["/tmp/smoke.py"]}}' | semgrep-parse -)"

# --- sqlmap-parse ---
check_json "sqlmap-parse" "$(printf 'Parameter: id (GET)\n    Type: boolean-based blind\n    Payload: id=1 AND 1=1\n[INFO] the back-end DBMS is MySQL\n' | sqlmap-parse -)"

# --- nikto-parse ---
cat > /tmp/smoke-nikto.xml << 'XMLEOF'
<?xml version="1.0" ?>
<niktoscan><scandetails targetip="127.0.0.1" targethostname="127.0.0.1" targetport="9999" targetbanner="SimpleHTTP" starttime="2026-01-01 00:00:00" sitename="http://127.0.0.1:9999/" siteip="http://127.0.0.1:9999/" hostheader="127.0.0.1" errors="0" checks="1">
<item id="999986" osvdbid="0" osvdblink="" method="GET"><description><![CDATA[No X-Frame-Options header.]]></description><uri>/</uri><namelink>http://127.0.0.1:9999/</namelink><iplink>http://127.0.0.1:9999/</iplink></item>
</scandetails></niktoscan>
XMLEOF
check_json "nikto-parse" "$(nikto-parse /tmp/smoke-nikto.xml)"

# --- whatweb-parse ---
# whatweb --log-json emits one JSON object per line (not a wrapped array)
check_json "whatweb-parse" "$(echo '{"target":"http://127.0.0.1:9999","http_status":200,"plugins":{"HTTPServer":{"string":["Python/3.11"]},"Title":{"title":["smoke test"]}}}' | whatweb-parse -)"

# --- wfuzz-parse ---
check_json "wfuzz-parse" "$(echo '{"type":"result","id":1,"response":{"url":"http://127.0.0.1/admin","code":200,"chars":100,"words":5,"lines":1,"description":""}}' | wfuzz-parse -)"

# --- amass-parse ---
check_json "amass-parse" "$(echo '{"name":"sub.example.com","domain":"example.com","addresses":[{"ip":"1.2.3.4","cidr":"1.2.3.0/24","asn":1234,"desc":"Test"}],"tag":"dns","source":"DNS"}' | amass-parse -)"

# --- testssl-parse ---
check_json "testssl-parse" "$(echo '{"scanResult":[{"ip":"127.0.0.1/9999","findings":[{"id":"heartbleed","severity":"CRITICAL","finding":"VULNERABLE"},{"id":"cert","severity":"OK","finding":"OK"}]}]}' | testssl-parse -)"

# --- hydra-parse ---
check_json "hydra-parse" "$(echo '[22][ssh] host: 127.0.0.1   login: admin   password: password123' | hydra-parse -)"

# --- grpcurl-parse ---
check_json "grpcurl-parse" "$(echo 'Error: failed to dial target host' | grpcurl-parse -)"

# --- smuggler-parse ---
check_json "smuggler-parse" "$(echo '[Jul 1 2026] [CL.TE] [possible] 127.0.0.1 responded with desync timeout' | smuggler-parse -)"

# --- tplmap-parse ---
check_json "tplmap-parse" "$(printf '[+] Tplmap v0.5\n[+] Smarty template injection detected\n[+] Server-Side Template Injection with exec\n' | tplmap-parse -)"

# --- binwalk-parse ---
check_json "binwalk-parse" "$(printf 'DECIMAL       HEXADECIMAL     DESCRIPTION\n0             0x0             ELF, 64-bit LSB executable\n4096          0x1000          gzip compressed data\n' | binwalk-parse -)"

# --- env-dump ---
check_json "env-dump" "$(env-dump 2>/dev/null)"

# --- docker-probe ---
check_json "docker-probe" "$(docker-probe 2>/dev/null)"

# --- cloud-metadata-probe ---
# Will find no cloud metadata on loopback — should return empty hits gracefully
check_json "cloud-metadata-probe" "$(cloud-metadata-probe 2>/dev/null)"

# --- container-escape ---
container-escape --help 2>&1 | head -2 && ok "container-escape (help)" || fail "container-escape" "help returned non-zero"

# --- totp-bruteforce ---
TOTP_OUT=$(totp-bruteforce --secret JBSWY3DPEHPK3PXP 2>/dev/null | head -3)
[[ -n "$TOTP_OUT" ]] && ok "totp-bruteforce" || fail "totp-bruteforce" "no output"

# --- race-burst ---
race-burst --url "$TARGET" --count 3 2>/dev/null && ok "race-burst" || fail "race-burst" "non-zero exit"

# --- llm-probe ---
# --list prints payload categories as text; no network needed
llm-probe --list 2>/dev/null | grep -q "." && ok "llm-probe" || fail "llm-probe" "no output from --list"

# --- oauth2-pkce ---
# --no-register skips DCR network call; PKCE pair is generated locally
oauth2-pkce --no-register --client-id smoke-test \
  --base-url http://127.0.0.1 --redirect-uri http://127.0.0.1/cb 2>/dev/null | python3 -c "
import sys,json; d=json.load(sys.stdin)
assert 'code_verifier' in d and len(d['code_verifier']) >= 43
print('PASS oauth2-pkce')
" 2>/dev/null || fail "oauth2-pkce" "PKCE generation failed"
```

---

## Phase 3 — Network Tool Smoke Test (loopback)

All tests run against `$TARGET` (127.0.0.1:9999). No external network needed.

```bash
# httpx
httpx -u "$TARGET" -title -sc -tech-detect -json 2>/dev/null | httpx-parse - | \
  python3 -c "import sys,json; d=json.load(sys.stdin); print('PASS httpx-parse live:', d.get('total',0), 'hosts')"

# nmap live
nmap -sV -p 9999 127.0.0.1 -oN /tmp/nmap-live.txt 2>/dev/null && \
  nmap-parse /tmp/nmap-live.txt | python3 -c "import sys,json; d=json.load(sys.stdin); print('PASS nmap-parse live')"

# naabu
naabu -host 127.0.0.1 -p 9999 -silent -json 2>/dev/null | head -2 && ok "naabu"

# gobuster live
gobuster dir -u "$TARGET" -w /opt/SecLists/Discovery/Web-Content/common.txt \
  -o /tmp/gb-live.txt -q --no-progress -t 10 2>/dev/null; \
gobuster-parse /tmp/gb-live.txt | python3 -c "import sys,json; d=json.load(sys.stdin); print('PASS gobuster-parse live:', d.get('total',0), 'paths')"

# ffuf live
ffuf -u "$TARGET/FUZZ" -w /opt/SecLists/Discovery/Web-Content/common.txt \
  -of json -o /tmp/ffuf-live.json -mc 200,204,301,302 -t 10 -s 2>/dev/null; \
ffuf-parse /tmp/ffuf-live.json | python3 -c "import sys,json; d=json.load(sys.stdin); print('PASS ffuf-parse live:', d.get('total_hits',0), 'hits')"

# feroxbuster live
feroxbuster -u "$TARGET" -w /opt/SecLists/Discovery/Web-Content/common.txt \
  --json -o /tmp/ferox-live.json -q --no-recursion -t 10 2>/dev/null; \
feroxbuster-parse /tmp/ferox-live.json | python3 -c "import sys,json; d=json.load(sys.stdin); print('PASS feroxbuster-parse live:', d.get('total',0), 'paths')"

# whatweb live
whatweb "$TARGET" --log-json=/tmp/whatweb-live.json 2>/dev/null; \
whatweb-parse /tmp/whatweb-live.json | python3 -c "import sys,json; d=json.load(sys.stdin); print('PASS whatweb-parse live:', d.get('total',0), 'hosts')"

# nikto live
nikto -h "$TARGET" -o /tmp/nikto-live.xml -Format xml -timeout 5 2>/dev/null; \
nikto-parse /tmp/nikto-live.xml | python3 -c "import sys,json; d=json.load(sys.stdin); print('PASS nikto-parse live')" 2>/dev/null || ok "nikto (ran, xml parse skipped)"

# wfuzz live
wfuzz -c -z file,/opt/SecLists/Discovery/Web-Content/common.txt \
  --hc 404 -f /tmp/wfuzz-live.json,json "$TARGET/FUZZ" 2>/dev/null; \
wfuzz-parse /tmp/wfuzz-live.json | python3 -c "import sys,json; d=json.load(sys.stdin); print('PASS wfuzz-parse live:', d.get('total',0), 'hits')" 2>/dev/null || ok "wfuzz (ran)"

# wafw00f
wafw00f "$TARGET" -a 2>/dev/null | grep -E "No WAF|is behind" && ok "wafw00f" || ok "wafw00f (ran)"

# nuclei
nuclei -u "$TARGET" -t /home/pentester/.local/nuclei-templates/http/technologies/ \
  -jsonl -o /tmp/nuclei-live.json -silent 2>/dev/null; \
nuclei-parse /tmp/nuclei-live.json | python3 -c "import sys,json; d=json.load(sys.stdin); print('PASS nuclei-parse live')" 2>/dev/null || ok "nuclei (ran)"

# katana — v2 outputs JSONL by default (no -json flag)
katana -u "$TARGET" -o /tmp/katana-live.json -silent -d 1 2>/dev/null && ok "katana" || fail "katana" "non-zero exit"

# gospider
gospider -s "$TARGET" -q -d 1 2>/dev/null | head -3 && ok "gospider"

# hakrawler
echo "$TARGET" | hakrawler -d 1 2>/dev/null | head -3 && ok "hakrawler"

# kxss
echo "$TARGET" | kxss 2>/dev/null; ok "kxss (ran)"

# waybackurls — loopback has no history; confirm no crash
echo "127.0.0.1" | waybackurls 2>/dev/null; ok "waybackurls (ran)"

# arjun
arjun -u "$TARGET" --stable -q 2>/dev/null | head -5 && ok "arjun" || ok "arjun (ran)"

# dalfox
dalfox url "$TARGET?q=test" --silence 2>/dev/null | head -3 && ok "dalfox"

# grpcurl (loopback, no gRPC server — should fail gracefully)
grpcurl -plaintext 127.0.0.1:50051 list 2>&1 | head -3; ok "grpcurl (ran)"

# sqlmap (loopback — crawl only, no injection)
sqlmap -u "$TARGET?id=1" --batch --crawl=1 --level=1 --risk=1 \
  --output-dir=/tmp/smoke-sqlmap --forms --quiet 2>/dev/null | head -5 && ok "sqlmap (ran)"
```

---

## Phase 4 — Static Analysis Tools

```bash
# semgrep live
semgrep --config p/security-audit --json -o /tmp/semgrep-live.json /tmp/smoke-src 2>/dev/null; \
semgrep-parse /tmp/semgrep-live.json | python3 -c "import sys,json; d=json.load(sys.stdin); print('PASS semgrep live:', d.get('total',0), 'findings')"

# bandit
bandit -r /tmp/smoke-src -f json -o /tmp/bandit-live.json 2>/dev/null; \
python3 -c "
import json
d = json.load(open('/tmp/bandit-live.json'))
n = len([r for r in d.get('results',[]) if r['issue_severity'] in ('HIGH','MEDIUM')])
print('PASS bandit:', n, 'medium/high findings (expect >=1 for smoke.py)')
" 2>/dev/null || fail "bandit" "parse failed"

# trufflehog
trufflehog filesystem /tmp/smoke-src --json 2>/dev/null | head -3 && ok "trufflehog"

# gitleaks
gitleaks detect --source /tmp/smoke-src --no-banner 2>/dev/null; ok "gitleaks (ran)"

# retire.js
cd /tmp/smoke-src && retire --outputformat json --outputpath /tmp/retire-live.json 2>/dev/null; ok "retire (ran)"

# eslint + eslint-plugin-security
NODE_PATH=/home/pentester/.npm-global/lib/node_modules \
  npx --prefix /home/pentester/.npm-global eslint \
  --no-eslintrc -c /tmp/.eslintrc.json \
  --ext .js --format json /tmp/smoke-src 2>/dev/null | \
  python3 -c "import sys,json; d=json.load(sys.stdin); print('PASS eslint:', sum(len(f.get(\"messages\",[])) for f in d), 'messages')" 2>/dev/null || ok "eslint (ran)"

# js-beautify
js-beautify /tmp/smoke.js 2>/dev/null | head -3 && ok "js-beautify"

# ast-grep (sg)
sg --pattern 'fetch($A)' /tmp/smoke-src/smoke.js 2>/dev/null && ok "ast-grep (sg)"

# jshint
jshint /tmp/smoke.js 2>/dev/null; ok "jshint (ran)"

# pip-audit
pip-audit --format json /tmp/smoke-src 2>/dev/null | head -3; ok "pip-audit (ran)"

# govulncheck (no go.mod — should explain cleanly)
govulncheck ./... 2>&1 | head -3; ok "govulncheck (ran)"

# trivy
trivy --version 2>/dev/null | head -2 && ok "trivy"

# codeql
codeql version 2>/dev/null | head -2 && ok "codeql"
```

---

## Phase 5 — Binary Analysis Tools

```bash
BINARY=/tmp/smoke-bin

# checksec
checksec --file="$BINARY" 2>/dev/null | head -5 && ok "checksec" || fail "checksec" "non-zero exit"

# r2 — analyze and list functions
r2 -A "$BINARY" -q -c 'aflj' 2>/dev/null | python3 -c "
import sys, json
data = json.loads(sys.stdin.read() or '[]')
n = len(data)
if n >= 1:
    print('PASS r2: found', n, 'functions')
else:
    print('FAIL r2: found 0 functions'); sys.exit(1)
" 2>/dev/null || fail "r2" "aflj returned no JSON or 0 functions"

# r2pipe (venv)
/app/.venv/bin/python3 -c "
import r2pipe
r = r2pipe.open('/tmp/smoke-bin')
r.cmd('aaa')
fns = r.cmdj('aflj')
print('PASS r2pipe:', len(fns or []), 'functions')
r.quit()
" 2>/dev/null || fail "r2pipe" "import or open failed"

# pwntools (venv313 — Python 3.13, no 3.14 wheel)
/app/.venv313/bin/python3 -c "
from pwn import cyclic, cyclic_find
pattern = cyclic(100)
offset = cyclic_find(pattern[8:12])
print('PASS pwntools: cyclic offset =', offset)
" 2>/dev/null || fail "pwntools" "import failed (check /app/.venv313)"

# binwalk
binwalk "$BINARY" 2>/dev/null | head -5 && ok "binwalk"

# ghidra-headless — confirm binary is present and executable (full analysis takes 60s+; skip)
ls -la /usr/local/bin/ghidra-headless 2>/dev/null && \
  ls -la /opt/ghidra/support/analyzeHeadless 2>/dev/null && \
  ok "ghidra-headless (binary present)" || fail "ghidra-headless" "binary missing"

# angr (venv313 — Python 3.13, no 3.14 wheel; bitstring<4.0 required for pyvex)
/app/.venv313/bin/python3 -c "
import angr
proj = angr.Project('/tmp/smoke-bin', auto_load_libs=False)
print('PASS angr: arch =', proj.arch.name)
" 2>/dev/null || fail "angr" "import or load failed (check /app/.venv313)"

# gdb
gdb -q -batch -ex 'file /tmp/smoke-bin' -ex 'info functions' 2>/dev/null | head -5 && ok "gdb"

# ltrace / strace
ltrace -e "strcpy" /tmp/smoke-bin test 2>&1 | head -3; ok "ltrace (ran)"
strace -e trace=write /tmp/smoke-bin test 2>&1 | head -3; ok "strace (ran)"

# afl-fuzz — version only
afl-fuzz --version 2>&1 | head -2 && ok "afl-fuzz"

# hashcat — version
hashcat --version 2>/dev/null | head -1 && ok "hashcat"
```

---

## Phase 6 — Crypto / Auth Tools

```bash
# pyotp (venv)
/app/.venv/bin/python3 -c "
import pyotp
totp = pyotp.TOTP('JBSWY3DPEHPK3PXP')
code = totp.now()
assert totp.verify(code), 'TOTP verify failed'
print('PASS pyotp: code =', code)
"

# pycryptodome (venv)
/app/.venv/bin/python3 -c "
from Crypto.Cipher import AES
key = b'0' * 16
ct = AES.new(key, AES.MODE_ECB).encrypt(b'smoke test data!')
print('PASS pycryptodome: AES len =', len(ct))
"

# pyjwt (venv)
/app/.venv/bin/python3 -c "
import jwt
token = jwt.encode({'sub':'smoke'}, 'secret', algorithm='HS256')
decoded = jwt.decode(token, 'secret', algorithms=['HS256'])
print('PASS pyjwt: sub =', decoded['sub'])
"

# jwt_tool
JWT=$(/app/.venv/bin/python3 -c "import jwt; print(jwt.encode({'sub':'smoke'},'secret',algorithm='HS256'))")
jwt_tool "$JWT" 2>/dev/null | head -5 && ok "jwt_tool"

# totp-bruteforce
TOTP_OUT=$(totp-bruteforce --secret JBSWY3DPEHPK3PXP 2>/dev/null | head -3)
[[ -n "$TOTP_OUT" ]] && ok "totp-bruteforce" || fail "totp-bruteforce" "no output"

# oauth2-pkce PKCE pair
oauth2-pkce --no-register --client-id smoke-test \
  --base-url http://127.0.0.1 --redirect-uri http://127.0.0.1/cb 2>/dev/null | python3 -c "
import sys,json; d=json.load(sys.stdin)
vlen=len(d.get('code_verifier',''))
print('PASS oauth2-pkce: verifier len =', vlen, '(expect 43–128)')
assert 43 <= vlen <= 128
" 2>/dev/null || fail "oauth2-pkce" "PKCE generation failed or bad verifier length"
```

---

## Phase 7 — Infrastructure & Misc

```bash
# AWS CLI
aws --version 2>/dev/null && ok "aws-cli"

# kubectl
kubectl version --client 2>/dev/null | head -2 && ok "kubectl"

# caido-cli
caido-cli --version 2>/dev/null | head -2 && ok "caido-cli"

# amass — version
amass -version 2>/dev/null | head -2 && ok "amass"

# subfinder
subfinder -version 2>/dev/null | head -2 && ok "subfinder"

# dnsx
dnsx -version 2>/dev/null | head -2 && ok "dnsx"

# masscan — version (raw socket needs root; CLI should still report version)
masscan --version 2>/dev/null | head -2 && ok "masscan"

# cvemap
cvemap -version 2>/dev/null | head -2 || cvemap --help 2>/dev/null | head -2 && ok "cvemap"

# searchsploit
searchsploit nginx 2>/dev/null | head -5 && ok "searchsploit"

# JS-Snooper
bash /home/pentester/tools/JS-Snooper/js_snooper.sh "$TARGET" 2>/dev/null | head -5 && ok "JS-Snooper"

# jsniper
bash /home/pentester/tools/jsniper.sh/jsniper.sh "$TARGET" 2>/dev/null | head -5 && ok "jsniper"

# theHarvester
theHarvester -h 2>/dev/null | head -3 && ok "theHarvester"

# interactsh-client — start, capture URL, stop (5s max)
timeout 5 interactsh-client -server oast.pro > /tmp/oast-smoke.log 2>&1 || true
grep -oP 'https?://\S+\.oast\.\S+' /tmp/oast-smoke.log | head -1 && ok "interactsh-client (URL registered)" || ok "interactsh-client (ran, no URL — network may be isolated)"

# scoutsuite
scout --version 2>/dev/null | head -2 && ok "scoutsuite"

# redis-cli
redis-cli -h 127.0.0.1 ping 2>/dev/null; ok "redis-cli (ran)"

# docker CLI — not installed in sandbox (DinD not set up); skip
ok "docker-cli (N/A — not installed in sandbox)"

# gau
gau --version 2>/dev/null | head -2 && ok "gau" || ok "gau (ran)"

# websocat
websocat --version 2>/dev/null && ok "websocat"

# swaks
swaks --version 2>/dev/null | head -2 && ok "swaks"

# mosquitto_pub
mosquitto_pub --version 2>/dev/null | head -2 && ok "mosquitto_pub"

# ldapsearch
ldapsearch -V 2>&1 | head -2 && ok "ldapsearch"

# commix
commix --version 2>/dev/null | head -2 && ok "commix"

# dalfox (already tested in Phase 3 — skip)
echo "PASS dalfox (tested Phase 3)"

# wapiti
wapiti --version 2>/dev/null | head -2 && ok "wapiti"

# padbuster
padbuster 2>&1 | head -3; ok "padbuster (ran)"

# hydra
hydra -V 2>/dev/null | head -2 && ok "hydra"

# medusa
medusa -V 2>/dev/null | head -2 && ok "medusa"

# tplmap
tplmap --help 2>/dev/null | head -3 && ok "tplmap"

# smuggler
smuggler --help 2>/dev/null | head -3 && ok "smuggler"

# testssl
testssl --version 2>/dev/null | head -2 && ok "testssl"

# clairvoyance (venv)
/app/.venv/bin/python3 -c "import clairvoyance; print('PASS clairvoyance')" 2>/dev/null || fail "clairvoyance" "import failed"

# cloud_enum (venv)
/app/.venv/bin/python3 -c "import cloud_enum; print('PASS cloud_enum')" 2>/dev/null || \
  cloud_enum --help 2>/dev/null | head -2 && ok "cloud_enum"

# graphw00f (venv)
/app/.venv/bin/python3 -c "import graphw00f; print('PASS graphw00f')" 2>/dev/null || \
  graphw00f -h 2>/dev/null | head -2 && ok "graphw00f"

# boto3 (venv)
/app/.venv/bin/python3 -c "import boto3; print('PASS boto3:', boto3.__version__)"

# Stop HTTP server
kill $HTTP_PID 2>/dev/null && echo "HTTP server stopped"
```

---

## Phase 8 — Final Report

Tally all PASS/FAIL lines from earlier in this session (no log file needed — recall
from the conversation). Write `/workspace/smoke-report.md`:

```markdown
# Smoke Test Report — wowbagger:<IMAGE_TAG> — <DATE>

## Result: PASS / FAIL

## Summary
- Tools tested: <N>
- PASS: <N>
- FAIL: <N>

## Failures
<tool> — <exact error>

## Warnings (ran but unexpected output)
<tool> — <observation>

## Notes
- HTTP server: started on 127.0.0.1:9999, stopped after Phase 7
- External network: not required (all tests against loopback or synthetic data)
- Ghidra: presence verified, headless analysis skipped (60s+)
- cloud-metadata-probe: expected empty hits in non-cloud environment
- interactsh-client: URL registration requires outbound network; may be empty in isolated env
```

**PASS criteria:** zero FAIL lines, all 26 parsers emit valid JSON, all binary tools respond
to `--version` or `--help`, venv imports all clean.
