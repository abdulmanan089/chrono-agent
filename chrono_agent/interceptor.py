# Chrono Agent  (c) 2026 Abdul Manan.  Source-available; see LICENSE.
# Resale or offering as a hosted service is prohibited.  All rights reserved.
"""Advisory command-risk scanner.

It reads the *text* of a command and matches it against known risky patterns.
It cannot inspect or sandbox what a program does once it runs, so an allowed
result is not proof of safety. What it does well:

* recognises destructive commands across shells, languages, databases, git,
  containers and cloud CLIs;
* treats ``rm`` as a command only where a command can start, so ``docker run
  --rm`` or ``git rm --cached`` are not mistaken for ``rm -rf``;
* looks through common text-level obfuscation (line continuations, quote
  splitting, backslashes, zero-width characters, ``$IFS``, ANSI-C ``$'..'``
  quoting, brace expansion) by scanning several normalised forms.

What it cannot do: follow variables (``a=rm; $a -rf /``), decode arbitrary
payloads, or know what a program does once it runs. Inline interpreter code
(``python -c ...``) is reported as MEDIUM because its contents are only
partly understood.

Since 0.5.0, when the caller passes the folder the command will run in
(``assess(cmd, cwd=...)``, which every enforcing path does), the scanner also
reads what the command is about to run and scans that too: script files
(``python cleanup.py``, ``node x.js``, ``powershell -File x.ps1``, ``x.bat``,
``bash x.sh``...), npm/yarn/pnpm/bun package scripts (``npm test``) and Makefile
targets (``make clean``). It looks one level deep plus the scripts those
commands name, not at modules a script imports.
"""
import os
import re
import shlex
import stat
import unicodedata
from pathlib import Path

# A command can start at: line start, after ; & | ( ` { or a quote, after $(,
# or after a wrapper word such as sudo/xargs/env/exec/-exec.
_START = (r"(?:^|[;&|(`{\"']|\$\(|"
          r"\b(?:sudo|doas|xargs|exec|env|command|nohup|time|busybox|then|do|else|-exec|-execdir)\b"
          r"(?:\s+[^\s;&|]+){0,4}?)\s*(?:\\)?(?:[\w.~-]*/)*")


def _cmd(name):
    return _START + name + r"\b"


_RM = _cmd("rm")
_RM_RECURSIVE = _RM + r"(?:[^;&|\n]*?\s)?(?:--recursive\b|-[A-Za-z]*[rR][A-Za-z]*(?=\s|$))"
_RM_FORCE = _RM + r"(?:[^;&|\n]*?\s)?(?:--force\b|-[A-Za-z]*f[A-Za-z]*(?=\s|$))"
_RM_DANGEROUS_TARGET = (_RM + r"[^;&|\n]*?\s(?:/(?:\*|etc|usr|var|bin|sbin|lib|boot|home|root|opt)?|~/?|\*|\.|\.\.)"
                        r"(?:/?\*)?(?=\s|$)")

# A WHERE clause that is always true (WHERE 1=1 / WHERE true) does not limit anything.
_REAL_WHERE = r"\bwhere\b(?!\s+\(?\s*(?:1\s*=\s*1|true|1)\s*\)?[\s\"'`;)]*$)"
_SECRETS = (r"(?:id_rsa|id_ed25519|\.aws/credentials|\.ssh/|\.npmrc|\.pypirc|\.netrc|\.git-credentials|"
            r"\.kube/config|\.docker/config\.json|\.gnupg|/etc/(?:passwd|shadow|sudoers)|"
            r"(?<![\w.-])[\w-][\w.-]{0,63}\.env\b|\.env\b)")
_NET_SEND = r"\b(?:curl|wget|nc|ncat|scp|socat|Invoke-WebRequest|Invoke-RestMethod|iwr|irm)\b"
MAX_SCAN = 65536   # larger inputs are scanned at both ends and refused (fail closed)

# Verbs that change or remove the path they name, wherever it appears; copy verbs
# only matter when the protected path is the destination (the last argument).
_TAMPER_VERBS = (r"del|erase|rm|rmdir|rd|Remove-Item|ri|ren|rename|Rename-Item|mv|move|Move-Item|Set-Content|"
                 r"Add-Content|Out-File|Clear-Content|truncate|shred|tee")
_COPY_VERBS = r"copy|cp|Copy-Item|xcopy|robocopy"


def _protect(path_rx):
    """A rule pattern for commands that change, remove or overwrite `path_rx`."""
    return (r"(?:\b(?:" + _TAMPER_VERBS + r")\b|>)[^;&|\n]*" + path_rx +
            r"|\b(?:" + _COPY_VERBS + r")\b[^;&|\n]*\s['\"]?\S*" + path_rx + r"\S*['\"]?\s*(?=$|[;&|])")

# (regex, score, reason[, exempt]) -- a match is skipped when `exempt` matches it.
RULES = [
    # --- file deletion: shell -------------------------------------------------
    (_RM_RECURSIVE, 98, "Recursive delete"),
    (_RM_FORCE, 85, "Forced delete"),
    (_RM_DANGEROUS_TARGET, 85, "Deletes root, home, parent or everything (wildcard)"),
    (r"\bdel\s+/[sq]|\b(?:rmdir|rd)\s+/s|\bRemove-Item\b[^;\n]*-Recurse", 96, "Recursive delete (Windows)"),
    (r"\b(?:del|erase)\b[^;\n]*\s/[fsq]\b|\bRemove-Item\b[^;\n]*-Force", 85, "Forced delete (Windows)"),
    (r"\bfind\b[^;&|\n]*\s-delete\b", 92, "find -delete removes everything it matches"),
    (r"\bxargs\b[^;\n]*\b(?:rm|unlink|shred|rmdir)\b", 80, "Bulk delete via xargs"),
    (r"\bshred\b|\bwipe\s+-|\bsrm\b", 92, "Securely destroys files"),
    (r"\btruncate\s+(?:-[a-z]|--size)", 80, "Truncates a file"),
    (r"(?:^|[;&|]\s*):\s*>\s*\S", 70, "Truncates a file"),
    (r"\bmv\b[^;&|\n]*\s/dev/null\b", 85, "Discards files into /dev/null"),
    # --- file deletion: languages --------------------------------------------
    (r"\bshutil\s*\.\s*rmtree\b|\brmtree\s*\(", 90, "Recursive delete (Python)"),
    (r"\bos\s*\.\s*(?:remove|unlink|rmdir|removedirs)\b|\.unlink\s*\(", 60, "File delete (Python)"),
    (r"\brimraf\b", 92, "Recursive delete (Node)"),
    (r"\b(?:rmSync|rmdirSync)\b|\bfs(?:\.promises)?\s*\.\s*(?:rm|rmdir)\b", 85, "Recursive delete (Node)"),
    (r"\bunlinkSync\b|\bfs(?:\.promises)?\s*\.\s*unlink\b", 60, "File delete (Node)"),
    (r"\bFileUtils\s*\.\s*(?:rm_rf|remove_dir|rm_r)\b", 90, "Recursive delete (Ruby)"),
    (r"\bFile\s*\.\s*delete\b|\bDir\s*\.\s*rmdir\b|\bunlink\s*\(", 60, "File delete (script)"),
    (r"\bunlink\s+(?:glob\b|@)", 85, "Bulk file delete (script)"),
    (r"\b(?:listdir|glob|walk|scandir|iterdir|readdirSync|readdir)\b[^\n]*(?:\bos\s*\.\s*(?:remove|unlink)\b|\.unlink\s*\(|\bunlinkSync\b|\brmSync\b|\brmtree\b)|"
     r"(?:\bos\s*\.\s*(?:remove|unlink)\b|\.unlink\s*\(|\bunlinkSync\b|\brmSync\b|\brmtree\b)[^\n]*\b(?:listdir|glob|walk|scandir|iterdir|readdirSync|readdir)\b",
     85, "Bulk file delete (script loop)"),
    (r"\bfind\b[^;&|\n]*-exec(?:dir)?\s+(?:rm|unlink|shred|rmdir)\b", 88, "find -exec deletes everything it matches"),
    (r"(?:^|[;&|]\s*)(?:cat\s+/dev/null\s*|true\s*|echo(?:\s+-n)?(?:\s+(?:\"\"|''))?\s*)?>\s*[^\s>&|]", 70,
     "Truncates a file"),
    (r"\b(?:openssl\s+enc|gpg\s+(?:-c|--symmetric|-e|--encrypt)|7z\s+a\b[^;\n]*-p|zip\b[^;\n]*\s-e)\b[^\n]*(?:&&|;)\s*(?:rm|shred|del)\b",
     85, "Encrypts a file then deletes the original (ransomware pattern)"),
    (r"\b(?:openssl\s+enc|gpg\s+(?:-c|--symmetric|-e|--encrypt))\b[^\n]*(?:\.locked\b|\.encrypted\b|\.(?:db|sqlite3?)\b)",
     88, "Encrypts a database or produces .locked files (ransomware pattern)"),
    (r"--suffix\s+\.?(?:locked|encrypted|crypt)\b|\b(?:encrypt|ransom)[\w-]*\.(?:py|js|ps1|sh)\b[^\n]*(?:--root|\s\.(?=\s|$))",
     88, "Bulk file-encryption script (ransomware pattern)"),
    (r"\bgh\s+(?:repo|release|issue|pr|gist|secret|variable|workflow|run|label|ssh-key|gpg-key|cache|extension)\s+(?:delete|remove)\b|"
     r"\bgh\s+api\b[^;\n]*(?:-X|--method)[ =]*DELETE", 85, "Deletes GitHub resources"),
    # --- disks, system --------------------------------------------------------
    (r"\bformat(?:\.com|\.exe)?\s+[a-z]:|\bmkfs(?:\.\w+)?\b|\bdd\s+if=|\bof=/dev/(?!null\b|zero\b|stdout\b|stderr\b)",
     99, "Disk format / overwrite"),
    (r"\bcipher(?:\.exe)?\b[^;\n]*\s/[ewEW]\b", 90, "Windows cipher bulk encryption / free-space wipe"),
    (r"\brobocopy(?:\.exe)?\b[^;\n]*\s/(?:MIR|PURGE)\b", 92, "Robocopy mirror/purge deletes destination files"),
    (r"\bcertutil(?:\.exe)?\b[^;\n]*\s-(?:encode|decode|encodehex|decodehex|urlcache)\b", 85,
     "Certutil encode/decode or remote download (LOLBin)"),
    (r"\bwipefs\b|\bblkdiscard\b|\bfdisk\b|\bsgdisk\b|\bparted\b|\bdiskpart\b|\bFormat-Volume\b|\bClear-Disk\b",
     95, "Partitions or wipes disks"),
    # --- Ransomware recovery wiping ---
    (r"\bvssadmin(?:\.exe)?\b[^;\n]*\b(?:delete\s+shadows|resize\s+shadowstorage)\b|\bwmic\b[^;\n]*\bshadowcopy\b[^;\n]*\bdelete\b|\bGet-WmiObject\b[^;\n]*Win32_ShadowCopy[^;\n]*Delete", 95, "Deletes Windows shadow copies (ransomware recovery wipe)"),
    (r"\bwbadmin(?:\.exe)?\b[^;\n]*\bdelete\s+(?:catalog|backup|systemstatebackup)\b", 95, "Deletes Windows backup catalog"),
    (r"\bbcdedit(?:\.exe)?\b[^;\n]*(?:recoveryenabled\s+no|bootstatuspolicy\s+ignoreallfailures)", 95, "Disables Windows recovery"),
    # --- Defense evasion ---
    (r"\bnetsh\b[^;\n]*\b(?:advfirewall|firewall)\b[^;\n]*\bstate\s+off\b|\bnetsh\s+firewall\s+set\s+opmode\s+disable|\bSet-NetFirewallProfile\b[^;\n]*-Enabled\s+(?:False|\$false|0)", 92, "Disables the firewall"),
    (r"\bSet-MpPreference\b[^;\n]*-(?:Disable\w+\s+(?:\$true|1|true)|ExclusionPath)|\bAdd-MpPreference\b[^;\n]*-Exclusion", 92, "Disables Microsoft Defender protection"),
    (r"\b(?:sc|sc\.exe)\s+(?:stop|delete|config)\s+(?:WinDefend|wscsvc|WdNisSvc|Sense|MpsSvc|EventLog)\b|\b(?:Stop|Set)-Service\b[^;\n]*\b(?:WinDefend|wscsvc|MpsSvc|EventLog)\b|\bwevtutil\s+cl\b", 92, "Stops security service or clears logs"),
    (r"\breg(?:\.exe)?\s+add\b[^;\n]*Windows Defender[^;\n]*Disable", 92, "Disables Defender via registry"),
    # --- Chrono's own controls: a person must change these, never an agent ---
    (r"\b(?:chrono(?:\.exe)?|chrono_agent)\s+(?:approvals\s+(?:approve|deny)|policy\s+(?:pin|unpin)|"
     r"team\s+(?:add|remove)|guard\s+uninstall|prune|audit\b[^;&|\n]*--(?:reset-witness|rotate-key)|"
     r"run\b[^;&|\n]*--force)\b",
     92, "Changes Chrono's own safety controls (approvals, policy pin, team, guard, prune, audit keys, run --force)"),
    (_protect(r"\.chrono(?:-agent)?(?=[\\/\s\"']|$)"), 92, "Tampers with Chrono's own records (.chrono / .chrono-agent)"),
    (_protect(r"chrono-policy\.yaml"), 90, "Changes or removes the Chrono policy file"),
    (_protect(r"\.claude[\\/]settings(?:\.local)?\.json"), 88,
     "Rewrites the AI client's settings (can switch off the Chrono guard)"),
    # --- Persistence & stealth ---
    (r"\breg(?:\.exe)?\s+(?:add|import|copy|load|restore)\b[^;\n]*\\(?:Run|RunOnce|RunServices|RunServicesOnce|"
     r"Winlogon|Image File Execution Options|AppInit_DLLs|User Shell Folders|Shell Folders|"
     r"CurrentControlSet\\Services)\b|\b(?:New|Set)-ItemProperty\b[^;\n]*\\(?:Run|RunOnce|Winlogon)\b",
     95, "Registry autostart / persistence key"),
    (r"\bschtasks(?:\.exe)?\b[^;\n]*\s/(?:create|delete|change)\b|\bRegister-ScheduledTask\b", 88, "Creates or alters a scheduled task (persistence)"),
    (r"\breg(?:\.exe)?\s+(?:add|delete|import)\b|\b(?:New|Set|Remove)-ItemProperty\b[^;\n]*HK(?:LM|CU)", 88, "Modifies the Windows Registry"),
    (r"\bwmic\b[^;\n]*\bprocess\s+call\s+create\b|\bInvoke-WmiMethod\b[^;\n]*Win32_Process", 88, "Spawns a process via WMI"),
    (r"\b(?:powershell|pwsh)(?:\.exe)?\b[^;\n]*\s-w(?:indowstyle)?\s+hidden\b", 88, "Hidden PowerShell window"),
    (r"\b(?:iex|Invoke-Expression)\b[^;\n]*FromBase64String|FromBase64String[^;\n]*\b(?:iex|Invoke-Expression)\b", 90, "Executes decoded in-memory payload"),
    (r">>?\s*\S*\.git[/\\]hooks[/\\]\S+", 88, "Writes a git hook (persistence)"),
    # --- Supply chain ---
    (r"\b(?:pip3?|python[\d.]*\s+-m\s+pip|uv\s+pip|npm|pnpm|yarn|bun)\s+(?:install|add|i)\b[^;\n]*(?:git\+(?:http|ssh|git)|https?://|\S+\.(?:whl|tgz|tar\.gz)\b|--(?:index-url|extra-index-url|trusted-host)\b)", 85, "Installs package from unverified source"),
    (r":\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:", 99, "Fork bomb"),
    (r"\b(?:shutdown|reboot|poweroff)\b|\binit\s+0\b", 75, "Shuts down or reboots the machine"),
    (r"\bkill\s+-9\s+-1\b|\bkillall5\b", 85, "Kills every process"),
    (r"\b(?:iptables\s+-F|ufw\s+(?:disable|reset))\b", 75, "Flushes or disables the firewall"),
    (r"\bcrontab\s+-r\b", 78, "Deletes all cron jobs"),
    (r"\bsystemctl\s+(?:stop|disable|mask)\b", 40, "Stops or disables a service"),
    (r"\bchmod\b(?=[^;\n]*(?:-R|--recursive))(?=[^;\n]*(?:777|000|a\+rwx))", 70, "World-writable or locked-out permissions"),
    (r"\bchown\b[^;\n]*(?:-R|--recursive)", 70, "Recursive ownership change"),
    (r">>?\s*/etc/\S|>\s*/dev/(?:sd|nvme|hd|disk|mmcblk)", 80, "Overwrites system config or device"),
    (r">\s*\S+\.(?:db|sqlite3?)\b", 72, "Overwrites device / database file"),
    # --- databases ------------------------------------------------------------
    (r"\bdrop\s+(?:table|database|schema)\b", 95, "Destroys database objects"),
    (r"\bdrop\s+(?:index|view|user|role|column)\b|\balter\s+table\b[^;\n]*\bdrop\b", 82, "Drops database structure"),
    (r"\btruncate\s+(?:table\s+)?[\w\[\"`]", 90, "Wipes table data"),
    (r"\bdelete\s+from\s+[^;]{0,400}", 88, "DELETE without WHERE", _REAL_WHERE),
    (r"\bupdate\s+[\w.\"`\[\]]+\s+set\s+[^;]{0,400}", 80, "UPDATE without WHERE", _REAL_WHERE),
    (r"\b(?:dropdb|dropuser|mysqladmin\s+drop)\b", 92, "Drops a database or user"),
    (r"\bflush(?:all|db)\b", 92, "Wipes a Redis database"),
    (r"\bdropDatabase\b|\.drop\s*\(\s*\)", 92, "Drops a MongoDB database or collection"),
    # --- git ------------------------------------------------------------------
    (r"\bgit\s+push\b[^;\n]*(?:--force(?:-with-lease)?\b|-f\b|\s\+[\w./-]+)", 85, "Force push rewrites remote history"),
    (r"\bgit\s+push\b[^;\n]*(?:--delete\b|\s:[\w./-]+)", 80, "Deletes a remote branch or tag"),
    (r"\bgit\s+reset\s+--hard", 80, "Discards uncommitted work"),
    (r"\bgit\s+rm\b[^;&|\n]*(?:\s-[A-Za-z]*[rf][A-Za-z]*|--force)(?=\s|$)", 78, "Removes tracked files recursively or by force"),
    (r"\bgit\s+(?:checkout|restore)\b[^;&|\n]*\s\.(?=\s|$)", 78, "Discards uncommitted work"),
    (r"\bgit\s+clean\b[^;\n]*-[a-z]*f", 78, "Deletes untracked files"),
    (r"\bgit\s+(?:filter-branch|filter-repo)\b", 80, "Rewrites repository history"),
    (r"\bgit\s+reflog\s+expire\b|\bgit\s+gc\b[^;\n]*--prune=now", 80, "Destroys git recovery data"),
    (r"\bgit\s+branch\b[^;\n]*\s-D\b|\bgit\s+stash\s+(?:drop|clear)\b", 60, "Deletes git branches or stashes"),
    # --- containers, cloud, infrastructure -----------------------------------
    (r"\bterraform\s+destroy\b|\btofu\s+destroy\b", 92, "Destroys infrastructure"),
    (r"\b(?:terraform|tofu)\s+apply\b[^;\n]*-auto-approve", 75, "Applies infrastructure changes unreviewed"),
    (r"\bkubectl\s+delete\b", 80, "Deletes Kubernetes resources"),
    (r"\bhelm\s+(?:uninstall|delete)\b", 75, "Removes a Helm release"),
    (r"\bdocker\s+(?:system|volume|image|container|network|builder)\s+prune\b", 75, "Prunes Docker data"),
    (r"\bdocker\s+(?:rm|rmi|volume\s+rm)\b[^;\n]*(?:-f\b|--force)", 70, "Force-removes Docker objects"),
    (r"\bdocker[\s-]+compose\s+down\b[^;\n]*(?:-v\b|--volumes)", 78, "Deletes Docker volumes"),
    (r"\baws\s+s3\s+(?:rm\b[^;\n]*--recursive|rb\b)|\bgsutil\b[^;\n]*\brm\b[^;\n]*\s-[a-z]*r", 92, "Bulk-deletes cloud storage"),
    (r"\baws\s+s3\s+sync\b[^;\n]*--delete|\brsync\b[^;\n]*--delete", 85, "Sync that deletes the destination"),
    (r"\baws\b[^;\n]*\b(?:terminate-instances|delete-[\w-]+|deregister-[\w-]+)\b|\b(?:gcloud|az)\b[^;\n]*\bdelete\b",
     80, "Deletes cloud resources"),
    (r"\brclone\s+(?:purge|delete|deletefile)\b", 85, "Deletes remote files"),
    (r"\bheroku\s+(?:apps:destroy|pg:reset)\b", 90, "Destroys a Heroku app or database"),
    (r"\bnpm\s+unpublish\b", 80, "Unpublishes a package"),
    (r"\b(?:curl|wget|http|https|xh)\b[^;\n]*(?:-X\s*DELETE|--request\s+DELETE|--method[ =]DELETE)|-Method\s+Delete\b",
     70, "HTTP DELETE request"),
    # --- remote code, secrets -------------------------------------------------
    (r"\b(?:curl|wget)\b[^|]*\|\s*(?:sudo(?:\s+-\S+)*\s+)?(?:bash|sh|zsh|python\w*|powershell|pwsh)\b|"
     r"\b(?:ba|z|da)?sh\s+<\(\s*(?:curl|wget)", 75, "Pipes remote code to interpreter"),
    (r"\b(?:base64|openssl\s+enc|xxd)\b[^;\n]*(?:-d\b|--decode|-r\b)[^;\n]*\|\s*(?:sudo\s+)?(?:ba|z|da|k)?sh\b",
     85, "Executes a decoded payload"),
    (r"\b(?:iex|Invoke-Expression)\b[^;\n]*(?:DownloadString|iwr|irm|Invoke-WebRequest|Invoke-RestMethod|curl|wget)|"
     r"\b(?:iwr|irm|Invoke-WebRequest|Invoke-RestMethod)\b[^;\n]*\|\s*(?:iex|Invoke-Expression)\b",
     85, "Executes a downloaded PowerShell payload"),
    (r"\b(?:powershell|pwsh)(?:\.exe)?\b[^;\n]*\s-(?:enc|encodedcommand)\b", 80, "Encoded PowerShell command"),
    (r"\bnc\b[^;\n]*\s-e\b|\bncat\b[^;\n]*--exec|/dev/tcp/\d", 95, "Reverse shell"),
    (_SECRETS + r"[^\n]*" + _NET_SEND + r"|" + _NET_SEND + r"[^\n]*" + _SECRETS,
     85, "Possible secret exfiltration"),
    (r"\b(?:cat|type|Get-Content|gc)\b[^\n]*" + _SECRETS + r"[^\n]*\|\s*(?:base64|xxd|certutil)\b",
     80, "Encodes a secret file (exfiltration staging)"),
    (r"\b(?:python[\d.]*|py|node|nodejs|ruby|perl|powershell|pwsh)\b[^\n]*\s-(?:c|e|Command)\b[^\n]*"
     r"(?:b64encode|base64|btoa|ToBase64String|urlopen|requests\.|fetch\(|http\.client|socket)[^\n]*" + _SECRETS +
     r"|\b(?:python[\d.]*|py|node|nodejs|ruby|perl|powershell|pwsh)\b[^\n]*\s-(?:c|e|Command)\b[^\n]*" + _SECRETS +
     r"[^\n]*(?:b64encode|base64|btoa|ToBase64String|urlopen|requests\.|fetch\(|http\.client|socket)",
     80, "Inline code encodes or sends a secret file"),
    (r"(?:^|[;&|(])\s*(?:env|printenv|set)(?:\s+-\w+)*\s*\|[^;\n]*\b(?:curl|wget|nc|ncat|socat)\b",
     80, "Sends environment variables to the network"),
    (r"\b(?:tar|zip|7z|zstd|gzip|cpio)\b[^;&\n]*\|\s*(?:curl|wget|nc|ncat|socat)\b", 75,
     "Streams an archive to the network"),
    (r"\b(?:scp|rsync)\b(?=[^;&\n]*\s(?:~/?|/home/?|/etc/?|/root/?|\$HOME/?)\s)(?=[^;&\n]*\s[\w.-]+@?[\w.-]+:)",
     75, "Copies home or system directories off the machine"),
    # --- inline code: contents only partly understood -------------------------
    (r"\b(?:python[\d.]*|py)\b(?:\s+-[A-Za-z]+)*\s+-c\b|\b(?:node|nodejs)\b(?:\s+-[A-Za-z-]+)*\s+(?:-e|-p|--eval|--print)\b|"
     r"\b(?:ruby|perl|php|lua)\b(?:\s+-[A-Za-z]+)*\s+-(?:e|E|pe|ne|r)\b|\bdeno\s+eval\b|"
     r"\b(?:bash|sh|zsh|dash|ksh|fish)\b(?:\s+-[A-Za-z]+)*\s+-c\b|\beval\b|"
     r"\b(?:powershell|pwsh)(?:\.exe)?\b[^;\n]*\s-c(?:ommand)?\b|\bcmd(?:\.exe)?\s+/[ck]\b",
     35, "Inline code execution; contents are only partly inspected"),
    # --- misc -----------------------------------------------------------------
    (r"\bsudo\b", 40, "Elevated privileges"),
    (r"\bpip\s+uninstall|\bnpm\s+uninstall", 30, "Removes dependencies"),
]

_COMPILED = [(re.compile(r[0], re.I | re.M), r[1], r[2],
              re.compile(r[3], re.I) if len(r) > 3 else None) for r in RULES]

_ZERO_WIDTH = dict.fromkeys(map(ord, "\u200b\u200c\u200d\u2060\ufeff\u00ad"), None)
_GIT_RM_CACHED = re.compile(r"\bgit\s+rm\b[^;&|\n]*--cached[^;&|\n]*", re.I)
# A git commit/tag message is prose, not a command.
_GIT_MESSAGE = re.compile(r"(\bgit\s+(?:commit|tag|notes|merge)\b[^;&|\n]*?\s(?:-[A-Za-z]*m|--message)(?:=|\s+))(\"[^\"]*\"|'[^']*')", re.I)
_SEARCH = re.compile(r"(\b(?:grep|egrep|fgrep|zgrep|rg|ag|ack|man|apropos)\b[^;&|\n]*?\s)(?:-e\s+)?(\"[^\"]*\"|'[^']*')", re.I)


def _neutral_search(m):
    q = m.group(2)   # a quoted search pattern cannot execute, unless it hides a substitution
    return m.group(0) if ("$(" in q or "`" in q or "${" in q) else m.group(1) + "PATTERN"


_ANSI_C = re.compile(r"\$'((?:[^'\\]|\\.)*)'")
_BRACES = re.compile(r"\{([^{}\s]*(?:,[^{}\s]*)+)\}")


def level_for(score):
    return "CRITICAL" if score >= 90 else "HIGH" if score >= 70 else "MEDIUM" if score >= 30 else "LOW"


def _ansi_c(match):
    try:
        return match.group(1).encode("latin-1", "backslashreplace").decode("unicode_escape")
    except (UnicodeError, ValueError):
        return match.group(1)


def _variants(cmd):
    """The command plus text-level de-obfuscated forms of it."""
    base = unicodedata.normalize("NFKC", cmd).translate(_ZERO_WIDTH)
    base = re.sub(r"\\\r?\n[ \t]*", " ", base)            # line continuation
    base = re.sub(r"\$\{IFS\}|\$IFS(?![\w])", " ", base)     # $IFS used as a space
    base = _GIT_RM_CACHED.sub(" ", base)                       # git rm --cached keeps files
    base = _GIT_MESSAGE.sub(lambda m: m.group(1) + "MESSAGE", base)  # commit messages are prose
    base = _SEARCH.sub(_neutral_search, base)                    # grep 'DROP TABLE' is a search
    forms = [base]
    plain = _ANSI_C.sub(_ansi_c, base)                         # $'\x72m'
    plain = re.sub(r"(?<=\w)\\(?=\w)", "", plain)              # r\m
    plain = plain.replace("''", "").replace('""', "")           # r''m
    plain = re.sub(r"[\"']", "", plain)                        # "r"m
    plain = _BRACES.sub(lambda m: m.group(1).replace(",", " "), plain)  # {rm,-rf,/}
    if plain != base:
        forms.append(plain)
    return forms


def _scan_text(cmd, hits, prefix="", min_score=0):
    """Add every rule that matches `cmd` (or a de-obfuscated form) to `hits`."""
    for text in _variants(cmd):
        for rx, score, why, exempt in _COMPILED:
            if score < min_score:
                continue
            for match in rx.finditer(text):
                if exempt is not None and exempt.search(match.group()):
                    continue
                key = prefix + why
                if key not in hits or score > hits[key]:
                    hits[key] = score
                break


def assess(cmd, cwd=None):
    """Risk of running `cmd`. With `cwd` (the folder it will run in), the
    scripts, package scripts and make targets it starts are read and scanned too."""
    hits = {}
    oversized = len(cmd) > MAX_SCAN
    if oversized:   # keep both ends so padding cannot hide a payload, and refuse
        cmd = cmd[:20000] + "\n" + cmd[-20000:]
        hits["Input larger than 64 KB was not fully inspected"] = 70
    _scan_text(cmd, hits)
    if cwd is not None:
        try:
            _inspect_targets(cmd, Path(cwd), hits)
        except Exception:            # fail closed: an input that breaks inspection must not slip through
            hits["What this command runs could not be inspected (blocked to be safe)"] = 70
    score = max(hits.values(), default=5)
    ordered = sorted(hits.items(), key=lambda kv: -kv[1])
    return {"score": score, "level": level_for(score),
            "reasons": [w for w, _ in ordered] or ["No dangerous pattern detected; program behavior is not inspected"],
            "blocked": score >= 70}


# --------------------------------------------------------------------------
# What a command runs: script files, package scripts and make targets.
# --------------------------------------------------------------------------
MAX_SCRIPT = 1024 * 1024      # bytes scanned per file; larger files are scanned at both ends and refused
MAX_FILES = 16                # files and package scripts inspected per command; more is refused
MAX_DEPTH = 4                 # a package script that runs a script that runs a script...; deeper is refused
TOO_MANY = "Runs more scripts than Chrono inspects at once (%d); the rest could not be checked" % MAX_FILES
CONTENT_MIN_SCORE = 60        # inside files only clear findings count; MEDIUM hints stay out
SCRIPT_EXT = {".py", ".pyw", ".js", ".mjs", ".cjs", ".ts", ".mts", ".cts", ".ps1", ".psm1", ".bat", ".cmd",
              ".sh", ".bash", ".zsh", ".rb", ".pl", ".php", ".lua", ".r"}
_COMMENT = {".py": ("#",), ".pyw": ("#",), ".sh": ("#",), ".bash": ("#",), ".zsh": ("#",), ".ps1": ("#",),
            ".psm1": ("#",), ".rb": ("#",), ".pl": ("#",), ".r": ("#",), ".bat": ("rem ", "::", "@rem "),
            ".cmd": ("rem ", "::", "@rem "), ".js": ("//",), ".mjs": ("//",), ".cjs": ("//",), ".ts": ("//",),
            ".mts": ("//",), ".cts": ("//",), ".php": ("//", "#"), ".lua": ("--",)}
_PY = re.compile(r"(?:python(?:\d+(?:\.\d+)*)?w?|py|pypy\d*)\Z")
_JS = {"node", "nodejs", "tsx", "ts-node", "deno", "bun"}
_OTHER_INTERP = {"ruby", "perl", "php", "lua", "rscript"}
_SHELLS = {"bash", "sh", "zsh", "dash", "ksh", "fish"}
_WRAPPERS = {"sudo", "doas", "env", "nohup", "time", "exec", "command", "call", "start", "nice", "timeout"}
_PKG = {"npm", "pnpm", "yarn", "bun"}
_NPM_BUILTIN = {"test": "test", "t": "test", "tst": "test", "start": "start", "stop": "stop", "restart": "restart"}
_INSTALL_HOOKS = ("preinstall", "install", "postinstall", "prepare")


def _split_segments(cmd):
    """Split a command line at ; & | && || newlines and parentheses outside quotes."""
    out, buf, quote = [], [], None
    for ch in cmd:
        if quote:
            buf.append(ch)
            if ch == quote:
                quote = None
        elif ch in "\"'":
            quote = ch
            buf.append(ch)
        elif ch in ";&|\n()":
            out.append("".join(buf))
            buf = []
        else:
            buf.append(ch)
    out.append("".join(buf))
    return [s.strip() for s in out if s.strip()]


def _tokens(segment):
    try:
        toks = shlex.split(segment, posix=(os.name != "nt"))
    except ValueError:
        toks = segment.split()
    return [t[1:-1] if len(t) >= 2 and t[0] == t[-1] and t[0] in "\"'" else t for t in toks]


_KNOWN_PROGS = _JS | _OTHER_INTERP | _SHELLS | _PKG | _WRAPPERS | {
    "cmd", "powershell", "pwsh", "make", "mingw32-make", "gmake", "python", "py"}


def _prog(token):
    """Lower-case program name: path and .exe/.com removed; .cmd/.bat only for
    known launchers such as npm.cmd (other batch files are scripts to read)."""
    name = re.split(r"[\\/]", token)[-1].lower()
    for ext in (".exe", ".com"):
        if name.endswith(ext):
            return name[:-len(ext)]
    for ext in (".cmd", ".bat"):
        if name.endswith(ext) and name[:-len(ext)] in _KNOWN_PROGS:
            return name[:-len(ext)]
    return name


def _read_limited(path):
    """(text, partly_inspected) of a regular file, or (None, False)."""
    try:
        st = path.stat()
    except OSError:
        return None, False
    if not stat.S_ISREG(st.st_mode):
        return None, False
    with open(path, "rb") as f:
        if st.st_size <= MAX_SCRIPT:
            data, partly = f.read(MAX_SCRIPT + 1), False
        else:
            head = f.read(MAX_SCRIPT // 2)
            f.seek(max(0, st.st_size - MAX_SCRIPT // 2))
            data, partly = head + b"\n" + f.read(MAX_SCRIPT // 2), True
    if b"\0" in data[:4096]:
        return "\0", partly                     # binary: cannot be read as a script
    return data.decode("utf-8", errors="replace"), partly


def _strip_comments(text, ext):
    marks = _COMMENT.get(ext)
    if not marks:
        return text
    keep = []
    for line in text.splitlines():
        low = line.lstrip().lower()
        if low.startswith(tuple(marks)) and not low.startswith("#!"):
            continue
        keep.append(line)
    return "\n".join(keep)


class _Inspector:
    def __init__(self, cwd, hits):
        self.cwd, self.hits, self.seen, self.count = cwd, hits, set(), 0

    def note(self, key, score):
        if key not in self.hits or score > self.hits[key]:
            self.hits[key] = score

    def label(self, path):
        try:
            return path.resolve().relative_to(self.cwd.resolve()).as_posix()
        except ValueError:
            return str(path)

    def resolve(self, name, exts=()):
        p = Path(name)
        if not p.is_absolute():
            p = self.cwd / p
        candidates = [p] + [p.with_name(p.name + e) for e in exts if not p.name.lower().endswith(e)]
        for c in candidates:
            try:
                if c.is_file():
                    return c
            except OSError:
                return None
        return None

    def full(self, depth=0):
        """True (and a blocking note) when the inspection limits are reached."""
        if depth > MAX_DEPTH:
            self.note("Starts scripts nested deeper than Chrono inspects (%d levels)" % MAX_DEPTH, 70)
            return True
        if self.count >= MAX_FILES:
            self.note(TOO_MANY, 70)
            return True
        return False

    def script(self, path, depth):
        key = os.path.normcase(str(path.resolve()))
        if key in self.seen or self.full(depth):
            return
        self.seen.add(key)
        self.count += 1
        text, partly = _read_limited(path)
        name = self.label(path)
        if text is None:
            return
        if text == "\0":
            self.note("%s is a binary file; its behaviour was not inspected" % name, 35)
            return
        if partly:
            self.note("%s is larger than 1 MB and was only partly inspected" % name, 70)
        ext = path.suffix.lower()
        body = _strip_comments(text, ext)
        _scan_text(body, self.hits, prefix="In %s: " % name, min_score=CONTENT_MIN_SCORE)
        if ext in (".bat", ".cmd", ".sh", ".bash", ".zsh", ".ps1"):
            for line in body.splitlines():          # a batch/shell script that starts other scripts
                self.command(line, depth + 1)

    def package_script(self, name, depth, tool):
        pkg = self.cwd / "package.json"
        if not pkg.is_file() or self.full(depth):
            return
        import json
        try:
            scripts = json.loads(pkg.read_text(encoding="utf-8", errors="replace")).get("scripts") or {}
        except (ValueError, AttributeError):
            self.note("package.json could not be read, so %s scripts were not inspected" % tool, 35)
            return
        if not isinstance(scripts, dict):
            return
        names = [name] if name in _INSTALL_HOOKS else ["pre" + name, name, "post" + name]
        for n in names:
            body = scripts.get(n)
            if not isinstance(body, str) or ("pkg", n) in self.seen:
                continue
            if self.full(depth):
                return
            self.seen.add(("pkg", n))
            self.count += 1
            _scan_text(body, self.hits, prefix='In %s script "%s": ' % (tool, n), min_score=CONTENT_MIN_SCORE)
            self.command(body, depth + 1)

    def make_target(self, makefile, targets, depth):
        if self.full(depth):
            return
        text, _ = _read_limited(makefile)
        if not text or text == "\0":
            return
        self.count += 1
        rules, order, current = {}, [], None
        for line in text.splitlines():
            if line.startswith("\t"):
                if current:
                    for t in current:
                        rules.setdefault(t, {"recipes": [], "deps": []})["recipes"].append(
                            line.strip().lstrip("@-+").strip())
                continue
            m = re.match(r"^([A-Za-z0-9_./%$(){}-][^:=#]*?)\s*::?(?!=)(.*)$", line)
            if m and not line.startswith("#"):
                current = m.group(1).split()
                rest = m.group(2).split("#", 1)[0]
                rest, _, inline = rest.partition(";")             # "target: deps ; recipe"
                for t in current:
                    rule = rules.setdefault(t, {"recipes": [], "deps": []})
                    rule["deps"].extend(rest.split())
                    if inline.strip():
                        rule["recipes"].append(inline.strip())
                order.extend(t for t in current if not t.startswith("."))
            elif line.strip() and not line.startswith("#"):
                current = None
        todo, done = list(targets or order[:1]), set()
        while todo and len(done) < 64:                            # the target and what it depends on
            t = todo.pop(0)
            if t in done:
                continue
            done.add(t)
            rule = rules.get(t)
            if not rule:
                continue
            for recipe in rule["recipes"]:
                _scan_text(recipe, self.hits, prefix='In make target "%s": ' % t, min_score=CONTENT_MIN_SCORE)
                self.command(recipe, depth + 1)
            todo.extend(rule["deps"])

    def command(self, cmd, depth=0):
        # Limits are enforced where a script, package script or makefile would be
        # read (full()), so plain lines such as "@echo off" never trip them.
        for segment in _split_segments(cmd):
            self.segment(_tokens(segment), depth)

    def segment(self, toks, depth):
        while toks and (re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*=.*", toks[0]) or _prog(toks[0]) in _WRAPPERS):
            toks = toks[1:]
            while toks and toks[0].startswith("-") and len(toks) > 1:      # wrapper options (sudo -E, timeout 5)
                toks = toks[1:]
            if toks and re.fullmatch(r"\d+[smhd]?", toks[0]) and len(toks) > 1:
                toks = toks[1:]
            if toks and toks[0] in ('""', "") and len(toks) > 1:            # start "" program
                toks = toks[1:]
        if not toks:
            return
        prog, args = _prog(toks[0]), toks[1:]
        ext = Path(toks[0]).suffix.lower()
        if _PY.fullmatch(prog) and args[:2] == ["-m", "chrono_agent"]:   # python -m chrono_agent run ...
            prog, args = "chrono", args[2:]
        if prog == "chrono" and args[:1] == ["run"]:                     # chrono run [options] [--] program ...
            rest, shell = args[1:], False
            while rest and rest[0].startswith("-"):
                flag, rest = rest[0], rest[1:]
                if flag == "--":
                    break
                if flag == "--shell":
                    shell = True
                elif flag in ("--approver", "--approval-reason") and rest:
                    rest = rest[1:]
            if shell and rest:
                return self.command(rest[0], depth)
            return self.segment(rest, depth)
        if prog == "cmd":
            for i, a in enumerate(args):
                if a.lower() in ("/c", "/k", "/r"):
                    return self.command(" ".join(args[i + 1:]), depth + 1)
            return
        if prog in ("powershell", "pwsh"):
            for i, a in enumerate(args):
                if a.lower() in ("-file", "-f") and i + 1 < len(args):
                    p = self.resolve(args[i + 1], (".ps1",))
                    return self.script(p, depth) if p else None
                if a.lower() in ("-command", "-c", "-encodedcommand", "-enc", "-e", "-ec"):
                    return None
            for a in args:
                if a.lower().endswith(".ps1"):
                    p = self.resolve(a)
                    return self.script(p, depth) if p else None
            return
        if prog in _PKG:
            return self.package(prog, args, depth)
        if prog in ("make", "mingw32-make", "gmake"):
            return self.make(args, depth)
        if _PY.fullmatch(prog):
            return self.interpreter(args, depth, inline=("-c",), takes_value=("-W", "-X"), module=True,
                                    exts=(".py",))
        if prog in _JS:
            if prog in ("deno", "bun") and args and args[0] in ("run", "x"):
                if prog == "bun" and len(args) > 1 and not self.resolve(args[1]):
                    return self.package_script(args[1], depth, "bun")
                args = args[1:]
            return self.interpreter(args, depth, inline=("-e", "--eval", "-p", "--print"),
                                    takes_value=("-r", "--require", "--import", "--loader"),
                                    exts=(".js", ".mjs", ".cjs", ".ts"))
        if prog in _OTHER_INTERP:
            return self.interpreter(args, depth, inline=("-e", "-E", "-r"), takes_value=("-I", "-f"))
        if prog in _SHELLS:
            return self.interpreter(args, depth, inline=("-c",), takes_value=("-o", "+o"))
        if ext in SCRIPT_EXT:                                               # ./x.sh, x.bat, .\x.ps1
            p = self.resolve(toks[0])
            if p:
                self.script(p, depth)
            return
        if os.name == "nt" and not ext and not re.search(r"[\\/]", toks[0]):
            for e in (".bat", ".cmd", ".ps1"):                              # cmd runs x.bat when told "x"
                p = self.cwd / (toks[0] + e)
                if p.is_file():
                    return self.script(p, depth)

    def interpreter(self, args, depth, inline=(), takes_value=(), module=False, exts=()):
        i = 0
        while i < len(args):
            a = args[i]
            if a in inline:
                return None
            if module and a == "-m" and i + 1 < len(args):
                mod = args[i + 1]
                base = self.cwd.joinpath(*mod.split("."))
                for p in (base.with_name(base.name + ".py"), base / "__main__.py"):
                    if p.is_file():
                        return self.script(p, depth)
                return None
            if a in takes_value:
                i += 2
                continue
            if a.startswith("-") and a != "-":
                i += 1
                continue
            p = self.resolve(a, exts)
            return self.script(p, depth) if p else None
        return None

    def install_hooks(self, depth, tool):
        for hook in _INSTALL_HOOKS:          # npm install / yarn run the project's own lifecycle scripts
            self.package_script(hook, depth, tool)

    def package(self, tool, args, depth):
        if not args:
            return self.install_hooks(depth, tool) if tool == "yarn" else None
        first = args[0]
        bare = not [a for a in args[1:] if not a.startswith("-")]
        if tool == "npm":
            if first in ("run", "run-script", "rum", "urn") and len(args) > 1:
                return self.package_script(args[1], depth, tool)
            if first in _NPM_BUILTIN:
                return self.package_script(_NPM_BUILTIN[first], depth, tool)
            if first in ("install", "i", "ci", "add") and bare:
                self.install_hooks(depth, tool)
            return None
        if first == "run" and len(args) > 1:
            return self.package_script(args[1], depth, tool)
        if first in ("test", "start", "stop", "restart"):
            return self.package_script(first, depth, tool)
        if first in ("install", "i") and bare:
            return self.install_hooks(depth, tool)
        if tool in ("yarn", "pnpm") and not first.startswith("-") and first not in (
                "add", "remove", "upgrade", "up", "update", "why", "info", "list", "ls", "init", "create",
                "dlx", "exec", "link", "unlink", "publish", "pack", "config", "cache", "outdated", "audit",
                "help", "version", "--version", "-v", "global", "store", "import", "rebuild", "prune",
                "workspace", "workspaces", "set", "plugin", "node", "patch", "explain"):
            return self.package_script(first, depth, tool)
        return None

    def make(self, args, depth):
        makefile, targets, i = None, [], 0
        while i < len(args):
            a = args[i]
            if a in ("-f", "--file", "--makefile") and i + 1 < len(args):
                makefile = self.resolve(args[i + 1])
                i += 2
                continue
            if a in ("-C", "--directory"):
                return None                  # another folder: not inspected
            if not a.startswith("-") and "=" not in a:
                targets.append(a)
            i += 1
        if makefile is None:
            for name in ("GNUmakefile", "makefile", "Makefile"):
                p = self.cwd / name
                if p.is_file():
                    makefile = p
                    break
        if makefile is not None:
            self.make_target(makefile, targets, depth)


def _inspect_targets(cmd, cwd, hits):
    if not cwd.is_dir():
        return
    _Inspector(cwd, hits).command(cmd)


# --------------------------------------------------------------------------
# Read-only commands: nothing on disk can change, so no savepoint is needed.
# Deliberately short. Anything not listed here, any redirection, substitution
# or explicit program path makes a command "not read-only".
# --------------------------------------------------------------------------
_RO_PROGRAMS = {"dir", "ls", "pwd", "cd", "chdir", "echo", "type", "cat", "head", "tail", "wc", "where", "which",
                "whoami", "hostname", "ver", "vol", "tree", "findstr", "grep", "egrep", "fgrep", "rg", "uname",
                "get-childitem", "gci", "get-content", "gc", "get-location", "gl", "get-item", "gi", "test-path",
                "select-string", "sls", "get-command", "gcm", "get-date", "resolve-path", "get-filehash",
                "measure-object", "select-object", "sort-object", "format-table", "format-list", "out-string",
                "write-output", "write-host"}
_RO_VERSION = {"python", "python3", "py", "node", "npm", "npx", "pip", "pip3", "git", "java", "javac", "go",
               "cargo", "rustc", "dotnet", "ruby", "perl", "php", "deno", "bun", "yarn", "pnpm", "docker",
               "kubectl", "terraform", "gcc", "clang", "cmake", "make", "chrono", "uv", "poetry", "conda"}
_RO_GIT = {"status", "log", "diff", "show", "rev-parse", "describe", "blame", "ls-files", "shortlog", "remote",
           "branch", "tag", "config"}
_RO_PIP = {"list", "show", "freeze", "check", "--version", "-V"}
_RO_NPM = {"ls", "list", "view", "outdated", "root", "prefix", "--version", "-v", "help", "explain", "why"}
_RO_CHRONO = {"status", "log", "diff", "scan", "policy", "--version", "-h", "--help"}


def _shadowed(cwd, name):
    """On Windows, cmd runs a program from the current folder before PATH."""
    if os.name != "nt" or cwd is None:
        return False
    exts = [e.lower() for e in os.environ.get("PATHEXT", ".COM;.EXE;.BAT;.CMD").split(";") if e]
    for e in [""] + exts:
        try:
            if (Path(cwd) / (name + e)).is_file():
                return True
        except OSError:
            return True
    return False


def _ro_segment(toks, cwd):
    if not toks or re.search(r"[\\/]", toks[0]):
        return False
    prog = toks[0].lower()
    args = toks[1:]
    if prog in _RO_PROGRAMS:
        return not _shadowed(cwd, prog)
    if prog == "python" and args[:2] == ["-m", "pip"]:
        prog, args = "pip", args[2:]
    if prog in _RO_VERSION and len(args) == 1 and args[0] in ("--version", "-V", "-v", "version") and \
            not (prog == "npm" and args[0] == "version") and not (prog in ("yarn", "pnpm") and args[0] == "version"):
        return not _shadowed(cwd, prog)
    if _shadowed(cwd, prog):
        return False
    if prog == "git":
        if not args or args[0].startswith("-"):
            return False                                   # git -c ... can run configured programs
        sub, rest = args[0], args[1:]
        if any(a.startswith(("--output", "--ext-diff", "--exec", "-o")) for a in rest):
            return False
        if sub == "remote":
            return rest in ([], ["-v"], ["show"]) or rest[:1] == ["get-url"]
        if sub == "branch":
            return all(a in ("-a", "-r", "-v", "-vv", "--list", "--show-current", "--all", "--remotes") for a in rest)
        if sub == "tag":
            return all(a in ("-l", "--list") for a in rest)
        if sub == "config":
            return bool(rest) and rest[0] in ("--get", "--list", "-l", "--get-all")
        return sub in _RO_GIT
    if prog in ("pip", "pip3"):
        return bool(args) and args[0] in _RO_PIP
    if prog == "npm":
        return bool(args) and args[0] in _RO_NPM
    if prog in ("chrono",):
        if not args:
            return False
        if args[0] == "audit":
            return not any(a in ("--push", "--out", "--reset-witness", "--rotate-key") for a in args[1:])
        return args[0] in _RO_CHRONO and args[1:2] != ["pin"] and args[1:2] != ["unpin"]
    return False


def is_read_only(cmd, cwd=None):
    """True only for commands that cannot change files: a short list of listing,
    printing and status commands, with no redirection or substitution."""
    if not isinstance(cmd, str) or not cmd.strip() or len(cmd) > 2000:
        return False
    if re.search(r"[<>`]|\$\(|\$\{|%\(|\^", cmd):
        return False
    segments = _split_segments(cmd)
    if not segments or "(" in cmd or ")" in cmd:
        return False
    return all(_ro_segment(_tokens(s), cwd) for s in segments)
