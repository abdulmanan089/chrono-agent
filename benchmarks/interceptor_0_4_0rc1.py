"""Advisory pattern detector. It cannot inspect or sandbox program behavior."""
import re

RULES = [
    (r"\brm\b[^;&|\n]*(?:--recursive|-[a-z]*r)", 98, "Recursive delete"),
    (r"\brm\b[^;&|\n]*(?:--force|-[a-z]*f)", 85, "Forced delete"),
    (r"\bdel\s+/[sq]|\b(?:rmdir|rd)\s+/s|\bRemove-Item\b[^;\n]*-Recurse", 96, "Recursive delete (Windows)"),
    (r"\bformat\s+[a-z]:|\bmkfs\b|\bdd\s+if=", 99, "Disk format / overwrite"),
    (r"\bdrop\s+(?:table|database|schema)\b", 95, "Destroys database objects"),
    (r"\btruncate\s+(?:table\s+)?[\w\[\"`]", 90, "Wipes table data"),
    (r"\bdelete\s+from\s+[^;\n]+", 88, "DELETE without WHERE"),
    (r"\bgit\s+push\b[^;\n]*(?:--force(?:-with-lease)?\b|-f\b)", 85, "Force push rewrites remote history"),
    (r"\bgit\s+reset\s+--hard", 80, "Discards uncommitted work"),
    (r"\bgit\s+clean\b[^;\n]*-[a-z]*f", 78, "Deletes untracked files"),
    (r"\bchmod\b[^;\n]*(?:-R|--recursive)[^;\n]*777", 70, "World-writable permissions"),
    (r"\b(?:curl|wget)\b[^|]*\|\s*(?:sudo\s+)?(?:bash|sh|zsh|python\w*|powershell|pwsh)\b", 75, "Pipes remote code to interpreter"),
    (r">\s*/dev/sd|>\s*\S+\.(?:db|sqlite)\b", 72, "Overwrites device / database file"),
    (r"\bsudo\b", 40, "Elevated privileges"),
    (r"\bpip\s+uninstall|\bnpm\s+uninstall", 30, "Removes dependencies"),
]


def assess(cmd):
    hits = []
    for pat, score, why in RULES:
        for match in re.finditer(pat, cmd, re.I):
            if why == "DELETE without WHERE" and re.search(r"\bwhere\b", match.group(), re.I):
                continue
            hits.append((score, why)); break
    score = max([s for s, _ in hits], default=5)
    return {"score": score, "level": "CRITICAL" if score >= 90 else "HIGH" if score >= 70 else "MEDIUM" if score >= 30 else "LOW",
            "reasons": [w for _, w in hits] or ["No dangerous pattern detected; program behavior is not inspected"],
            "blocked": score >= 70}
