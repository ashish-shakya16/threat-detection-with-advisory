"""Consistency checks for main.tex / references.bib (no LaTeX needed).

- every \\cite key exists in references.bib, and every bib entry is cited
- every \\label{fig:..}/\\label{tab:..} is referenced with \\ref
- figure files exist
- rough word count of the body text
"""

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
tex = (ROOT / "main.tex").read_text(encoding="utf-8")
bib = (ROOT / "references.bib").read_text(encoding="utf-8")

cited = {k.strip() for group in re.findall(r"\\cite\{([^}]*)\}", tex) for k in group.split(",")}
entries = set(re.findall(r"^@\w+\{([^,]+),", bib, flags=re.M))
print(f"cited keys: {len(cited)}, bib entries: {len(entries)}")
print("cited but missing from bib:", sorted(cited - entries) or "none")
print("in bib but never cited:", sorted(entries - cited) or "none")

labels = set(re.findall(r"\\label\{((?:fig|tab|eq):[^}]*)\}", tex))
refs = set(re.findall(r"\\(?:ref|eqref)\{([^}]*)\}", tex))
print("labels never referenced:", sorted(labels - refs) or "none")
print("refs without label:", sorted(refs - labels) or "none")

for path in re.findall(r"\\includegraphics(?:\[[^]]*\])?\{([^}]*)\}", tex):
    print(("ok      " if (ROOT / path).exists() else "MISSING ") + path)

body = tex.split(r"\begin{document}")[1]
body = re.sub(r"\\begin\{(table\*?|tikzpicture)\}.*?\\end\{\1\}", " ", body, flags=re.S)
body = re.sub(r"\\[a-zA-Z]+\*?(\[[^]]*\])?(\{[^}]*\})?", " ", body)
print("approx. body words (excluding tables/diagrams):", len(re.findall(r"[A-Za-z]{2,}", body)))
