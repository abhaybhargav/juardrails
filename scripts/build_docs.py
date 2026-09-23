#!/usr/bin/env python3
"""Build the dependency-free GitHub Pages documentation from HTML fragments."""
from html import escape
from html.parser import HTMLParser
from pathlib import Path
import json
import re

ROOT = Path(__file__).resolve().parents[1]
DOCS = ROOT / "docs"
SOURCE = DOCS / "source"
PAGES = [
    ("index", "Overview", "Start here", "A practical guardrail service for AI workflows.", "home"),
    ("start", "Get started", "Essentials", "Bootstrap Juardrails and make your first decision.", "rocket"),
    ("policies", "Policies and decisions", "Essentials", "Author YAML policies and understand evaluation results.", "layers"),
    ("cli", "CLI guide", "Build", "Use a local service account to work with policies and administration.", "terminal"),
    ("access", "Access control", "Build", "Namespaces, service accounts, grants, tokens, and admin operations.", "lock"),
    ("api", "REST API", "Build", "Endpoints, versioning, authentication, and response handling.", "braces"),
    ("claude-code", "Claude Code pack", "Integrations", "Screen tool calls with a policy, hook, and agent skills.", "spark"),
    ("operations", "Operate securely", "Reference", "Providers, deployment, audit, migration, and limits.", "shield"),
]

class Text(HTMLParser):
    def __init__(self):
        super().__init__(); self.parts = []
    def handle_data(self, data):
        self.parts.append(data)


def nav(active):
    groups = []
    for slug, title, group, summary, icon in PAGES:
        if not groups or groups[-1][0] != group:
            groups.append((group, []))
        groups[-1][1].append((slug, title, icon))
    return "\n".join(
        f'<div class="nav-group"><div class="nav-label">{escape(group)}</div>' +
        "".join(f'<a class="nav-link{" active" if slug == active else ""}" href="{slug}.html" {"aria-current=page" if slug == active else ""}><span class="nav-dot"></span>{escape(title)}</a>' for slug, title, icon in items) +
        '</div>' for group, items in groups
    )


def toc(fragment):
    entries = re.findall(r'<h([23]) id="([^"]+)">(.+?)</h[23]>', fragment)
    return "\n".join(f'<a class="toc-link toc-{level}" href="#{anchor}">{re.sub("<[^>]+>", "", label)}</a>' for level, anchor, label in entries)


def render(slug, title, group, summary, icon, fragment, prev_page, next_page):
    home = slug == "index"
    title_tag = "Juardrails — Guardrails for AI workflows" if home else f"{title} · Juardrails Docs"
    crumbs = "Overview" if home else f'<a href="index.html">Docs</a><span>/</span>{escape(title)}'
    pager = '<nav class="page-pager" aria-label="Page navigation">'
    for page, label in [(prev_page, "Previous"), (next_page, "Next")]:
        if page:
            pager += f'<a href="{page[0]}.html"><small>{label}</small><strong>{escape(page[1])}</strong></a>'
    pager += '</nav>'
    return f'''<!doctype html>
<html lang="en" data-theme="light">
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="description" content="{escape(summary)}">
<meta name="theme-color" content="#f8f7f3">
<title>{escape(title_tag)}</title>
<link rel="icon" type="image/svg+xml" href="assets/favicon.svg">
<link rel="stylesheet" href="assets/site.css">
</head>
<body>
<a class="skip-link" href="#main">Skip to content</a>
<div class="site-shell">
<aside class="sidebar" id="sidebar" aria-label="Documentation navigation">
  <a class="brand" href="index.html" aria-label="Juardrails documentation home"><span class="brand-mark"><span></span></span><span>juardrails<small>Documentation</small></span></a>
  <nav class="side-nav">{nav(slug)}</nav>
  <div class="sidebar-footer"><span class="status-light"></span><span>Open source · Go 1.26+</span><a href="https://github.com/abhaybhargav/juardrails" target="_blank" rel="noopener">View on GitHub ↗</a></div>
</aside>
<div class="page-frame">
<header class="topbar"><button class="menu-button icon-button" id="menu-button" aria-label="Open navigation" aria-controls="sidebar" aria-expanded="false">☰</button><div class="breadcrumb">{crumbs}</div><div class="top-actions"><button class="search-trigger" id="search-trigger" type="button"><span>⌕</span> Search docs <kbd>⌘ K</kbd></button><button class="theme-button icon-button" id="theme-button" type="button" aria-label="Toggle color theme">◐</button><a class="github-button" href="https://github.com/abhaybhargav/juardrails" target="_blank" rel="noopener">GitHub ↗</a></div></header>
<div class="content-layout"><main id="main" class="content {'home-content' if home else ''}"><div class="mobile-eyebrow">Juardrails documentation</div>{fragment}{pager}<footer class="footer"><span>Juardrails · Guardrails that stay in your control.</span><a href="https://github.com/abhaybhargav/juardrails/issues" target="_blank" rel="noopener">Suggest an improvement ↗</a></footer></main>{'' if home else f'<aside class="toc" aria-label="On this page"><div class="toc-title">On this page</div>{toc(fragment)}</aside>'}</div>
</div></div>
<div class="scrim" id="scrim" hidden></div>
<dialog class="search-dialog" id="search-dialog" aria-label="Search documentation"><div class="search-head"><span>⌕</span><input id="search-input" type="search" placeholder="Search documentation..." autocomplete="off" aria-label="Search documentation"><button id="search-close" type="button" aria-label="Close search">Esc</button></div><div id="search-results" class="search-results"></div><div class="search-foot">Search page titles and content · Enter to open</div></dialog>
<script src="assets/site.js" defer></script>
</body></html>'''


def main():
    search = []
    for i, page in enumerate(PAGES):
        slug, title, group, summary, icon = page
        fragment = (SOURCE / f"{slug}.html").read_text()
        previous = PAGES[i - 1] if i else None
        following = PAGES[i + 1] if i + 1 < len(PAGES) else None
        output = render(slug, title, group, summary, icon, fragment, previous, following)
        (DOCS / f"{slug}.html").write_text(output)
        parser = Text(); parser.feed(fragment)
        search.append({"title": title, "group": group, "summary": summary, "url": f"{slug}.html", "text": " ".join(parser.parts)[:6000]})
    (DOCS / "assets" / "search-index.json").write_text(json.dumps(search, ensure_ascii=False, separators=(",", ":")))
    print(f"Built {len(PAGES)} documentation pages")

if __name__ == "__main__": main()
