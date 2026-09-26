#!/usr/bin/env python3
"""Build the dependency-free GitHub Pages documentation from HTML fragments."""
from html import escape
from html.parser import HTMLParser
from pathlib import Path
from hashlib import sha256
import json
import re

ROOT = Path(__file__).resolve().parents[1]
DOCS = ROOT / "docs"
SOURCE = DOCS / "source"
BRAND = ROOT / "internal" / "server" / "web" / "static" / "brand.svg"
PAGES = [
    ("index", "Overview", "Start here", "Fast, flexible AI guardrails powered by Jev decisions.", "home"),
    ("why-jev", "Why Jev", "Start here", "Why typed Jev decisions make practical guardrails fast, flexible, and cost efficient.", "spark"),
    ("install", "Install", "Essentials", "Install one Juardrails executable for macOS, Linux, or Windows.", "download"),
    ("start", "Get started", "Essentials", "Bootstrap Juardrails and make your first decision.", "rocket"),
    ("web-ui", "Web UI walkthrough", "Essentials", "Create, test, inspect, and administer guardrails in the browser.", "monitor"),
    ("policies", "Policies and decisions", "Essentials", "Author YAML policies and understand evaluation results.", "layers"),
    ("cli", "CLI guide", "Build", "Use a local service account to work with policies and administration.", "terminal"),
    ("access", "Access control", "Build", "Namespaces, service accounts, grants, tokens, and admin operations.", "lock"),
    ("api", "REST API", "Build", "Endpoints, versioning, authentication, and response handling.", "braces"),
    ("claude-code", "Claude Code pack", "Integrations", "Screen tool calls with a policy, hook, and agent skills.", "spark"),
    ("agent-skills", "Generate agent skills", "Integrations", "Turn an active policy into an installable skill for an authorized agent.", "spark"),
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


def render(slug, title, group, summary, icon, fragment, prev_page, next_page, css_version, js_version, brand_version):
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
<link rel="icon" type="image/svg+xml" href="assets/favicon.svg?v={brand_version}">
<link rel="stylesheet" href="assets/site.css?v={css_version}">
</head>
<body>
<a class="skip-link" href="#main">Skip to content</a>
<div class="site-shell">
<aside class="sidebar" id="sidebar" aria-label="Documentation navigation">
  <a class="brand" href="index.html" aria-label="Juardrails documentation home"><img class="brand-mark" src="assets/favicon.svg?v={brand_version}" width="34" height="34" alt=""><span>juardrails<small>Documentation</small></span></a>
  <nav class="side-nav">{nav(slug)}</nav>
  <div class="sidebar-footer"><span class="status-light"></span><span>Open source · Go 1.26+</span><a href="https://github.com/abhaybhargav/juardrails" target="_blank" rel="noopener">View on GitHub ↗</a></div>
</aside>
<div class="page-frame">
<header class="topbar"><button class="menu-button icon-button" id="menu-button" aria-label="Open navigation" aria-controls="sidebar" aria-expanded="false">☰</button><div class="breadcrumb">{crumbs}</div><div class="top-actions"><button class="search-trigger" id="search-trigger" type="button"><span>⌕</span> Search docs <kbd>⌘ K</kbd></button><button class="theme-button icon-button" id="theme-button" type="button" aria-label="Toggle color theme">◐</button><a class="github-button" href="https://github.com/abhaybhargav/juardrails" target="_blank" rel="noopener">GitHub ↗</a></div></header>
<div class="content-layout"><main id="main" class="content {'home-content' if home else ''}"><div class="mobile-eyebrow">Juardrails documentation</div>{fragment}{pager}<footer class="footer"><span>Juardrails · Guardrails that stay in your control.</span><a href="https://github.com/abhaybhargav/juardrails/issues" target="_blank" rel="noopener">Suggest an improvement ↗</a></footer></main>{'' if home else f'<aside class="toc" aria-label="On this page"><div class="toc-title">On this page</div>{toc(fragment)}</aside>'}</div>
</div></div>
<div class="scrim" id="scrim" hidden></div>
<dialog class="search-dialog" id="search-dialog" aria-label="Search documentation"><div class="search-head"><span>⌕</span><input id="search-input" type="search" placeholder="Search documentation..." autocomplete="off" aria-label="Search documentation"><button id="search-close" type="button" aria-label="Close search">Esc</button></div><div id="search-results" class="search-results"></div><div class="search-foot">Search page titles and content · Enter to open</div></dialog>
<script src="assets/site.js?v={js_version}" defer></script>
</body></html>'''


def main():
    search = []
    brand = BRAND.read_bytes()
    (DOCS / "assets" / "favicon.svg").write_bytes(brand)
    brand_version = sha256(brand).hexdigest()[:12]
    screenshot_versions = {
        path.name: sha256(path.read_bytes()).hexdigest()[:12]
        for path in (DOCS / "assets" / "screenshots").glob("*.png")
    }
    css_version = sha256((DOCS / "assets" / "site.css").read_bytes()).hexdigest()[:12]
    js_version = sha256((DOCS / "assets" / "site.js").read_bytes()).hexdigest()[:12]
    for i, page in enumerate(PAGES):
        slug, title, group, summary, icon = page
        fragment = (SOURCE / f"{slug}.html").read_text()
        fragment = re.sub(
            r"assets/screenshots/([a-z0-9-]+\.png)",
            lambda match: f"{match.group(0)}?v={screenshot_versions[match.group(1)]}",
            fragment,
        )
        previous = PAGES[i - 1] if i else None
        following = PAGES[i + 1] if i + 1 < len(PAGES) else None
        output = render(slug, title, group, summary, icon, fragment, previous, following, css_version, js_version, brand_version)
        (DOCS / f"{slug}.html").write_text(output)
        parser = Text(); parser.feed(fragment)
        search.append({"title": title, "group": group, "summary": summary, "url": f"{slug}.html", "text": " ".join(parser.parts)[:6000]})
    (DOCS / "assets" / "search-index.json").write_text(json.dumps(search, ensure_ascii=False, separators=(",", ":")))
    print(f"Built {len(PAGES)} documentation pages")

if __name__ == "__main__": main()
