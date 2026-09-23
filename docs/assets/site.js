(() => {
  const root = document.documentElement;
  const stored = localStorage.getItem('juardrails-docs-theme');
  if (stored === 'dark' || (!stored && matchMedia('(prefers-color-scheme: dark)').matches)) root.dataset.theme = 'dark';
  document.getElementById('theme-button')?.addEventListener('click', () => {
    root.dataset.theme = root.dataset.theme === 'dark' ? 'light' : 'dark';
    localStorage.setItem('juardrails-docs-theme', root.dataset.theme);
  });
  const sidebar = document.getElementById('sidebar');
  const scrim = document.getElementById('scrim');
  const menu = document.getElementById('menu-button');
  function closeMenu() { sidebar?.classList.remove('open'); scrim.hidden = true; menu?.setAttribute('aria-expanded', 'false'); }
  menu?.addEventListener('click', () => { const open = sidebar.classList.toggle('open'); scrim.hidden = !open; menu.setAttribute('aria-expanded', String(open)); });
  scrim?.addEventListener('click', closeMenu);
  sidebar?.querySelectorAll('a').forEach(a => a.addEventListener('click', closeMenu));
  document.querySelectorAll('pre').forEach(pre => {
    const button = document.createElement('button'); button.className = 'copy-button'; button.textContent = 'Copy'; button.type = 'button';
    button.addEventListener('click', async () => { try { await navigator.clipboard.writeText(pre.querySelector('code')?.textContent || pre.textContent); button.textContent = 'Copied'; setTimeout(() => button.textContent = 'Copy', 1500); } catch { button.textContent = 'Failed'; } });
    pre.append(button);
  });
  const dialog = document.getElementById('search-dialog');
  const input = document.getElementById('search-input');
  const results = document.getElementById('search-results');
  let index = [], filtered = [], selected = 0;
  async function openSearch() {
    if (!index.length) { try { index = await (await fetch('assets/search-index.json')).json(); } catch { index = []; } }
    dialog.showModal(); input.value = ''; update(); input.focus();
  }
  function update() {
    const q = input.value.trim().toLowerCase();
    const terms = q.split(/\s+/).filter(Boolean);
    filtered = index.map(p => {
      const title = p.title.toLowerCase();
      const summary = p.summary.toLowerCase();
      const body = p.text.toLowerCase();
      const matches = terms.every(term => title.includes(term) || summary.includes(term) || body.includes(term));
      const score = terms.reduce((total, term) => total + (title.includes(term) ? 4 : 0) + (summary.includes(term) ? 2 : 0) + (body.includes(term) ? 1 : 0), 0);
      return { ...p, score: matches ? score : 0 };
    }).filter(p => !q || p.score).sort((a,b) => b.score-a.score).slice(0,8);
    selected = 0;
    results.replaceChildren();
    if (!filtered.length) { const empty=document.createElement('div'); empty.className='search-empty'; empty.textContent='No matching pages'; results.append(empty); return; }
    filtered.forEach((p,i) => { const a=document.createElement('a'); a.className='search-result'+(i===0?' selected':''); a.href=p.url; const group=document.createElement('small'); group.textContent=p.group; const title=document.createElement('strong'); title.textContent=p.title; const summary=document.createElement('span'); summary.textContent=p.summary; a.append(group,title,summary); results.append(a); });
  }
  document.getElementById('search-trigger')?.addEventListener('click', openSearch);
  document.getElementById('search-close')?.addEventListener('click', () => dialog.close());
  input?.addEventListener('input', update);
  input?.addEventListener('keydown', e => { if (e.key === 'ArrowDown' || e.key === 'ArrowUp') { e.preventDefault(); const nodes=[...results.querySelectorAll('.search-result')]; if (!nodes.length) return; nodes[selected]?.classList.remove('selected'); selected=(selected+(e.key==='ArrowDown'?1:-1)+nodes.length)%nodes.length; nodes[selected].classList.add('selected'); nodes[selected].scrollIntoView({block:'nearest'}); } else if (e.key === 'Enter' && filtered[selected]) location.href=filtered[selected].url; });
  document.addEventListener('keydown', e => { if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') { e.preventDefault(); if (!dialog.open) openSearch(); else dialog.close(); } if (e.key === 'Escape') closeMenu(); });
})();
