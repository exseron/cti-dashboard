'use strict';
/* CTI Dashboard frontend — vanilla JS, no innerHTML with remote data (XSS-safe). */

// ---------------------------------------------------------------- helpers
const $ = (s, r = document) => r.querySelector(s);

function h(tag, attrs, ...children) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v == null || v === false) continue;
    if (k === 'class') el.className = v;
    else if (k === 'style') Object.assign(el.style, v);
    else if (k === 'dataset') Object.assign(el.dataset, v);
    else if (k.startsWith('on') && typeof v === 'function') el.addEventListener(k.slice(2), v);
    else el.setAttribute(k, v === true ? '' : v);
  }
  for (const c of children.flat(Infinity)) {
    if (c == null || c === false) continue;
    el.append(c instanceof Node ? c : String(c));
  }
  return el;
}

function safeUrl(u) {
  try {
    const x = new URL(u);
    return x.protocol === 'https:' || x.protocol === 'http:' ? x.href : null;
  } catch { return null; }
}

function extLink(url, text, cls) {
  const s = safeUrl(url);
  return s ? h('a', { href: s, target: '_blank', rel: 'noopener noreferrer', class: cls }, text) : h('span', { class: cls }, text);
}

async function api(path, opts = {}) {
  const r = await fetch(path, { credentials: 'same-origin', ...opts });
  if (!r.ok) {
    let msg = `${r.status}`;
    try { msg = (await r.json()).detail || msg; } catch { /* ignore */ }
    throw new Error(msg);
  }
  return r.json();
}

function toast(msg, ms = 3500) {
  const t = $('#toast');
  t.textContent = msg;
  t.hidden = false;
  clearTimeout(toast._t);
  toast._t = setTimeout(() => { t.hidden = true; }, ms);
}

function relTime(ts) {
  if (!ts) return '-';
  const d = (Date.now() / 1000) - ts;
  if (d < 60) return 'az önce';
  if (d < 3600) return `${Math.floor(d / 60)} dk önce`;
  if (d < 86400) return `${Math.floor(d / 3600)} sa önce`;
  return `${Math.floor(d / 86400)} gün önce`;
}
const fmtDate = (ts) => ts ? new Date(ts * 1000).toLocaleString('tr-TR') : '-';
const fmtIsoDate = (s) => s ? new Date(s.endsWith('Z') || s.includes('+') ? s : s + 'Z').toLocaleDateString('tr-TR') : '-';
const debounce = (fn, ms = 200) => { let t; return (...a) => { clearTimeout(t); t = setTimeout(() => fn(...a), ms); }; };
const store = {
  get(k, d) { try { const v = localStorage.getItem(k); return v ? JSON.parse(v) : d; } catch { return d; } },
  set(k, v) { try { localStorage.setItem(k, JSON.stringify(v)); } catch { /* ignore */ } },
};

async function triggerRefresh(what, reload) {
  try {
    await api(`/api/refresh/${what}`, { method: 'POST', headers: { 'X-Requested-With': 'cti-dashboard' } });
    toast('Yenileme başlatıldı; birkaç dakika içinde güncellenecek.');
    setTimeout(reload, 20000);
    setTimeout(reload, 90000);
  } catch (e) { toast(`Yenilenemedi: ${e.message}`); }
}

// ---------------------------------------------------------------- tabs
const loaded = {};
function showTab(name) {
  if (!['news', 'cves', 'attack'].includes(name)) name = 'news';
  document.querySelectorAll('.tab').forEach((b) => b.classList.toggle('active', b.dataset.tab === name));
  document.querySelectorAll('.panel').forEach((p) => { p.hidden = p.id !== `panel-${name}`; });
  if (location.hash !== `#${name}`) history.replaceState(null, '', `#${name}`);
  if (!loaded[name]) {
    loaded[name] = true;
    ({ news: News.load, cves: CVE.load, attack: Attack.init })[name]();
  }
}
document.querySelectorAll('.tab').forEach((b) => b.addEventListener('click', () => showTab(b.dataset.tab)));

// ================================================================ NEWS
const News = {
  items: [], shown: 60, tagsOn: new Set(),

  async load() {
    $('#news-status').textContent = 'Yükleniyor…';
    try {
      const d = await api('/api/news');
      News.items = d.items;
      const sel = $('#news-source');
      if (sel.options.length <= 1) d.sources.forEach((s) => sel.append(h('option', { value: s }, s)));
      const failed = Object.entries(d.feed_status || {}).filter(([, v]) => !v.ok).map(([k]) => k);
      $('#news-status').textContent =
        `${d.items.length} haber · son güncelleme ${relTime(d.last_updated)}` +
        (d.llm_enabled ? ' · AI özet açık' : '') +
        (failed.length ? ` · erişilemeyen: ${failed.join(', ')}` : '');
      if (!d.last_updated) $('#news-status').textContent = 'İlk veri çekiliyor, lütfen 1-2 dk sonra yenileyin…';
      News.render();
    } catch (e) { $('#news-status').textContent = `Hata: ${e.message}`; }
  },

  baseFiltered() {
    const days = +$('#news-range').value;
    const src = $('#news-source').value;
    const min = days ? Date.now() / 1000 - days * 86400 : 0;
    return News.items.filter((i) => i.published >= min && (!src || i.source === src));
  },

  render() {
    const q = $('#news-q').value.trim().toLowerCase();
    const base = News.baseFiltered();
    // tag cloud
    const counts = new Map();
    base.forEach((i) => i.tags.forEach((t) => counts.set(t, (counts.get(t) || 0) + 1)));
    const top = [...counts.entries()].sort((a, b) => b[1] - a[1]).slice(0, 45);
    News.tagsOn.forEach((t) => { if (!top.find(([x]) => x === t)) top.unshift([t, counts.get(t) || 0]); });
    $('#news-tags').replaceChildren(...top.map(([t, n]) =>
      h('span', { class: `tag${News.tagsOn.has(t) ? ' on' : ''}`, onclick: () => News.toggleTag(t) }, t, h('span', { class: 'n' }, n))));

    const list = base.filter((i) => {
      for (const t of News.tagsOn) if (!i.tags.includes(t)) return false;
      if (!q) return true;
      return (`${i.title} ${i.summary} ${i.source} ${i.tags.join(' ')} ${i.cves.join(' ')}`).toLowerCase().includes(q);
    });
    const cards = list.slice(0, News.shown).map(News.card);
    $('#news-list').replaceChildren(...(cards.length ? cards : [h('div', { class: 'empty' }, 'Kriterlere uyan haber yok.')]));
    $('#news-more').hidden = list.length <= News.shown;
  },

  card(i) {
    return h('article', { class: 'card' },
      h('div', { class: 'meta' },
        h('span', { class: 'src' }, i.source),
        h('span', { title: fmtDate(i.published) }, relTime(i.published)),
        i.ai ? h('span', { class: 'ai', title: 'Claude ile özetlendi' }, 'AI') : null),
      h('h3', {}, extLink(i.link, i.title)),
      h('p', { class: 'summary' }, i.summary),
      h('div', { class: 'tags' },
        i.tags.map((t) => h('span', { class: `tag${News.tagsOn.has(t) ? ' on' : ''}`, onclick: () => News.toggleTag(t) }, t)),
        i.cves.map((c) => h('span', { class: 'tag cve', title: "CVE panelinde aç", onclick: () => CVE.focus(c) }, c)),
        i.ttps.map((t) => h('span', { class: 'tag ttp', title: 'Navigator\'da seç', onclick: () => Attack.focus(t) }, t))));
  },

  toggleTag(t) {
    News.tagsOn.has(t) ? News.tagsOn.delete(t) : News.tagsOn.add(t);
    News.shown = 60;
    News.render();
    window.scrollTo({ top: 0 });
  },
};
$('#news-q').addEventListener('input', debounce(() => { News.shown = 60; News.render(); }));
$('#news-source').addEventListener('change', () => { News.shown = 60; News.render(); });
$('#news-range').addEventListener('change', () => { News.shown = 60; News.render(); });
$('#news-more').addEventListener('click', () => { News.shown += 60; News.render(); });
$('#news-refresh').addEventListener('click', () => triggerRefresh('news', News.load));

// ================================================================ CVEs
const SEVS = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'N/A'];
const CVE = {
  items: [], shown: 100, sevOn: new Set(SEVS), open: new Set(), ghResults: {},

  async load() {
    $('#cve-status').textContent = 'Yükleniyor…';
    try {
      const d = await api('/api/cves');
      CVE.items = d.items;
      const errs = Object.keys(d.errors || {});
      $('#cve-status').textContent = d.last_updated
        ? `Son ${d.days} gün · güncelleme ${relTime(d.last_updated)}${errs.length ? ` · hata: ${errs.join(', ')}` : ''}`
        : 'İlk veri çekiliyor (NVD yavaş olabilir), 1-3 dk sonra yenileyin…';
      CVE.render();
    } catch (e) { $('#cve-status').textContent = `Hata: ${e.message}`; }
  },

  filtered() {
    const q = $('#cve-q').value.trim().toLowerCase();
    const poc = $('#cve-poc').checked, kev = $('#cve-kev').checked;
    const sort = $('#cve-sort').value;
    let list = CVE.items.filter((c) => {
      const sev = SEVS.includes(c.severity) ? c.severity : 'N/A';
      if (!CVE.sevOn.has(sev)) return false;
      if (poc && !c.pocs.length) return false;
      if (kev && !c.kev) return false;
      if (q && !(`${c.id} ${c.description} ${c.products.join(' ')} ${c.cwes.join(' ')}`).toLowerCase().includes(q)) return false;
      return true;
    });
    const key = {
      score: (c) => c.score ?? -1, epss: (c) => c.epss ?? -1, pocs: (c) => c.pocs.length,
    }[sort];
    if (key) list = [...list].sort((a, b) => key(b) - key(a));
    return list;
  },

  render() {
    const list = CVE.filtered();
    const all = CVE.items;
    const stat = (n, l) => h('div', { class: 'stat' }, h('b', {}, n), h('span', {}, l));
    $('#cve-stats').replaceChildren(
      stat(all.length, 'toplam CVE'),
      stat(all.filter((c) => c.severity === 'CRITICAL').length, 'kritik'),
      stat(all.filter((c) => c.severity === 'HIGH').length, 'yüksek'),
      stat(all.filter((c) => c.pocs.length).length, 'PoC / exploit'),
      stat(all.filter((c) => c.kev).length, 'CISA KEV'),
      stat(list.length, 'filtrelenmiş'));
    const rows = list.slice(0, CVE.shown).map(CVE.row);
    $('#cve-list').replaceChildren(...(rows.length ? rows : [h('div', { class: 'empty' }, 'Kriterlere uyan CVE yok.')]));
    $('#cve-more').hidden = list.length <= CVE.shown;
  },

  row(c) {
    const sev = SEVS.includes(c.severity) ? c.severity : 'N/A';
    const wrap = h('div', { class: 'cve' });
    const row = h('div', { class: 'cve-row', onclick: () => {
      CVE.open.has(c.id) ? CVE.open.delete(c.id) : CVE.open.add(c.id);
      wrap.replaceWith(CVE.row(c));
    } },
      h('div', {}, h('div', { class: 'cve-id' }, c.id), h('div', { class: 'muted small' }, fmtIsoDate(c.published))),
      h('span', { class: `badge sev-${sev}` }, c.score != null ? `${c.score} ${sev}` : 'N/A'),
      h('span', { title: 'EPSS (30 gün içinde istismar olasılığı)', class: 'small' }, c.epss != null ? `EPSS ${(c.epss * 100).toFixed(1)}%` : 'EPSS -'),
      h('div', { class: 'desc-clamp' }, c.description),
      h('div', { class: 'products', title: c.products.join(', ') }, c.products.join(', ')),
      h('div', { class: 'cve-flags' },
        c.kev ? h('span', { class: 'badge kev', title: 'CISA Known Exploited Vulnerabilities' }, 'KEV') : null,
        c.pocs.length ? h('span', { class: 'badge poc' }, `PoC ${c.pocs.length}`) : null));
    wrap.append(row);
    if (CVE.open.has(c.id)) wrap.append(CVE.detail(c));
    return wrap;
  },

  detail(c) {
    const pocItem = (p) => h('li', {},
      h('span', { class: 'pill' }, p.source), ' ', extLink(p.url, p.title || p.url),
      p.stars != null ? h('span', { class: 'muted' }, `★ ${p.stars}`) : null,
      p.verified ? h('span', { class: 'muted' }, '✔ verified') : null,
      p.description ? h('div', { class: 'muted small' }, p.description) : null);
    const ghBox = h('div', {});
    const renderGh = () => {
      const res = CVE.ghResults[c.id];
      if (!res) return;
      ghBox.replaceChildren(res.length ? h('ul', { class: 'poc-list' }, res.map(pocItem)) : h('div', { class: 'muted' }, 'GitHub\'da sonuç yok.'));
    };
    renderGh();
    const ghBtn = h('button', { class: 'btn ghost', onclick: async (ev) => {
      ev.stopPropagation();
      ghBtn.disabled = true; ghBtn.textContent = 'Aranıyor…';
      try { CVE.ghResults[c.id] = (await api(`/api/cves/${encodeURIComponent(c.id)}/github`)).items; renderGh(); }
      catch (e) { toast(`GitHub araması: ${e.message}`); }
      ghBtn.disabled = false; ghBtn.textContent = 'GitHub\'da PoC ara';
    } }, 'GitHub\'da PoC ara');

    return h('div', { class: 'cve-detail' },
      h('div', {}, c.description),
      h('div', { class: 'kv' },
        h('span', {}, h('b', {}, 'NVD:'), extLink(`https://nvd.nist.gov/vuln/detail/${encodeURIComponent(c.id)}`, c.id)),
        h('span', {}, h('b', {}, 'Durum:'), c.status || '-'),
        h('span', {}, h('b', {}, 'Yayın:'), fmtIsoDate(c.published)),
        h('span', {}, h('b', {}, 'CVSS:'), c.cvss_version ? `v${c.cvss_version} ${c.score}` : '-'),
        c.epss != null ? h('span', {}, h('b', {}, 'EPSS:'), `${(c.epss * 100).toFixed(2)}% (persentil ${(c.epss_pct * 100).toFixed(0)})`) : null,
        c.cwes.length ? h('span', {}, h('b', {}, 'CWE:'), c.cwes.join(', ')) : null),
      c.vector ? h('div', { class: 'mono' }, c.vector) : null,
      c.products.length ? h('div', { class: 'kv' }, h('span', {}, h('b', {}, 'Etkilenen:'), c.products.join(', '))) : null,
      c.kev ? h('div', { class: 'kev-box' },
        h('b', {}, 'CISA KEV: '), c.kev.name || '', ` · eklenme ${c.kev.dateAdded} · son tarih ${c.kev.dueDate}`,
        c.kev.ransomware === 'Known' ? ' · Fidye yazılımı kampanyalarında kullanıldı' : '',
        c.kev.action ? h('div', { class: 'small muted' }, c.kev.action) : null) : null,
      h('h4', {}, `PoC / Exploit (${c.pocs.length})`),
      c.pocs.length ? h('ul', { class: 'poc-list' }, c.pocs.map(pocItem)) : h('div', { class: 'muted' }, 'Bilinen kaynaklarda PoC bulunamadı.'),
      h('div', {}, ghBtn), ghBox,
      h('div', { class: 'small muted' }, '⚠ PoC depoları üçüncü taraf koddur; zararlı içerik barındırabilir — yalnızca izole ortamda inceleyin.'),
      c.refs.length ? [h('h4', {}, 'Referanslar'),
        h('ul', { class: 'ref-list' }, c.refs.slice(0, 20).map((r) => h('li', {}, extLink(r.url, r.url),
          r.tags.length ? h('span', { class: 'muted small' }, `  [${r.tags.join(', ')}]`) : null)))] : null);
  },

  focus(id) {
    $('#cve-q').value = id;
    CVE.open.add(id);
    showTab('cves');
    if (CVE.items.length) {
      CVE.render();
      if (!CVE.items.find((c) => c.id === id)) {
        toast(`${id} güncel CVE penceresinde yok — NVD sayfası açılıyor.`);
        window.open(`https://nvd.nist.gov/vuln/detail/${encodeURIComponent(id)}`, '_blank', 'noopener,noreferrer');
      }
    }
  },
};
$('#cve-sevs').replaceChildren(...SEVS.map((s) => {
  const b = h('button', { class: 'sev-btn on', dataset: { sev: s } }, s);
  b.addEventListener('click', () => {
    CVE.sevOn.has(s) ? CVE.sevOn.delete(s) : CVE.sevOn.add(s);
    b.classList.toggle('on', CVE.sevOn.has(s));
    CVE.shown = 100; CVE.render();
  });
  return b;
}));
$('#cve-q').addEventListener('input', debounce(() => { CVE.shown = 100; CVE.render(); }));
['#cve-poc', '#cve-kev', '#cve-sort'].forEach((s) => $(s).addEventListener('change', () => { CVE.shown = 100; CVE.render(); }));
$('#cve-more').addEventListener('click', () => { CVE.shown += 100; CVE.render(); });
$('#cve-refresh').addEventListener('click', () => triggerRefresh('cves', CVE.load));

// ================================================================ ATT&CK NAVIGATOR
const TID_RE = /^T\d{4}(\.\d{3})?$/;
const HEX_RE = /^#[0-9a-f]{6}([0-9a-f]{2})?$/i;
const DEFAULT_GRADIENT = { colors: ['#ff6666', '#ffe766', '#8ec843'], min: 0, max: 100 };

const Attack = {
  data: null, domain: 'enterprise-attack',
  ann: {}, legend: [], expanded: new Set(), selected: new Set(), gradient: DEFAULT_GRADIENT,
  pendingFocus: [],

  async init() {
    Attack.domain = store.get('cti-att-domain', 'enterprise-attack');
    $('#att-domain').value = Attack.domain;
    await Attack.loadDomain(Attack.domain);
  },

  async loadDomain(domain) {
    $('#att-status').textContent = 'ATT&CK verisi yükleniyor (ilk seferde ~1 dk sürebilir)…';
    $('#att-matrix').replaceChildren();
    try {
      Attack.data = await api(`/api/attack/${domain}`);
    } catch (e) { $('#att-status').textContent = `Hata: ${e.message}`; return; }
    Attack.domain = domain;
    store.set('cti-att-domain', domain);
    const saved = store.get(`cti-att-layer-${domain}`, null);
    Attack.ann = saved?.ann || {};
    Attack.legend = saved?.legend || [];
    Attack.expanded = new Set(saved?.expanded || []);
    Attack.gradient = saved?.gradient || DEFAULT_GRADIENT;
    $('#att-name').value = saved?.name || 'Yeni katman';
    Attack.selected.clear();

    const d = Attack.data;
    $('#att-platform').replaceChildren(h('option', { value: '' }, 'Tüm platformlar'), ...d.platforms.map((p) => h('option', { value: p }, p)));
    const opt = (a, kind) => h('option', { value: `${a.name} (${a.id})` }, `${kind} · ${a.techniques.length} teknik${a.aliases.length ? ' · ' + a.aliases.slice(0, 3).join(', ') : ''}`);
    $('#att-actor-list').replaceChildren(
      ...d.groups.map((a) => opt(a, 'Grup')), ...d.software.map((a) => opt(a, 'Yazılım')), ...d.campaigns.map((a) => opt(a, 'Kampanya')));
    $('#att-status').textContent = `${d.name} ATT&CK v${d.version} · ${Object.keys(d.techniques).length} teknik · ${d.groups.length} grup · ${d.software.length} yazılım`;
    Attack.render();
    if (Attack.pendingFocus.length) { Attack.selectIds(Attack.pendingFocus); Attack.pendingFocus = []; }
  },

  save: debounce(() => store.set(`cti-att-layer-${Attack.domain}`, {
    name: $('#att-name').value, ann: Attack.ann, legend: Attack.legend, expanded: [...Attack.expanded], gradient: Attack.gradient,
  }), 300),

  gradientColor(score) {
    const g = Attack.gradient, cs = g.colors.map(hexToRgb);
    if (cs.length === 1) return g.colors[0];
    const t = Math.min(1, Math.max(0, (score - g.min) / ((g.max - g.min) || 1)));
    const seg = Math.min(cs.length - 2, Math.floor(t * (cs.length - 1)));
    const lt = t * (cs.length - 1) - seg;
    const mix = cs[seg].map((v, i) => Math.round(v + (cs[seg + 1][i] - v) * lt));
    return rgbToHex(mix);
  },

  colorFor(id) {
    const a = Attack.ann[id];
    if (!a) return null;
    if (a.color) return a.color;
    if (a.score != null && a.score !== '') return Attack.gradientColor(+a.score);
    return null;
  },

  isAnnotated(id) { return !!Attack.ann[id]; },

  render() {
    const d = Attack.data;
    if (!d) return;
    const plat = $('#att-platform').value;
    const only = $('#att-only').checked;
    const showAll = $('#att-showsubs').checked;
    const showId = $('#att-showid').checked;
    const q = $('#att-search').value.trim().toLowerCase();
    const T = d.techniques;
    const matches = (t) => q && (t.id.toLowerCase().includes(q) || t.name.toLowerCase().includes(q));
    const platOk = (t) => !plat || t.platforms.includes(plat);
    const subsOf = (t, tac) => (t.subs || []).map((s) => T[s]).filter((s) => s && s.tactics.includes(tac) && platOk(s));

    $('#att-title').textContent = $('#att-name').value || 'ATT&CK Katmanı';
    $('#att-subtitle').textContent = `MITRE ATT&CK® ${d.name} v${d.version}${plat ? ' · ' + plat : ''} · ${new Date().toLocaleDateString('tr-TR')}`;

    const cell = (t, isSub) => {
      const color = Attack.colorFor(t.id);
      const a = Attack.ann[t.id];
      const cls = ['tech-cell'];
      if (a) cls.push('annot');
      if (Attack.selected.has(t.id)) cls.push('selected');
      if (matches(t)) cls.push('match');
      const style = color ? { background: color, color: textColorFor(color) } : {};
      const tip = [`${t.id} ${t.name}`, t.desc, a?.score != null && a.score !== '' ? `Skor: ${a.score}` : '', a?.comment ? `Yorum: ${a.comment}` : '']
        .filter(Boolean).join('\n\n');
      const el = h('div', { class: cls.join(' '), style, title: tip, onclick: (ev) => { Attack.toggleSelect(t.id, ev); } },
        h('div', { class: 'lbl' }, showId ? h('span', { class: 'tid' }, t.id) : null, t.name),
        a?.score != null && a.score !== '' ? h('span', { class: 'score' }, a.score) : null);
      return el;
    };

    const cols = [];
    for (const tac of d.tactics) {
      let techs = Object.values(T).filter((t) => !t.sub && t.tactics.includes(tac.short) && platOk(t));
      techs.sort((a, b) => a.name.localeCompare(b.name));
      const rows = [];
      for (const t of techs) {
        const subs = subsOf(t, tac.short);
        const subAnnot = subs.some((s) => Attack.isAnnotated(s.id));
        const subMatch = subs.some(matches);
        if (only && !Attack.isAnnotated(t.id) && !subAnnot && !Attack.selected.has(t.id)) continue;
        const open = subs.length && (showAll || Attack.expanded.has(t.id) || (q && subMatch) || (only && subAnnot));
        const c = cell(t, false);
        if (subs.length) {
          const tg = h('span', { class: 'toggle', title: `${subs.length} alt teknik`, onclick: (ev) => {
            ev.stopPropagation();
            Attack.expanded.has(t.id) ? Attack.expanded.delete(t.id) : Attack.expanded.add(t.id);
            Attack.save(); Attack.render();
          } }, open ? '▾' : (subAnnot ? '●' : '▸'));
          c.append(tg);
        }
        const box = h('div', { class: 'tech' }, c);
        if (open) {
          const shownSubs = only ? subs.filter((s) => Attack.isAnnotated(s.id) || Attack.selected.has(s.id)) : subs;
          if (shownSubs.length) box.append(h('div', { class: 'subs' }, shownSubs.map((s) => cell(s, true))));
        }
        rows.push(box);
      }
      if (only && !rows.length) continue;
      cols.push(h('div', { class: 'tactic' },
        h('div', { class: 'tactic-head' }, tac.name, h('span', { class: 'cnt' }, `${techs.length} teknik`)), rows));
    }
    $('#att-matrix').replaceChildren(...cols);
    Attack.renderLegend();
    $('#att-selcount').textContent = `${Attack.selected.size} seçili`;
  },

  renderLegend() {
    $('#att-legend').replaceChildren(...Attack.legend.map((l, i) => h('span', { class: 'legend-item' },
      h('span', { class: 'legend-swatch', style: { background: l.color } }), l.label,
      h('span', { class: 'x', title: 'Lejanttan kaldır', onclick: () => { Attack.legend.splice(i, 1); Attack.save(); Attack.renderLegend(); } }, '✕'))));
  },

  toggleSelect(id) {
    Attack.selected.has(id) ? Attack.selected.delete(id) : Attack.selected.add(id);
    Attack.render();
  },

  selectIds(ids) {
    const T = Attack.data.techniques;
    let n = 0; const missing = [];
    for (const raw of ids) {
      const id = raw.trim().toUpperCase();
      if (!id) continue;
      if (T[id]) {
        Attack.selected.add(id); n++;
        if (T[id].sub) Attack.expanded.add(id.split('.')[0]);
      } else missing.push(id);
    }
    Attack.render();
    toast(`${n} teknik seçildi${missing.length ? ` · bulunamadı: ${missing.slice(0, 8).join(', ')}` : ''}`);
  },

  focus(id) {
    showTab('attack');
    if (Attack.data) Attack.selectIds([id]); else Attack.pendingFocus.push(id);
  },

  apply() {
    if (!Attack.selected.size) return toast('Önce matristen teknik seçin.');
    const color = $('#att-color').value;
    const scoreRaw = $('#att-score').value;
    const score = scoreRaw === '' ? null : Math.max(0, Math.min(100, +scoreRaw));
    const comment = $('#att-comment').value.trim();
    // "Renk" unchecked -> no fixed color, so the score gradient colors the cell.
    const useColor = $('#att-usecolor').checked;
    if (!useColor && score == null && !comment) return toast('Renk, skor veya yorumdan en az birini girin.');
    for (const id of Attack.selected) {
      const prev = Attack.ann[id] || {};
      Attack.ann[id] = {
        color: useColor ? color : '',
        score: score ?? prev.score ?? null,
        comment: comment || prev.comment || '',
      };
    }
    const label = $('#att-label').value.trim();
    if (label && useColor) {
      const ex = Attack.legend.find((l) => l.color.toLowerCase() === color.toLowerCase());
      if (ex) ex.label = label; else Attack.legend.push({ label, color });
    }
    Attack.selected.clear();
    Attack.save(); Attack.render();
  },

  removeSelected() {
    for (const id of Attack.selected) delete Attack.ann[id];
    Attack.selected.clear();
    Attack.save(); Attack.render();
  },

  reset() {
    if (!confirm('Bu katmandaki tüm anotasyonlar ve lejant silinsin mi?')) return;
    Attack.ann = {}; Attack.legend = []; Attack.selected.clear(); Attack.expanded.clear();
    Attack.gradient = DEFAULT_GRADIENT;
    Attack.save(); Attack.render();
  },

  async exportPng() {
    if (!Attack.data) return;
    if (typeof html2canvas !== 'function') return toast('html2canvas yüklenemedi.');
    const area = $('#att-export-area');
    const light = $('#att-light').checked;
    area.classList.add('exporting');
    area.classList.toggle('light', light);
    const btn = $('#att-png'); btn.disabled = true; btn.textContent = 'Oluşturuluyor…';
    try {
      const canvas = await html2canvas(area, {
        backgroundColor: light ? '#ffffff' : '#0d1117',
        scale: +$('#att-scale').value,
        width: area.scrollWidth, height: area.scrollHeight,
        windowWidth: area.scrollWidth + 40, windowHeight: area.scrollHeight + 40,
        scrollX: 0, scrollY: -window.scrollY, logging: false,
      });
      const blob = await new Promise((res) => canvas.toBlob(res, 'image/png'));
      if (!blob) throw new Error('PNG çok büyük olabilir; ölçeği düşürün.');
      download(blob, `${slug($('#att-name').value || 'attack-layer')}.png`);
    } catch (e) { toast(`PNG oluşturulamadı: ${e.message}`); }
    finally {
      area.classList.remove('exporting', 'light');
      btn.disabled = false; btn.textContent = '⬇ PNG';
    }
  },

  exportLayer() {
    const d = Attack.data;
    if (!d) return;
    const ids = new Set([...Object.keys(Attack.ann), ...Attack.expanded]);
    const layer = {
      name: $('#att-name').value || 'layer',
      versions: { attack: String(d.version || '').split('.')[0], navigator: '5.1.0', layer: '4.5' },
      domain: d.domain,
      description: 'CTI Dashboard ile oluşturuldu',
      filters: { platforms: $('#att-platform').value ? [$('#att-platform').value] : d.platforms },
      sorting: 0,
      layout: { layout: 'side', aggregateFunction: 'average', showID: $('#att-showid').checked, showName: true, showAggregateScores: false, countUnscored: false, expandedSubtechniques: 'none' },
      hideDisabled: false,
      techniques: [...ids].map((id) => {
        const a = Attack.ann[id] || {};
        const o = { techniqueID: id, color: a.color || '', comment: a.comment || '', enabled: true, metadata: [], links: [], showSubtechniques: Attack.expanded.has(id) };
        if (a.score != null && a.score !== '') o.score = +a.score;
        return o;
      }),
      gradient: { colors: Attack.gradient.colors.map((c) => c.length === 7 ? c + 'ff' : c), minValue: Attack.gradient.min, maxValue: Attack.gradient.max },
      legendItems: Attack.legend.map((l) => ({ label: l.label, color: l.color })),
      metadata: [], links: [], showTacticRowBackground: false, tacticRowBackground: '#dddddd',
      selectTechniquesAcrossTactics: true, selectSubtechniquesWithParent: false, selectVisibleTechniques: false,
    };
    download(new Blob([JSON.stringify(layer, null, 2)], { type: 'application/json' }), `${slug(layer.name)}.json`);
  },

  async importLayer(file) {
    let layer;
    try { layer = JSON.parse(await file.text()); } catch { return toast('Geçersiz JSON dosyası.'); }
    if (!layer || !Array.isArray(layer.techniques)) return toast('Geçerli bir ATT&CK Navigator layer dosyası değil.');
    const domMap = { 'mitre-enterprise': 'enterprise-attack', 'mitre-mobile': 'mobile-attack' };
    const dom = domMap[layer.domain] || layer.domain;
    if (['enterprise-attack', 'mobile-attack', 'ics-attack'].includes(dom) && dom !== Attack.domain) {
      $('#att-domain').value = dom;
      await Attack.loadDomain(dom);
    }
    const ann = {}, expanded = new Set();
    for (const t of layer.techniques) {
      const id = String(t.techniqueID || '').toUpperCase();
      if (!TID_RE.test(id)) continue;
      const color = HEX_RE.test(t.color || '') ? t.color.slice(0, 7) : '';
      const score = Number.isFinite(t.score) ? t.score : null;
      const comment = typeof t.comment === 'string' ? t.comment.slice(0, 300) : '';
      if (t.showSubtechniques) expanded.add(id);
      if (t.enabled === false) continue;
      if (color || score != null || comment) ann[id] = { color, score, comment };
    }
    Attack.ann = ann;
    Attack.expanded = expanded;
    Attack.legend = (Array.isArray(layer.legendItems) ? layer.legendItems : [])
      .filter((l) => l && typeof l.label === 'string' && HEX_RE.test(l.color || ''))
      .map((l) => ({ label: l.label.slice(0, 60), color: l.color.slice(0, 7) }));
    const g = layer.gradient;
    Attack.gradient = g && Array.isArray(g.colors) && g.colors.every((c) => HEX_RE.test(c))
      ? { colors: g.colors.map((c) => c.slice(0, 7)), min: +g.minValue || 0, max: Number.isFinite(+g.maxValue) ? +g.maxValue : 100 }
      : DEFAULT_GRADIENT;
    if (typeof layer.name === 'string') $('#att-name').value = layer.name.slice(0, 120);
    Attack.selected.clear();
    Attack.save(); Attack.render();
    toast(`${Object.keys(ann).length} anotasyon içe aktarıldı.`);
  },
};

function hexToRgb(hex) { const n = parseInt(hex.slice(1, 7), 16); return [(n >> 16) & 255, (n >> 8) & 255, n & 255]; }
function rgbToHex(rgb) { return '#' + rgb.map((v) => v.toString(16).padStart(2, '0')).join(''); }
function textColorFor(hex) {
  const [r, g, b] = hexToRgb(hex);
  return (0.299 * r + 0.587 * g + 0.114 * b) > 150 ? '#111111' : '#ffffff';
}
function slug(s) { return s.toLowerCase().replace(/[^a-z0-9ğüşıöç_-]+/gi, '-').replace(/^-+|-+$/g, '').slice(0, 60) || 'layer'; }
function download(blob, name) {
  const url = URL.createObjectURL(blob);
  const a = h('a', { href: url, download: name });
  document.body.append(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 5000);
}

$('#att-domain').addEventListener('change', (e) => Attack.loadDomain(e.target.value));
$('#att-name').addEventListener('input', debounce(() => { Attack.save(); $('#att-title').textContent = $('#att-name').value; }));
['#att-platform', '#att-only', '#att-showsubs', '#att-showid'].forEach((s) => $(s).addEventListener('change', () => Attack.render()));
$('#att-search').addEventListener('input', debounce(() => Attack.render(), 250));
$('#att-select-matches').addEventListener('click', () => {
  const q = $('#att-search').value.trim().toLowerCase();
  if (!q || !Attack.data) return toast('Önce arama yapın.');
  const plat = $('#att-platform').value;
  const ids = Object.values(Attack.data.techniques)
    .filter((t) => (!plat || t.platforms.includes(plat)) && (t.id.toLowerCase().includes(q) || t.name.toLowerCase().includes(q)))
    .map((t) => t.id);
  Attack.selectIds(ids);
});
$('#att-add-ids').addEventListener('click', () => {
  if (!Attack.data) return;
  Attack.selectIds($('#att-ids').value.split(/[\s,;]+/));
  $('#att-ids').value = '';
});
$('#att-add-actor').addEventListener('click', () => {
  const d = Attack.data;
  if (!d) return;
  const v = $('#att-actor').value.trim();
  const idm = v.match(/\(([^()]+)\)\s*$/);
  const all = [...d.groups, ...d.software, ...d.campaigns];
  const a = (idm && all.find((x) => x.id === idm[1])) ||
    all.find((x) => x.name.toLowerCase() === v.toLowerCase() || x.aliases.some((al) => al.toLowerCase() === v.toLowerCase()));
  if (!a) return toast('Grup/yazılım bulunamadı — listeden seçin.');
  Attack.selectIds(a.techniques);
  if (!$('#att-label').value.trim()) $('#att-label').value = a.name;
});
$('#att-clear-sel').addEventListener('click', () => { Attack.selected.clear(); Attack.render(); });
$('#att-apply').addEventListener('click', () => Attack.apply());
$('#att-remove').addEventListener('click', () => Attack.removeSelected());
$('#att-reset').addEventListener('click', () => Attack.reset());
$('#att-png').addEventListener('click', () => Attack.exportPng());
$('#att-export').addEventListener('click', () => Attack.exportLayer());
$('#att-import').addEventListener('change', (e) => { const f = e.target.files[0]; if (f) Attack.importLayer(f); e.target.value = ''; });

// ---------------------------------------------------------------- boot
window.addEventListener('hashchange', () => showTab(location.hash.slice(1)));
showTab(location.hash.slice(1) || 'news');
setInterval(() => {
  if (document.hidden) return;
  if (loaded.news) News.load();
  if (loaded.cves) CVE.load();
}, 5 * 60 * 1000);
