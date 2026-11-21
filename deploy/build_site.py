#!/usr/bin/env python3
"""合并「第4期AI沙龙」海报与「AI作品」门户为单页双 Tab 站点。"""
import re
import pathlib

ROOT = pathlib.Path(__file__).resolve().parent
POSTER = pathlib.Path("/Users/zs/WorkBuddy/2026-10-30-19-56-59/training-prep-poster.html")
PORTAL = ROOT / "portal-base.html"
OUT = ROOT / "site" / "index.html"

poster_src = POSTER.read_text(encoding="utf-8")
portal_src = PORTAL.read_text(encoding="utf-8")


# ---------- 1. 取海报 style 与 body 内容 ----------
def extract(src, tag_open, tag_close):
    i = src.index(tag_open) + len(tag_open)
    j = src.index(tag_close, i)
    return src[i:j]


poster_css = extract(poster_src, "<style>", "</style>")
poster_css = re.sub(r"/\*.*?\*/", "", poster_css, flags=re.S)
poster_body = extract(poster_src, "<body>", "</body>")

portal_head_css = extract(portal_src, "<style>", "</style>")


# ---------- 2. CSS 作用域化 ----------
def split_rules(css):
    """按顶层规则切分，返回 [(selector_or_atrule, block_content_or_None)]。"""
    items, buf, depth = [], [], 0
    i = 0
    while i < len(css):
        ch = css[i]
        buf.append(ch)
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                text = "".join(buf).strip()
                sel, _, body = text.partition("{")
                items.append((sel.strip(), body.rstrip("}")))
                buf = []
        i += 1
    if "".join(buf).strip():
        items.append(("".join(buf).strip(), None))
    return items


def scope_selector(sel, scope):
    parts = []
    for s in sel.split(","):
        s = s.strip()
        if not s:
            continue
        if s == ":root":
            parts.append(scope)
        elif s == "body":
            parts.append(f"{scope} .poster-stage")
        elif s == "*":
            parts.append(f"{scope} *")
        elif s.startswith("body "):
            parts.append(f"{scope} .poster-stage{s[4:]}")
        else:
            parts.append(f"{scope} {s}")
    return ", ".join(parts)


def scope_css(css, scope, drop_print=True):
    out = []
    for sel, body in split_rules(css):
        if sel.startswith("@media"):
            if drop_print and "print" in sel:
                continue
            out.append(f"{sel}{{{scope_css(body, scope, drop_print)}}}")
        elif sel.startswith("@"):
            out.append(f"{sel}{{{body}}}")
        else:
            out.append(f"{scope_selector(sel, scope)}{{{body}}}")
    return "\n".join(out)


scoped = scope_css(poster_css, "#tab-salon")

TABS_CSS = """
/* ---- 双 Tab 站点布局 ---- */
body { background: #f5f6fa; }
.topbar {
  position: sticky; top: 0; z-index: 60;
  display: flex; align-items: center; gap: 16px; flex-wrap: wrap;
  padding: 12px 20px; background: rgba(255,255,255,.94);
  backdrop-filter: saturate(180%) blur(10px);
  border-bottom: 1px solid #e8e8f0;
}
.topbar .brand { font-size: 16px; font-weight: 600; letter-spacing: .5px; color: #3C3489; }
.tabs { display: flex; gap: 8px; margin-left: 10px; }
.tab {
  font: inherit; font-size: 14px; font-weight: 500; cursor: pointer;
  width: 144px; padding: 7px 12px; text-align: center; white-space: nowrap;
  border-radius: 999px; border: 1px solid #e0defa;
  background: #F1F0FE; border-color: #DCDAF7; color: #4A41AE;
}
.tab:hover { background: #E7E5FD; }
.tab.active { background: linear-gradient(135deg,#534AB7,#7F77DD); color: #fff; border-color: transparent; }
.raw-link { margin-left: auto; font-size: 13px; font-weight: 500; color: #4A41AE; text-decoration: none;
  padding: 6px 12px; border: 1px dashed #c9c4f2; border-radius: 999px; background: #FBFAFF; }
.raw-link:hover { background: #F1F0FE; border-color: #a9a2ea; }
.raw-link:hover { color: #534AB7; }
.panel { display: none; }
.panel.active { display: block; }
.card.featured {
  grid-column: 1 / -1;
  border-color: #b9b4f0;
  background: linear-gradient(135deg,#FBFAFF 0%, #F3F1FF 100%);
  box-shadow: 0 10px 28px rgba(83,74,183,.10);
  display: grid; grid-template-columns: auto 1fr; gap: 0 22px; align-items: start;
}
.card.featured .icon { grid-row: 1 / span 4; font-size: 44px; margin: 4px 0 0; }
.card.featured h3 { display: flex; align-items: center; gap: 10px; font-size: 20px; }
.card.featured h3 .new-badge {
  font-size: 11px; font-weight: 700; letter-spacing: .5px; color: #fff;
  padding: 2px 9px; border-radius: 999px; background: linear-gradient(135deg,#534AB7,#7F77DD);
}
.card.featured .btn { max-width: 220px; }
@media (max-width: 560px) {
  .card.featured { grid-template-columns: 1fr; }
  .card.featured .icon { grid-row: auto; }
  .card.featured .btn { max-width: none; }
}
@media (max-width: 640px) {
  .topbar { padding: 10px 14px; }
  .tabs { width: 100%; margin-left: 0; }
  .tab { flex: 1; text-align: center; }
}
"""

# ---------- 3. 取门户 hero / 卡片区 ----------
works_cards = extract(portal_src, '<div class="container">', "</div>\n\n<footer>").strip()
works_cards = works_cards.replace("已部署应用", "游戏合集")

FEATURED_CARD = """    <div class="card featured">
      <div class="icon">🎨</div>
      <h3>第四季 AI 沙龙 <span class="new-badge">最新</span></h3>
      <div class="desc">小学生用 AI 制作《植物大战僵尸》小游戏：课前准备清单、180 分钟六环节教学过程、AI 作品集与往期活动留影。</div>
      <div class="tags">
        <span class="tag">线下沙龙</span>
        <span class="tag green">180 分钟</span>
        <span class="tag amber">6 个环节</span>
      </div>
      <div class="meta">
        <div><span>访问路径</span><span>/training-prep-poster/</span></div>
        <div><span>面向</span><span>小学生（含家长参与）</span></div>
      </div>
      <a class="btn" href="/training-prep-poster/" target="_blank" rel="noopener">打开海报页 ↗</a>
    </div>

"""
SHOW_FEATURED_CARD = False  # 首页卡片入口已去掉，改用顶栏「海报页 ↗」
if SHOW_FEATURED_CARD:
    works_cards = works_cards.replace('<div class="grid">', '<div class="grid">\n' + FEATURED_CARD, 1)

# ---------- 3.1 学员主页 ----------
STUDENTS = [
    ("赵同学", "zhaoyihe", "👧", "AI 沙龙学员，个人主页用于陈列自己的游戏作品。"),
]


def student_card(name, pinyin, icon, desc):
    return f"""    <div class="card">
      <div class="icon">{icon}</div>
      <h3>{name} 的游戏小屋</h3>
      <div class="desc">{desc}</div>
      <div class="tags">
        <span class="tag">学员主页</span>
        <span class="tag amber">作品待上架</span>
      </div>
      <div class="meta">
        <div><span>访问路径</span><span>/{pinyin}/</span></div>
      </div>
      <a class="btn" href="/{pinyin}/">进入主页 →</a>
    </div>"""


students_html = "\n\n".join(student_card(*s) for s in STUDENTS)
works_cards = works_cards + f"""

<div class="container" style="padding-top:0">
  <div class="section-title">学员主页</div>
  <div class="grid">
{students_html}
  </div>
</div>"""

HTML = f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>小盒子AI乐园 · 第4期AI沙龙 / AI作品</title>
<style>{portal_head_css}</style>
<style>{TABS_CSS}</style>
<style>/* 海报样式（作用域限定在 #tab-salon 内） */
{scoped}</style>
</head>
<body>

<div class="topbar">
  <div class="brand">🤖 小盒子AI乐园</div>
  <nav class="tabs" role="tablist">
    <button class="tab active" role="tab" data-target="salon">第四季 AI 沙龙</button>
    <a class="tab" href="/works/" style="text-decoration:none">AI 作品集</a>
  </nav>
</div>

<section id="tab-salon" class="panel active" role="tabpanel">
  <div class="poster-stage">
{poster_body.strip()}
  </div>
</section>

<section id="tab-works" class="panel" role="tabpanel">
<div class="hero">
  <h1>小盒子AI乐园</h1>
  <div class="badge">🤖 所有应用均由 AI 一句话部署上线</div>
</div>

<div class="container">
{works_cards}
</div>

</section>

<footer>Powered by WorkBuddy · smart-deploy 自动化部署 · 2026</footer>

<script>
(function () {{
  var tabs = Array.prototype.slice.call(document.querySelectorAll('.tab[data-target]'));
  var panels = {{ salon: document.getElementById('tab-salon'), works: document.getElementById('tab-works') }};
  function show(name) {{
    if (!panels[name]) name = 'salon';
    tabs.forEach(function (t) {{ t.classList.toggle('active', t.dataset.target === name); }});
    Object.keys(panels).forEach(function (k) {{ panels[k].classList.toggle('active', k === name); }});
    if (history.replaceState) history.replaceState(null, '', '#' + name);
    window.scrollTo(0, 0);
  }}
  tabs.forEach(function (t) {{ t.addEventListener('click', function () {{ show(t.dataset.target); }}); }});
  window.addEventListener('hashchange', function () {{ show((location.hash || '').replace('#', '') || 'salon'); }});
  show((location.hash || '').replace('#', '') || 'salon');
}})();
</script>

</body>
</html>
"""

OUT.parent.mkdir(parents=True, exist_ok=True)
OUT.write_text(HTML, encoding="utf-8")
print(f"written {OUT} ({OUT.stat().st_size/1024:.0f} KB)")
