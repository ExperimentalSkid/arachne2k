"""Authoritative visual system for Arachne's authenticated Streamlit workspace.

Geometry lives in ``DASHBOARD_CSS`` and is deliberately declared once.  The
light theme only replaces semantic colour tokens, so dark and light modes use
the same hierarchy, density, interaction states, and responsive contracts.
Page modules should use the shared component classes instead of local CSS.
"""


DASHBOARD_CSS = r"""
<style>
  /* -----------------------------------------------------------------------
     Tokens and document foundation
     ----------------------------------------------------------------------- */
  :root {
    color-scheme:dark;
    --rt-bg:#0c141a;
    --rt-panel:#121d24;
    --rt-panel-2:#17242c;
    --rt-panel-3:#1d2c35;
    --rt-panel-hover:#1b2a32;
    --rt-sidebar:#091219;
    --rt-line:#263640;
    --rt-line-2:#344751;
    --rt-line-strong:#536872;
    --rt-text:#f2f5f5;
    --rt-text-2:#c7d1d4;
    --rt-muted:#8fa0a8;
    --rt-faint:#6f8189;
    --rt-accent:#269896;
    --rt-accent-strong:#5db6b2;
    --rt-accent-soft:rgba(38,152,150,.14);
    --rt-ok:#58a77c;
    --rt-ok-soft:rgba(88,167,124,.12);
    --rt-warn:#c89a4b;
    --rt-warn-soft:rgba(200,154,75,.12);
    --rt-crit:#d2666f;
    --rt-crit-soft:rgba(210,102,111,.12);
    --rt-info:#6b97bc;
    --rt-info-soft:rgba(107,151,188,.12);
    --rt-purple:#9b82bd;
    --rt-purple-soft:rgba(155,130,189,.12);
    --rt-es-red:#c85860;
    --rt-es-yellow:#b68a32;
    --rt-focus:rgba(75,154,157,.24);
    --rt-radius:8px;
    --rt-radius-sm:5px;
    --rt-shadow-dialog:0 24px 72px rgba(0,0,0,.38);
    --rt-sans:"Inter","Segoe UI",Arial,sans-serif;
    --rt-mono:"Cascadia Code","SFMono-Regular",Consolas,monospace;
    --rt-space-1:.25rem;
    --rt-space-2:.5rem;
    --rt-space-3:.75rem;
    --rt-space-4:1rem;
    --rt-space-5:1.5rem;
    --rt-title:1.58rem;
    --rt-section:1.08rem;
    --rt-body:.9rem;
    --rt-helper:.8rem;
    --rt-sidebar-width:17rem;
  }

  html,body,[class*="css"] {font-family:var(--rt-sans);}
  html {scrollbar-color:var(--rt-line-strong) var(--rt-bg);}
  body {
    -webkit-font-smoothing:antialiased;
    text-rendering:optimizeLegibility;
    font-synthesis:none;
  }
  body,.stApp,[data-testid="stAppViewContainer"] {
    background:var(--rt-bg)!important;
    color:var(--rt-text)!important;
  }
  .block-container {
    max-width:1540px;
    padding:1.25rem clamp(1rem,2vw,1.8rem) 3.5rem;
  }
  .block-container > [data-testid="stVerticalBlock"] {gap:.58rem!important;}
  header[data-testid="stHeader"] {background:transparent!important;}
  #MainMenu,footer,.stDeployButton,[data-testid="stAppDeployButton"],
  [data-testid="stStatusWidget"] {display:none!important;visibility:hidden!important;}
  [data-testid="stSidebarCollapsedControl"] {display:flex!important;visibility:visible!important;}
  [data-testid="stSidebarCollapsedControl"] button {
    color:var(--rt-text)!important;
    background:var(--rt-panel)!important;
    border:1px solid var(--rt-line)!important;
    border-radius:var(--rt-radius-sm)!important;
  }
  * {scrollbar-width:thin;scrollbar-color:var(--rt-line-strong) transparent;}
  ::selection {background:var(--rt-accent-soft);color:var(--rt-text);}
  hr {border-color:var(--rt-line)!important;}

  button:focus-visible,a:focus-visible,input:focus-visible,textarea:focus-visible,
  [role="button"]:focus-visible,[role="tab"]:focus-visible,[tabindex]:focus-visible {
    outline:2px solid var(--rt-accent)!important;
    outline-offset:2px!important;
    box-shadow:0 0 0 3px var(--rt-focus)!important;
  }

  /* -----------------------------------------------------------------------
     Product shell and navigation
     ----------------------------------------------------------------------- */
  section[data-testid="stMain"] {
    position:relative!important;
    inset:auto!important;
    width:100%!important;
    max-width:100%!important;
    min-width:0!important;
  }
  section[data-testid="stSidebar"] {
    width:var(--rt-sidebar-width)!important;
    min-width:var(--rt-sidebar-width)!important;
    max-width:var(--rt-sidebar-width)!important;
    background:var(--rt-sidebar)!important;
    border-right:1px solid var(--rt-line)!important;
  }
  section[data-testid="stSidebar"] > div {
    width:var(--rt-sidebar-width)!important;
    padding-top:.85rem;
  }
  section[data-testid="stSidebar"] > div > [data-testid="stVerticalBlock"] {
    padding-inline:.58rem!important;
  }
  section[data-testid="stSidebar"] [data-testid="stVerticalBlock"] {gap:.12rem!important;}
  section[data-testid="stSidebar"] div[data-testid="stRadio"]:has(div[role="radiogroup"][aria-label="Compatibility page router"]),
  section[data-testid="stSidebar"] div[data-testid="stRadio"]:has(div[role="radiogroup"][aria-label="Main workspace"]),
  section[data-testid="stSidebar"] div[data-testid="stRadio"]:has(div[role="radiogroup"][aria-label="Workspace section"]) {
    display:none;
  }
  .rt-brand {
    display:flex;
    align-items:center;
    gap:.65rem;
    margin:0 .08rem .42rem;
    padding:.1rem .25rem .82rem;
    border-bottom:1px solid var(--rt-line);
  }
  .rt-brand-badge {
    display:flex;
    align-items:center;
    justify-content:center;
    width:40px;
    height:40px;
    border:0;
    background:transparent;
  }
  .rt-brand-badge img {
    display:block;
    width:38px;
    height:38px;
    object-fit:contain;
    filter:drop-shadow(0 0 3px rgba(38,152,150,.2));
  }
  .rt-brand-mark {
    color:var(--rt-text);
    font-size:1rem;
    font-weight:750;
    letter-spacing:.018em;
  }
  .rt-brand-copy {
    max-width:12rem;
    margin-top:.08rem;
    color:var(--rt-muted);
    font-size:.69rem;
    line-height:1.4;
  }
  .rt-nav-label,.osint-kicker {
    margin:.92rem .58rem .3rem;
    color:var(--rt-muted);
    font-size:.63rem;
    font-weight:700;
    letter-spacing:.11em;
    text-transform:uppercase;
  }
  [class*="st-key-nav_btn_"] .stButton > button {
    width:100%;
    min-height:2.12rem!important;
    justify-content:flex-start!important;
    padding:.38rem .58rem!important;
    border:0!important;
    border-radius:3px!important;
    background:transparent!important;
    box-shadow:none!important;
    color:var(--rt-text-2)!important;
    text-align:left!important;
    white-space:normal!important;
    font-weight:640!important;
    transition:background .12s,color .12s;
  }
  [class*="st-key-nav_btn_"] .stButton > button:hover {
    background:var(--rt-panel-hover)!important;
    color:var(--rt-text)!important;
  }
  [class*="st-key-nav_btn_"] .stButton > button[kind="primary"] {
    background:color-mix(in srgb,var(--rt-accent-soft) 82%,transparent)!important;
    color:var(--rt-text)!important;
    box-shadow:inset 3px 0 0 var(--rt-accent)!important;
  }
  [class*="st-key-nav_btn_spain"] .stButton > button[kind="primary"] {
    box-shadow:inset 3px 0 0 var(--rt-es-red)!important;
  }
  [class*="st-key-nav_btn_"] .stButton p {
    margin:0!important;
    font-size:.82rem!important;
    line-height:1.24!important;
  }
  [class*="st-key-nav_btn_"] .stButton p + p {
    margin-top:.08rem!important;
    color:var(--rt-muted)!important;
    font-size:.72rem!important;
  }
  [class*="st-key-sidebar-add-source"] {margin:.12rem 0 .25rem;}
  section[data-testid="stSidebar"] [class*="st-key-sidebar-add-source"] button[data-testid^="stBaseButton"] {
    min-height:2.45rem!important;
    justify-content:flex-start!important;
    padding:.48rem .62rem!important;
    border-color:var(--rt-accent)!important;
    border-radius:var(--rt-radius-sm)!important;
    background:var(--rt-accent)!important;
    background-image:none!important;
    box-shadow:none!important;
    color:#fff!important;
    -webkit-text-fill-color:#fff!important;
    font-weight:700!important;
  }
  section[data-testid="stSidebar"] [class*="st-key-sidebar-add-source"] button[data-testid^="stBaseButton"]:hover {
    border-color:var(--rt-accent-strong)!important;
    background:var(--rt-accent-strong)!important;
    color:#fff!important;
  }
  section[data-testid="stSidebar"] div[data-testid="stExpander"] {
    margin:.12rem 0;
    border:0!important;
    border-bottom:1px solid var(--rt-line)!important;
    border-radius:0!important;
  }
  section[data-testid="stSidebar"] div[data-testid="stExpander"] summary {
    min-height:2rem;
    padding:.3rem .5rem!important;
    border-radius:0!important;
    background:transparent!important;
    color:var(--rt-text-2)!important;
  }
  section[data-testid="stSidebar"] div[data-testid="stExpander"] summary:hover {
    background:var(--rt-panel-hover)!important;
    color:var(--rt-text)!important;
  }
  section[data-testid="stSidebar"] div[data-testid="stExpander"] summary p,
  section[data-testid="stSidebar"] div[data-testid="stExpander"] summary svg {
    color:inherit!important;
    fill:currentColor!important;
  }
  section[data-testid="stSidebar"] [data-testid="stCheckbox"] {
    padding:.18rem .5rem;
    border-radius:var(--rt-radius-sm);
    transition:background .12s ease;
  }
  section[data-testid="stSidebar"] [data-testid="stCheckbox"]:hover {
    background:var(--rt-panel-hover);
  }
  section[data-testid="stSidebar"] [data-testid="stCheckbox"] [data-testid="stWidgetLabel"] p {
    color:var(--rt-text-2)!important;
    font-size:.78rem!important;
  }
  .rt-sidebar-note {
    margin:.82rem .18rem .35rem;
    padding:.62rem .48rem;
    border-top:1px solid var(--rt-line);
    border-bottom:1px solid var(--rt-line);
    color:var(--rt-muted);
    font-size:.75rem;
    line-height:1.45;
  }
  .rt-nav-list {display:flex;flex-direction:column;gap:.14rem;}
  .rt-nav-item {
    display:grid;
    grid-template-columns:24px minmax(0,1fr) auto;
    gap:.5rem;
    align-items:center;
    padding:.45rem .5rem;
    border-radius:var(--rt-radius-sm);
    color:var(--rt-text-2)!important;
  }
  .rt-nav-item:hover,.rt-nav-item.active {background:var(--rt-panel-hover);}
  .rt-nav-item.active {box-shadow:inset 3px 0 0 var(--rt-accent);}
  .rt-nav-icon {color:var(--rt-muted);font-size:.76rem;font-weight:700;}
  .rt-nav-title {display:block;color:var(--rt-text);font-size:.82rem;font-weight:700;}
  .rt-nav-desc {display:block;color:var(--rt-muted);font-size:.72rem;}
  .rt-nav-count {color:var(--rt-muted);font-family:var(--rt-mono);font-size:.7rem;}

  /* -----------------------------------------------------------------------
     Page hierarchy and typography
     ----------------------------------------------------------------------- */
  .rt-hero {
    display:flex;
    align-items:flex-start;
    gap:.8rem;
    flex-wrap:wrap;
    margin-bottom:.82rem;
    padding:.08rem 0 .72rem;
    border-bottom:1px solid var(--rt-line);
  }
  .rt-hero-copy {min-width:0;}
  .rt-hero-title {
    color:var(--rt-text);
    font-size:var(--rt-title);
    font-weight:735;
    letter-spacing:-.03em;
    line-height:1.2;
  }
  .rt-hero-subtitle {
    max-width:46rem;
    margin-top:.18rem;
    color:var(--rt-muted);
    font-size:.8rem;
    line-height:1.45;
  }
  .rt-status-rail {
    display:flex;
    flex-wrap:wrap;
    justify-content:flex-end;
    gap:.38rem 0;
    margin-left:auto;
    padding-top:.3rem;
  }
  .rt-status-chip {
    display:inline-flex;
    align-items:center;
    gap:.38rem;
    padding:0 .72rem;
    color:var(--rt-text-2);
    font-size:.67rem;
    font-weight:650;
    letter-spacing:.015em;
    white-space:nowrap;
  }
  .rt-status-chip:first-child {padding-left:0;}
  .rt-status-chip + .rt-status-chip {border-left:1px solid var(--rt-line);}
  .rt-status-chip i {
    width:6px;
    height:6px;
    border-radius:50%;
    background:var(--rt-muted);
  }
  .rt-chip-ok i{background:var(--rt-ok);}
  .rt-chip-warn i{background:var(--rt-warn);}
  .rt-chip-info i{background:var(--rt-info);}
  .rt-chip-crit i{background:var(--rt-crit);}
  .rt-chip-spain i {
    background:linear-gradient(180deg,var(--rt-es-red) 50%,var(--rt-es-yellow) 50%);
  }
  .rt-context-line {display:none;}
  h1,h2,h3,h4 {
    color:var(--rt-text)!important;
    letter-spacing:-.015em;
    line-height:1.24!important;
  }
  h2 {font-size:var(--rt-title)!important;font-weight:720!important;}
  h3 {margin-top:1.2rem!important;font-size:var(--rt-section)!important;font-weight:700!important;}
  h4 {font-size:.96rem!important;font-weight:680!important;}
  p,li,.stMarkdown p,.stAlert p {
    color:var(--rt-text-2);
    font-size:var(--rt-body);
    line-height:1.55;
  }
  .stMarkdown a {
    color:var(--rt-accent-strong);
    text-decoration-color:color-mix(in srgb,var(--rt-accent) 55%,transparent);
    text-underline-offset:.16em;
  }
  .stMarkdown a:hover {color:var(--rt-text);text-decoration-color:var(--rt-accent);}
  [data-testid="stCaptionContainer"] p {
    color:var(--rt-muted)!important;
    font-size:var(--rt-helper)!important;
    line-height:1.48!important;
  }
  .osint-subtitle {color:var(--rt-text-2);font-size:.9rem;}
  .osint-meta,.card-meta {
    color:var(--rt-muted);
    font-family:var(--rt-mono);
    font-size:.75rem;
    line-height:1.55;
  }
  .rt-page-intro,.rt-page-lead {
    display:flex;
    align-items:center;
    justify-content:space-between;
    gap:1rem;
    margin:0 0 .82rem;
    padding:.15rem 0 .72rem;
    border:0;
    border-bottom:1px solid var(--rt-line);
    border-radius:0;
    background:transparent;
    box-shadow:none;
  }
  .rt-page-intro h3,.rt-page-lead h2 {
    margin:.08rem 0 .16rem!important;
    font-size:1.16rem!important;
  }
  .rt-page-intro p,.rt-page-lead p {
    max-width:820px;
    margin:0;
    color:var(--rt-text-2);
    font-size:.84rem;
  }
  .rt-page-intro-pill,.rt-page-lead-aside {
    flex:none;
    padding:.16rem 0 .16rem .6rem;
    border:0;
    border-left:2px solid var(--rt-accent);
    border-radius:0!important;
    background:transparent!important;
    color:var(--rt-muted);
    font-size:.72rem;
    font-weight:650;
    letter-spacing:.035em;
  }
  .rt-page-lead-eyebrow {
    display:block;
    margin-bottom:.15rem;
    color:var(--rt-accent-strong);
    font-size:.7rem;
    font-weight:700;
    letter-spacing:.065em;
    text-transform:uppercase;
  }
  .rt-page-lead-no-title {align-items:center;padding-top:.05rem;}
  .rt-page-lead-no-title p {max-width:920px;}
  .rt-overview-lead {
    max-width:78rem;
    margin:.1rem 0 .8rem;
    padding:.18rem 0 .18rem .72rem;
    border-left:2px solid var(--rt-accent);
    color:var(--rt-text-2);
    font-size:.85rem;
    line-height:1.55;
  }
  .rt-overview-lead strong {color:var(--rt-text);font-weight:720;}
  .rt-section-head {
    display:flex;
    align-items:flex-end;
    justify-content:space-between;
    gap:1rem;
    margin:1.35rem 0 .48rem;
    padding-bottom:.32rem;
    border-bottom:1px solid var(--rt-line);
  }
  .rt-section-head h3 {margin:0!important;font-size:1.02rem!important;}
  .rt-section-head p {margin:.08rem 0 0;color:var(--rt-muted);font-size:.8rem;}
  .rt-section-count {color:var(--rt-muted);font-family:var(--rt-mono);font-size:.8rem;}
  .section-note {
    padding:.5rem 0 .55rem;
    border:0;
    border-bottom:1px solid var(--rt-line);
    background:transparent;
    color:var(--rt-muted);
    font-size:.82rem;
  }

  /* -----------------------------------------------------------------------
     Shared information primitives
     ----------------------------------------------------------------------- */
  div[data-testid="stMetric"] {
    min-height:58px;
    padding:.32rem .62rem;
    border:0;
    border-left:1px solid var(--rt-line-2);
    border-radius:0;
    background:transparent;
    box-shadow:none;
  }
  div[data-testid="stMetric"] label {
    color:var(--rt-muted)!important;
    font-size:.68rem!important;
    font-weight:650!important;
    letter-spacing:.045em;
  }
  div[data-testid="stMetricValue"] {
    color:var(--rt-text)!important;
    font-size:1.28rem!important;
    font-weight:680!important;
    line-height:1.18!important;
  }
  [data-testid="stMetricDelta"] {color:var(--rt-text-2)!important;}
  .rt-lane-head {
    display:flex;
    align-items:center;
    justify-content:space-between;
    gap:.7rem;
    padding:.12rem 0;
  }
  .rt-lane-head span {color:var(--rt-text-2);font-size:.82rem;font-weight:650;}
  .rt-lane-head strong {color:var(--rt-text);font-size:1.35rem;}
  .rt-workflow-strip {
    display:flex;
    flex-wrap:wrap;
    align-items:center;
    gap:.42rem 0;
    margin:.2rem 0 .85rem;
    border-top:1px solid var(--rt-line);
    border-bottom:1px solid var(--rt-line);
  }
  .rt-workflow-strip span {
    margin-right:.7rem;
    padding:.42rem .7rem .42rem 0;
    border-right:1px solid var(--rt-line);
    color:var(--rt-text-2);
    font-size:.75rem;
  }
  .analyst-card {
    position:relative;
    margin:.12rem 0;
    padding:.72rem .15rem;
    border:0;
    border-bottom:1px solid var(--rt-line);
    border-radius:0;
    background:transparent;
    box-shadow:none;
  }
  .analyst-card::before {
    content:"";
    position:absolute;
    top:.78rem;
    left:-.15rem;
    width:2px;
    height:1.05rem;
    background:var(--rt-info);
  }
  .analyst-card h3 {margin:0 0 .28rem!important;font-size:.96rem!important;}
  .badge {
    display:inline-flex;
    align-items:center;
    margin:0 .22rem .2rem 0;
    padding:.18rem .4rem;
    border:1px solid var(--rt-line-2);
    border-radius:var(--rt-radius-sm);
    background:transparent;
    color:var(--rt-text-2);
    font-size:.7rem;
    font-weight:650;
    letter-spacing:0;
    line-height:1.3;
  }
  .badge-blue,.badge-cyan {color:var(--rt-info);border-color:color-mix(in srgb,var(--rt-info) 42%,transparent);}
  .badge-green {color:var(--rt-ok);border-color:color-mix(in srgb,var(--rt-ok) 42%,transparent);}
  .badge-amber,.badge-orange {color:var(--rt-warn);border-color:color-mix(in srgb,var(--rt-warn) 42%,transparent);}
  .badge-red {color:var(--rt-crit);border-color:color-mix(in srgb,var(--rt-crit) 42%,transparent);}
  .badge-purple {color:var(--rt-purple);border-color:color-mix(in srgb,var(--rt-purple) 42%,transparent);}
  .badge-gray {color:var(--rt-muted);}
  .badge-category {font-weight:650;}
  .badge-risk {font-weight:720;}
  .badge-importance {border-style:dashed;}
  .rt-sr-only {
    position:absolute!important;
    width:1px!important;
    height:1px!important;
    margin:-1px!important;
    padding:0!important;
    overflow:hidden!important;
    clip:rect(0,0,0,0)!important;
    white-space:nowrap!important;
    border:0!important;
  }
  .rt-spain-flag {
    display:inline-block;
    width:1.18rem;
    height:.78rem;
    vertical-align:-.12rem;
    border:1px solid #7f1015;
    border-radius:2px;
    background:linear-gradient(to bottom,#aa151b 0 25%,#f1bf00 25% 75%,#aa151b 75% 100%);
    box-shadow:0 0 0 1px rgba(0,0,0,.08);
  }
  .muted-label {
    display:block;
    margin:0 0 .28rem;
    color:var(--rt-muted);
    font-size:.69rem;
    font-weight:700;
    letter-spacing:.07em;
    line-height:1.3;
    text-transform:uppercase;
  }
  .reason-box,.safe-note {
    padding:.62rem .05rem;
    border:0;
    border-top:1px solid var(--rt-line);
    border-bottom:1px solid var(--rt-line);
    border-radius:0;
    background:transparent;
    color:var(--rt-text-2);
  }
  .empty-preview {
    min-height:130px;
    display:flex;
    align-items:center;
    justify-content:center;
    border:1px dashed var(--rt-line-2);
    border-radius:var(--rt-radius);
    color:var(--rt-muted);
    font-size:.8rem;
  }
  .restricted-preview {
    min-height:145px;
    display:flex;
    flex-direction:column;
    align-items:center;
    justify-content:center;
    padding:1rem;
    border:1px solid var(--rt-crit);
    border-radius:var(--rt-radius);
    background:var(--rt-crit-soft);
    color:var(--rt-crit);
    text-align:center;
    font-family:var(--rt-mono);
  }
  .restricted-preview small {color:var(--rt-muted);}
  .rt-empty-state {
    display:flex;
    align-items:center;
    gap:.7rem;
    min-height:76px;
    margin:.3rem 0;
    padding:.65rem .1rem;
    border-top:1px solid var(--rt-line);
    border-bottom:1px solid var(--rt-line);
  }
  .rt-empty-state > span {
    width:2px;
    height:30px;
    flex:0 0 2px;
    border:0;
    border-radius:0;
    background:var(--rt-accent);
    color:transparent;
  }
  .rt-empty-state strong {display:block;color:var(--rt-text);font-size:.84rem;}
  .rt-empty-state p {margin:.08rem 0 0;color:var(--rt-muted);font-size:.78rem;}
  .rt-data-row {
    display:flex;
    align-items:center;
    justify-content:space-between;
    gap:.8rem;
    padding:.52rem .08rem;
    border-bottom:1px solid var(--rt-line);
    font-size:.8rem;
  }
  .rt-data-row span {color:var(--rt-muted);}
  .rt-data-row strong {
    color:var(--rt-text);
    font-family:var(--rt-mono);
    font-size:.76rem;
    overflow-wrap:anywhere;
    text-align:right;
  }
  .rt-data-row-ok strong {color:var(--rt-ok);}
  .rt-data-row-warn strong {color:var(--rt-warn);}
  .rt-data-row-critical strong {color:var(--rt-crit);}
  .rt-data-row-muted strong {color:var(--rt-muted);}
  .rt-queue-row {
    display:grid;
    grid-template-columns:minmax(0,1fr) auto;
    align-items:center;
    gap:.75rem;
    padding:.58rem .08rem;
    border-bottom:1px solid var(--rt-line);
    box-shadow:inset 2px 0 0 transparent;
  }
  .rt-queue-main {min-width:0;}
  .rt-queue-main strong {
    display:block;
    overflow:hidden;
    color:var(--rt-text);
    font-size:.82rem;
    line-height:1.35;
    text-overflow:ellipsis;
    white-space:nowrap;
  }
  .rt-queue-main code {
    display:block;
    margin-top:.12rem;
    padding:0!important;
    background:transparent!important;
    color:var(--rt-muted)!important;
    font-size:.7rem!important;
  }
  .rt-queue-meta {
    display:flex;
    align-items:center;
    justify-content:flex-end;
    gap:.35rem .65rem;
    flex-wrap:wrap;
    color:var(--rt-muted);
    font-size:.7rem;
  }
  .rt-queue-meta b {color:var(--rt-text-2);font-weight:700;}
  .rt-queue-ok {box-shadow:inset 2px 0 0 var(--rt-ok);}
  .rt-queue-warn {box-shadow:inset 2px 0 0 var(--rt-warn);}
  .rt-queue-danger {box-shadow:inset 2px 0 0 var(--rt-crit);}
  .rt-quick-action {
    display:grid;
    grid-template-columns:1.35rem minmax(0,1fr);
    grid-template-rows:auto auto;
    column-gap:.42rem;
    min-height:3.35rem;
    padding:.16rem .08rem .42rem;
    border-bottom:1px solid var(--rt-line);
  }
  .rt-quick-action > span {
    grid-row:1 / span 2;
    color:var(--rt-accent-strong);
    font-size:.9rem;
    font-weight:720;
  }
  .rt-quick-action > strong {color:var(--rt-text);font-size:.83rem;line-height:1.25;}
  .rt-quick-action > small {color:var(--rt-muted);font-size:.74rem;line-height:1.35;}
  .rt-filter-summary {display:flex;flex-wrap:wrap;gap:.35rem .45rem;margin:.32rem 0 .15rem;}
  .rt-filter-chip {
    display:inline-flex;
    align-items:center;
    gap:.32rem;
    padding:.24rem .42rem;
    border:1px solid var(--rt-line);
    border-radius:3px;
    background:var(--rt-panel-2);
    color:var(--rt-text-2);
    font-size:.72rem;
    line-height:1.25;
  }
  .rt-filter-chip b {
    color:var(--rt-muted);
    font-size:.64rem;
    letter-spacing:.04em;
    text-transform:uppercase;
  }

  /* -----------------------------------------------------------------------
     Native Streamlit controls and data surfaces
     ----------------------------------------------------------------------- */
  .stButton > button,.stDownloadButton > button,.stLinkButton > a {
    min-height:2.35rem;
    border:1px solid var(--rt-line-2)!important;
    border-radius:var(--rt-radius-sm)!important;
    background:var(--rt-panel)!important;
    box-shadow:none!important;
    color:var(--rt-text)!important;
    font-size:.82rem!important;
    font-weight:620!important;
    transition:background .12s,border-color .12s;
  }
  .stButton > button:hover,.stDownloadButton > button:hover,.stLinkButton > a:hover {
    border-color:var(--rt-accent)!important;
    background:var(--rt-panel-hover)!important;
    color:var(--rt-text)!important;
  }
  .stButton > button[kind="primary"],.stDownloadButton > button[kind="primary"],
  .stLinkButton > a[kind="primary"] {
    border-color:var(--rt-accent)!important;
    background:var(--rt-accent)!important;
    color:#fff!important;
  }
  .stButton > button[kind="primary"] *,
  .stDownloadButton > button[kind="primary"] *,
  .stLinkButton > a[kind="primary"] * {
    color:#fff!important;
    -webkit-text-fill-color:#fff!important;
  }
  .stButton > button:not([kind="primary"]),.stDownloadButton > button:not([kind="primary"]),
  .stLinkButton > a:not([kind="primary"]) {
    border-color:var(--rt-line)!important;
    background:transparent!important;
  }
  .stButton > button:not([kind="primary"]):hover,
  .stDownloadButton > button:not([kind="primary"]):hover,
  .stLinkButton > a:not([kind="primary"]):hover {
    border-color:var(--rt-line-strong)!important;
    background:var(--rt-panel-hover)!important;
  }
  .stButton > button:disabled {cursor:not-allowed!important;opacity:.5!important;}
  div[data-baseweb="select"] > div,.stTextInput input,.stTextArea textarea,
  .stNumberInput input,.stDateInput input,.stTimeInput input {
    border-color:var(--rt-line-2)!important;
    border-radius:var(--rt-radius-sm)!important;
    background:var(--rt-panel)!important;
    box-shadow:none!important;
    color:var(--rt-text)!important;
  }
  [data-testid="stSelectbox"] *:has(> input[role="combobox"]) {
    border-color:var(--rt-line-2)!important;
    background:var(--rt-panel)!important;
    color:var(--rt-text)!important;
  }
  [data-testid="stSelectbox"] *:has(> input[role="combobox"]):focus-within {
    border-color:var(--rt-accent)!important;
    box-shadow:0 0 0 2px var(--rt-focus)!important;
  }
  [data-testid="stSelectbox"] input[role="combobox"] {
    background:transparent!important;
    caret-color:var(--rt-text)!important;
    color:var(--rt-text)!important;
    -webkit-text-fill-color:var(--rt-text)!important;
  }
  [data-testid="stSelectbox"] input[role="combobox"]::placeholder {
    color:var(--rt-muted)!important;
    -webkit-text-fill-color:var(--rt-muted)!important;
    opacity:1;
  }
  [data-testid="stSelectbox"] button[aria-label="Open"],
  [data-testid="stSelectbox"] button[aria-label="Clear value"] {
    border:0!important;
    background:transparent!important;
    box-shadow:none!important;
    color:var(--rt-text-2)!important;
  }
  [data-testid="stSelectbox"] svg {fill:currentColor!important;color:var(--rt-text-2)!important;}
  [data-testid="stSelectboxVirtualDropdown"] {
    border:1px solid var(--rt-line-2)!important;
    background:var(--rt-panel)!important;
    box-shadow:var(--rt-shadow-dialog)!important;
    color:var(--rt-text)!important;
  }
  [data-testid="stNumberInputContainer"] {
    overflow:hidden;
    border:1px solid var(--rt-line-2)!important;
    border-radius:var(--rt-radius-sm)!important;
    background:var(--rt-panel)!important;
    box-shadow:none!important;
    color:var(--rt-text)!important;
  }
  [data-testid="stNumberInputContainer"]:focus-within {
    border-color:var(--rt-accent)!important;
    box-shadow:0 0 0 2px var(--rt-focus)!important;
  }
  [data-testid="stNumberInputField"] {
    border:0!important;
    border-radius:0!important;
    background:transparent!important;
    box-shadow:none!important;
    color:var(--rt-text)!important;
    -webkit-text-fill-color:var(--rt-text)!important;
  }
  [data-testid="stNumberInputStepDown"],[data-testid="stNumberInputStepUp"],
  [data-testid="stNumberInputClearButton"] {
    border:0!important;
    border-left:1px solid var(--rt-line)!important;
    border-radius:0!important;
    background:var(--rt-panel-2)!important;
    box-shadow:none!important;
    color:var(--rt-text-2)!important;
  }
  [data-testid="stNumberInputStepDown"]:hover,[data-testid="stNumberInputStepUp"]:hover,
  [data-testid="stNumberInputClearButton"]:hover {
    background:var(--rt-panel-hover)!important;
    color:var(--rt-text)!important;
  }
  [data-testid="stNumberInput"] svg {fill:currentColor!important;color:currentColor!important;}
  [data-testid="stWidgetLabel"] p {
    color:var(--rt-text-2)!important;
    font-size:.78rem!important;
    font-weight:620!important;
  }
  [data-testid="stCheckbox"] {accent-color:var(--rt-accent);}
  [data-testid="stCheckbox"] label {color:var(--rt-text-2)!important;}
  [data-testid="stCheckbox"] label:has(input[role="switch"]) > div:first-of-type {
    background:var(--rt-line-2)!important;
    box-shadow:inset 0 0 0 1px var(--rt-line-strong);
  }
  [data-testid="stCheckbox"] label[data-selected]:has(input[role="switch"]) > div:first-of-type {
    background:var(--rt-accent)!important;
    box-shadow:inset 0 0 0 1px var(--rt-accent-strong);
  }
  [data-testid="stCheckbox"] label:has(input[role="switch"]) > div:first-of-type > div {
    background:var(--rt-text)!important;
  }
  [data-baseweb="popover"],[data-baseweb="menu"],ul[role="listbox"] {
    background:var(--rt-panel)!important;
    color:var(--rt-text)!important;
  }
  [role="option"] {color:var(--rt-text-2)!important;}
  [role="option"]:hover,[role="option"][aria-selected="true"] {
    background:var(--rt-panel-hover)!important;
    color:var(--rt-text)!important;
  }

  /* Authoritative flat grouping contract. These selectors intentionally occur
     once outside responsive media so later rules cannot silently re-box them. */
  [data-testid="stVerticalBlockBorderWrapper"] {
    padding:.68rem .08rem .58rem!important;
    border:0!important;
    border-top:1px solid var(--rt-line)!important;
    border-bottom:1px solid var(--rt-line)!important;
    border-radius:0!important;
    background:transparent!important;
    box-shadow:none!important;
  }
  [data-testid="stVerticalBlockBorderWrapper"] > div {background:transparent!important;}
  [data-testid="stVerticalBlockBorderWrapper"] [data-testid="stVerticalBlockBorderWrapper"] {
    padding:.35rem 0!important;
    border-top:0!important;
    border-bottom:0!important;
  }
  [data-testid="stForm"] {
    padding:.72rem .08rem .65rem!important;
    border:0!important;
    border-top:1px solid var(--rt-line)!important;
    border-bottom:1px solid var(--rt-line)!important;
    border-radius:0!important;
    background:transparent!important;
    box-shadow:none!important;
  }
  [data-testid="stForm"] [data-testid="stVerticalBlock"] {gap:.52rem!important;}
  div[data-testid="stExpander"] {
    border:0!important;
    border-bottom:1px solid var(--rt-line)!important;
    border-radius:0!important;
    background:transparent!important;
    box-shadow:none!important;
  }
  div[data-testid="stExpander"] summary {
    min-height:2.25rem;
    padding:.38rem .08rem!important;
  }
  div[data-testid="stExpander"] summary:hover {
    background:transparent!important;
    color:var(--rt-text)!important;
  }
  div[data-testid="stExpander"]:has(details[open]) {
    border-bottom-color:var(--rt-line-strong)!important;
    background:color-mix(in srgb,var(--rt-panel) 42%,transparent)!important;
    box-shadow:none!important;
  }
  [data-testid="stAlert"] {
    border:0!important;
    border-radius:0!important;
    background:transparent!important;
    box-shadow:none!important;
    color:var(--rt-text-2)!important;
  }
  [data-testid="stAlertContainer"] {
    padding:.58rem .72rem!important;
    border:0!important;
    border-left:2px solid var(--rt-info)!important;
    border-radius:0!important;
    background:var(--rt-panel-2)!important;
    box-shadow:none!important;
    color:var(--rt-text-2)!important;
  }
  [data-testid="stAlert"]:has([data-testid="stAlertContentInfo"]) [data-testid="stAlertContainer"] {
    border-left-color:var(--rt-info)!important;
    background:color-mix(in srgb,var(--rt-info-soft) 45%,var(--rt-panel-2))!important;
  }
  [data-testid="stAlert"]:has([data-testid="stAlertContentSuccess"]) [data-testid="stAlertContainer"] {
    border-left-color:var(--rt-ok)!important;
    background:color-mix(in srgb,var(--rt-ok-soft) 45%,var(--rt-panel-2))!important;
  }
  [data-testid="stAlert"]:has([data-testid="stAlertContentWarning"]) [data-testid="stAlertContainer"] {
    border-left-color:var(--rt-warn)!important;
    background:color-mix(in srgb,var(--rt-warn-soft) 45%,var(--rt-panel-2))!important;
  }
  [data-testid="stAlert"]:has([data-testid="stAlertContentError"]) [data-testid="stAlertContainer"] {
    border-left-color:var(--rt-crit)!important;
    background:color-mix(in srgb,var(--rt-crit-soft) 45%,var(--rt-panel-2))!important;
  }
  [data-testid="stDataFrame"],[data-testid="stTable"] {
    overflow:auto;
    border:0!important;
    border-top:1px solid var(--rt-line)!important;
    border-bottom:1px solid var(--rt-line)!important;
    border-radius:0!important;
    background:var(--rt-panel)!important;
    box-shadow:none!important;
  }
  table {color:var(--rt-text-2)!important;}
  table thead {position:sticky;top:0;z-index:1;}
  thead tr {background:var(--rt-panel-2)!important;}
  tbody tr {border-color:var(--rt-line)!important;}
  [data-testid="stJson"],[data-testid="stCodeBlock"],pre {
    border:1px solid var(--rt-line)!important;
    border-radius:4px!important;
    background:var(--rt-panel-2)!important;
  }
  code {
    overflow-wrap:anywhere;
    background:var(--rt-info-soft)!important;
    color:var(--rt-info)!important;
    font-family:var(--rt-mono)!important;
  }
  [data-testid="stProgress"] > div > div > div {background:var(--rt-accent)!important;}
  [data-testid="stGraphVizChart"] {
    padding:.5rem 0;
    border:0;
    border-top:1px solid var(--rt-line);
    border-bottom:1px solid var(--rt-line);
    border-radius:0;
    background:transparent;
  }
  [data-baseweb="tab-list"] {
    gap:.7rem;
    overflow-x:auto;
    border-bottom:1px solid var(--rt-line);
    scrollbar-width:none;
  }
  button[role="tab"] {
    min-width:max-content;
    padding-inline:.18rem!important;
    border-radius:0!important;
    color:var(--rt-muted)!important;
    font-size:.8rem!important;
  }
  button[role="tab"][aria-selected="true"] {
    border-bottom-color:var(--rt-accent)!important;
    color:var(--rt-text)!important;
  }
  div[role="dialog"] {
    max-width:min(94vw,76rem);
    max-height:92vh;
    overflow:auto;
    border:1px solid var(--rt-line)!important;
    border-radius:6px!important;
    background:var(--rt-panel)!important;
    box-shadow:var(--rt-shadow-dialog)!important;
  }
  div[role="dialog"] h2 {font-size:1.3rem!important;letter-spacing:-.025em;}
  div[role="dialog"] [data-testid="stVerticalBlock"] {gap:.58rem!important;}
  div[role="dialog"] [data-baseweb="tab-list"] {
    position:sticky;
    top:0;
    z-index:2;
    background:var(--rt-panel);
  }

  /* -----------------------------------------------------------------------
     Site cards, entities, timelines, and help
     ----------------------------------------------------------------------- */
  [class*="st-key-directory-card-"],[class*="st-key-home-card-"] {
    height:100%;
    margin:.06rem 0 .45rem;
  }
  [class*="st-key-directory-card-"] .stButton,[class*="st-key-home-card-"] .stButton {
    height:100%;
  }
  [class*="st-key-directory-card-"] .stButton button[data-testid^="stBaseButton"],
  [class*="st-key-home-card-"] .stButton button[data-testid^="stBaseButton"] {
    width:100%!important;
    min-height:132px!important;
    height:100%!important;
    justify-content:flex-start!important;
    align-items:flex-start!important;
    padding:.78rem .32rem .68rem!important;
    border:0!important;
    border-bottom:1px solid var(--rt-line)!important;
    border-radius:0!important;
    background:transparent!important;
    box-shadow:none!important;
    text-align:left!important;
    white-space:normal!important;
  }
  [class*="st-key-directory-card-"] .stButton button[data-testid^="stBaseButton"]:hover,
  [class*="st-key-home-card-"] .stButton button[data-testid^="stBaseButton"]:hover {
    border-bottom-color:var(--rt-line-strong)!important;
    background:var(--rt-panel-hover)!important;
    transform:none!important;
  }
  [class*="st-key-directory-card-"] .stButton button > div,
  [class*="st-key-home-card-"] .stButton button > div {
    width:100%;
    align-items:flex-start;
  }
  [class*="st-key-directory-card-"] .stButton p,[class*="st-key-home-card-"] .stButton p {
    width:100%;
    margin:0 0 .24rem!important;
    color:var(--rt-text-2)!important;
    font-size:.78rem!important;
    line-height:1.38!important;
    text-align:left!important;
  }
  [class*="st-key-directory-card-"] .stButton p strong,
  [class*="st-key-home-card-"] .stButton p strong {
    color:var(--rt-text)!important;
    font-size:.94rem;
    line-height:1.22;
  }
  [class*="st-key-directory-card-"] .stButton code,[class*="st-key-home-card-"] .stButton code {
    padding:0!important;
    background:transparent!important;
    color:var(--rt-muted)!important;
    font-size:.72rem!important;
  }
  [class*="st-key-directory-card-"][class*="-high-"] .stButton button,
  [class*="st-key-directory-card-"][class*="-critical-"] .stButton button {
    padding-left:.7rem!important;
    border-left:3px solid var(--rt-crit)!important;
  }
  [class*="st-key-directory-card-"][class*="-medium-"] .stButton button {
    padding-left:.7rem!important;
    border-left:3px solid var(--rt-warn)!important;
  }
  [class*="st-key-directory-card-"][class*="-low-"] .stButton button {
    padding-left:.7rem!important;
    border-left:3px solid var(--rt-ok)!important;
  }
  [class*="st-key-directory-card-"][class*="-forum-case-"] .stButton button {
    padding-left:.7rem!important;
    border-left:3px solid var(--rt-purple)!important;
  }
  [class*="st-key-directory-card-"][class*="-spain-"] .stButton button,
  [class*="st-key-home-card-"][class*="-spain-"] .stButton button {
    border-top:2px solid var(--rt-es-red)!important;
  }
  .spain-review-pulse,.rt-spain-hero {
    position:relative;
    margin:.25rem 0 .85rem;
    padding:.72rem 0 .72rem .8rem;
    border:0;
    border-left:3px solid var(--rt-es-red);
    border-bottom:1px solid var(--rt-line);
    border-radius:0;
    background:transparent;
    box-shadow:none;
    color:var(--rt-text);
    animation:none!important;
  }
  .rt-workbench-hero {
    position:relative;
    margin:.25rem 0 .85rem;
    padding:.72rem 0 .72rem .8rem;
    border:0;
    border-left:3px solid var(--rt-accent);
    border-bottom:1px solid var(--rt-line);
    border-radius:0;
    background:transparent;
    box-shadow:none;
    color:var(--rt-text);
  }
  .rt-spain-hit,.rt-spain-case,.rt-entity-row,.rt-timeline-item {
    margin:.2rem 0;
    padding:.65rem .12rem;
    border:0;
    border-bottom:1px solid var(--rt-line);
    border-radius:0;
    background:transparent;
    box-shadow:none;
  }
  .rt-spain-case-label,.rt-spain-hit-kind,.rt-timeline-meta,.rt-timeline-time {
    color:var(--rt-muted);
    font-size:.72rem;
  }
  .rt-timeline-title {color:var(--rt-text);font-size:.86rem;font-weight:680;}
  .rt-timeline-note {color:var(--rt-text-2);font-size:.8rem;}
  .rt-timeline-dot {background:var(--rt-accent);}
  .faq-hero {
    margin:.15rem 0 1rem;
    padding:.15rem 0 .8rem;
    border:0;
    border-bottom:1px solid var(--rt-line);
    background:transparent;
  }
  .faq-hero h2 {margin:0 0 .28rem!important;font-size:1.25rem!important;}
  .faq-hero p {max-width:800px;margin:0;color:var(--rt-text-2);font-size:.86rem;}
  .faq-section {margin:1.15rem 0 .45rem;}
  .faq-section-title {color:var(--rt-accent-strong);font-size:.78rem;font-weight:700;}
  .faq-section-intro {color:var(--rt-muted);font-size:.8rem;}
  .faq-card {
    min-height:112px;
    margin-bottom:.7rem;
    padding:.7rem .2rem .68rem .72rem;
    border:0;
    border-left:2px solid var(--rt-line-2);
    border-bottom:1px solid var(--rt-line);
    border-radius:0;
    background:transparent;
    box-shadow:none;
  }
  .faq-card-title {margin-bottom:.35rem;color:var(--rt-text);font-size:.9rem;font-weight:700;}
  .faq-card-body {color:var(--rt-text-2);font-size:.81rem;line-height:1.5;}
  .faq-card-hot {border-left-color:var(--rt-crit);}
  .faq-card-safe {border-left-color:var(--rt-ok);}
  .faq-card-work {border-left-color:var(--rt-info);}
  .faq-card-warn {border-left-color:var(--rt-warn);}
  .rt-session-timer {
    position:relative;
    z-index:auto;
    display:flex;
    align-items:center;
    gap:.42rem;
    width:max-content;
    max-width:100%;
    margin:.08rem 0 .55rem auto;
    padding:.26rem .08rem .26rem .55rem;
    border:0;
    border-left:1px solid var(--rt-line-2);
    border-radius:0;
    background:transparent;
    box-shadow:none;
    color:var(--rt-muted);
    font-size:.7rem;
  }
  .rt-session-timer strong {
    color:var(--rt-accent-strong);
    font-family:var(--rt-mono);
    font-size:.72rem;
  }
  .rt-session-timer span {color:inherit;}
  .rt-theme-marker {display:none!important;}

  /* -----------------------------------------------------------------------
     Workspaces: connected information bands, never nested floating tiles
     ----------------------------------------------------------------------- */
  [class*="st-key-rt-home-intro"] {margin:.35rem 0 .85rem;padding:.55rem 0 .2rem;}
  [class*="st-key-rt-home-intro"] div[data-testid="stHorizontalBlock"] {align-items:flex-end;}
  [class*="st-key-rt-home-intro"] [data-testid="column"]:last-child div[data-testid="stHorizontalBlock"] {
    align-items:center;
  }
  [class*="st-key-rt-home-intro"] .stButton > button {
    min-height:2.5rem!important;
    white-space:nowrap!important;
  }
  [class*="st-key-rt-home-intro"] .stButton > button[kind="primary"] {
    color:#fff!important;
    -webkit-text-fill-color:#fff!important;
  }
  .rt-home-kicker {
    margin-bottom:.38rem;
    color:var(--rt-muted);
    font-size:.67rem;
    font-weight:760;
    letter-spacing:.11em;
    text-transform:uppercase;
  }
  .rt-home-heading {
    margin:.05rem 0 .34rem!important;
    color:var(--rt-text)!important;
    font-size:1.72rem!important;
    font-weight:780!important;
    letter-spacing:-.03em!important;
    line-height:1.16!important;
  }
  .rt-home-summary {
    max-width:48rem;
    margin:0;
    color:var(--rt-muted);
    font-size:.86rem;
    line-height:1.5;
  }
  .rt-kpi-strip {
    display:grid;
    grid-template-columns:repeat(4,minmax(0,1fr));
    margin:.2rem 0 1.05rem;
    border-top:1px solid var(--rt-line);
    border-bottom:1px solid var(--rt-line);
    border-radius:0;
    background:transparent;
    box-shadow:none;
    overflow:hidden;
  }
  .rt-kpi {
    position:relative;
    min-width:0;
    min-height:6.6rem;
    padding:.78rem .88rem .72rem;
    border-right:1px solid var(--rt-line);
    border-radius:0;
    background:transparent;
    box-shadow:none;
  }
  .rt-kpi:last-child {border-right:0;}
  .rt-kpi::before {
    content:"";
    position:absolute;
    top:0;
    left:0;
    width:2px;
    height:100%;
    background:var(--rt-line-2);
  }
  .rt-kpi-ok::before {background:var(--rt-ok);}
  .rt-kpi-warn::before {background:var(--rt-warn);}
  .rt-kpi-critical::before {background:var(--rt-crit);}
  .rt-kpi-info::before {background:var(--rt-info);}
  .rt-kpi > span {
    display:block;
    color:var(--rt-muted);
    font-size:.67rem;
    font-weight:720;
    letter-spacing:.045em;
    text-transform:uppercase;
  }
  .rt-kpi > strong {
    display:block;
    margin:.2rem 0 .08rem;
    color:var(--rt-text);
    font-family:var(--rt-mono);
    font-size:1.42rem;
    font-weight:720;
    line-height:1.15;
  }
  .rt-kpi > small {display:block;color:var(--rt-muted);font-size:.72rem;line-height:1.4;}
  [class*="st-key-rt-home-workbench"] {
    margin:.12rem 0 1rem;
    padding:.15rem 0 .35rem;
    border:0;
    border-bottom:1px solid var(--rt-line);
    border-radius:0;
    background:transparent;
    box-shadow:none;
  }
  [class*="st-key-rt-home-workbench"] > [data-testid="stVerticalBlock"] {gap:.5rem!important;}
  [class*="st-key-rt-home-workbench"] div[data-testid="stHorizontalBlock"] {align-items:stretch;}
  [class*="st-key-rt-home-workbench"] div[data-testid="stHorizontalBlock"] > [data-testid="column"]:first-child {
    padding-right:.8rem;
  }
  [class*="st-key-rt-home-review-panel"],
  [class*="st-key-rt-home-health-panel"],
  [class*="st-key-rt-home-recent-panel"] {
    height:100%;
    padding:.55rem 0 .45rem;
    border:0;
    border-radius:0;
    background:transparent;
    box-shadow:none;
  }
  [class*="st-key-rt-home-health-panel"] {padding-left:.9rem;border-left:1px solid var(--rt-line);}
  [class*="st-key-rt-home-recent-panel"] {
    height:auto;
    margin:0 0 1rem;
    border-top:1px solid var(--rt-line);
  }
  [class*="st-key-rt-home-review-panel"] > [data-testid="stVerticalBlock"],
  [class*="st-key-rt-home-health-panel"] > [data-testid="stVerticalBlock"],
  [class*="st-key-rt-home-recent-panel"] > [data-testid="stVerticalBlock"] {
    gap:.45rem!important;
  }
  .rt-workbench-head {
    display:flex;
    align-items:flex-end;
    justify-content:space-between;
    gap:1rem;
    min-height:3.65rem;
    margin:0 0 .35rem;
    padding:0 0 .72rem;
    border-bottom:1px solid var(--rt-line);
  }
  .rt-workbench-head h3 {margin:.08rem 0 .12rem!important;font-size:.98rem!important;font-weight:760!important;}
  .rt-workbench-head p {max-width:38rem;margin:0;color:var(--rt-muted);font-size:.76rem;line-height:1.42;}
  .rt-workbench-eyebrow {
    display:block;
    color:var(--rt-accent-strong);
    font-size:.62rem;
    font-weight:760;
    letter-spacing:.1em;
    text-transform:uppercase;
  }
  .rt-workbench-aside {
    flex:none;
    padding:.24rem 0;
    color:var(--rt-text);
    font-family:var(--rt-mono);
    font-size:1.12rem;
    font-weight:720;
  }
  [class*="st-key-rt-home-lane-"],[class*="st-key-rt-home-recent-"] {
    min-height:3.55rem;
    margin:0;
    padding:.42rem .08rem;
    border:0;
    border-bottom:1px solid var(--rt-line);
    border-radius:0;
    background:transparent;
    box-shadow:none;
  }
  [class*="st-key-rt-home-lane-"]:last-of-type,
  [class*="st-key-rt-home-recent-"]:last-of-type {border-bottom-color:transparent;}
  [class*="st-key-rt-home-lane-"] .stButton > button,
  [class*="st-key-rt-home-recent-"] .stButton > button {
    min-height:2rem!important;
    padding:.28rem .48rem!important;
    font-size:.72rem!important;
  }
  .rt-lane-icon {
    display:inline-flex;
    align-items:center;
    justify-content:center;
    width:1.65rem;
    height:1.65rem;
    border:0;
    border-radius:50%;
    background:var(--rt-panel-2);
    color:var(--rt-accent-strong);
    font-size:.76rem;
  }
  .rt-lane-copy {
    display:grid;
    grid-template-columns:minmax(0,1fr) auto;
    gap:.05rem .65rem;
    align-items:center;
  }
  .rt-lane-copy strong {color:var(--rt-text);font-size:.79rem;line-height:1.3;}
  .rt-lane-copy b {color:var(--rt-text);font-family:var(--rt-mono);font-size:.95rem;}
  .rt-lane-copy small {grid-column:1 / -1;color:var(--rt-muted);font-size:.7rem;line-height:1.32;}
  .rt-health-row {
    display:flex;
    align-items:center;
    justify-content:space-between;
    gap:1rem;
    min-height:3.55rem;
    margin:0;
    padding:.48rem .08rem;
    border:0;
    border-bottom:1px solid var(--rt-line);
    border-radius:0;
    background:transparent;
  }
  .rt-health-row strong {display:block;color:var(--rt-text);font-size:.79rem;}
  .rt-health-row small {display:block;margin-top:.12rem;color:var(--rt-muted);font-size:.7rem;}
  .rt-health-row > span {
    min-width:2rem;
    color:var(--rt-text);
    text-align:center;
    font-family:var(--rt-mono);
    font-size:.86rem;
    font-weight:760;
  }
  .rt-live-dot {
    display:inline-block;
    width:.5rem;
    height:.5rem;
    margin:.6rem 0 0 .25rem;
    border-radius:50%;
    background:var(--rt-faint);
    box-shadow:0 0 0 3px color-mix(in srgb,var(--rt-faint) 14%,transparent);
  }
  .rt-live-dot-on {background:var(--rt-ok);box-shadow:0 0 0 3px var(--rt-ok-soft);}
  .rt-record-identity strong {
    display:block;
    max-width:100%;
    overflow:hidden;
    color:var(--rt-text);
    font-size:.79rem;
    text-overflow:ellipsis;
    white-space:nowrap;
  }
  .rt-record-identity code {
    display:block;
    margin-top:.1rem;
    padding:0!important;
    overflow:hidden;
    background:transparent!important;
    color:var(--rt-muted)!important;
    font-size:.66rem!important;
    text-overflow:ellipsis;
    white-space:nowrap;
  }
  .rt-record-classification {display:flex;align-items:center;gap:.35rem;flex-wrap:wrap;}
  .rt-record-classification strong {color:var(--rt-text-2);font-size:.71rem;font-weight:680;}
  .rt-record-classification small {display:block;width:100%;color:var(--rt-muted);font-size:.66rem;}
  .rt-inline-flag {font-size:.78rem;}
  [class*="st-key-rt-home-actions"] {
    margin:.05rem 0 1rem;
    padding:.18rem 0 .55rem;
    border:0;
    border-top:1px solid var(--rt-line);
    border-bottom:1px solid var(--rt-line);
    background:transparent;
  }
  [class*="st-key-rt-home-actions"] > [data-testid="stVerticalBlock"] >
  div[data-testid="stHorizontalBlock"] > [data-testid="column"] {
    padding:.62rem .8rem .4rem 0;
    border:0;
    border-right:1px solid var(--rt-line);
    border-radius:0;
    background:transparent;
    box-shadow:none;
  }
  [class*="st-key-rt-home-actions"] > [data-testid="stVerticalBlock"] >
  div[data-testid="stHorizontalBlock"] > [data-testid="column"]:last-child {
    border-right:0;
  }
  [class*="st-key-rt-home-actions"] .rt-quick-action {min-height:3.6rem;border-bottom:0;}
  [class*="st-key-rt-home-actions"] .rt-quick-action > span {
    display:inline-flex;
    align-items:center;
    justify-content:center;
    width:1.8rem;
    height:1.8rem;
    margin-bottom:.45rem;
    border:0;
    border-radius:50%;
    background:var(--rt-panel-2);
    color:var(--rt-accent-strong);
  }
  [class*="st-key-rt-home-actions"] .stButton > button {
    min-height:2.05rem!important;
    padding:.3rem .5rem!important;
    font-size:.74rem!important;
  }

  /* Directory command bar and record rows. */
  [class*="st-key-rt-directory-command"] {
    margin:.18rem 0 .65rem;
    padding:.72rem .08rem .64rem;
    border:0;
    border-top:1px solid var(--rt-line);
    border-bottom:1px solid var(--rt-line);
    border-radius:0;
    background:transparent;
  }
  [class*="st-key-rt-directory-command"] > [data-testid="stVerticalBlock"] {gap:.48rem!important;}
  [class*="st-key-rt-directory-command"] [data-testid="stWidgetLabel"] p {
    color:var(--rt-muted)!important;
    font-size:.68rem!important;
    letter-spacing:.035em;
    text-transform:uppercase;
  }
  div[data-testid="stHorizontalBlock"]:has([class*="st-key-card-sort-"]) {
    align-items:flex-end!important;
    gap:.65rem!important;
    margin:.15rem 0 .08rem;
    padding:.52rem 0 .58rem;
    border-top:1px solid var(--rt-line);
    border-bottom:1px solid var(--rt-line);
  }
  [class*="st-key-card-search-"] {margin-bottom:.08rem;}
  [class*="st-key-card-display-"] [role="radiogroup"] {gap:.18rem!important;}
  [class*="st-key-card-display-"] [role="radiogroup"] label {
    min-height:2.12rem;
    padding:.24rem .48rem;
    border:1px solid transparent;
    border-radius:3px;
  }
  [class*="st-key-card-display-"] [role="radiogroup"] label:has(input:checked) {
    border-color:var(--rt-line-2);
    background:var(--rt-accent-soft);
  }
  [class*="st-key-rt-site-row-"] {
    min-height:3.7rem;
    padding:.5rem .6rem .42rem;
    border-bottom:1px solid var(--rt-line);
    border-left:2px solid transparent;
    transition:background .12s,border-color .12s;
  }
  [class*="st-key-rt-site-row-"]:hover {
    border-left-color:var(--rt-accent);
    background:var(--rt-panel-hover);
  }
  [class*="st-key-rt-site-row-"] div[data-testid="stHorizontalBlock"] {align-items:center;}
  [class*="st-key-rt-site-row-"] .stButton > button {
    min-height:2rem!important;
    padding:.28rem .52rem!important;
    font-size:.72rem!important;
  }
  [class*="st-key-rt-site-row-"] [data-testid="stCaptionContainer"] p {margin-top:.04rem!important;}

  /* Dossier and Spain master-detail surfaces. */
  [class*="st-key-rt-dossier-head-"] {
    margin:.1rem 0 .72rem;
    padding:.82rem .08rem .72rem .9rem;
    border:0;
    border-left:2px solid var(--rt-accent);
    border-bottom:1px solid var(--rt-line);
    border-radius:0;
    background:transparent;
    box-shadow:none;
  }
  [class*="st-key-rt-dossier-head-"] .rt-page-lead {
    margin:0;
    padding:0 0 .55rem;
    border-bottom:0;
  }
  [class*="st-key-rt-dossier-head-"] [data-testid="stCodeBlock"] {
    border-color:var(--rt-line)!important;
    background:var(--rt-panel-2)!important;
  }
  [class*="st-key-rt-dossier-actions-"] {
    margin:0 0 .75rem;
    padding:.15rem .08rem .72rem;
    border:0;
    border-top:1px solid var(--rt-line);
    border-bottom:1px solid var(--rt-line);
    border-radius:0;
    background:transparent;
  }
  [class*="st-key-rt-dossier-actions-"] .rt-section-head {
    margin:.55rem 0;
    padding-bottom:.42rem;
  }
  [class*="st-key-rt-spain-filters"] {
    margin:.1rem 0 .75rem;
    padding:.68rem .08rem .62rem;
    border:0;
    border-top:1px solid var(--rt-line);
    border-bottom:1px solid var(--rt-line);
    border-radius:0;
    background:transparent;
  }
  [class*="st-key-rt-spain-filters"] div[data-testid="stHorizontalBlock"] {align-items:flex-end;}
  [class*="st-key-rt-spain-queue-"] {
    margin:0;
    padding:.48rem .08rem .5rem;
    border:0;
    border-bottom:1px solid var(--rt-line);
    border-radius:0;
    background:transparent;
    transition:border-color .12s,background .12s;
  }
  [class*="st-key-rt-spain-queue-"]:hover {
    border-bottom-color:var(--rt-line-strong);
    background:var(--rt-panel-hover);
  }
  [class*="st-key-rt-spain-queue-"] .rt-queue-row {
    grid-template-columns:1fr;
    padding:.12rem 0 .4rem;
    border-bottom:0;
  }
  [class*="st-key-rt-spain-queue-"] .rt-queue-meta {justify-content:flex-start;}
  [class*="st-key-rt-spain-queue-"] .stButton > button {
    min-height:1.95rem!important;
    padding:.25rem .45rem!important;
    font-size:.7rem!important;
  }
  [data-testid="column"]:has(.rt-spain-detail-marker) {
    padding:.7rem .08rem .8rem .95rem;
    border:0;
    border-left:1px solid var(--rt-line);
    border-radius:0;
    background:transparent;
    box-shadow:none;
  }
  .rt-spain-detail-marker {display:block;width:0;height:0;}
  [data-testid="column"]:has(.rt-spain-detail-marker) .rt-spain-case {
    margin:0 0 .55rem;
    padding:.05rem 0 .72rem;
    border-bottom:1px solid var(--rt-line);
  }
  [data-testid="column"]:has(.rt-spain-detail-marker) .rt-spain-case h3 {
    margin:.2rem 0 .45rem!important;
    font-size:1.15rem!important;
  }
  .rt-stage-strip {
    display:grid;
    grid-template-columns:repeat(auto-fit,minmax(8.5rem,1fr));
    margin:.35rem 0 .85rem;
    border-top:1px solid var(--rt-line);
    border-bottom:1px solid var(--rt-line);
    border-radius:0;
    background:transparent;
    overflow:hidden;
  }
  .rt-stage {
    position:relative;
    padding:.64rem .72rem;
    border-right:1px solid var(--rt-line);
  }
  .rt-stage:last-child {border-right:0;}
  .rt-stage::after {
    content:"";
    position:absolute;
    z-index:1;
    top:50%;
    right:-4px;
    width:7px;
    height:7px;
    border-top:1px solid var(--rt-line-strong);
    border-right:1px solid var(--rt-line-strong);
    background:var(--rt-bg);
    transform:translateY(-50%) rotate(45deg);
  }
  .rt-stage:last-child::after {display:none;}
  .rt-stage span {
    display:block;
    color:var(--rt-muted);
    font-size:.66rem;
    letter-spacing:.05em;
    text-transform:uppercase;
  }
  .rt-stage strong {
    display:block;
    margin-top:.12rem;
    color:var(--rt-text);
    font-family:var(--rt-mono);
    font-size:.82rem;
  }
  .rt-stage-active strong,.rt-stage-ok strong {color:var(--rt-ok);}
  .rt-stage-warn strong {color:var(--rt-warn);}
  .rt-stage-critical strong {color:var(--rt-crit);}

  /* Existing opt-in layout hooks. */
  div[data-testid="stHorizontalBlock"]:has([class*="st-key-home-review-lane-"]) {
    align-items:center!important;
    min-height:3.25rem;
    padding:.34rem .08rem;
    border-bottom:1px solid var(--rt-line);
  }
  div[data-testid="stHorizontalBlock"]:has([class*="st-key-home-destination-"]) {
    align-items:stretch!important;
  }

  /* -----------------------------------------------------------------------
     Accessibility and responsive behavior
     ----------------------------------------------------------------------- */
  @media (prefers-reduced-motion:reduce) {
    *,*::before,*::after {
      scroll-behavior:auto!important;
      animation-duration:.001ms!important;
      animation-iteration-count:1!important;
      transition-duration:.001ms!important;
    }
  }
  @media (max-width:1100px) {
    .block-container {padding:1rem 1rem 3rem;}
    .rt-status-rail {
      width:100%;
      justify-content:flex-start;
      margin-left:0;
      padding-top:0;
    }
    .rt-kpi-strip {grid-template-columns:repeat(2,minmax(0,1fr));}
    [class*="st-key-rt-home-workbench"] > div > [data-testid="stVerticalBlock"] >
    [data-testid="stHorizontalBlock"] {flex-wrap:wrap!important;}
    [class*="st-key-rt-home-workbench"] > div > [data-testid="stVerticalBlock"] >
    [data-testid="stHorizontalBlock"] > [data-testid="column"] {
      width:auto!important;
      min-width:min(100%,26rem)!important;
      flex:1 1 26rem!important;
    }
    [class*="st-key-rt-home-health-panel"] {
      padding-left:0;
      border-left:0;
      border-top:1px solid var(--rt-line);
    }
    div[data-testid="stHorizontalBlock"]:has([class*="st-key-directory-card-"]),
    div[data-testid="stHorizontalBlock"]:has([class*="st-key-home-card-"]) {
      flex-wrap:wrap!important;
    }
    div[data-testid="stHorizontalBlock"]:has([class*="st-key-directory-card-"])>[data-testid="column"],
    div[data-testid="stHorizontalBlock"]:has([class*="st-key-home-card-"])>[data-testid="column"] {
      width:auto!important;
      min-width:min(100%,16rem)!important;
      flex:1 1 16rem!important;
    }
  }
  @media (max-width:700px) {
    :root {
      --rt-title:1.32rem;
      --rt-section:1rem;
      --rt-body:.86rem;
    }
    .block-container {padding:.8rem .68rem 2.4rem;}
    section[data-testid="stSidebar"],section[data-testid="stSidebar"] > div {
      width:min(86vw,var(--rt-sidebar-width))!important;
      min-width:min(86vw,var(--rt-sidebar-width))!important;
      max-width:min(86vw,var(--rt-sidebar-width))!important;
    }
    .rt-hero,.rt-page-intro,.rt-page-lead,.rt-section-head {
      align-items:flex-start;
      flex-direction:column;
    }
    .rt-page-intro-pill,.rt-page-lead-aside {align-self:flex-start;}
    .rt-workflow-strip {display:grid;grid-template-columns:1fr 1fr;}
    .rt-workflow-strip span {margin:0;padding:.4rem .35rem;border-right:0;}
    div[data-testid="stHorizontalBlock"]:has([class*="st-key-directory-card-"])>[data-testid="column"],
    div[data-testid="stHorizontalBlock"]:has([class*="st-key-home-card-"])>[data-testid="column"] {
      width:100%!important;
      min-width:100%!important;
      flex:1 1 100%!important;
    }
    [class*="st-key-directory-card-"] .stButton button[data-testid^="stBaseButton"],
    [class*="st-key-home-card-"] .stButton button[data-testid^="stBaseButton"] {
      min-height:0!important;
    }
    .rt-session-timer {margin:.05rem 0 .45rem auto;}
    .rt-session-timer span {display:none;}
    .rt-queue-row {grid-template-columns:1fr;}
    .rt-queue-meta {justify-content:flex-start;}
    .rt-status-chip {padding:.08rem .55rem;}
    .rt-status-chip + .rt-status-chip {border-left:0;}
    div[data-testid="stHorizontalBlock"]:has([class*="st-key-card-sort-"]),
    div[data-testid="stHorizontalBlock"]:has([class*="st-key-home-review-lane-"]) {
      flex-wrap:wrap!important;
    }
    div[data-testid="stHorizontalBlock"]:has([class*="st-key-card-sort-"])>[data-testid="column"],
    div[data-testid="stHorizontalBlock"]:has([class*="st-key-home-review-lane-"])>[data-testid="column"] {
      width:auto!important;
      min-width:min(100%,12rem)!important;
      flex:1 1 12rem!important;
    }
    [data-baseweb="tab-list"] {max-width:calc(100vw - 1.6rem);}
    div[role="dialog"] {
      width:calc(100vw - 1rem)!important;
      max-width:calc(100vw - 1rem)!important;
    }
    .rt-kpi-strip {grid-template-columns:1fr 1fr;margin-bottom:.72rem;}
    .rt-kpi {min-height:5.1rem;padding:.62rem .68rem;}
    .rt-kpi:nth-child(2n) {border-right:0;}
    .rt-kpi > strong {font-size:1.16rem;}
    .rt-kpi > small {display:none;}
    [class*="st-key-rt-home-workbench"],
    [class*="st-key-rt-directory-command"],
    [class*="st-key-rt-dossier-head-"],
    [class*="st-key-rt-dossier-actions-"],
    [class*="st-key-rt-spain-filters"] {
      padding-right:.1rem;
      padding-left:.1rem;
    }
    [class*="st-key-rt-site-row-"] div[data-testid="stHorizontalBlock"] {
      flex-wrap:wrap!important;
    }
    [class*="st-key-rt-site-row-"] div[data-testid="stHorizontalBlock"] > [data-testid="column"] {
      width:auto!important;
      min-width:min(100%,11rem)!important;
      flex:1 1 11rem!important;
    }
    .rt-workbench-head {min-height:0;align-items:flex-start;}
    .rt-workbench-aside {font-size:1rem;}
    [data-testid="column"]:has(.rt-spain-detail-marker) {
      padding-left:.08rem;
      border-left:0;
      border-top:1px solid var(--rt-line);
    }
  }
</style>
"""


ARACHNE_LIGHT_CSS = r"""
<style>
  :root {
    color-scheme:light;
    --rt-bg:#f5f7fb;
    --rt-panel:#ffffff;
    --rt-panel-2:#f9fafc;
    --rt-panel-3:#eef3f8;
    --rt-panel-hover:#f1f5f9;
    --rt-sidebar:#eef3f8;
    --rt-line:#dbe2ea;
    --rt-line-2:#c7d1dd;
    --rt-line-strong:#9eacbb;
    --rt-text:#182230;
    --rt-text-2:#344054;
    --rt-muted:#667085;
    --rt-faint:#98a2b3;
    --rt-accent:#2f68a8;
    --rt-accent-strong:#24588f;
    --rt-accent-soft:rgba(47,104,168,.10);
    --rt-ok:#247a54;
    --rt-ok-soft:rgba(36,122,84,.09);
    --rt-warn:#b66a16;
    --rt-warn-soft:rgba(182,106,22,.09);
    --rt-crit:#c23b49;
    --rt-crit-soft:rgba(194,59,73,.09);
    --rt-info:#2f68a8;
    --rt-info-soft:rgba(47,104,168,.09);
    --rt-purple:#6f4dbf;
    --rt-purple-soft:rgba(111,77,191,.09);
    --rt-es-red:#c23b49;
    --rt-es-yellow:#b07a16;
    --rt-focus:rgba(47,104,168,.2);
    --rt-shadow-dialog:0 22px 64px rgba(16,24,40,.16);
  }
</style>
"""
