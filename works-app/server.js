#!/usr/bin/env node
'use strict';
/**
 * AI 作品集后端 · 零依赖（Node 内置模块）+ RBAC 权限管理
 *   GET  /api/health
 *   POST /api/login            {py, code}            -> {token, student, perms}
 *   GET  /api/me                                    -> {student, perms, canAdmin}
 *   GET  /api/data                                  -> {students, works(含 locked)}
 *   POST /api/publish          {title,desc,type,emoji,link?,html?{content}}  (Bearer, 需 works:upload)
 *   POST /api/delete           {id}                  (Bearer, 自己需 works:del:own，他人需 works:del:any)
 *   POST /api/like             {id}
 *   POST /api/password         {oldCode,newCode}     (Bearer)
 *   POST /api/admin/student    {adminCode,...} 或 Bearer(需 stu:manage) -> {code}
 *   POST /api/admin/reset      {adminCode,py}  或 Bearer(需 stu:manage) -> {code}
 *   GET  /api/admin/list?adminCode=...
 *   ---- RBAC（Bearer，需 role:manage）----
 *   POST /api/rbac/get                       -> {roles, resources, users, logs, perms}
 *   POST /api/rbac/role.save    {key?,name,perms[]}   新建/更新角色
 *   POST /api/rbac/role.delete  {key}                 删除自定义角色
 *   POST /api/rbac/user.roles   {py, roles[]}         调整用户角色
 *   POST /api/rbac/user.reset   {py}                  重置密码
 *   POST /api/rbac/user.off     {py, off}             停用/启用
 *   POST /api/rbac/res.save     {key, roles?, on?}    资源授权调整
 *   POST /api/rbac/logs.clear   {}                    清空访问记录
 *   ---- AI 赛事 ----
 *   GET  /api/events                          -> {events}
 *   POST /api/events/save      {...}          (Bearer, 需 event:manage)
 *   POST /api/events/delete    {id}           (Bearer, 需 event:manage)
 *   POST /api/events/subscribe {email}        赛事提醒订阅
 *   ---- AI 沙龙 ----
 *   GET  /api/salons                          -> {salons}
 *   POST /api/salons/save      {...}          (Bearer, 需 salon:manage)
 *   POST /api/salons/delete    {id}           (Bearer, 需 salon:manage)
 */
const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const zlib = require('zlib');

const ROOT = '/var/www/works';
const DATA_DIR = path.join(ROOT, 'data');
const DB_FILE = path.join(DATA_DIR, 'db.json');
const SESS_FILE = path.join(DATA_DIR, 'sessions.json');
const SITES = path.join(ROOT, 'sites');
const PORT = 8790;
const MAX_BODY = 12 * 1024 * 1024;
const MAX_ZIP_BODY = 100 * 1024 * 1024;   /* 压缩包二进制直传上限 */
const MAX_AUDIO_BODY = 30 * 1024 * 1024;  /* MP3 音频直传上限 */
const MAX_VIDEO_BODY = 100 * 1024 * 1024; /* MP4 视频直传上限 */
const TOKEN_TTL = 30 * 24 * 3600 * 1000;

const TYPES = ['小游戏', '动画', '音乐', '视频', '网页', '其他'];
const EMOJIS = ['🌻', '🐹', '🚀', '🐱', '🌐', '🎮', '🏰', '🦖', '🐟', '⚽', '🎨', '🤖', '🎵', '🎬'];

/* ---------------- RBAC 常量 ---------------- */
const PERM_GROUPS = [
  { group: '作品操作', perms: [
    { key: 'works:view',    name: '浏览作品集',    desc: '查看作品列表与主页' },
    { key: 'works:upload',  name: '上传作品',      desc: '发布新作品' },
    { key: 'works:del:own', name: '删除自己作品',  desc: '仅本人作品' },
    { key: 'works:del:any', name: '删除任意作品',  desc: '管理员级' },
    { key: 'works:audit',   name: '作品上架/下架', desc: '审核作品可见性' },
  ]},
  { group: '学员管理', perms: [
    { key: 'stu:manage',  name: '学员账号管理',  desc: '新增学员/重置密码/停用' },
    { key: 'stats:view',  name: '数据统计查看',  desc: '作品量、活跃度等' },
  ]},
  { group: '系统管理', perms: [
    { key: 'role:manage', name: '角色与授权管理', desc: '编辑矩阵、分配角色、资源配置' },
    { key: 'log:view',    name: '访问记录查看',   desc: '审计日志' },
  ]},
  { group: '内容运营', perms: [
    { key: 'event:manage', name: '赛事内容维护', desc: '新增/编辑/删除 AI 赛事与活动' },
    { key: 'salon:manage', name: '沙龙内容维护', desc: '新增/编辑/删除 AI 沙龙期次' },
  ]},
];
const ALL_PERMS = PERM_GROUPS.reduce((a, g) => a.concat(g.perms.map(p => p.key)), []);

function defaultRoles() {
  return [
    { key: 'admin',   name: '超级管理员', builtin: true, perms: ALL_PERMS.slice() },
    { key: 'teacher', name: '老师',       builtin: true, perms: ['works:view','works:upload','works:del:any','works:audit','stu:manage','stats:view'] },
    { key: 'student', name: '学员',       builtin: true, perms: ['works:view','works:upload','works:del:own'] },
    { key: 'guest',   name: '游客',       builtin: true, perms: ['works:view'] },
  ];
}

function defaultResources() {
  // 作品类资源通过 workId 关联到具体作品；找不到对应作品时仅作展示不生效
  const res = [
    { key: 'page.gallery', name: '页面 · AI 作品集',   type: 'page', roles: ['admin','teacher','student','guest'], on: true },
    { key: 'page.upload',  name: '页面 · 上传作品',     type: 'page', roles: ['admin','teacher','student'], on: true },
    { key: 'page.home',    name: '页面 · 我的主页',     type: 'page', roles: ['admin','teacher','student'], on: true },
    { key: 'page.admin',   name: '页面 · 权限管理入口', type: 'page', roles: ['admin'], on: true },
    { key: 'data.stats',   name: '数据 · 统计看板',     type: 'data', roles: ['admin','teacher'], on: true },
    { key: 'data.logs',    name: '数据 · 访问记录',     type: 'data', roles: ['admin'], on: true },
  ];
  // 把已有作品里的《植物大战僵尸》《贪吃蛇大作战》挂为示例作品资源
  const map = [['植物大战僵尸', 'work.pvz'], ['贪吃蛇大作战', 'work.snake']];
  map.forEach(([title, key]) => {
    const w = (db.works || []).find(x => x.title === title);
    res.push({
      key, name: '作品 · ' + title, type: 'work',
      roles: key === 'work.snake' ? ['admin','teacher','student'] : ['admin','teacher','student','guest'],
      on: true, workId: w ? w.id : ''
    });
  });
  return res;
}

/* ---------------- AI 沙龙 种子数据 ---------------- */
function defaultSalons() {
  return [
    {
      id: 'salon-05', no: 5,
      title: '小小 AI 音乐制作人',
      sub: 'AI 音乐家 · 180 分钟工作坊',
      status: '筹备中',
      dateText: '待定', timeText: '9:00–12:00',
      place: '现场 · 一人一台电脑',
      duration: '180 分钟',
      output: '1 首热梗歌 + 1 份汇报页',
      desc: '先听旋律找线索，再把想听见的声音写成提示词：给贪吃蛇配上 8bit 音乐，用校园热梗写一首 Rap，最后上台讲讲自己是怎么做出来的。',
      tags: ['猜歌名', 'AI 科普', '游戏配乐', '热梗写歌', '作品汇报'],
      points: [
        '暖场 · 上期沙龙回顾 + 新同学自我介绍（9:00–9:15）',
        '猜歌名 · 九首歌听片段，各队一起亮答案（9:15–9:20）',
        'AI 音乐制作科普 · 看《用 AI 做一首歌》，留意人和 AI 各做了什么（9:20–9:40）',
        '游戏配乐示范 · 给趣味贪吃蛇配一段 8bit 音乐（9:40–9:50）',
        '热梗写歌示范 · 用《课间操场梗声漫》走一遍完整流程（9:50–9:55）',
        '休息（9:55–10:15）',
        '游戏配乐实操 · 各组自己写提示词、生成配乐、接进游戏（10:15–10:35）',
        '热梗写歌制作 · 从找梗到合成，做一首自己的 Rap（10:35–10:55）',
        '制作汇报材料 · 用 AI 生成可在浏览器打开的汇报 HTML（10:55–11:05）',
        '上传作品 · 发布到小盒子 AI 乐园的个人主页（11:05–11:10）',
        '作品汇报 · 每人 5 分钟，边演示边讲制作过程（11:10–12:00）'
      ],
      photo: '',
      link: '/works/play/salon/05/index.html', linkText: '查看教师教案 ↗'
    },
    {
      id: 'salon-04', no: 4,
      title: 'AI 游戏沙龙 ·《植物大战僵尸》',
      sub: '6 个环节 · 180 分钟，从 AI 科普到作品演示',
      status: '已结束',
      dateText: '待补', timeText: '',
      place: '现场 · 一人一台电脑',
      duration: '180 分钟',
      output: '1 件可玩游戏',
      desc: '自我介绍 → AI 科普 → 试玩原作 → 拆解制作过程 → 现场用 AI 做自己的游戏 → 作品演示（家长参与）。',
      tags: ['AI 科普', '游戏制作', '作品演示'],
      points: [
        '小朋友自我介绍 · 说说自己想做的游戏（10 分钟）',
        'AI 知识科普 · AI 是什么、能帮我们做什么（10 分钟）',
        '《植物大战僵尸》试玩 · 先玩一遍，找找想改造的地方（10 分钟）',
        '拆解制作过程 · 一个游戏从头到尾怎么做出来（20 分钟）',
        '动手制作 · 用 AI 做出自己的小游戏（90 分钟）',
        '作品演示 · 作品介绍 HTML 与现场演示，家长参与（40 分钟）'
      ],
      photo: '',
      link: '/training-prep-poster/', linkText: '课前准备海报 ↗'
    },
    {
      id: 'salon-03', no: 3,
      title: 'AI 视频制作沙龙',
      sub: '用 AI 把一段想法做成视频',
      status: '已结束',
      dateText: '待补', timeText: '',
      place: '现场 · 一人一台电脑',
      duration: '180 分钟',
      output: '1 条 AI 短片',
      desc: '从一句想法到一条成片：现场写分镜、生成画面、配上音乐，每人交出一段自己的 AI 视频。',
      tags: ['AI 视频', '分镜', '成片'],
      points: [
        '想法与分镜 · 用一句话说清想拍的画面',
        '画面生成 · 用 AI 产出人物与场景',
        '配音配乐 · 给画面配上声音',
        '一起看片 · 每人放映自己的作品'
      ],
      photo: 'assets/salon/s3.jpg',
      link: '', linkText: ''
    },
    {
      id: 'salon-02', no: 2,
      title: 'AI 游戏沙龙',
      sub: '继续用 AI 做小游戏',
      status: '已结束',
      dateText: '待补', timeText: '',
      place: '现场 · 一人一台电脑',
      duration: '180 分钟',
      output: '1 件可玩游戏',
      desc: '接着第一次的玩法，这次把游戏做得更完整：加关卡、加音效、加胜利条件。',
      tags: ['AI 游戏', '动手制作'],
      points: [
        '回顾上一期作品 · 说说哪里还想改',
        '玩法拆解 · 一局游戏由哪几块组成',
        '动手制作 · 用 AI 把想法写成能玩的页面',
        '互相试玩 · 交换作品找问题再改'
      ],
      photo: 'assets/salon/s2.jpg',
      link: '', linkText: ''
    },
    {
      id: 'salon-01', no: 1,
      title: 'AI 游戏沙龙 ·《植物大战僵尸》',
      sub: '第一期开张',
      status: '已结束',
      dateText: '待补', timeText: '',
      place: '现场 · 一人一台电脑',
      duration: '180 分钟',
      output: '1 件可玩游戏',
      desc: '第一期开张：孩子们第一次用 AI 做出能玩的小游戏，从一句想法到点开就能玩的网页。',
      tags: ['AI 游戏', '第一次'],
      points: [
        '认识 AI · 它能帮我们做什么',
        '试玩《植物大战僵尸》 · 找想改造的地方',
        '动手制作 · 用 AI 做出自己的第一版游戏',
        '作品演示 · 点开就能玩'
      ],
      photo: 'assets/salon/s1.jpg',
      link: '', linkText: ''
    }
  ];
}

[DATA_DIR, SITES].forEach((d) => fs.mkdirSync(d, { recursive: true }));
/* ---------------- 存储 ---------------- */
function readJSON(file, fallback) {
  try { return JSON.parse(fs.readFileSync(file, 'utf8')); } catch (e) { return fallback; }
}
function writeJSON(file, obj) {
  const tmp = file + '.' + process.pid + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(obj, null, 2));
  fs.renameSync(tmp, file);
}

let db = readJSON(DB_FILE, null);
if (!db || !Array.isArray(db.students)) {
  db = { adminCode: 'admin' + crypto.randomBytes(3).toString('hex'), students: [], works: [] };
  writeJSON(DB_FILE, db);
}
if (!Array.isArray(db.works)) db.works = [];
if (!db.adminCode) db.adminCode = 'admin' + crypto.randomBytes(3).toString('hex');

/* ---------------- RBAC 引导/迁移 ---------------- */
let dbDirty = false;
if (!Array.isArray(db.roles) || !db.roles.length) { db.roles = defaultRoles(); dbDirty = true; }
if (!Array.isArray(db.resources) || !db.resources.length) { db.resources = defaultResources(); dbDirty = true; }
if (!Array.isArray(db.logs)) { db.logs = []; dbDirty = true; }
db.students.forEach((s) => {
  if (!Array.isArray(s.roles) || !s.roles.length) { s.roles = ['student']; dbDirty = true; }
});
if (!db.students.some((s) => s.py === 'admin')) {
  db.students.push({
    py: 'admin', name: 'admin', ava: '🛡️', tint: '#FCEBE9',
    grade: '', term: '', roles: ['admin'], code: process.env.ADMIN_SEED_CODE || '111111',
    created: Date.now()
  });
  dbDirty = true;
}
// 重新关联缺失 workId 的作品资源
db.resources.forEach((r) => {
  if (r.type === 'work' && !r.workId) {
    const title = String(r.name || '').replace('作品 · ', '');
    const w = db.works.find((x) => x.title === title);
    if (w) { r.workId = w.id; dbDirty = true; }
  }
});
/* 赛事数据 / 订阅名单 引导 */
if (!Array.isArray(db.events)) { db.events = []; dbDirty = true; }
if (!Array.isArray(db.subs)) { db.subs = []; dbDirty = true; }
/* 沙龙期次引导（仅首次缺字段时写入，清空后不会复活） */
if (!Array.isArray(db.salons)) { db.salons = defaultSalons(); dbDirty = true; }
/* 新增权限点时同步超管（admin 角色恒为全权限） */
const adminRole = db.roles.find((r) => r.key === 'admin');
if (adminRole && (adminRole.perms || []).length !== ALL_PERMS.length) {
  adminRole.perms = ALL_PERMS.slice();
  dbDirty = true;
}
if (dbDirty) writeJSON(DB_FILE, db);

const sessions = readJSON(SESS_FILE, {});
function saveSessions() { writeJSON(SESS_FILE, sessions); }

/* ---------------- 小工具 ---------------- */
const PUBLIC_STUDENT = (s) => ({
  py: s.py, name: s.name, ava: s.ava || '🙂', tint: s.tint || '#EDE7FF',
  grade: s.grade || '', term: s.term || '',
  system: !!s.system
});

function today() { return new Date().toISOString().slice(0, 10); }
function rid(prefix) { return prefix + Date.now().toString(36) + crypto.randomBytes(2).toString('hex'); }
function newCode() { return String(crypto.randomInt(100000, 1000000)); }

function send(res, code, obj) {
  const body = Buffer.from(JSON.stringify(obj));
  res.writeHead(code, {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store',
    'Content-Length': body.length
  });
  res.end(body);
}

function readBody(req, max) {
  const limit = max || MAX_BODY;
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks = [];
    req.on('data', (c) => {
      size += c.length;
      if (size > limit) { reject(Object.assign(new Error('文件太大'), { status: 413 })); req.destroy(); return; }
      chunks.push(c);
    });
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

function bearer(req) {
  const h = String(req.headers.authorization || '');
  const t = h.replace(/^Bearer\s+/i, '').trim();
  if (!t) return null;
  const s = sessions[t];
  if (!s) return null;
  if (s.exp < Date.now()) { delete sessions[t]; saveSessions(); return null; }
  return s;
}
function issueToken(py) {
  const t = crypto.randomBytes(24).toString('hex');
  sessions[t] = { py, exp: Date.now() + TOKEN_TTL };
  saveSessions();
  return t;
}

function safeLink(v) {
  const s = String(v || '').trim().slice(0, 400);
  if (!s) return '';
  if (/^https?:\/\/[^\s"'<>]+$/i.test(s)) return s;
  if (/^\/[A-Za-z0-9\-_./?=&%#]*$/.test(s)) return s;
  return '';
}

function isHtmlFile(text) {
  return /<\s*(!doctype|html|head|body|script|canvas|div)/i.test(text.slice(0, 4000));
}

/* ---------------- ZIP 解包（零依赖：stored + deflate） ---------------- */
const ZIP_MAX_FILES = 2000;
const ZIP_MAX_B64 = 100 * 1024 * 1024;      /* 压缩包原始大小上限 */
const ZIP_MAX_TOTAL = 400 * 1024 * 1024;    /* 解压后总大小上限 */
const ZIP_BLOCK_EXT = /\.(php|phtml|phar|cgi|pl|py|sh|bash|exe|dll|so|bat|cmd|jsp|asp|aspx)$/i;

function zipReadEntries(buf) {
  if (buf.length < 22) return null;
  let eocd = -1;
  const floor = Math.max(0, buf.length - 65557);
  for (let i = buf.length - 22; i >= floor; i--) {
    if (buf.readUInt32LE(i) === 0x06054b50) { eocd = i; break; }
  }
  if (eocd < 0) return null;
  const total = buf.readUInt16LE(eocd + 10);
  if (total === 0xffff) return 'ZIP64';
  const cdOff = buf.readUInt32LE(eocd + 16);
  if (cdOff <= 0 || cdOff >= buf.length) return null;
  const list = [];
  let p = cdOff;
  for (let n = 0; n < total; n++) {
    if (p + 46 > buf.length || buf.readUInt32LE(p) !== 0x02014b50) break;
    const method = buf.readUInt16LE(p + 10);
    const csize = buf.readUInt32LE(p + 20);
    const usize = buf.readUInt32LE(p + 24);
    const nlen = buf.readUInt16LE(p + 28);
    const elen = buf.readUInt16LE(p + 30);
    const clen = buf.readUInt16LE(p + 32);
    const lho = buf.readUInt32LE(p + 42);
    if (csize === 0xffffffff || usize === 0xffffffff || lho === 0xffffffff) return 'ZIP64';
    list.push({ name: buf.toString('utf8', p + 46, p + 46 + nlen), method, csize, lho });
    p += 46 + nlen + elen + clen;
  }
  return list;
}

function unzipSafe(buf) {
  const entries = zipReadEntries(buf);
  if (entries === 'ZIP64') throw new Error('压缩包格式不受支持（ZIP64），请用普通 zip 重新打包');
  if (!entries || !entries.length) throw new Error('这不是一个有效的 zip 压缩包');
  if (entries.length > ZIP_MAX_FILES) throw new Error('压缩包内文件太多（上限 ' + ZIP_MAX_FILES + ' 个）');

  const out = [];
  let total = 0;
  for (const e of entries) {
    const name = String(e.name || '').replace(/\\/g, '/');
    if (!name || name.endsWith('/')) continue;
    if (/(^|\/)__MACOSX\//i.test(name) || /(^|\/)\.DS_Store$/i.test(name)) continue;
    if (name.startsWith('/') || name.indexOf('..') >= 0 || name.indexOf(':') >= 0) {
      throw new Error('压缩包内存在非法路径');
    }
    if (ZIP_BLOCK_EXT.test(name)) throw new Error('压缩包内含有不允许的文件类型');
    if (e.lho + 30 > buf.length) throw new Error('压缩包结构损坏');
    const nl = buf.readUInt16LE(e.lho + 26);
    const el = buf.readUInt16LE(e.lho + 28);
    const start = e.lho + 30 + nl + el;
    const end = start + e.csize;
    if (end > buf.length) throw new Error('压缩包结构损坏');
    let data;
    try {
      data = e.method === 0 ? Buffer.from(buf.subarray(start, end)) : zlib.inflateRawSync(buf.subarray(start, end));
    } catch (err) {
      throw new Error('压缩包解压失败（可能已加密）');
    }
    total += data.length;
    if (total > ZIP_MAX_TOTAL) throw new Error('解压后总大小超过 ' + (ZIP_MAX_TOTAL / 1024 / 1024) + 'MB');
    out.push({ name, data });
  }
  if (!out.length) throw new Error('压缩包里没有可用文件');
  return out;
}

/* 入口 HTML：根目录 index.html > 根目录唯一 html > 路径最短的 html */
function pickEntryHtml(files) {
  const htmls = files.filter((f) => /\.html?$/i.test(f.name));
  if (!htmls.length) return '';
  const rootIndex = htmls.find((f) => /^index\.html?$/i.test(f.name));
  if (rootIndex) return rootIndex.name;
  const rootAny = htmls.filter((f) => f.name.indexOf('/') < 0);
  if (rootAny.length === 1) return rootAny[0].name;
  htmls.sort((a, b) => a.name.length - b.name.length || (a.name < b.name ? -1 : 1));
  return htmls[0].name;
}

/* 登录失败限流：ip -> {n, until} */
const fails = new Map();
function tooMany(ip) {
  const f = fails.get(ip);
  return !!(f && f.until && f.until > Date.now());
}
function markFail(ip) {
  const f = fails.get(ip) || { n: 0, until: 0 };
  f.n += 1;
  if (f.n >= 8) { f.until = Date.now() + 10 * 60 * 1000; f.n = 0; }
  fails.set(ip, f);
}
function clearFail(ip) { fails.delete(ip); }

/* ---------------- RBAC 核心 ---------------- */
function userRoles(py) {
  if (!py) return ['guest'];
  const s = db.students.find((x) => x.py === py);
  return (s && Array.isArray(s.roles) && s.roles.length) ? s.roles : ['guest'];
}
function permsOf(py) {
  const set = {};
  userRoles(py).forEach((rk) => {
    const r = db.roles.find((x) => x.key === rk);
    if (r && Array.isArray(r.perms)) r.perms.forEach((p) => { set[p] = 1; });
  });
  return Object.keys(set);
}
function hasPerm(py, perm) { return permsOf(py).indexOf(perm) >= 0; }

function resVisible(py, resKey) {
  const r = db.resources.find((x) => x.key === resKey);
  if (!r) return true;
  if (r.on === false) return false;
  const rs = userRoles(py);
  return (r.roles || []).some((k) => rs.indexOf(k) >= 0);
}

function audit(who, act, desc) {
  db.logs.unshift({ t: new Date().toISOString().slice(0, 19).replace('T', ' '), act, who, desc });
  if (db.logs.length > 500) db.logs.length = 500;
  writeJSON(DB_FILE, db);
}

function pyBearer(req) {
  const s = bearer(req);
  return s ? s.py : null;
}

/* ---------------- 业务 ---------------- */
function handleData(req, res) {
  const viewer = pyBearer(req);
  const viewerRoles = viewer ? userRoles(viewer) : ['guest'];
  const works = db.works.slice().sort((a, b) => (b.created || 0) - (a.created || 0)).map((w) => {
    const r = db.resources.find((x) => x.type === 'work' && x.workId && x.workId === w.id);
    const locked = !!r && (r.on === false || !(r.roles || []).some((k) => viewerRoles.indexOf(k) >= 0));
    return Object.assign({}, w, { locked: !!locked });
  });
  send(res, 200, {
    students: db.students.map(PUBLIC_STUDENT),
    works,
    salons: db.salons.slice().sort((a, b) => (b.no || 0) - (a.no || 0)),
    stats: { works: db.works.length, students: db.students.length }
  });
}

function handleLogin(req, res, body, ip) {
  if (tooMany(ip)) return send(res, 429, { error: '尝试次数过多，请 10 分钟后再试' });
  const py = String(body.py || '').trim();
  const code = String(body.code || '').trim();
  const stu = db.students.find((s) => s.py === py);
  if (!stu || !code || stu.code !== code) {
    markFail(ip);
    audit(py || '未知', 'deny', '登录失败（账号或密码不对）');
    return send(res, 401, { error: '账号或密码不对，请再试一次' });
  }
  if (stu.off) {
    audit(py, 'deny', '登录被拒（账号已停用）');
    return send(res, 403, { error: '账号已停用，请联系老师' });
  }
  clearFail(ip);
  audit(py, 'allow', '登录系统');
  send(res, 200, { token: issueToken(py), student: PUBLIC_STUDENT(stu), perms: permsOf(py) });
}

function handleMe(req, res) {
  const py = pyBearer(req);
  const stu = py ? db.students.find((x) => x.py === py) : null;
  if (!stu) return send(res, 401, { error: '未登录' });
  send(res, 200, {
    student: PUBLIC_STUDENT(stu),
    roles: userRoles(py).map((k) => {
      const r = db.roles.find((x) => x.key === k);
      return { key: k, name: r ? r.name : k };
    }),
    perms: permsOf(py),
    canAdmin: hasPerm(py, 'role:manage') && resVisible(py, 'page.admin')
  });
}

/* 解包 zip 并落到 sites/<py>/<slug>/，返回 {url} 或 {error,status} */
function buildZipWork(stu, buf) {
  if (!buf.length) return { error: '压缩包是空的', status: 400 };
  if (buf.length > ZIP_MAX_B64) return { error: '压缩包超过 100MB', status: 413 };
  let files;
  try { files = unzipSafe(buf); } catch (e) { return { error: e.message, status: 400 }; }
  const entry = pickEntryHtml(files);
  if (!entry) return { error: '压缩包里没有 .html 文件', status: 400 };

  const slug = rid('w');
  const dir = path.join(SITES, stu.py, slug);
  fs.mkdirSync(dir, { recursive: true });
  try {
    for (const f of files) {
      const dest = path.join(dir, f.name);
      if (!dest.startsWith(dir + path.sep)) continue;
      fs.mkdirSync(path.dirname(dest), { recursive: true });
      fs.writeFileSync(dest, f.data);
    }
  } catch (e) {
    try { fs.rmSync(dir, { recursive: true, force: true }); } catch (_) {}
    return { error: '写入作品文件失败，请稍后重试', status: 500 };
  }
  const entryPath = entry.split('/').map(encodeURIComponent).join('/');
  return { url: '/works/play/' + stu.py + '/' + slug + '/' + entryPath };
}

/* 落库 + 审计 */
function commitWork(py, stu, meta, url, source) {
  const work = {
    id: rid('k'), py: stu.py,
    title: String(meta.title || '').trim().slice(0, 24),
    desc: String(meta.desc || '').trim().slice(0, 60),
    type: TYPES.indexOf(meta.type) >= 0 ? meta.type : '小游戏',
    emoji: EMOJIS.indexOf(meta.emoji) >= 0 ? meta.emoji : '🎮',
    url, source, likes: 0, date: today(), created: Date.now()
  };
  db.works.unshift(work);
  writeJSON(DB_FILE, db);
  audit(py, 'allow', '上传作品《' + work.title + '》');
  return work;
}

function handlePublish(req, res, body) {
  const py = pyBearer(req);
  if (!py) return send(res, 401, { error: '登录已过期，请重新登录' });
  if (!hasPerm(py, 'works:upload')) {
    audit(py, 'deny', '尝试上传作品《' + String(body.title || '').slice(0, 24) + '》→ 拦截（缺少 works:upload 权限）');
    return send(res, 403, { error: '当前账号没有上传作品的权限' });
  }
  const stu = db.students.find((x) => x.py === py);
  if (!stu) return send(res, 401, { error: '账号不存在' });

  const title = String(body.title || '').trim().slice(0, 24);
  if (!title) return send(res, 400, { error: '请给作品起个名字' });
  const desc = String(body.desc || '').trim().slice(0, 60);
  const type = TYPES.indexOf(body.type) >= 0 ? body.type : '小游戏';
  const emoji = EMOJIS.indexOf(body.emoji) >= 0 ? body.emoji : '🎮';

  let url = '';
  let source = 'link';

  const html = body.html && typeof body.html.content === 'string' ? body.html.content : '';
  const zipB64 = body.zip && typeof body.zip.data === 'string' ? body.zip.data : '';
  if (html) {
    if (Buffer.byteLength(html) > 8 * 1024 * 1024) return send(res, 413, { error: '文件超过 8MB' });
    if (!isHtmlFile(html)) return send(res, 400, { error: '这不是一个 HTML 文件' });
    const slug = rid('w');
    const dir = path.join(SITES, stu.py, slug);
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(path.join(dir, 'index.html'), html, 'utf8');
    url = '/works/play/' + stu.py + '/' + slug + '/';
    source = 'upload';
  } else if (zipB64) {
    let buf;
    try { buf = Buffer.from(zipB64, 'base64'); } catch (e) { return send(res, 400, { error: '压缩包数据异常' }); }
    const r = buildZipWork(stu, buf);
    if (r.error) return send(res, r.status || 400, { error: r.error });
    url = r.url;
    source = 'upload';
  } else {
    url = safeLink(body.link);
    if (String(body.link || '').trim() && !url) return send(res, 400, { error: '作品链接格式不对，需以 http(s):// 或 / 开头' });
  }

  const work = {
    id: rid('k'), py: stu.py, title, desc, type, emoji, url, source,
    likes: 0, date: today(), created: Date.now()
  };
  db.works.unshift(work);
  writeJSON(DB_FILE, db);
  audit(py, 'allow', '上传作品《' + title + '》');
  send(res, 200, { work });
}

/* 压缩包二进制直传：body 就是 zip 原始字节，作品信息放 X-Work-Meta（base64 JSON） */
async function handlePublishZip(req, res) {
  const py = pyBearer(req);
  if (!py) return send(res, 401, { error: '登录已过期，请重新登录' });
  if (!hasPerm(py, 'works:upload')) {
    audit(py, 'deny', '尝试上传压缩包作品 → 拦截（缺少 works:upload 权限）');
    return send(res, 403, { error: '当前账号没有上传作品的权限' });
  }
  const stu = db.students.find((x) => x.py === py);
  if (!stu) return send(res, 401, { error: '账号不存在' });

  let meta = {};
  try {
    const rawMeta = Buffer.from(String(req.headers['x-work-meta'] || ''), 'base64').toString('utf8');
    meta = rawMeta ? JSON.parse(rawMeta) : {};
  } catch (e) { return send(res, 400, { error: '作品信息解析失败，请重试' }); }
  if (!String(meta.title || '').trim()) return send(res, 400, { error: '请给作品起个名字' });

  const declared = Number(req.headers['content-length'] || 0);
  if (declared > MAX_ZIP_BODY) return send(res, 413, { error: '压缩包超过 100MB' });

  let raw;
  try {
    raw = await readBody(req, MAX_ZIP_BODY);
  } catch (e) {
    return send(res, 413, { error: '压缩包超过 100MB' });
  }

  const r = buildZipWork(stu, raw);
  if (r.error) return send(res, r.status || 400, { error: r.error });

  send(res, 200, { work: commitWork(py, stu, meta, r.url, 'upload') });
}

/* ---------------- MP3 作品：直传音频 + 自动生成播放页 ---------------- */
function escHTML(v) {
  return String(v == null ? '' : v).replace(/[&<>"']/g, (c) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
  }[c]));
}

function isMp3Buf(buf) {
  if (buf.length < 128) return false;
  if (buf.slice(0, 3).toString('latin1') === 'ID3') return true;      // 带 ID3v2 标签
  if (buf[0] === 0xFF && (buf[1] & 0xE0) === 0xE0) return true;       // MPEG 帧同步
  return false;
}

/* 生成一个干净的音频播放页（作品在画廊里点「试听」直接打开这一页） */
function buildAudioPage(meta, author, file) {
  const title = escHTML(meta.title || '我的 AI 音乐作品');
  const desc = escHTML(meta.desc || '');
  const emoji = escHTML(meta.emoji || '🎵');
  const who = escHTML(author);
  const src = escHTML(file);
  return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>${title}｜小盒子 AI 乐园</title>
<meta name="description" content="${desc || title}">
<style>
  *{box-sizing:border-box}
  html,body{height:100%}
  body{
    margin:0; display:flex; align-items:center; justify-content:center; padding:24px;
    font-family:-apple-system,BlinkMacSystemFont,"PingFang SC","Microsoft YaHei",sans-serif;
    background:radial-gradient(1200px 600px at 12% 8%,#EDE9FF 0%,transparent 60%),
               radial-gradient(900px 500px at 88% 92%,#E6F4FF 0%,transparent 58%),
               linear-gradient(160deg,#FBFAFF,#F4F2FF 65%,#EEECFB);
    color:#232045;
  }
  .card{
    width:100%; max-width:520px; background:#fff; border:1px solid rgba(91,82,196,.14);
    border-radius:24px; padding:30px 28px 24px; text-align:center;
    box-shadow:0 24px 60px rgba(56,44,132,.14), 0 2px 6px rgba(56,44,132,.06);
  }
  .disc{
    width:96px; height:96px; margin:0 auto 16px; border-radius:50%;
    display:grid; place-items:center; font-size:40px; line-height:1;
    background:linear-gradient(140deg,#EDE7FF,#D6CDFF); box-shadow:inset 0 0 0 8px rgba(255,255,255,.6);
    animation:spin 9s linear infinite;
  }
  @keyframes spin{to{transform:rotate(360deg)}}
  @media (prefers-reduced-motion: reduce){.disc{animation:none}}
  .tag{display:inline-block; font-size:11px; letter-spacing:1.4px; font-weight:700; color:#6C63D6; margin-bottom:8px}
  h1{margin:0 0 8px; font-size:22px; line-height:1.4; letter-spacing:-.2px; word-break:break-word}
  .desc{margin:0 0 20px; font-size:13.5px; line-height:1.7; color:#6b6890}
  audio{width:100%; height:46px; display:block}
  .who{margin:18px 0 0; display:flex; align-items:center; justify-content:center; gap:8px; font-size:13px; color:#6b6890}
  .ava{width:24px; height:24px; border-radius:50%; background:#EDE7FF; display:grid; place-items:center; font-size:12px}
  .foot{margin:18px 0 0; padding-top:14px; border-top:1px dashed #EDEBF7; font-size:11.5px; color:#a3a1b8}
  .foot a{color:#6C63D6; text-decoration:none}
</style>
</head>
<body>
  <main class="card">
    <div class="disc">${emoji}</div>
    <div class="tag">AI MUSIC · 小作者作品</div>
    <h1>${title}</h1>
    ${desc ? `<p class="desc">${desc}</p>` : '<p class="desc">用 AI 做出来的一首曲子，戴上耳机听听看。</p>'}
    <audio controls preload="metadata" src="${src}"></audio>
    <p class="who"><span class="ava">${escHTML(author.slice(0, 1))}</span>${who} · 小盒子 AI 乐园</p>
    <p class="foot">这首曲子由小朋友在 AI 沙龙现场创作 · <a href="/works/#gallery">看看更多作品 →</a></p>
  </main>
</body>
</html>`;
}

/* MP3 二进制直传：body 就是音频原始字节，作品信息放 X-Work-Meta（base64 JSON） */
async function handlePublishAudio(req, res) {
  const py = pyBearer(req);
  if (!py) return send(res, 401, { error: '登录已过期，请重新登录' });
  if (!hasPerm(py, 'works:upload')) {
    audit(py, 'deny', '尝试上传音频作品 → 拦截（缺少 works:upload 权限）');
    return send(res, 403, { error: '当前账号没有上传作品的权限' });
  }
  const stu = db.students.find((x) => x.py === py);
  if (!stu) return send(res, 401, { error: '账号不存在' });

  let meta = {};
  try {
    const rawMeta = Buffer.from(String(req.headers['x-work-meta'] || ''), 'base64').toString('utf8');
    meta = rawMeta ? JSON.parse(rawMeta) : {};
  } catch (e) { return send(res, 400, { error: '作品信息解析失败，请重试' }); }
  if (!String(meta.title || '').trim()) return send(res, 400, { error: '请给作品起个名字' });

  const declared = Number(req.headers['content-length'] || 0);
  if (declared > MAX_AUDIO_BODY) return send(res, 413, { error: '音频超过 30MB，请压缩后再传' });

  let raw;
  try {
    raw = await readBody(req, MAX_AUDIO_BODY);
  } catch (e) {
    return send(res, 413, { error: '音频超过 30MB，请压缩后再传' });
  }
  if (!raw.length) return send(res, 400, { error: '音频是空的，请重新选择文件' });
  if (!isMp3Buf(raw)) return send(res, 400, { error: '这不是一个 MP3 文件，请确认后重试' });

  const slug = rid('w');
  const dir = path.join(SITES, stu.py, slug);
  fs.mkdirSync(dir, { recursive: true });
  try {
    fs.writeFileSync(path.join(dir, 'audio.mp3'), raw);
    fs.writeFileSync(path.join(dir, 'index.html'), buildAudioPage(meta, stu.name, 'audio.mp3'), 'utf8');
  } catch (e) {
    try { fs.rmSync(dir, { recursive: true, force: true }); } catch (_) {}
    return send(res, 500, { error: '写入作品文件失败，请稍后重试' });
  }

  const url = '/works/play/' + stu.py + '/' + slug + '/';
  send(res, 200, { work: commitWork(py, stu, Object.assign({}, meta, { type: '音乐' }), url, 'upload') });
}

/* ---------------- MP4 作品：直传视频 + 自动生成播放页 ---------------- */
function isMp4Buf(buf) {
  /* ISO BMFF：第 5–8 字节为 'ftyp'，兼容 mp4/m4v 与 fMP4 */
  return buf.length > 12 && buf.toString('latin1', 4, 8) === 'ftyp';
}

function buildVideoPage(meta, author, file) {
  const title = escHTML(meta.title || '我的 AI 视频作品');
  const desc = escHTML(meta.desc || '');
  const emoji = escHTML(meta.emoji || '🎬');
  const who = escHTML(author);
  const src = escHTML(file);
  return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>${title}｜小盒子 AI 乐园</title>
<meta name="description" content="${desc || title}">
<style>
  *{box-sizing:border-box}
  body{
    margin:0; min-height:100vh; display:flex; flex-direction:column; align-items:center; justify-content:center;
    gap:16px; padding:22px 18px 30px;
    font-family:-apple-system,BlinkMacSystemFont,"PingFang SC","Microsoft YaHei",sans-serif;
    background:radial-gradient(900px 520px at 15% 6%,#2B2550 0%,transparent 62%),
               radial-gradient(760px 460px at 86% 94%,#1C2A44 0%,transparent 60%),
               #14121F;
    color:#F2F0FA;
  }
  .stage{
    width:100%; max-width:920px; background:#000; border-radius:18px; overflow:hidden;
    box-shadow:0 26px 60px rgba(0,0,0,.55), 0 0 0 1px rgba(255,255,255,.08);
    display:flex; align-items:center; justify-content:center;
  }
  video{display:block; width:100%; max-height:74vh; background:#000}
  .meta{width:100%; max-width:920px; text-align:left}
  .tag{display:inline-flex; align-items:center; gap:6px; font-size:11px; letter-spacing:1.4px; font-weight:700; color:#B9AEFF}
  h1{margin:8px 0 6px; font-size:20px; line-height:1.45; letter-spacing:-.2px; word-break:break-word}
  .desc{margin:0 0 10px; font-size:13.5px; line-height:1.7; color:#B6B2CC}
  .who{margin:0; display:flex; align-items:center; gap:8px; font-size:12.5px; color:#8E8AA8}
  .ava{width:24px; height:24px; border-radius:50%; background:#2C2748; display:flex; align-items:center; justify-content:center; font-size:12px; font-weight:600; flex:0 0 auto}
  .who a{color:#B9AEFF; text-decoration:none}
  @media (max-width:560px){
    body{padding:12px 10px 20px; gap:12px}
    .stage{border-radius:12px}
    video{max-height:64vh}
    h1{font-size:17px}
  }
</style>
</head>
<body>
  <div class="stage">
    <video controls playsinline preload="metadata" controlslist="nodownload" src="${src}"></video>
  </div>
  <div class="meta">
    <span class="tag">${emoji} AI VIDEO · 小作者作品</span>
    <h1>${title}</h1>
    ${desc ? `<p class="desc">${desc}</p>` : '<p class="desc">用 AI 做出来的一段视频，点播放看看。</p>'}
    <p class="who"><span class="ava">${escHTML(author.slice(0, 1))}</span>${who} · 小盒子 AI 乐园 · <a href="/works/#gallery">更多作品 →</a></p>
  </div>
</body>
</html>`;
}

/* MP4 二进制直传：body 就是视频原始字节，作品信息放 X-Work-Meta（base64 JSON） */
async function handlePublishVideo(req, res) {
  const py = pyBearer(req);
  if (!py) return send(res, 401, { error: '登录已过期，请重新登录' });
  if (!hasPerm(py, 'works:upload')) {
    audit(py, 'deny', '尝试上传视频作品 → 拦截（缺少 works:upload 权限）');
    return send(res, 403, { error: '当前账号没有上传作品的权限' });
  }
  const stu = db.students.find((x) => x.py === py);
  if (!stu) return send(res, 401, { error: '账号不存在' });

  let meta = {};
  try {
    const rawMeta = Buffer.from(String(req.headers['x-work-meta'] || ''), 'base64').toString('utf8');
    meta = rawMeta ? JSON.parse(rawMeta) : {};
  } catch (e) { return send(res, 400, { error: '作品信息解析失败，请重试' }); }
  if (!String(meta.title || '').trim()) return send(res, 400, { error: '请给作品起个名字' });

  const declared = Number(req.headers['content-length'] || 0);
  if (declared > MAX_VIDEO_BODY) return send(res, 413, { error: '视频超过 100MB，请压缩后再传' });

  let raw;
  try {
    raw = await readBody(req, MAX_VIDEO_BODY);
  } catch (e) {
    return send(res, 413, { error: '视频超过 100MB，请压缩后再传' });
  }
  if (!raw.length) return send(res, 400, { error: '视频是空的，请重新选择文件' });
  if (!isMp4Buf(raw)) return send(res, 400, { error: '这不是一个 MP4 文件，请确认后重试' });

  const slug = rid('w');
  const dir = path.join(SITES, stu.py, slug);
  fs.mkdirSync(dir, { recursive: true });
  try {
    fs.writeFileSync(path.join(dir, 'video.mp4'), raw);
    fs.writeFileSync(path.join(dir, 'index.html'), buildVideoPage(meta, stu.name, 'video.mp4'), 'utf8');
  } catch (e) {
    try { fs.rmSync(dir, { recursive: true, force: true }); } catch (_) {}
    return send(res, 500, { error: '写入作品文件失败，请稍后重试' });
  }

  const url = '/works/play/' + stu.py + '/' + slug + '/';
  send(res, 200, { work: commitWork(py, stu, Object.assign({}, meta, { type: '视频' }), url, 'upload') });
}

function safeRemoveWorkDir(url, py) {
  const m = /^\/works\/play\/([a-z0-9]+)\/([a-z0-9]+)(?:\/|$)/.exec(String(url || ''));
  if (!m || m[1] !== py) return;
  const dir = path.join(SITES, m[1], m[2]);
  if (dir.startsWith(SITES + '/') && fs.existsSync(dir)) {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

function handleDelete(req, res, body) {
  const py = pyBearer(req);
  if (!py) return send(res, 401, { error: '登录已过期，请重新登录' });
  const id = String(body.id || '');
  const idx = db.works.findIndex((w) => w.id === id);
  if (idx === -1) return send(res, 404, { error: '作品不存在' });
  const own = db.works[idx].py === py;
  if (own ? !hasPerm(py, 'works:del:own') : !hasPerm(py, 'works:del:any')) {
    audit(py, 'deny', '尝试删除作品《' + db.works[idx].title + '》→ 拦截（' + (own ? '缺少 works:del:own' : '缺少 works:del:any') + '）');
    return send(res, 403, { error: own ? '当前账号没有删除作品的权限' : '只能删除自己的作品' });
  }
  const work = db.works.splice(idx, 1)[0];
  // 删除他人作品时，作品的静态文件只清本人的归属目录
  if (own) safeRemoveWorkDir(work.url, py);
  writeJSON(DB_FILE, db);
  audit(py, 'allow', (own ? '删除自己' : '删除他人') + '作品《' + work.title + '》');
  send(res, 200, { ok: true });
}

function handleLike(res, body) {
  const id = String(body.id || '');
  const w = db.works.find((x) => x.id === id);
  if (!w) return send(res, 404, { error: '作品不存在' });
  w.likes = (w.likes || 0) + 1;
  writeJSON(DB_FILE, db);
  send(res, 200, { likes: w.likes });
}

function handlePassword(req, res, body) {
  const py = pyBearer(req);
  if (!py) return send(res, 401, { error: '请先登录' });
  const stu = db.students.find((x) => x.py === py);
  if (!stu) return send(res, 404, { error: '账号不存在' });
  const oldCode = String(body.oldCode || '').trim();
  const newCode = String(body.newCode || '').trim();
  if (stu.code !== oldCode) return send(res, 403, { error: '原密码不对' });
  if (!/^\d{6}$/.test(newCode)) return send(res, 400, { error: '新密码需为 6 位数字' });
  stu.code = newCode;
  writeJSON(DB_FILE, db);
  audit(py, 'allow', '修改了自己的密码');
  send(res, 200, { ok: true });
}

/* adminCode 或 stu:manage 权限均可走管理接口 */
function adminAuth(req, body) {
  if (String(body.adminCode || '') === db.adminCode) return 'adminCode';
  const py = pyBearer(req);
  if (py && hasPerm(py, 'stu:manage')) return py;
  return null;
}

function handleAdminStudent(req, res, body) {
  const who = adminAuth(req, body);
  if (!who) return send(res, 403, { error: '需要管理员或学员管理权限' });
  const name = String(body.name || '').trim().slice(0, 20);
  const py = String(body.py || '').trim().toLowerCase();
  if (!name) return send(res, 400, { error: '缺少姓名' });
  if (!/^[a-z][a-z0-9]{2,19}$/.test(py)) return send(res, 400, { error: '拼音标识需 3-20 位小写字母数字，且字母开头' });
  if (db.students.some((s) => s.py === py)) return send(res, 409, { error: '该拼音标识已存在' });
  const tints = ['#FFE4EF', '#E2E6FF', '#FFF4D6', '#DFF5EC', '#EDE7FF', '#FFE9D6', '#E4F4FB'];
  const stu = {
    py, name,
    ava: String(body.ava || '🙂').slice(0, 4),
    tint: tints[db.students.length % tints.length],
    grade: String(body.grade || '').slice(0, 10),
    term: String(body.term || '').slice(0, 12),
    roles: ['student'],
    code: newCode(),
    created: Date.now()
  };
  db.students.push(stu);
  writeJSON(DB_FILE, db);
  audit(who, 'allow', '新增学员「' + name + '」(' + py + ')');
  send(res, 200, { student: PUBLIC_STUDENT(stu), code: stu.code, nginxHint: 'location = /' + py + ' 与 location /' + py + '/ 需在服务器补一条' });
}

function handleAdminReset(req, res, body) {
  const who = adminAuth(req, body);
  if (!who) return send(res, 403, { error: '需要管理员或学员管理权限' });
  const stu = db.students.find((s) => s.py === String(body.py || ''));
  if (!stu) return send(res, 404, { error: '学员不存在' });
  stu.code = newCode();
  writeJSON(DB_FILE, db);
  audit(who, 'allow', '重置「' + stu.name + '」的密码');
  send(res, 200, { py: stu.py, name: stu.name, code: stu.code });
}

function handleAdminList(res, query) {
  if (String(query.get('adminCode') || '') !== db.adminCode) return send(res, 403, { error: '管理员口令不对' });
  send(res, 200, {
    adminCode: db.adminCode,
    students: db.students.map((s) => Object.assign(PUBLIC_STUDENT(s), { code: s.code, works: db.works.filter((w) => w.py === s.py).length })),
    works: db.works
  });
}

/* ---------------- RBAC 接口 ---------------- */
function rbacUser(req, res) {
  const py = pyBearer(req);
  if (!py) { send(res, 401, { error: '未登录' }); return null; }
  if (!hasPerm(py, 'role:manage')) {
    audit(py, 'deny', '尝试进入权限管理 → 拦截（缺少 role:manage 权限）');
    send(res, 403, { error: '需要「角色与授权管理」权限' });
    return null;
  }
  return py;
}

function handleRbacGet(req, res) {
  const py = rbacUser(req, res);
  if (!py) return;
  const users = db.students.map((s) => Object.assign(PUBLIC_STUDENT(s), {
    roles: (s.roles || []).slice(),
    code: s.code,
    off: !!s.off,
    works: db.works.filter((w) => w.py === s.py).length,
    builtin: s.py === 'admin'
  }));
  send(res, 200, {
    perms: PERM_GROUPS,
    roles: db.roles,
    resources: db.resources,
    users,
    logs: hasPerm(py, 'log:view') ? db.logs : [],
    canViewLogs: hasPerm(py, 'log:view'),
    me: py
  });
}

function handleRoleSave(req, res, body) {
  const py = rbacUser(req, res);
  if (!py) return;
  const name = String(body.name || '').trim().slice(0, 20);
  let perms = Array.isArray(body.perms) ? body.perms.filter((p) => ALL_PERMS.indexOf(p) >= 0) : [];
  const key = String(body.key || '').trim();

  if (key) {
    const role = db.roles.find((r) => r.key === key);
    if (!role) return send(res, 404, { error: '角色不存在' });
    if (key === 'admin' && perms.indexOf('role:manage') < 0) {
      return send(res, 400, { error: '超级管理员必须保留「角色与授权管理」权限' });
    }
    role.perms = perms;
    writeJSON(DB_FILE, db);
    audit(py, 'allow', '更新角色「' + role.name + '」的权限（' + perms.length + ' 项）');
    return send(res, 200, { role });
  }
  if (!name) return send(res, 400, { error: '请填写角色名称' });
  if (db.roles.some((r) => r.name === name)) return send(res, 409, { error: '已存在同名角色' });
  if (!perms.length) perms = ['works:view'];
  const role = { key: 'c' + Date.now().toString(36), name, builtin: false, perms };
  db.roles.push(role);
  writeJSON(DB_FILE, db);
  audit(py, 'allow', '新建角色「' + name + '」');
  send(res, 200, { role });
}

function handleRoleDelete(req, res, body) {
  const py = rbacUser(req, res);
  if (!py) return;
  const key = String(body.key || '');
  const role = db.roles.find((r) => r.key === key);
  if (!role) return send(res, 404, { error: '角色不存在' });
  if (role.builtin) return send(res, 400, { error: '内置角色不能删除' });
  db.roles = db.roles.filter((r) => r.key !== key);
  db.students.forEach((s) => { if (Array.isArray(s.roles)) s.roles = s.roles.filter((k) => k !== key); });
  db.resources.forEach((r) => { if (Array.isArray(r.roles)) r.roles = r.roles.filter((k) => k !== key); });
  writeJSON(DB_FILE, db);
  audit(py, 'allow', '删除角色「' + role.name + '」');
  send(res, 200, { ok: true });
}

function handleUserRoles(req, res, body) {
  const py = rbacUser(req, res);
  if (!py) return;
  const target = db.students.find((s) => s.py === String(body.py || ''));
  if (!target) return send(res, 404, { error: '用户不存在' });
  if (target.py === 'admin') return send(res, 400, { error: 'admin 为内置账号，角色不可修改' });
  let roles = Array.isArray(body.roles) ? body.roles.filter((k) => db.roles.some((r) => r.key === k)) : [];
  if (!roles.length) return send(res, 400, { error: '至少保留一个角色' });
  const old = (target.roles || []).join('、');
  target.roles = roles;
  writeJSON(DB_FILE, db);
  audit(py, 'allow', '将「' + target.name + '」的角色从 [' + old + '] 调整为 [' + roles.join('、') + ']');
  send(res, 200, { ok: true });
}

function handleUserReset(req, res, body) {
  const py = rbacUser(req, res);
  if (!py) return;
  const target = db.students.find((s) => s.py === String(body.py || ''));
  if (!target) return send(res, 404, { error: '用户不存在' });
  target.code = newCode();
  writeJSON(DB_FILE, db);
  audit(py, 'allow', '重置「' + target.name + '」的密码');
  send(res, 200, { py: target.py, name: target.name, code: target.code });
}

function handleUserOff(req, res, body) {
  const py = rbacUser(req, res);
  if (!py) return;
  const target = db.students.find((s) => s.py === String(body.py || ''));
  if (!target) return send(res, 404, { error: '用户不存在' });
  if (target.py === 'admin') return send(res, 400, { error: 'admin 账号不能停用' });
  target.off = !!body.off;
  writeJSON(DB_FILE, db);
  audit(py, 'allow', (target.off ? '停用' : '启用') + '账号「' + target.name + '」');
  send(res, 200, { py: target.py, off: !!target.off });
}

function handleUserCreate(req, res, body) {
  const py = rbacUser(req, res);
  if (!py) return;
  const name = String(body.name || '').trim().slice(0, 20);
  const id = String(body.py || '').trim().toLowerCase();
  const code = String(body.code || '').trim();
  if (!name) return send(res, 400, { error: '请填写姓名' });
  if (!/^[a-z][a-z0-9]{2,19}$/.test(id)) return send(res, 400, { error: '拼音标识需 3-20 位小写字母数字，且字母开头' });
  if (db.students.some((s) => s.py === id)) return send(res, 409, { error: '该拼音标识已存在' });
  let c;
  if (code) {
    if (!/^\d{6}$/.test(code)) return send(res, 400, { error: '密码需为 6 位数字' });
    c = code;
  } else {
    c = newCode();
  }
  const tints = ['#FFE4EF', '#E2E6FF', '#FFF4D6', '#DFF5EC', '#EDE7FF', '#FFE9D6', '#E4F4FB'];
  const stu = {
    py: id, name,
    ava: String(body.ava || '🙂').slice(0, 4),
    tint: tints[db.students.length % tints.length],
    grade: String(body.grade || '').slice(0, 10),
    term: String(body.term || '').slice(0, 12),
    roles: ['student'],
    code: c,
    created: Date.now()
  };
  db.students.push(stu);
  writeJSON(DB_FILE, db);
  audit(py, 'allow', '新增用户「' + name + '」(' + id + ')，默认学员角色');
  send(res, 200, {
    student: PUBLIC_STUDENT(stu), code: c,
    nginxHint: '如需短链 /' + id + '，需在服务器 nginx 补一条 location'
  });
}

function handleUserCode(req, res, body) {
  const py = rbacUser(req, res);
  if (!py) return;
  const target = db.students.find((s) => s.py === String(body.py || ''));
  if (!target) return send(res, 404, { error: '用户不存在' });
  const code = String(body.code || '').trim();
  if (code) {
    if (!/^\d{6}$/.test(code)) return send(res, 400, { error: '密码需为 6 位数字' });
    target.code = code;
  } else {
    target.code = newCode();
  }
  writeJSON(DB_FILE, db);
  audit(py, 'allow', '修改「' + target.name + '」的密码');
  send(res, 200, { py: target.py, name: target.name, code: target.code, random: !code });
}

function handleUserEdit(req, res, body) {
  const py = rbacUser(req, res);
  if (!py) return;
  const target = db.students.find((s) => s.py === String(body.py || ''));
  if (!target) return send(res, 404, { error: '用户不存在' });
  const changes = [];
  if (body.name !== undefined) {
    const name = String(body.name || '').trim().slice(0, 20);
    if (!name) return send(res, 400, { error: '姓名不能为空' });
    if (name !== target.name) { target.name = name; changes.push('姓名→' + name); }
  }
  if (body.ava !== undefined) {
    const ava = String(body.ava || '🙂').slice(0, 4);
    if (ava && ava !== target.ava) { target.ava = ava; changes.push('头像 ' + ava); }
  }
  if (body.term !== undefined) {
    const term = String(body.term || '').slice(0, 12);
    if (term !== (target.term || '')) { target.term = term; changes.push('期数→' + (term || '清空')); }
  }
  if (body.grade !== undefined) {
    const grade = String(body.grade || '').slice(0, 10);
    if (grade !== (target.grade || '')) { target.grade = grade; changes.push('年级→' + (grade || '清空')); }
  }
  if (String(body.code || '').trim() !== '') {
    const code = String(body.code).trim();
    if (!/^\d{6}$/.test(code)) return send(res, 400, { error: '密码需为 6 位数字' });
    if (code !== target.code) { target.code = code; changes.push('密码已修改'); }
  }
  if (!changes.length) return send(res, 200, { ok: true, changed: false });
  writeJSON(DB_FILE, db);
  audit(py, 'allow', '编辑用户「' + target.name + '」：' + changes.join('、'));
  send(res, 200, { ok: true, changed: true, student: PUBLIC_STUDENT(target) });
}

function handleResSave(req, res, body) {
  const py = rbacUser(req, res);
  if (!py) return;
  const r = db.resources.find((x) => x.key === String(body.key || ''));
  if (!r) return send(res, 404, { error: '资源不存在' });
  const who = (roleKey) => {
    const rr = db.roles.find((x) => x.key === roleKey);
    return rr ? rr.name : roleKey;
  };
  if (Array.isArray(body.roles)) {
    const roles = body.roles.filter((k) => db.roles.some((x) => x.key === k));
    const removed = (r.roles || []).filter((k) => roles.indexOf(k) < 0).map(who).join('、') || '无';
    const added = roles.filter((k) => (r.roles || []).indexOf(k) < 0).map(who).join('、') || '无';
    r.roles = roles;
    audit(py, 'allow', '资源「' + r.name + '」授权变更：+[' + added + '] -[' + removed + ']');
  }
  if (typeof body.on === 'boolean' && body.on !== r.on) {
    r.on = body.on;
    audit(py, 'allow', '资源「' + r.name + '」' + (r.on ? '恢复开放' : '整体下架'));
  }
  writeJSON(DB_FILE, db);
  send(res, 200, { resource: r });
}

function handleLogsClear(req, res) {
  const py = rbacUser(req, res);
  if (!py) return;
  db.logs = [];
  writeJSON(DB_FILE, db);
  audit(py, 'allow', '清空访问记录');
  send(res, 200, { ok: true });
}

/* ---------------- AI 赛事 ---------------- */
const EVENT_TYPES = ['黑客松', '挑战赛', '训练营', '分享会'];
const EVENT_STATUS = ['报名中', '进行中', '已结束'];

function cleanTags(v, max) {
  return Array.isArray(v) ? v.map((x) => String(x || '').trim().slice(0, 16)).filter(Boolean).slice(0, max || 6) : [];
}
function cleanLines(v, max) {
  return Array.isArray(v) ? v.map((x) => String(x || '').trim().slice(0, 80)).filter(Boolean).slice(0, max || 12) : [];
}

function handleEvents(res) {
  send(res, 200, { events: db.events });
}

function eventManager(req, res) {
  const py = pyBearer(req);
  if (!py) { send(res, 401, { error: '未登录' }); return null; }
  if (!hasPerm(py, 'event:manage')) {
    audit(py, 'deny', '尝试维护赛事内容 → 拦截（缺少 event:manage 权限）');
    send(res, 403, { error: '需要「赛事内容维护」权限' });
    return null;
  }
  return py;
}

function handleEventSave(req, res, body) {
  const py = eventManager(req, res);
  if (!py) return;
  const title = String(body.title || '').trim().slice(0, 60);
  if (!title) return send(res, 400, { error: '请填写赛事名称' });
  const type = EVENT_TYPES.indexOf(body.type) >= 0 ? body.type : '黑客松';
  const status = EVENT_STATUS.indexOf(body.status) >= 0 ? body.status : '报名中';
  const fields = {
    title, type, status,
    emoji: String(body.emoji || '🚀').slice(0, 4),
    tint: String(body.tint || 'linear-gradient(135deg,#EDE7FF,#CFC4FF)').slice(0, 120),
    desc: String(body.desc || '').slice(0, 400),
    host: String(body.host || '').slice(0, 40),
    dateText: String(body.dateText || '').slice(0, 40),
    place: String(body.place || '线上').slice(0, 30),
    prize: String(body.prize || '—').slice(0, 30),
    prizeNum: Math.max(0, parseInt(body.prizeNum, 10) || 0),
    people: Math.max(0, parseInt(body.people, 10) || 0),
    deadlineText: String(body.deadlineText || '').slice(0, 30),
    deadlineAt: String(body.deadlineAt || '').slice(0, 40),
    featured: !!body.featured,
    link: safeLink(body.link),
    req: String(body.req || '').slice(0, 400),
    prizeText: String(body.prizeText || '').slice(0, 400),
    tags: cleanTags(body.tags, 6),
    schedule: cleanLines(body.schedule, 12),
    milestones: Array.isArray(body.milestones) ? body.milestones.filter((m) => m && m.date).slice(0, 10).map((m) => ({
      date: String(m.date).slice(0, 10),
      title: String(m.title || '').slice(0, 60),
      note: String(m.note || '').slice(0, 80),
      right: String(m.right || '').slice(0, 20)
    })) : []
  };

  const id = String(body.id || '').trim();
  let ev = id ? db.events.find((x) => x.id === id) : null;
  if (ev) {
    Object.assign(ev, fields, { updated: Date.now() });
    audit(py, 'allow', '编辑赛事「' + ev.title + '」');
  } else {
    ev = Object.assign({ id: rid('ev'), created: Date.now() }, fields);
    db.events.unshift(ev);
    audit(py, 'allow', '新增赛事「' + ev.title + '」');
  }
  writeJSON(DB_FILE, db);
  send(res, 200, { event: ev });
}

function handleEventDelete(req, res, body) {
  const py = eventManager(req, res);
  if (!py) return;
  const id = String(body.id || '');
  const ev = db.events.find((x) => x.id === id);
  if (!ev) return send(res, 404, { error: '赛事不存在' });
  db.events = db.events.filter((x) => x.id !== id);
  writeJSON(DB_FILE, db);
  audit(py, 'allow', '删除赛事「' + ev.title + '」');
  send(res, 200, { ok: true });
}

/* ---------------- AI 沙龙 ---------------- */
const SALON_STATUS = ['筹备中', '进行中', '已结束'];

function handleSalons(res) {
  send(res, 200, { salons: db.salons });
}

function salonManager(req, res) {
  const py = pyBearer(req);
  if (!py) { send(res, 401, { error: '未登录' }); return null; }
  if (!hasPerm(py, 'salon:manage')) {
    audit(py, 'deny', '尝试维护沙龙期次 → 拦截（缺少 salon:manage 权限）');
    send(res, 403, { error: '需要「沙龙内容维护」权限' });
    return null;
  }
  return py;
}

function handleSalonSave(req, res, body) {
  const py = salonManager(req, res);
  if (!py) return;
  const title = String(body.title || '').trim().slice(0, 60);
  if (!title) return send(res, 400, { error: '请填写本期主题' });
  const fields = {
    no: Math.max(1, parseInt(body.no, 10) || 1),
    title,
    sub: String(body.sub || '').slice(0, 80),
    status: SALON_STATUS.indexOf(body.status) >= 0 ? body.status : '已结束',
    dateText: String(body.dateText || '').slice(0, 40),
    timeText: String(body.timeText || '').slice(0, 30),
    place: String(body.place || '现场 · 一人一台电脑').slice(0, 40),
    duration: String(body.duration || '180 分钟').slice(0, 20),
    output: String(body.output || '').slice(0, 40),
    desc: String(body.desc || '').slice(0, 400),
    tags: cleanTags(body.tags, 6),
    points: cleanLines(body.points, 14),
    photo: String(body.photo || '').slice(0, 300),
    link: safeLink(body.link),
    linkText: String(body.linkText || '').slice(0, 20)
  };

  const id = String(body.id || '').trim();
  let s = id ? db.salons.find((x) => x.id === id) : null;
  if (s) {
    Object.assign(s, fields, { updated: Date.now() });
    audit(py, 'allow', '编辑沙龙「第 ' + s.no + ' 期 · ' + s.title + '」');
  } else {
    s = Object.assign({ id: rid('sl'), created: Date.now() }, fields);
    db.salons.unshift(s);
    audit(py, 'allow', '新增沙龙「第 ' + s.no + ' 期 · ' + s.title + '」');
  }
  db.salons.sort((a, b) => (b.no || 0) - (a.no || 0));
  writeJSON(DB_FILE, db);
  send(res, 200, { salon: s });
}

function handleSalonDelete(req, res, body) {
  const py = salonManager(req, res);
  if (!py) return;
  const id = String(body.id || '');
  const s = db.salons.find((x) => x.id === id);
  if (!s) return send(res, 404, { error: '期次不存在' });
  db.salons = db.salons.filter((x) => x.id !== id);
  writeJSON(DB_FILE, db);
  audit(py, 'allow', '删除沙龙「第 ' + s.no + ' 期 · ' + s.title + '」');
  send(res, 200, { ok: true });
}

function handleEventSubscribe(req, res, body) {
  const email = String(body.email || '').trim().toLowerCase();
  if (!/^[^\s@]+@[^\s@]+\.[a-z]{2,}$/i.test(email) || email.length > 80) {
    return send(res, 400, { error: '请填写正确的邮箱地址' });
  }
  if ((db.subs || []).some((s) => s.email === email)) {
    return send(res, 200, { ok: true, repeat: true });
  }
  db.subs.push({ email, at: Date.now() });
  if (db.subs.length > 2000) db.subs = db.subs.slice(-2000);
  writeJSON(DB_FILE, db);
  audit(email, 'allow', '订阅赛事提醒');
  send(res, 200, { ok: true, total: db.subs.length });
}

/* ---------------- 路由 ---------------- */
const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, 'http://localhost');
  let p = url.pathname;
  if (p.startsWith('/api/')) p = p.slice(4); // 兼容直连与 nginx 前缀
  const ip = (req.headers['x-forwarded-for'] || '').split(',')[0].trim() || req.socket.remoteAddress || '-';

  try {
    if (req.method === 'GET' && (p === '/health' || p === '/api/health')) {
      return send(res, 200, { ok: true, students: db.students.length, works: db.works.length, time: new Date().toISOString() });
    }
    if (req.method === 'GET' && p === '/data') return handleData(req, res);
    if (req.method === 'GET' && p === '/events') return handleEvents(res);
    if (req.method === 'GET' && p === '/salons') return handleSalons(res);

    if (req.method === 'GET' && p === '/me') return handleMe(req, res);

    if (req.method === 'GET' && p === '/admin/list') return handleAdminList(res, url.searchParams);

    /* 压缩包直传：原始字节 body，不走 JSON */
    if (req.method === 'POST' && p === '/publish-zip') return await handlePublishZip(req, res);

    /* MP3 直传：原始字节 body，自动生成播放页 */
    if (req.method === 'POST' && p === '/publish-audio') return await handlePublishAudio(req, res);

    /* MP4 直传：原始字节 body，自动生成播放页 */
    if (req.method === 'POST' && p === '/publish-video') return await handlePublishVideo(req, res);

    if (req.method !== 'POST') return send(res, 405, { error: '不支持的请求' });

    const raw = await readBody(req);
    let body = {};
    try { body = raw.length ? JSON.parse(raw.toString('utf8')) : {}; } catch (e) { return send(res, 400, { error: '请求格式错误' }); }

    if (p === '/login') return handleLogin(req, res, body, ip);
    if (p === '/publish') return handlePublish(req, res, body);
    if (p === '/delete') return handleDelete(req, res, body);
    if (p === '/like') return handleLike(res, body);
    if (p === '/password') return handlePassword(req, res, body);
    if (p === '/admin/student') return handleAdminStudent(req, res, body);
    if (p === '/admin/reset') return handleAdminReset(req, res, body);

    if (p === '/rbac/get') return handleRbacGet(req, res);
    if (p === '/rbac/role.save') return handleRoleSave(req, res, body);
    if (p === '/rbac/role.delete') return handleRoleDelete(req, res, body);
    if (p === '/rbac/user.roles') return handleUserRoles(req, res, body);
    if (p === '/rbac/user.reset') return handleUserReset(req, res, body);
    if (p === '/rbac/user.off') return handleUserOff(req, res, body);
    if (p === '/rbac/user.create') return handleUserCreate(req, res, body);
    if (p === '/rbac/user.code') return handleUserCode(req, res, body);
    if (p === '/rbac/user.edit') return handleUserEdit(req, res, body);
    if (p === '/rbac/res.save') return handleResSave(req, res, body);
    if (p === '/rbac/logs.clear') return handleLogsClear(req, res);

    if (p === '/events/save') return handleEventSave(req, res, body);
    if (p === '/events/delete') return handleEventDelete(req, res, body);
    if (p === '/salons/save') return handleSalonSave(req, res, body);
    if (p === '/salons/delete') return handleSalonDelete(req, res, body);
    if (p === '/events/subscribe') return handleEventSubscribe(req, res, body);

    return send(res, 404, { error: '接口不存在' });
  } catch (e) {
    const code = e.status || 500;
    if (code === 413) return send(res, 413, { error: '提交内容太大（HTML 上限 8MB / 压缩包上限 100MB）' });
    console.error('[error]', req.method, req.url, e && e.message);
    if (!res.headersSent) send(res, code, { error: '服务器开小差了，请稍后再试' });
  }
});

server.listen(PORT, '127.0.0.1', () => {
  console.log('[works-api] listening on 127.0.0.1:' + PORT,
    '· students=' + db.students.length, '· works=' + db.works.length,
    '· roles=' + db.roles.length, '· resources=' + db.resources.length);
});
