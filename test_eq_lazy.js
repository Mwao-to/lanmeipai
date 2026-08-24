/* EQ懒加载逻辑单元测试(Node桩):验证首屏20条→触底40→80→80…、搜索过滤、data-idx高亮 */
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
/* v3.86:从 main_app.py 密文解密出界面(与Java/Python/Gradle同构keystream) */
function embHtml() {
  const py = fs.readFileSync(path.join(__dirname, 'app/corepkg/src/main_app.py'), 'utf8');
  const enc = Buffer.from(py.match(/EMBEDDED_ENC = '([^']+)'/)[1], 'base64');
  const key = Buffer.from('9f3ac1e25d84bb0721ce6a49f0183d76ab52de9047c31f68d9b024af6e1c8533', 'hex');
  const out = Buffer.from(enc);
  let i = 0, counter = 0;
  while (i < out.length) {
    const cBuf = Buffer.alloc(4); cBuf.writeUInt32BE(counter);
    const h = crypto.createHash('sha256').update(key).update(cBuf).digest();
    const n = Math.min(32, out.length - i);
    for (let j = 0; j < n; j++) out[i + j] ^= h[j];
    i += n; counter++;
  }
  return out.toString('utf8');
}
const html = embHtml();

function extract(startMarker, endMarker) {
  const s = html.indexOf(startMarker);
  const e = html.indexOf(endMarker, s);
  if (s < 0 || e < 0) throw new Error('标记未找到: ' + startMarker);
  return html.slice(s, e);
}
// 提取被测代码块
const blocks = [
  extract('function markEqActive', 'function eqCorsReload'),
  extract('/* ═══ 懒加载渲染', "$('eqModal').addEventListener('click'")
].join('\n');

/* ───── DOM桩 ───── */
const ROW_H = 36, VIEW_H = 282;   // 行高≈30+间隔6,可视区282px(与CSS一致)
function makeList() {
  const el = {
    _rows: [], _html: '', scrollTop: 0,
    get clientHeight() { return VIEW_H; },
    get scrollHeight() { return this._rows.length * ROW_H; },
    set innerHTML(v) { this._html = v; this._rows = v ? v.split('</div>').filter(x => x.includes('eq-row')).map(() => 1) : []; },
    get innerHTML() { return this._html; },
    get children() { return this._rows.map((_, i) => ({ idx: i })); },
    insertAdjacentHTML(pos, h) { const n = h.split('</div>').filter(x => x.includes('eq-row')).length; this._rows.push(...Array(n).fill(1)); this._html += h; },
    querySelector(sel) {
      const m = sel.match(/data-idx="(\d+)"/);
      if (sel === '.eq-row.on') return this._on !== undefined && this._on < this._rows.length ? { classList: mkCL(), _row: true } : null;
      if (m) return +m[1] < this._rows.length ? { classList: mkCL() } : null;
      return null;
    },
    addEventListener() { }
  };
  function mkCL() { const rm = [], ad = []; return { remove: c => rm.push(c), add: c => ad.push(c), _rm: rm, _ad: ad }; }
  // 简化:on类追踪用_on记录
  el._on = undefined;
  const origQ = el.querySelector.bind(el);
  el.querySelector = sel => {
    const r = origQ(sel);
    if (r && r._row) { r.classList = { remove() { el._on = undefined; }, add() { } }; }
    else if (r) { r.classList = { remove() { el._on = undefined; }, add() { el._on = +sel.match(/data-idx="(\d+)"/)[1]; } }; }
    return r;
  };
  return el;
}
const els = { eqList: makeList(), eqModal: { classList: { add() { }, remove() { } }, addEventListener() { } } };
global.$ = id => els[id];
global.document = { createElement: () => ({}) };
global.esc = s => String(s).replace(/[&<>"']/g, '');
global.toast = () => { };

/* 数据桩:内置2套+导入100套(共102) */
global.EQ_PRESETS = { '正常': [0, 0, 0, 0, 0, 0, 0, 0], '摇滚经典': [3, 2, 1, 1, -1, 1, 2, 3] };
global.EQ_IMPORTED = {};
for (let i = 0; i < 1000; i++) global.EQ_IMPORTED['耳机预设' + i] = { display: '耳机预设' + i, preamp: 0, bands: [] };
global.eqActiveName = '正常';
global.eqDisplay = name => { const o = global.EQ_IMPORTED[name]; return o ? o.display : name; };
global.requestAnimationFrame = fn => fn();   // 同步执行,便于测试分帧渲染终态
let applied = null; global.applyEq = n => { applied = n; };

eval(blocks
  .replace(/\blet (EQ_ORDER|eqRendered|eqLoadPtr|eqFilterMode|eqRenderedBefore|_eqWarmCache|_chunkSeq)\b/g, 'global.$1')
  .replace(/\bconst (EQ_BATCH)\b/g, 'global.$1'));

/* ───── 断言 ───── */
let pass = 0, fail = 0;
function ok(cond, msg) { cond ? (pass++, console.log('  ✓ ' + msg)) : (fail++, console.log('  ✗ ' + msg)); }

console.log('[1] 打开弹窗:先开窗后渲染,首屏20条');
els.eqList.scrollTop = 999;                       // 模拟上次滚动位置残留
resetEqList();
ok(els.eqModal && true, '开窗不报错');
ok(eqRendered === 20, '首屏渲染20条 (实际' + eqRendered + ')');
ok(els.eqList.scrollTop === 0, '滚动位置归零');
ok(EQ_ORDER.length === 1002, 'EQ_ORDER=内置2+导入1000=1002');

console.log('[2] 触底加载:批次20→40→80→80封顶');
const L = els.eqList;
L.scrollTop = L.scrollHeight - VIEW_H - 10;       // 距底10px<60 触发
maybeLoadMore();
ok(eqRendered === 60, '首次触底+40 → 已渲60 (实际' + eqRendered + ')');
L.scrollTop = L.scrollHeight - VIEW_H - 10;
maybeLoadMore();
ok(eqRendered === 140, '二次触底+80 → 已渲140 (实际' + eqRendered + ')');
L.scrollTop = L.scrollHeight - VIEW_H - 10;
maybeLoadMore();
ok(eqRendered === 220, '三次触底仍+80 → 已渲220 (实际' + eqRendered + ')');

console.log('[3] 未触底不加载');
const before = eqRendered;
L.scrollTop = 0;
maybeLoadMore();
ok(eqRendered === before, 'scrollTop=0距底远 不触发');

console.log('[4] 加载到尽头自动停止');
for (let i = 0; i < 20; i++) { L.scrollTop = L.scrollHeight - VIEW_H - 10; maybeLoadMore(); }
ok(eqRendered === EQ_ORDER.length, '反复触底最终渲满1002条不越界');

console.log('[5] 搜索:匹配行带原序号,清空还原触底前进度');
resetEqList();
L.scrollTop = L.scrollHeight - VIEW_H - 10; maybeLoadMore();   // 渲到60
doFilterEq('耳机预设7');
ok(L._html.includes('data-idx="9"'), '"耳机预设7"位于内置2条之后,idx=9在结果中'); 
doFilterEq('耳机预设70');
let exp = 0; for (let i = 0; i < EQ_ORDER.length; i++) { const k = EQ_ORDER[i]; if (eqDisplay(k).indexOf('耳机预设70') >= 0 || String(i + 1).indexOf('70') >= 0) exp++; }
ok(L._html.split('eq-row').length - 1 === exp && L._html.includes('data-idx="72"'), '"耳机预设70"按原版语义命中' + exp + '行且含名称行idx=72 实际' + (L._html.split('eq-row').length - 1) + '行');
doFilterEq('');
ok(eqFilterMode === false, '清空退出搜索模式');
ok(eqRendered === 60, '还原触底前进度60 (实际' + eqRendered + ')');
doFilterEq('不存在的预设xyz');
ok(L._html.includes('无匹配预设'), '无结果显示占位提示');
doFilterEq('');

console.log('[6] 高亮:data-idx定位(懒加载下与children序号解耦)');
resetEqList();
eqActiveName = '耳机预设50';                      // 原索引52,超出已渲20条
markEqActive('耳机预设50');
ok(true, '目标行未渲染时静默不报错');
L.scrollTop = L.scrollHeight - VIEW_H - 10; maybeLoadMore();   // 追加到60,覆盖idx52
ok(L._html.includes('data-idx="52"'), '追加渲染包含idx=52行');
markEqActive('耳机预设50');
ok(L._on === 52, 'data-idx=52正确加on类');

console.log('[7] 点击派发:applyEqIdx按原索引取EQ_ORDER');
applyEqIdx(1);
ok(applied === '摇滚经典', 'idx=1派发到「摇滚经典」');

console.log('[8] 大结果集分帧渲染(>120行走chunkedRender)');
resetEqList();
doFilterEq('耳机预设1');                       // 命中数百行,触发分帧路径
const bigCount = L._html.split('eq-row').length - 1;
let expBig = 0; for (let i = 0; i < EQ_ORDER.length; i++) { const k = EQ_ORDER[i]; if (eqDisplay(k).indexOf('耳机预设1') >= 0 || String(i + 1).indexOf('1') >= 0) expBig++; }
ok(bigCount === expBig && bigCount > 120, '分帧渲染完整落地' + bigCount + '行(期望' + expBig + ')');
ok(L._html.includes('data-idx="11"'), '首条名称命中idx=11在列');

console.log('[9] 预加载缓存:预热命中直出+预设变更失效');
_eqWarmCache = null; prewarmEq();
ok(typeof _eqWarmCache === 'string' && _eqWarmCache.length > 0, 'prewarmEq生成首屏缓存');
resetEqList();
ok(eqRendered === Math.min(EQ_BATCH[0], EQ_ORDER.length) && L._html.length > 0, '开窗命中缓存直出20条');
ok((html.match(/_eqWarmCache = null/g) || []).length >= 2, '源码中applyEq两分支均含缓存失效语句');

console.log('\n═══ 结果: ' + pass + ' 通过, ' + fail + ' 失败 ═══');
process.exit(fail ? 1 : 0);
