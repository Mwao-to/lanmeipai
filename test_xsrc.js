#!/usr/bin/env node
/* v3.71 D键·自定义音源 测试桩:抽取 index.html 中 xsrc 区块,在桩环境下验证
 * LX协议握手/静态分析/调用封装/非法脚本拒绝 等核心逻辑。 */
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
/* v3.86:从 main_app.py 密文解密出界面(与Java/Python/Gradle同构keystream),端到端验证加密链 */
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
const START = html.indexOf('/* ═══ D键·自定义音源(LX洛雪协议适配');
const END = html.indexOf('/* ═══ A键·扫码登录兜底') >= 0 ? html.indexOf('/* ═══ A键·扫码登录兜底') : html.indexOf('/* ═══ A键·扫码登录兑底');
if (START < 0 || END < 0 || END <= START) { console.error('✗ 未找到xsrc区块标记'); process.exit(1); }
const block = html.slice(START, END);

/* ─── 桩环境 ─── */
const els = {};
const mkEl = id => els[id] || (els[id] = {
  id, style: {}, dataset: {}, innerHTML: '', textContent: '',
  classList: { add() { }, remove() { }, contains: () => false },
  addEventListener() { }, isConnected: true,
});
['srcModal', 'srcListBox', 'srcEmpty', 'srcAddRow', 'srcScroll', 'vrfyModal', 'vrfyLog', 'vrfySum', 'vrfyName'].forEach(mkEl);
global.window = global;
global.document = { getElementById: id => els[id] || null, querySelector: () => null };
global.localStorage = { _d: {}, getItem(k) { return k in this._d ? this._d[k] : null; }, setItem(k, v) { this._d[k] = String(v); }, removeItem(k) { delete this._d[k]; } };
global.bridgeCall = () => undefined;
global.toast = () => { };
global.state = {};
global.$ = id => global.document.getElementById(id);
global.esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
let apiCalls = [];
global.api = url => { apiCalls.push(url); return Promise.resolve({ code: 200, status: 200, ctype: 'application/json', b64: false, body: '{"ok":1}' }); };

eval(block);

let pass = 0, fail = 0;
const ok = (cond, msg) => { console.log((cond ? '  ✓ ' : '  ✗ ') + msg); cond ? pass++ : fail++; };
(async () => {
  console.log('[1] 头部元信息+静态适配分析');
  const fakeSrc = `/**
 * @name 星海音乐源 v2.3
 * @description 聚合音源测试
 * @version 2.3.13
 * @author tester
 */
const { EVENT_NAMES, request, on, send } = globalThis.lx
on(EVENT_NAMES.request, function ({ source, action, info }) {
  if (action === 'musicUrl') return Promise.resolve('http://cdn.example/' + getSongId(info.musicInfo))
  if (action === 'lyric') return Promise.resolve('[00:01.00]test')
  if (action === 'pic') return Promise.resolve('http://img.example/pic.jpg')
  return Promise.reject('not support')
})
send(EVENT_NAMES.inited, { sources: { wy: { name: '网易云', type: 'music', actions: ['musicUrl', 'lyric', 'pic'], qualitys: ['128k'] } } })
function getSongId(m) { return m.songmid || m.id }`;
  const info = analyzeXsrcCode(fakeSrc, 'fallback.js');
  ok(info.name === '星海音乐源 v2.3', '@name解析: ' + info.name);
  ok(info.version === '2.3.13' && info.author === 'tester', '版本/作者解析');
  ok(info.protocolOk === true, '协议特征识别');
  ok(info.actions.has('musicUrl') && info.actions.has('pic') && info.actions.has('lyric'), 'action静态扫描: ' + [...info.actions].join('/'));
  ok(info.platforms.includes('wy'), '平台识别含wy');

  console.log('[2] 协议握手(runXsrc非提交模式)');
  global.window.lx = null;
  const ctx = await runXsrc('星海.js', fakeSrc, false);
  ok(ctx && !ctx.fail && typeof ctx.handler === 'function', 'inited握手成功拿到handler');
  ok(ctx.actions.has('lyric') && ctx.actions.has('pic'), '清单actions: ' + [...ctx.actions].join('/'));

  console.log('[3] 调用封装(xsrcCallOn)');
  const u = await xsrcCallOn(ctx, 'musicUrl', { songmid: '5257138' }, '320k');
  ok(u === 'http://cdn.example/5257138', 'musicUrl返回直链: ' + u);
  let threw = '';
  try { await xsrcCallOn(null, 'musicUrl', {}); } catch (e) { threw = e.message; }
  ok(threw === '音源不可用', '空ctx拒绝: ' + threw);

  console.log('[4] 非洛雪脚本拒绝');
  const bad1 = await runXsrc('bad.js', 'var x = 1;', false);
  ok(bad1 && bad1.fail && /inited/.test(bad1.fail), '无inited拒绝: ' + (bad1 && bad1.fail));
  const bad2 = await runXsrc('bad2.js', 'var lx = globalThis.lx; lx.on(lx.EVENT_NAMES.alert, () => {});', false);
  ok(bad2 && bad2.fail && /处理器|inited/.test(bad2.fail), '未注册request处理器拒绝: ' + (bad2 && bad2.fail));
  const bad3 = await runXsrc('bad3.js', 'throw new Error("boom")', false);
  ok(bad3 && bad3.fail && /boom/.test(bad3.fail), '执行异常捕获: ' + (bad3 && bad3.fail));

  console.log('[5] 垫片request走/api/xhttp代理(b64头编码往返)');
  let captured = null;
  global.api = url => { captured = url; return Promise.resolve({ code: 200, status: 200, ctype: 'application/json', b64: false, body: JSON.stringify({ code: 0, msg: 'x' }) }); };
  const shim = buildLxShim();
  await new Promise(res => shim.request('https://api.test/x?a=1&b=中文', { method: 'post', headers: { 'Cookie': 'a=b' }, body: 'p=1' }, (err, resp) => {
    ok(!err && resp.statusCode === 200 && resp.body === '{"code":0,"msg":"x"}', '代理响应回传: ' + resp.body);
    res();
  }));
  ok(captured.startsWith('/api/xhttp?url=https%3A%2F%2Fapi.test%2Fx'), 'URL已编码: ' + captured.slice(0, 46) + '…');
  ok(captured.includes('&method=post'), 'method透传');
  const hd = JSON.parse(Buffer.from(decodeURIComponent(captured.split('&headers=')[1]), 'base64').toString());
  ok(hd.Cookie === 'a=b', 'headers b64编解码往返: ' + JSON.stringify(hd));

  console.log('[6] 全局开关状态机');
  ok(xsrcActive() === false, '初始未启用');
  const okLoad = await loadXsrc('星海.js', fakeSrc, true);
  ok(okLoad === true && xsrcActive() === true && localStorage.getItem('xsrc_active') === '星海.js', '启用后持久化');
  stopXsrc(true);
  ok(xsrcActive() === false && localStorage.getItem('xsrc_active') === null, '停用后恢复三通道');

  console.log('[7] 启用自检(autoCheckXsrc)标记可用/失效');
  const toasts7 = [];
  global.toast = m => { toasts7.push(String(m)); };
  await loadXsrc('星海.js', fakeSrc, true);
  let t7 = Date.now();
  while (!toasts7.some(t => t.includes('音源自检完成')) && Date.now() - t7 < 3000) await new Promise(r => setTimeout(r, 20));
  const goodMsg = toasts7.filter(t => t.includes('音源自检完成')).pop() || '';
  ok(/歌曲链接 ✓/.test(goodMsg) && /歌词 ✓/.test(goodMsg) && /图片 ✓/.test(goodMsg), '全接口可用: ' + goodMsg);
  toasts7.length = 0;
  const deadSrc = fakeSrc.replace("return Promise.resolve('[00:01.00]test')", "return Promise.resolve('')");
  await loadXsrc('dead.js', deadSrc, true);
  t7 = Date.now();
  while (!toasts7.some(t => t.includes('音源自检完成')) && Date.now() - t7 < 3000) await new Promise(r => setTimeout(r, 20));
  const badMsg = toasts7.filter(t => t.includes('音源自检完成')).pop() || '';
  ok(/歌词 ✗失效/.test(badMsg) && /歌曲链接 ✓/.test(badMsg), '空歌词判定失效: ' + badMsg);
  stopXsrc(true);
  global.toast = () => { };

  console.log('[8] 取链接口失效:直接FAILED_SRC不重试不误报网络差(静态+自检行为断言)');
  global.toast = m => { toasts7.push(String(m)); };
  const deadUrlSrc = fakeSrc.replace("return Promise.resolve('http://cdn.example/' + getSongId(info.musicInfo))", "return Promise.resolve('')");
  ok(deadUrlSrc !== fakeSrc, '死链源构造成功');
  toasts7.length = 0;
  await loadXsrc('deadurl.js', deadUrlSrc, true);
  t7 = Date.now();
  while (!toasts7.some(t => t.includes('歌曲链接 ✗')) && Date.now() - t7 < 3000) await new Promise(r => setTimeout(r, 20));
  ok(toasts7.some(t => t.includes('歌曲链接 ✗')), '自检判定歌曲链接✗');
  ok(/ok\.musicUrl === false/.test(html) && /notifyBadOnce\('musicUrl'\)/.test(html) && /'FAILED_SRC'/.test(html) && !/res === 'FAILED_SRC'[\s\S]{0,200}网络环境较差/.test(html), '取链入口失效守卫→FAILED_SRC且不落入网络差分支');
  stopXsrc(true);
  global.toast = () => { };

  console.log('[9] 歌词失效静默兑底官方(仅当歌曲可播)');
  ok(/wholeDead[^\n]*\n[\s\S]{0,160}xsrcSkip: true/.test(html), '整源不可用→不兑底静默跳过分支存在');
  ok(/useSrcLyric/.test(html) && /歌词失效但歌曲可播→静默兑底官方歌词/.test(html), '失效但可播→兑底官方分支存在');

  console.log('[10] 统一判定口径judgeXsrcVal+SAF初始定位');
  ok(judgeXsrcVal('musicUrl', 'http://a/b.mp3').ok && !judgeXsrcVal('musicUrl', 'ftp://x').ok && !judgeXsrcVal('musicUrl', '').ok, 'musicUrl须http直链');
  ok(judgeXsrcVal('lyric', '[00:01]词').ok && !judgeXsrcVal('lyric', '   ').ok, 'lyric只要求非空(允许非直链)');
  ok(!judgeXsrcVal('pic', 'not-a-url').ok && judgeXsrcVal('pic', { lyric: '' }).ok === false, 'pic同musicUrl口径');
  ok(/const XSRC_PROBE = \{ songmid: '5257138', name: '屋顶'/.test(block), '探针曲常量共用');
  ok(/EXTRA_INITIAL_URI/.test(fs.readFileSync(path.join(__dirname, 'app/src/main/java/com/binsys/wy/MainActivity.java'), 'utf8')), 'SAF初始定位音源目录');

  console.log('[11] v3.86四项:去重导入/校验精简/标题缩略/HTML加密');
  ok(/findDuplicateSource/.test(fs.readFileSync(path.join(__dirname, 'app/src/main/java/com/binsys/wy/MainActivity.java'), 'utf8')), 'Java内容哈希去重拦截');
  ok(/音源「' \+ r\.name \+ '」已存在，内容相同，未重复导入/.test(html), 'JS重复回执提醒');
  ok(/协议握手成功 · 平台/.test(html) && /下载直链可下\(HTTP/.test(html) && /（' \+ \(Date\.now\(\) - t0\) \+ 'ms）'/.test(html), '校验回滚专业详版(握手/耗时/真探测)');
  ok(/vrfy-name \{ display:inline-block; max-width:56vw/.test(html), '校验弹窗长文件名缩略');
  ok(/EMBEDDED_ENC = '/.test(fs.readFileSync(path.join(__dirname, 'app/corepkg/src/main_app.py'), 'utf8')) && html.includes('<!DOCTYPE html>'), 'dex内HTML已密文化且解密链路可用');
  ok(/htmlsrc\/index\.html/.test(fs.readFileSync(path.join(__dirname, 'app/build.gradle'), 'utf8')), '明文源已移出assets目录(htmlsrc)');

  console.log('[12] v3.92合并下载:弹窗按钮/后端嵌入/转存桥');
  const pySrc = fs.readFileSync(path.join(__dirname, 'app/corepkg/src/main_app.py'), 'utf8');
  ok(/downloadMerged\(\)">ldM合并下载</.test(html) && !/dl-divider/.test(html) && /<button class="modal-btn secondary" onclick="downloadSong\(\)">下载歌曲<\/button>/.test(html), 'ldM合并下载钮+去隔离线+下载歌曲与歌词同外观');
  ok(/ldM合并下载 · 步骤1\/3/.test(html) && /步骤2\/3/.test(html) && /步骤3\/3/.test(html), '合并下载分步进度提示');
  ok(/api\/merge\?songmid=/.test(html) && /hasBridge\('promote'\)/.test(html), 'JS调用merge路由+promote桥');
  ok(/def api_merge\(/.test(pySrc) && /_embed_metadata\(/.test(pySrc) && /mutagen/.test(fs.readFileSync(path.join(__dirname, 'app/build.gradle'), 'utf8')), 'Python嵌入路由+mutagen依赖');
  const mAct = fs.readFileSync(path.join(__dirname, 'app/src/main/java/com/binsys/wy/MainActivity.java'), 'utf8');
  ok(/public String stageDir\(\)/.test(mAct) && /public void promote\(String filename\)/.test(mAct), 'Java暂存目录+转存公共Download桥');

  console.log('[13] v3.94歌词直传:播放器已加载歌词重建LRC经暂存文件嵌入');
  ok(/function currentLrcText\(\)/.test(html) && /state\.lyricTimes\.map/.test(html), '前端从lyricTimes重建标准LRC');
  ok(/hasBridge\('stageText'\)/.test(html) && /lrcfile=' \+ encodeURIComponent\(lf\)/.test(html), '歌词暂存文件直传merge路由');
  ok(/lrcfile = \(request\.args\.get\('lrcfile'\)/.test(pySrc) && /picurl/.test(pySrc) && /_fetch_lyric\(song, songmid\)/.test(pySrc), '后端优先暂存歌词+封面URL直传(官方兑底)');
  ok(/public boolean stageText\(String filename, String content\)/.test(mAct), 'Java stageText桥就位');

  console.log(`\n═══ 结果: ${pass} 通过, ${fail} 失败 ═══`);
  process.exit(fail ? 1 : 0);
})().catch(e => { console.error('✗ 桩异常:', e); process.exit(1); });
