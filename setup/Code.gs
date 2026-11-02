/**
 * Pro Smash Attendance — shared register connector.
 * Paste this into a new Google Apps Script project (script.google.com) on the academy's Gmail,
 * then Deploy > New deployment > Web app, Execute as: Me, Who has access: Anyone.
 *
 * All attendance is saved in a Google Sheet called "Pro Smash Attendance (data)" in this Google Drive.
 * Forgot the PIN?  Choose "resetPin" in the function list at the top of this editor and press Run.
 * The next time the app opens it asks for a new PIN. No attendance is lost.
 */

var SESSION_HOURS = 12;   // the app also asks for the PIN every time it is opened
var WRONG_LIMIT = 5;      // wrong PINs before a 10-minute pause
var LOAD_MONTHS = 3;      // months of attendance sent when the app opens (older months load when viewed)

var COLS = {
  Students: ['ID', 'Name', 'Batch ID', 'Batch', 'Parent name', 'Parent phone', 'Joined', 'Removed', 'Updated'],
  Attendance: ['Date', 'Present', 'Absent', 'Marks'],
  Reports: ['Month', 'Coach notes', 'Sent to parents'],
  Settings: ['Key', 'Value']
};

/* ---------- entry points ---------- */
function doGet() {
  return out_({ok: true, app: 'Pro Smash Attendance', message: 'Connector is running. Paste this link into the app.'});
}
function doPost(e) {
  var req = {};
  try { req = JSON.parse(e && e.postData && e.postData.contents || '{}'); } catch (x) { return out_({ok: false, error: 'bad_request'}); }
  try { return out_(handle_(req)); }
  catch (x) { console.error(x); return out_({ok: false, error: 'server', message: String(x && x.message || x)}); }
}
function out_(o) { return ContentService.createTextOutput(JSON.stringify(o)).setMimeType(ContentService.MimeType.JSON); }
function props_() { return PropertiesService.getScriptProperties(); }

function handle_(r) {
  var a = String(r.action || ''), d = r.data || {};
  if (a === 'hello') { var st = settings_(); return {ok: true, hasPin: !!props_().getProperty('PIN_HASH'), academy: st.academy, empty: studentsAll_().length === 0}; }
  if (a === 'setPin') return locked_(function () { return setPin_(d); });
  if (a === 'unlock') return unlock_(d);
  var who = checkToken_(r.token);
  if (!who) return {ok: false, error: 'auth'};
  switch (a) {
    case 'load': return load_(d);
    case 'attMonth': {
      var one = function (k) { return k.slice(0, 7) === d.month; }, rp = reports_(one);
      return {ok: true, month: d.month, att: attFor_(one), notes: rp.notes[d.month] || {}, sent: rp.sent[d.month] || {}};
    }
    case 'mark': return locked_(function () { return mark_(d); });
    case 'saveStudents': return locked_(function () { return saveStudents_(d); });
    case 'removeStudent': return locked_(function () { return removeStudent_(d); });
    case 'saveSettings': return locked_(function () { return saveSettings_(d); });
    case 'note': return locked_(function () { return report_(d.month, 1, d.sid, String(d.text || '').slice(0, 1500)); });
    case 'sent': return locked_(function () { return report_(d.month, 2, d.sid, String(d.date || '').slice(0, 10)); });
    case 'exportAll': return exportAll_();
    case 'importAll': return locked_(function () { return importAll_(d); });
    case 'changePin': return locked_(function () { return changePin_(d); });
  }
  return {ok: false, error: 'unknown'};
}

/* ---------- PIN + sessions ---------- */
function hash_(pin, salt) {
  var h = salt + ':' + pin;
  for (var i = 0; i < 300; i++) h = Utilities.base64Encode(Utilities.computeDigest(Utilities.DigestAlgorithm.SHA_256, h + salt, Utilities.Charset.UTF_8));
  return h;
}
function validPin_(p) { return /^\d{4}$/.test(String(p || '')); }
function newPin_(pin) {
  var p = props_(), ver = Number(p.getProperty('PIN_VER') || 0) + 1, salt = Utilities.getUuid();
  p.setProperties({PIN_SALT: salt, PIN_HASH: hash_(pin, salt), PIN_VER: String(ver), SECRET: Utilities.getUuid() + Utilities.getUuid()});
  return ver;
}
function token_() {
  var p = props_(), body = (Date.now() + SESSION_HOURS * 3600e3) + '.' + p.getProperty('PIN_VER');
  return body + '.' + Utilities.base64EncodeWebSafe(Utilities.computeHmacSha256Signature(body, p.getProperty('SECRET')));
}
function checkToken_(t) {
  var p = props_(), secret = p.getProperty('SECRET');
  if (!t || !secret) return false;
  var parts = String(t).split('.');
  if (parts.length !== 3 || !(Number(parts[0]) > Date.now()) || parts[1] !== p.getProperty('PIN_VER')) return false;
  return Utilities.base64EncodeWebSafe(Utilities.computeHmacSha256Signature(parts[0] + '.' + parts[1], secret)) === parts[2];
}
function setPin_(d) {
  if (props_().getProperty('PIN_HASH')) return {ok: false, error: 'exists'};
  if (!validPin_(d.pin)) return {ok: false, error: 'pin_format'};
  var ver = newPin_(String(d.pin));
  ss_();
  return {ok: true, token: token_(), pinVer: ver};
}
function unlock_(d) {
  var p = props_(), cache = CacheService.getScriptCache(), wrong = Number(cache.get('wrong') || 0);
  if (!p.getProperty('PIN_HASH')) return {ok: false, error: 'no_pin'};
  if (wrong >= WRONG_LIMIT) return {ok: false, error: 'locked'};
  if (!validPin_(d.pin) || hash_(String(d.pin), p.getProperty('PIN_SALT')) !== p.getProperty('PIN_HASH')) {
    cache.put('wrong', String(wrong + 1), 600);
    return {ok: false, error: 'wrong', left: Math.max(0, WRONG_LIMIT - wrong - 1)};
  }
  cache.remove('wrong');
  return {ok: true, token: token_(), pinVer: Number(p.getProperty('PIN_VER'))};
}
function changePin_(d) {
  var p = props_();
  if (hash_(String(d.oldPin || ''), p.getProperty('PIN_SALT')) !== p.getProperty('PIN_HASH')) return {ok: false, error: 'wrong'};
  if (!validPin_(d.newPin)) return {ok: false, error: 'pin_format'};
  var ver = newPin_(String(d.newPin));
  return {ok: true, token: token_(), pinVer: ver};
}
/** Forgot the PIN? Select resetPin above and press Run. The app will ask everyone to set a new PIN. */
function resetPin() {
  ['PIN_HASH', 'PIN_SALT', 'SECRET'].forEach(function (k) { props_().deleteProperty(k); });
  props_().setProperty('PIN_VER', String(Number(props_().getProperty('PIN_VER') || 0) + 1));
  CacheService.getScriptCache().remove('wrong');
  console.log('PIN removed. Open the app and create a new 4-digit PIN.');
}
function locked_(fn) {
  var lock = LockService.getScriptLock();
  if (!lock.tryLock(20000)) return {ok: false, error: 'busy'};
  try { return fn(); } finally { lock.releaseLock(); }
}

/* ---------- sheet helpers ---------- */
var SS = null;
function ss_() {
  if (SS) return SS;
  var p = props_(), id = p.getProperty('SHEET_ID'), ss = null;
  if (id) { try { ss = SpreadsheetApp.openById(id); } catch (x) { ss = null; } }
  if (!ss) {
    ss = SpreadsheetApp.create('Pro Smash Attendance (data)');
    p.setProperty('SHEET_ID', ss.getId());
    var first = ss.getSheets()[0]; first.setName('Students'); init_(first, 'Students');
    ['Attendance', 'Reports', 'Settings'].forEach(function (n) { init_(ss.insertSheet(n), n); });
  }
  return (SS = ss);
}
function init_(sh, name) {
  sh.getRange(1, 1, sh.getMaxRows(), COLS[name].length).setNumberFormat('@');
  sh.getRange(1, 1, 1, COLS[name].length).setValues([COLS[name]]).setFontWeight('bold');
  sh.setFrozenRows(1);
}
function sheet_(name) { var ss = ss_(), sh = ss.getSheetByName(name); if (!sh) { sh = ss.insertSheet(name); init_(sh, name); } return sh; }
function norm_(v) { return v instanceof Date ? Utilities.formatDate(v, Session.getScriptTimeZone(), 'yyyy-MM-dd') : (v === null || v === undefined ? '' : String(v)); }
function rows_(name) {
  var sh = sheet_(name), n = sh.getLastRow() - 1;
  return n < 1 ? [] : sh.getRange(2, 1, n, COLS[name].length).getValues().map(function (r) { return r.map(norm_); });
}
function findRow_(sh, key) {
  var n = sh.getLastRow() - 1; if (n < 1) return -1;
  var ids = sh.getRange(2, 1, n, 1).getValues();
  for (var i = 0; i < ids.length; i++) if (norm_(ids[i][0]) === key) return i + 2;
  return -1;
}
function cell_(v) { v = v === null || v === undefined ? '' : String(v); return /^[=+\-@]/.test(v) ? "'" + v : v; }
function write_(sh, row, vals) {
  if (row > sh.getMaxRows()) sh.insertRowsAfter(sh.getMaxRows(), 500);
  var rg = sh.getRange(row, 1, 1, vals.length); rg.setNumberFormat('@'); rg.setValues([vals.map(cell_)]);
}
function upsert_(name, key, vals) { var sh = sheet_(name), row = findRow_(sh, key); write_(sh, row < 0 ? Math.max(sh.getLastRow(), 1) + 1 : row, vals); }
function str_(v, n) { return String(v === null || v === undefined ? '' : v).trim().slice(0, n || 200); }
function isDate_(s) { return /^\d{4}-\d{2}-\d{2}$/.test(String(s)); }
function isMonth_(s) { return /^\d{4}-\d{2}$/.test(String(s)); }
function json_(s, dflt) { try { var v = JSON.parse(s || ''); return v && typeof v === 'object' ? v : dflt; } catch (x) { return dflt; } }

/* ---------- data ---------- */
function settings_() {
  var o = {academy: 'Pro Smash Badminton Academy', batches: [], lang: 'en'};
  var have = false;
  rows_('Settings').forEach(function (r) {
    if (r[0] === 'academy') { o.academy = r[1]; have = true; }
    else if (r[0] === 'batches') o.batches = json_(r[1], []);
    else if (r[0] === 'lang') o.lang = r[1] === 'hi' ? 'hi' : 'en';
  });
  if (!have) o.batches = [{id: 'b1', name: 'Beginner', time: ''}, {id: 'b2', name: 'Intermediate', time: ''}, {id: 'b3', name: 'Advance 1', time: ''}, {id: 'b4', name: 'Advance pro', time: ''}];
  return o;
}
function saveSettings_(d) {
  var batches = (Array.isArray(d.batches) ? d.batches : []).filter(function (b) { return b && b.id && str_(b.name); }).slice(0, 40)
    .map(function (b) { return {id: str_(b.id, 40), name: str_(b.name, 60), time: str_(b.time, 60)}; });
  upsert_('Settings', 'academy', ['academy', str_(d.academy, 120) || 'My academy']);
  upsert_('Settings', 'batches', ['batches', JSON.stringify(batches)]);
  upsert_('Settings', 'lang', ['lang', d.lang === 'hi' ? 'hi' : 'en']);
  var names = {}; batches.forEach(function (b) { names[b.id] = b.name; });
  var sh = sheet_('Students'), n = sh.getLastRow() - 1;
  if (n > 0) {
    var ids = sh.getRange(2, 3, n, 1).getValues(), rg = sh.getRange(2, 4, n, 1);
    rg.setNumberFormat('@'); rg.setValues(ids.map(function (r) { return [cell_(names[norm_(r[0])] || '')]; }));
  }
  return {ok: true, settings: settings_()};
}
function studentsAll_() {
  return rows_('Students').filter(function (r) { return r[0]; }).map(function (r) {
    return {id: r[0], name: r[1], batch: r[2], parentName: r[4], phone: r[5], joined: r[6], removed: r[7] === 'yes', updated: r[8]};
  });
}
function saveStudents_(d) {
  var list = Array.isArray(d.students) ? d.students.slice(0, 500) : [], st = settings_(), names = {}, saved = 0;
  st.batches.forEach(function (b) { names[b.id] = b.name; });
  var sh = sheet_('Students');
  list.forEach(function (s) {
    var id = str_(s.id, 40), name = str_(s.name, 100);
    if (!id || !name) return;
    var vals = [id, name, str_(s.batch, 40), names[s.batch] || '', str_(s.parentName, 100), str_(s.phone, 30), isDate_(s.joined) ? s.joined : '', '', new Date().toISOString()];
    var row = findRow_(sh, id);
    write_(sh, row < 0 ? Math.max(sh.getLastRow(), 1) + 1 : row, vals);
    saved++;
  });
  return {ok: true, saved: saved};
}
function removeStudent_(d) {
  var sh = sheet_('Students'), row = findRow_(sh, str_(d.id, 40));
  if (row > 1) { var rg = sh.getRange(row, 8, 1, 2); rg.setNumberFormat('@'); rg.setValues([['yes', new Date().toISOString()]]); }
  return {ok: true};
}
function attFor_(keep) {
  var o = {};
  rows_('Attendance').forEach(function (r) { if (r[0] && keep(r[0])) o[r[0]] = json_(r[3], {}); });
  return o;
}
function mark_(d) {
  var date = str_(d.date, 10);
  if (!isDate_(date)) return {ok: false, error: 'date'};
  var sh = sheet_('Attendance'), row = findRow_(sh, date), marks = {};
  if (row > 1) marks = json_(norm_(sh.getRange(row, 4).getValue()), {});
  var ch = d.changes || {};
  Object.keys(ch).forEach(function (k) { if (ch[k] === 'P' || ch[k] === 'A') marks[k] = ch[k]; else delete marks[k]; });
  var P = 0, A = 0; Object.keys(marks).forEach(function (k) { if (marks[k] === 'P') P++; else A++; });
  write_(sh, row < 0 ? Math.max(sh.getLastRow(), 1) + 1 : row, [date, P, A, JSON.stringify(marks)]);
  return {ok: true, date: date, marks: marks};
}
function report_(month, col, sid, value) {
  if (!isMonth_(month) || !sid) return {ok: false, error: 'bad'};
  var sh = sheet_('Reports'), row = findRow_(sh, month), notes = {}, sent = {};
  if (row > 1) { var v = sh.getRange(row, 1, 1, 3).getValues()[0]; notes = json_(norm_(v[1]), {}); sent = json_(norm_(v[2]), {}); }
  var target = col === 1 ? notes : sent;
  if (value) target[sid] = value; else delete target[sid];
  write_(sh, row < 0 ? Math.max(sh.getLastRow(), 1) + 1 : row, [month, JSON.stringify(notes), JSON.stringify(sent)]);
  return {ok: true};
}
function reports_(keep) {
  var notes = {}, sent = {};
  rows_('Reports').forEach(function (r) { if (r[0] && keep(r[0])) { notes[r[0]] = json_(r[1], {}); sent[r[0]] = json_(r[2], {}); } });
  return {notes: notes, sent: sent};
}
function load_(d) {
  var from = isMonth_(d.from) ? d.from : '0000-00';
  var keep = function (k) { return k.slice(0, 7) >= from; };
  var rep = reports_(keep), st = settings_();
  return {ok: true, academy: st.academy, batches: st.batches, lang: st.lang,
    students: studentsAll_().filter(function (s) { return !s.removed; }), att: attFor_(keep), notes: rep.notes, sent: rep.sent,
    from: from, pinVer: Number(props_().getProperty('PIN_VER') || 0), sheetUrl: ss_().getUrl()};
}
function exportAll_() {
  var all = function () { return true; }, rep = reports_(all), st = settings_();
  return {ok: true, data: {academy: st.academy, batches: st.batches, lang: st.lang, students: studentsAll_().filter(function (s) { return !s.removed; }),
    att: attFor_(all), notes: rep.notes, sent: rep.sent}};
}
function importAll_(d) {
  var data = d.data || {};
  if (studentsAll_().length && !d.replace) return {ok: false, error: 'not_empty'};
  saveSettings_({academy: data.academy, batches: data.batches, lang: data.lang});
  saveStudents_({students: data.students || []});
  var att = data.att || {}, sh = sheet_('Attendance'), rows = [];
  Object.keys(att).sort().forEach(function (date) {
    if (!isDate_(date)) return;
    var m = att[date] || {}, P = 0, A = 0, clean = {};
    Object.keys(m).forEach(function (k) { if (m[k] === 'P' || m[k] === 'A') { clean[k] = m[k]; if (m[k] === 'P') P++; else A++; } });
    rows.push([date, P, A, JSON.stringify(clean)]);
  });
  rows.forEach(function (r) { var row = findRow_(sh, r[0]); write_(sh, row < 0 ? Math.max(sh.getLastRow(), 1) + 1 : row, r); });
  var months = {};
  Object.keys(data.notes || {}).concat(Object.keys(data.sent || {})).forEach(function (m) { months[m] = 1; });
  var rs = sheet_('Reports');
  Object.keys(months).forEach(function (m) {
    if (!isMonth_(m)) return;
    var row = findRow_(rs, m);
    write_(rs, row < 0 ? Math.max(rs.getLastRow(), 1) + 1 : row, [m, JSON.stringify((data.notes || {})[m] || {}), JSON.stringify((data.sent || {})[m] || {})]);
  });
  return {ok: true, students: (data.students || []).length, days: rows.length};
}
