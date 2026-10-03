/* ============================================================
   Finanças JR — auth.js
   Sessão única do Supabase, compartilhada por todas as telas.

   AUTH_VERSION: v2026.10.03-a

   O que isso resolve
   ------------------
   Antes, o PIN era só enfeite: ele escondia a interface, mas os dados
   continuavam abertos a quem tivesse a chave anon (que está no HTML).
   Agora o PIN e o Face ID destravam uma SESSÃO REAL do Supabase, e é o
   token dessa sessão que vai em toda chamada ao banco.

   Como a sessão é guardada
   ------------------------
   A senha nunca é gravada. O que fica no aparelho é o refresh token,
   cifrado em AES-GCM por uma chave aleatória K. O K, por sua vez, é
   embrulhado:

     jr_rt       refresh token cifrado com K
     jr_k_pin    K embrulhado por chave derivada do PIN (PBKDF2, 210k)
     jr_k_bio    K embrulhado por chave do aparelho  (só se Face ID ligado)

   Por que uma chave intermediária, e não cifrar o token direto com o PIN:
   o Supabase ROTACIONA o refresh token a cada renovação. Com duas cópias
   independentes do token, entrar por Face ID invalidaria o PIN e vice-versa.
   Com K no meio, a rotação reescreve só jr_rt — os dois caminhos de
   destrave continuam valendo, porque os dois chegam ao mesmo K.

   Força de cada caminho
   ---------------------
   O PIN é proteção real: a chave dele não existe em lugar nenhum, é
   derivada na hora. O Face ID é conveniência: a chave do aparelho mora no
   localStorage, então vale enquanto o aparelho é seu. Não são
   equivalentes, e é proposital.

   Migração sem quebrar nada
   -------------------------
   Sem sessão, headers() devolve a chave anon, igual a hoje. As telas
   seguem funcionando durante a migração e só passam a exigir login quando
   o acesso anon for revogado no banco — que é o último passo, de propósito.
   ============================================================ */
'use strict';

window.JRAuth = (function () {

  const SB  = 'https://tggtktjblunlbsjbhlls.supabase.co';
  const KEY = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InRnZ3RrdGpibHVubGJzamJobGxzIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NzYyODM0MTksImV4cCI6MjA5MTg1OTQxOX0.POdSpd63K5WfCoLWn0LwqSm5SFRTOSEukLGRExCrP_o';

  const K_RT   = 'jr_rt';       // refresh token cifrado com K
  const K_PIN  = 'jr_k_pin';    // K embrulhado pelo PIN
  const K_BIO  = 'jr_k_bio';    // K embrulhado pela chave do aparelho
  const K_DEV  = 'jr_devkey';   // chave do aparelho (conveniência)
  const K_MAIL = 'jr_mail';     // e-mail, só para preencher o campo
  const ITER   = 210000;

  let _access  = null;          // access token: só em memória, nunca no disco
  let _exp     = 0;             // epoch em segundos
  let _refresh = null;          // refresh token em claro, só em memória
  let _K       = null;          // chave de cifragem, só em memória
  let _renovando = null;        // evita renovações simultâneas

  /* ---------- utilidades ---------- */
  const enc = new TextEncoder();
  const dec = new TextDecoder();
  const b64 = b => btoa(String.fromCharCode(...new Uint8Array(b)));
  const unb64 = s => { const t = atob(s), a = new Uint8Array(t.length);
                       for (let i = 0; i < t.length; i++) a[i] = t.charCodeAt(i); return a; };

  function ls(k, v) {
    try {
      if (v === undefined) return localStorage.getItem(k);
      if (v === null) { localStorage.removeItem(k); return null; }
      localStorage.setItem(k, v); return v;
    } catch (e) { return null; }      // navegação privada / storage bloqueado
  }

  /* ---------- camada de cifragem ---------- */

  // Chave derivada de um segredo (PIN ou chave de aparelho), usada só
  // para embrulhar e desembrulhar o K.
  async function chaveDerivada(segredo, salt) {
    const base = await crypto.subtle.importKey('raw', enc.encode(segredo), 'PBKDF2', false, ['deriveKey']);
    return crypto.subtle.deriveKey(
      { name: 'PBKDF2', salt, iterations: ITER, hash: 'SHA-256' },
      base, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
  }

  async function novoK() {
    return crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);
  }

  async function cifraCom(chave, texto) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, chave, enc.encode(texto));
    return JSON.stringify({ i: b64(iv), c: b64(ct) });
  }

  async function decifraCom(chave, pacote) {
    const o = JSON.parse(pacote);
    const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: unb64(o.i) }, chave, unb64(o.c));
    return dec.decode(pt);
  }

  // Embrulha o K com um segredo. Guarda o salt junto.
  async function embrulhaK(segredo) {
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const kd   = await chaveDerivada(segredo, salt);
    const raw  = await crypto.subtle.exportKey('raw', _K);
    const iv   = crypto.getRandomValues(new Uint8Array(12));
    const ct   = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, kd, raw);
    return JSON.stringify({ s: b64(salt), i: b64(iv), c: b64(ct) });
  }

  async function desembrulhaK(segredo, pacote) {
    const o  = JSON.parse(pacote);
    const kd = await chaveDerivada(segredo, unb64(o.s));
    const raw = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: unb64(o.i) }, kd, unb64(o.c));
    return crypto.subtle.importKey('raw', raw, { name: 'AES-GCM' }, true, ['encrypt', 'decrypt']);
  }

  // O token rotacionou: reescreve só jr_rt. Os embrulhos de K continuam valendo.
  async function gravaRT() {
    if (!_K || !_refresh) return;
    ls(K_RT, await cifraCom(_K, _refresh));
  }

  /* ---------- endpoint de auth ---------- */
  async function authPost(caminho, corpo, comToken) {
    const h = { 'apikey': KEY, 'Content-Type': 'application/json' };
    if (comToken && _access) h['Authorization'] = 'Bearer ' + _access;
    const r = await fetch(SB + '/auth/v1/' + caminho, {
      method: 'POST', headers: h, body: JSON.stringify(corpo || {})
    });
    const txt = await r.text();
    let j = null; try { j = txt ? JSON.parse(txt) : null; } catch (e) {}
    if (!r.ok) {
      const msg = (j && (j.error_description || j.msg || j.message || j.error)) || ('HTTP ' + r.status);
      throw new Error(msg);
    }
    return j;
  }

  function guardaSessao(j) {
    if (!j || !j.access_token) throw new Error('resposta de login sem token');
    _access  = j.access_token;
    _refresh = j.refresh_token || _refresh;
    _exp     = Math.floor(Date.now() / 1000) + (j.expires_in || 3600);
    return j;
  }

  /* ---------- API pública ---------- */

  // Headers de toda chamada ao banco. Sem sessão, devolve a chave anon —
  // é o que mantém o app de pé durante a migração.
  function headers(extra) {
    const h = {
      'apikey': KEY,
      'Authorization': 'Bearer ' + (_access || KEY),
      'Content-Type': 'application/json'
    };
    return extra ? Object.assign(h, extra) : h;
  }

  function temSessao()   { return !!_access && _exp > Math.floor(Date.now() / 1000) + 30; }
  function temCadastro() { return !!(ls(K_RT) && (ls(K_PIN) || ls(K_BIO))); }
  function emailSalvo()  { return ls(K_MAIL) || ''; }
  function token()       { return _access; }
  function bioHabilitado() { return !!(ls(K_BIO) && ls(K_DEV) && ls(K_RT)); }

  function renovar() {
    if (_renovando) return _renovando;
    if (!_refresh) return Promise.reject(new Error('sem refresh token'));
    _renovando = authPost('token?grant_type=refresh_token', { refresh_token: _refresh })
      .then(async j => { guardaSessao(j); await gravaRT(); return j; })
      .finally(() => { _renovando = null; });
    return _renovando;
  }

  // Garante token válido antes de uma chamada ao banco.
  async function pronto() {
    if (temSessao()) return true;
    if (_refresh) { try { await renovar(); return true; } catch (e) {} }
    return false;
  }

  // Primeiro acesso no aparelho: e-mail, senha e um PIN para guardar a sessão.
  async function entrarComSenha(email, senha, pin) {
    const j = await authPost('token?grant_type=password', { email: String(email).trim(), password: senha });
    guardaSessao(j);
    ls(K_MAIL, String(email).trim());
    if (pin) await definirPin(pin);
    return j;
  }

  // Cria (ou troca) o PIN deste aparelho.
  async function definirPin(pin) {
    if (!_refresh) throw new Error('sem sessão para guardar');
    if (!_K) _K = await novoK();
    await gravaRT();
    ls(K_PIN, await embrulhaK(pin));
    return true;
  }

  async function entrarComPin(pin) {
    const wk = ls(K_PIN), rt = ls(K_RT);
    if (!wk || !rt) throw new Error('nenhum PIN cadastrado neste aparelho');
    try { _K = await desembrulhaK(pin, wk); }
    catch (e) { throw new Error('PIN incorreto'); }
    _refresh = await decifraCom(_K, rt);
    await renovar();                 // já regrava o jr_rt rotacionado
    return true;
  }

  // Face ID / Touch ID: conveniência. A chave fica no próprio aparelho.
  async function habilitarBio() {
    if (!_K) throw new Error('destrave a sessão antes de habilitar o Face ID');
    let dk = ls(K_DEV);
    if (!dk) { dk = b64(crypto.getRandomValues(new Uint8Array(32))); ls(K_DEV, dk); }
    ls(K_BIO, await embrulhaK(dk));
    return true;
  }

  async function entrarComBio() {
    const wk = ls(K_BIO), dk = ls(K_DEV), rt = ls(K_RT);
    if (!wk || !dk || !rt) throw new Error('Face ID não está habilitado neste aparelho');
    _K = await desembrulhaK(dk, wk);
    _refresh = await decifraCom(_K, rt);
    await renovar();
    return true;
  }

  function desabilitarBio() { ls(K_BIO, null); ls(K_DEV, null); }

  async function sair(apagarAparelho) {
    try { if (_access) await authPost('logout', {}, true); } catch (e) {}
    _access = null; _refresh = null; _K = null; _exp = 0;
    if (apagarAparelho) { ls(K_RT, null); ls(K_PIN, null); ls(K_BIO, null); ls(K_DEV, null); }
  }

  // Confirma que a sessão é real, do lado do servidor.
  async function quemSou() {
    if (!await pronto()) return null;
    const r = await fetch(SB + '/auth/v1/user', { headers: headers() });
    return r.ok ? r.json() : null;
  }

  return {
    SB, KEY, headers, token, pronto, renovar,
    temSessao, temCadastro, emailSalvo,
    entrarComSenha, entrarComPin, definirPin,
    habilitarBio, entrarComBio, bioHabilitado, desabilitarBio,
    sair, quemSou,
    VERSION: 'v2026.10.03-a'
  };
})();
