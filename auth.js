/* ============================================================
   Finanças JR — auth.js
   Sessão única do Supabase, compartilhada por todas as telas.

   AUTH_VERSION: v2026.10.03-f

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
  const K_SESS = 'jr_sessao';   // sessão viva da ABA (sessionStorage)
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

  /* ---------- sessão viva da aba ----------
     O app são páginas separadas: trocar de módulo recarrega a página e
     zeraria a sessão em memória, obrigando a destravar a cada clique.
     A sessão fica no sessionStorage, que sobrevive à navegação e aos
     recarregamentos DA ABA e é descartado quando a aba fecha.
     Compromisso assumido: enquanto a aba está aberta, o refresh token
     fica legível ali. Fechou a aba ou o navegador, exige PIN ou Face ID
     de novo. O que fica guardado em disco (localStorage) continua
     cifrado, como antes.                                              */
  function ss(k, v) {
    try {
      if (v === undefined) return sessionStorage.getItem(k);
      if (v === null) { sessionStorage.removeItem(k); return null; }
      sessionStorage.setItem(k, v); return v;
    } catch (e) { return null; }
  }

  function salvaSessaoDaAba() {
    if (!_access) return;
    ss(K_SESS, JSON.stringify({ a: _access, e: _exp, r: _refresh || null }));
  }

  function restauraSessaoDaAba() {
    const raw = ss(K_SESS);
    if (!raw) return false;
    try {
      const o = JSON.parse(raw);
      if (!o || !o.a) return false;
      _access = o.a; _exp = o.e || 0; _refresh = o.r || null;
      // expirado e sem refresh: não serve de nada
      if (!temSessao() && !_refresh) { ss(K_SESS, null); _access=null; _exp=0; return false; }
      return true;
    } catch (e) { ss(K_SESS, null); return false; }
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
    salvaSessaoDaAba();
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

  // O refresh token guardado pode ter sido revogado do outro lado (logout
  // global, troca de senha, sessão expirada no servidor). Nesse caso não
  // adianta insistir: o vínculo deste aparelho morreu e é preciso entrar
  // com e-mail e senha de novo.
  function ehTokenMorto(e) {
    const m = String((e && e.message) || e).toLowerCase();
    return m.includes('refresh token') || m.includes('refresh_token_not_found')
        || m.includes('invalid grant') || m.includes('session') && m.includes('not found');
  }

  function limpaVinculo() {
    _access = null; _refresh = null; _K = null; _exp = 0;
    ls(K_RT, null); ls(K_PIN, null); ls(K_BIO, null); ls(K_DEV, null);
    ss(K_SESS, null);
  }

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
    if (_refresh) {
      try { await renovar(); return true; }
      catch (e) { if (ehTokenMorto(e)) limpaVinculo(); }
    }
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
    try { await renovar(); }         // já regrava o jr_rt rotacionado
    catch (e) {
      if (ehTokenMorto(e)) { limpaVinculo();
        throw new Error('A sessão deste aparelho expirou. Entre com e-mail e senha de novo.'); }
      throw e;
    }
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
    try { await renovar(); }
    catch (e) {
      if (ehTokenMorto(e)) { limpaVinculo();
        throw new Error('A sessão deste aparelho expirou. Entre com e-mail e senha de novo.'); }
      throw e;
    }
    return true;
  }

  function desabilitarBio() { ls(K_BIO, null); ls(K_DEV, null); }

  async function sair(apagarAparelho) {
    // scope=local encerra SÓ esta sessão. O padrão do Supabase é `global`,
    // que revoga o refresh token de TODOS os aparelhos — foi o que derrubou
    // o celular quando o logout foi feito no laptop.
    try { if (_access) await authPost('logout?scope=local', {}, true); } catch (e) {}
    _access = null; _refresh = null; _K = null; _exp = 0;
    ss(K_SESS, null);
    if (apagarAparelho) { ls(K_RT, null); ls(K_PIN, null); ls(K_BIO, null); ls(K_DEV, null); }
  }

  // Confirma que a sessão é real, do lado do servidor.
  async function quemSou() {
    if (!await pronto()) return null;
    const r = await fetch(SB + '/auth/v1/user', { headers: headers() });
    return r.ok ? r.json() : null;
  }


  /* ---------- tela de login embutida ----------
     As telas antigas trazem o próprio overlay no HTML. As que não trazem
     (index, emails, importar-quicken) usam este, injetado daqui: estilos
     próprios, sem depender do CSS da página. É o padrão para telas novas. */

  const CSS_LOGIN = `
#jrLogin{position:fixed;inset:0;z-index:99999;display:none;flex-direction:column;
  align-items:center;justify-content:center;padding:24px;
  background:var(--bg,#0d0f14);color:var(--text,#e8eaf0);
  font-family:'DM Sans',system-ui,sans-serif}
#jrLogin .jl{font-family:'DM Serif Display',Georgia,serif;font-size:36px;letter-spacing:-1px;margin-bottom:6px}
#jrLogin .jl span{color:var(--accent,#4f8ef7)}
#jrLogin .js{font-size:13px;color:var(--muted,#6b7280);margin-bottom:44px}
#jrLogin .jb{width:100%;max-width:320px}
#jrLogin label{font-size:10px;font-weight:600;text-transform:uppercase;letter-spacing:.8px;
  color:var(--muted,#6b7280);margin-bottom:8px;display:block}
#jrLogin input{width:100%;background:var(--surface,#13161e);border:1.5px solid var(--border,#252a38);
  border-radius:14px;padding:14px;color:var(--text,#e8eaf0);font-family:inherit;font-size:22px;
  outline:none;text-align:center;letter-spacing:6px;margin-bottom:10px;-webkit-appearance:none}
#jrLogin input.txt{font-size:14px;text-align:left;letter-spacing:0}
#jrLogin input:focus{border-color:var(--accent,#4f8ef7)}
#jrLogin input.err{border-color:var(--red,#f87171);animation:jrshake .3s}
@keyframes jrshake{0%,100%{transform:translateX(0)}25%{transform:translateX(-8px)}75%{transform:translateX(8px)}}
#jrLogin button{width:100%;padding:14px;background:var(--accent,#4f8ef7);color:#fff;border:none;
  border-radius:12px;font-family:inherit;font-size:15px;font-weight:700;cursor:pointer;margin-bottom:10px}
#jrLogin button.alt{background:rgba(79,142,247,.12);color:var(--accent,#4f8ef7);
  border:1px solid rgba(79,142,247,.3)}
#jrLogin .jerr{color:var(--red,#f87171);font-size:12px;text-align:center;min-height:18px;margin-bottom:8px}
#jrLogin .jhint{font-size:11px;color:var(--muted,#6b7280);text-align:center;line-height:1.5;margin-top:8px}
#jrLogin a{color:var(--accent,#4f8ef7);text-decoration:none}`;

  const HTML_LOGIN = `
<div class="jl">Finanças <span>JR</span></div>
<div class="js">Gestão Financeira Pessoal</div>
<div class="jb">
  <div id="jrNovo" style="display:none">
    <label>E-mail</label>
    <input type="email" class="txt" id="jrMail" autocomplete="username" placeholder="seu@email.com">
    <label style="margin-top:10px">Senha</label>
    <input type="password" class="txt" id="jrPwd" autocomplete="current-password" placeholder="••••••••">
  </div>
  <label id="jrPinLbl" style="margin-top:10px">PIN de acesso</label>
  <input type="password" inputmode="numeric" maxlength="8" id="jrPin" placeholder="••••">
  <div class="jerr" id="jrErr"></div>
  <button id="jrEntrar">Entrar</button>
  <button class="alt" id="jrBio" style="display:none">🔓 Entrar com Face ID / Touch ID</button>
  <div class="jhint" id="jrHint"></div>
</div>`;

  let _aoEntrar = null;

  function montaLogin() {
    if (document.getElementById('jrLogin')) return;
    const st = document.createElement('style'); st.textContent = CSS_LOGIN;
    document.head.appendChild(st);
    const ov = document.createElement('div'); ov.id = 'jrLogin'; ov.innerHTML = HTML_LOGIN;
    document.body.appendChild(ov);
    document.getElementById('jrEntrar').onclick = tentaEntrar;
    document.getElementById('jrBio').onclick = tentaBio;
    ['jrPin','jrPwd'].forEach(id => {
      const el = document.getElementById(id);
      if (el) el.onkeydown = e => { if (e.key === 'Enter') tentaEntrar(); };
    });
  }

  function mostraLogin() {
    montaLogin();
    const novo = !temCadastro();
    document.getElementById('jrLogin').style.display = 'flex';
    document.getElementById('jrNovo').style.display = novo ? 'block' : 'none';
    document.getElementById('jrPinLbl').textContent = novo ? 'Crie um PIN para este aparelho' : 'PIN de acesso';
    document.getElementById('jrHint').innerHTML = novo
      ? 'Na primeira vez em cada aparelho, entre com e-mail e senha e escolha um PIN.'
      : '<a href="#" id="jrOutra">Entrar com outra conta</a>';
    document.getElementById('jrBio').style.display = (!novo && bioHabilitado()) ? 'block' : 'none';
    const m = document.getElementById('jrMail'); if (m && !m.value) m.value = emailSalvo();
    const outra = document.getElementById('jrOutra');
    if (outra) outra.onclick = async e => { e.preventDefault(); await sair(true); mostraLogin(); };
    setTimeout(() => { try { document.getElementById(novo ? 'jrMail' : 'jrPin').focus(); } catch (e) {} }, 100);
  }

  function escondeLogin() {
    const ov = document.getElementById('jrLogin');
    if (ov) ov.style.display = 'none';
  }

  function entrou() {
    escondeLogin();
    const f = _aoEntrar; _aoEntrar = null;
    if (typeof f === 'function') f();
  }

  async function tentaEntrar() {
    const err = document.getElementById('jrErr');
    const inp = document.getElementById('jrPin');
    const pin = (inp.value || '').trim();
    err.textContent = '';
    try {
      if (!temCadastro()) {
        const mail = (document.getElementById('jrMail').value || '').trim();
        const senha = document.getElementById('jrPwd').value || '';
        if (!mail || !senha) { err.textContent = 'Informe e-mail e senha.'; return; }
        if (pin.length < 4) { err.textContent = 'Escolha um PIN de 4 a 8 dígitos.'; return; }
        err.textContent = 'Entrando...';
        await entrarComSenha(mail, senha, pin);
      } else {
        if (!pin) { err.textContent = 'Digite o PIN'; return; }
        await entrarComPin(pin);
      }
      inp.value = '';
      const pw = document.getElementById('jrPwd'); if (pw) pw.value = '';
      entrou();
    } catch (e) {
      inp.classList.add('err');
      err.textContent = e.message || 'Não foi possível entrar.';
      inp.value = '';
      setTimeout(() => inp.classList.remove('err'), 400);
      if (!temCadastro()) mostraLogin();   // vínculo morreu: volta para e-mail e senha
    }
  }

  async function tentaBio() {
    const err = document.getElementById('jrErr');
    try { await entrarComBio(); entrou(); }
    catch (e) { err.textContent = e.message || 'Face ID falhou. Use o PIN.'; if (!temCadastro()) mostraLogin(); }
  }

  // Única chamada que uma tela sem login próprio precisa fazer.
  async function protege(aoEntrar) {
    _aoEntrar = aoEntrar;
    if (await pronto()) { entrou(); return true; }
    mostraLogin();
    return false;
  }

  // Ao carregar a página, tenta retomar a sessão da aba antes de
  // qualquer coisa: é o que permite trocar de módulo sem destravar.
  restauraSessaoDaAba();

  return {
    SB, KEY, headers, token, pronto, renovar,
    temSessao, temCadastro, emailSalvo,
    entrarComSenha, entrarComPin, definirPin,
    habilitarBio, entrarComBio, bioHabilitado, desabilitarBio,
    sair, quemSou,
    protege, mostraLogin, escondeLogin,
    VERSION: 'v2026.10.03-f'
  };
})();
