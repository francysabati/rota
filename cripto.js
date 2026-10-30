// Mesmas contas do app Android (Seg.java): senha da loja -> código e chave; nome -> senha do motoboy;
// assinatura de cada aviso. Qualquer diferença aqui faz o painel recusar avisos verdadeiros.
(function (g) {
  const te = new TextEncoder();
  const ALFABETO = "ABCDEFGHJKMNPQRSTUVWXYZ23456789";
  const subtle = g.crypto.subtle;

  async function derivar(senha) {
    const k = await subtle.importKey("raw", te.encode(senha), "PBKDF2", false, ["deriveBits"]);
    const bits = await subtle.deriveBits(
      { name: "PBKDF2", hash: "SHA-256", salt: te.encode("rota-do-motoboy/loja"), iterations: 120000 }, k, 512);
    return new Uint8Array(bits);
  }
  const codigo = k => Array.from(k.slice(0, 8), b => ALFABETO[b % ALFABETO.length]).join("");
  const hex = b => Array.from(b, x => x.toString(16).padStart(2, "0")).join("");
  const unhex = s => new Uint8Array(s.match(/../g).map(x => parseInt(x, 16)));
  const chave = k => hex(k.slice(32, 64));
  const norm = n => n.trim().toLowerCase().normalize("NFD").replace(/\p{M}/gu, "").replace(/[ \t\n\x0B\f\r]+/g, " ");

  async function hmac(keyBytes, texto) {
    const k = await subtle.importKey("raw", keyBytes, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
    return new Uint8Array(await subtle.sign("HMAC", k, te.encode(texto)));
  }
  async function pin(chaveHex, nome) {
    const h = await hmac(unhex(chaveHex), "pin|" + norm(nome));
    const v = ((h[0] << 24) >>> 0) + (h[1] << 16) + (h[2] << 8) + h[3];
    return String(v % 1000000).padStart(6, "0");
  }
  const assinado = (msg, r) => r ? msg + "|r:" + r : msg;
  async function assinar(p, nome, status, msg, t) {
    return hex((await hmac(te.encode(p), norm(nome) + "|" + status + "|" + msg + "|" + t)).slice(0, 12));
  }
  g.RotaCripto = { derivar, codigo, chave, norm, pin, assinado, assinar };
})(typeof window !== "undefined" ? window : globalThis);
