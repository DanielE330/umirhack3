"use strict";
const $ = (id) => document.getElementById(id);
const views = ["f-login", "f-setup", "f-code", "s-codes", "s-home"];
let csrf = "";

function show(id) { views.forEach((v) => $(v).classList.toggle("hidden", v !== id)); $("msg").textContent = ""; }

async function api(path, body, method) {
  const res = await fetch(path, {
    method: method || (body === undefined ? "GET" : "POST"),
    headers: { "Content-Type": "application/json", "X-CSRF-Token": csrf },
    credentials: "same-origin",
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.detail || "Ошибка " + res.status);
  return data;
}

function fail(e) { $("msg").textContent = e.message; }

function home(d) {
  csrf = d.csrf;
  location.replace("/static/panel.html");  // вход выполнен: открываем панель
}

$("f-login").onsubmit = async (e) => {
  e.preventDefault();
  try {
    const r = await api("/api/auth/login", { username: $("u").value, password: $("p").value });
    $("p").value = "";
    if (r.next === "2fa_setup") {
      const s = await api("/api/auth/2fa/setup", {});
      $("qr").src = s.qr; $("secret").textContent = s.secret;
      show("f-setup"); $("c1").focus();
    } else { show("f-code"); $("c2").focus(); }
  } catch (err) { fail(err); }
};

$("f-setup").onsubmit = async (e) => {
  e.preventDefault();
  try {
    const d = await api("/api/auth/2fa/enable", { code: $("c1").value });
    csrf = d.csrf; $("c1").value = "";
    $("codes").replaceChildren(...d.recovery_codes.map((c) => Object.assign(document.createElement("li"), { textContent: c })));
    window._home = d; show("s-codes");
  } catch (err) { fail(err); }
};

$("saved").onclick = () => { $("codes").replaceChildren(); home(window._home); };

$("f-code").onsubmit = async (e) => {
  e.preventDefault();
  try { home(await api("/api/auth/2fa/verify", { code: $("c2").value })); $("c2").value = ""; }
  catch (err) { fail(err); }
};

$("back").onclick = () => show("f-login");
$("logout").onclick = async () => { try { await api("/api/auth/logout", {}); } catch (_) {} csrf = ""; show("f-login"); };

api("/api/auth/me").then(home).catch(() => show("f-login"));
