"use strict";

const $ = (selector, root = document) => root.querySelector(selector);
const enc = new TextEncoder();
const dec = new TextDecoder();
const ROUND_COUNT = 320000;
const FILE_PREFIX = "CHATRIX_FILE:";
const SAFE_FILE_TYPES = new Set(["image/png", "image/jpeg", "image/gif", "image/webp", "application/pdf", "text/plain", "application/msword", "application/vnd.openxmlformats-officedocument.wordprocessingml.document", "application/octet-stream"]);
const state = {
  me: null,
  privateKey: null,
  chats: [],
  active: null,
  filter: "all",
  searchTimer: 0,
  pollTimer: 0,
  polling: false,
  messages: [],
  lastId: 0,
  cryptoCache: new Map(),
  authBundle: null,
  theme: localStorage.getItem("chatrix-theme") || "dark",
  unverifiedPeers: new Set(),
  changedPeerKeys: new Set(),
};

function b64(bytes) {
  const data = bytes instanceof ArrayBuffer ? new Uint8Array(bytes) : bytes;
  let binary = "";
  for (let i = 0; i < data.length; i += 0x8000) binary += String.fromCharCode(...data.subarray(i, i + 0x8000));
  return btoa(binary);
}
function unb64(value) {
  const binary = atob(value);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}
function escapeHtml(value) {
  return String(value ?? "").replace(/[&<>"']/g, (ch) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[ch]);
}
function canonical(handle) { return String(handle || "").trim().replace(/^@/, "").toLowerCase(); }
function niceName(person) { return person?.displayName?.trim() || person?.handle || "User"; }
function firstLetter(person) { return (niceName(person).replace(/^@/, "").trim()[0] || "?").toLocaleUpperCase("ru"); }
function avatarTone(handle) { let n = 0; for (const ch of String(handle || "")) n = (n * 31 + ch.charCodeAt(0)) >>> 0; return `tone-${n % 6}`; }
function setTheme(theme) {
  state.theme = theme;
  document.body.classList.toggle("theme-light", theme === "light");
  localStorage.setItem("chatrix-theme", theme);
  const icon = theme === "light" ? "☼" : "◐";
  [$("#theme-auth"), $("#theme-app")].filter(Boolean).forEach((button) => { button.textContent = icon; });
}
function toast(message, type = "") {
  const element = document.createElement("div");
  element.className = `toast ${type}`;
  element.textContent = message;
  $("#toast-region").append(element);
  window.setTimeout(() => element.remove(), 3800);
}
async function api(path, options = {}) {
  const config = { credentials: "same-origin", ...options, headers: { ...(options.body ? { "Content-Type": "application/json" } : {}), ...(options.headers || {}) } };
  if (config.body && typeof config.body !== "string") config.body = JSON.stringify(config.body);
  let response;
  try { response = await fetch(path, config); }
  catch { throw new Error("Could not reach the server. Check your connection."); }
  let data;
  try { data = await response.json(); } catch { data = {}; }
  if (!response.ok) throw new Error(data.error || "The request could not be completed.");
  return data;
}

async function passwordKey(password, salt) {
  const material = await crypto.subtle.importKey("raw", enc.encode(password), "PBKDF2", false, ["deriveKey"]);
  return crypto.subtle.deriveKey({ name: "PBKDF2", hash: "SHA-256", salt, iterations: ROUND_COUNT }, material, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
}
async function prepareIdentity(password) {
  const pair = await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]);
  const publicKey = new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey));
  const privateKey = new Uint8Array(await crypto.subtle.exportKey("pkcs8", pair.privateKey));
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const wrapKey = await passwordKey(password, salt);
  const serialized = enc.encode(JSON.stringify({ privateKey: b64(privateKey), publicKey: b64(publicKey) }));
  const wrapped = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, wrapKey, serialized);
  return {
    publicKey: b64(publicKey), privateBundle: b64(wrapped), bundleIv: b64(iv), bundleSalt: b64(salt),
    privateKey: pair.privateKey,
  };
}
async function unlockIdentity(password, bundle, expectedPublicKey) {
  const wrapKey = await passwordKey(password, unb64(bundle.bundleSalt));
  const clear = await crypto.subtle.decrypt({ name: "AES-GCM", iv: unb64(bundle.bundleIv) }, wrapKey, unb64(bundle.privateBundle));
  const identity = JSON.parse(dec.decode(clear));
  if (identity.publicKey !== expectedPublicKey) throw new Error("The account key does not match. Sign-in was stopped to protect your chats.");
  return crypto.subtle.importKey("pkcs8", unb64(identity.privateKey), { name: "ECDH", namedCurve: "P-256" }, false, ["deriveBits"]);
}

function renderAuth(mode = "login", error = "", person = null, bundle = null) {
  state.authBundle = bundle;
  const content = $("#auth-content");
  const unlock = mode === "unlock";
  const signup = mode === "register";
  const handle = person?.handle || "";
  const userLine = unlock ? `<div class="auth-user-chip"><span class="avatar avatar-peer ${avatarTone(handle)}">${escapeHtml(firstLetter(person))}</span><span><strong>${escapeHtml(niceName(person))}</strong><small>${escapeHtml(handle)}</small></span></div>` : "";
  content.innerHTML = `
    ${unlock ? "" : `<div class="auth-kicker">${signup ? "YOUR NEW SPACE" : "WELCOME BACK"}</div>`}
    <h2 class="auth-title">${unlock ? "Welcome back" : signup ? "Create your account" : "Sign in to Chatrix"}</h2>
    <p class="auth-subtitle">${unlock ? "Enter your password to unlock your chat key on this device." : signup ? "Choose a username. Your messages are encrypted right in your browser." : "Your conversations are waiting. Sign in to pick up where you left off."}</p>
    ${userLine}
    <form id="auth-form" class="auth-form" data-mode="${mode}">
      ${unlock ? "" : `<div class="field"><label for="auth-username">Username</label><div class="input-wrap"><span class="input-prefix">@</span><input id="auth-username" name="username" autocomplete="username" placeholder="e.g. testerPRO" minlength="3" maxlength="24" required></div><span class="field-hint">3–24 characters: letters, numbers, and _</span></div>`}
      ${signup ? `<div class="field"><label for="auth-display-name">What should we call you? <span class="field-hint">· optional</span></label><input id="auth-display-name" name="displayName" autocomplete="name" placeholder="Your name" maxlength="48"></div>` : ""}
      <div class="field"><label for="auth-password">${unlock ? "Account password" : "Password"}</label><input id="auth-password" name="password" type="password" autocomplete="${signup ? "new-password" : "current-password"}" placeholder="At least 8 characters" minlength="8" maxlength="256" required autofocus></div>
      ${error ? `<p class="auth-error" role="alert">${escapeHtml(error)}</p>` : ""}
      <button type="submit" class="primary-button auth-submit">${unlock ? "Unlock Chatrix" : signup ? "Create account" : "Sign in"}<span>→</span></button>
    </form>
    ${unlock ? `<p class="auth-switch">Not your account? <button class="text-button" type="button" data-auth-action="logout">Sign out</button></p>` : `<p class="auth-switch">${signup ? "Already have an account?" : "New to Chatrix?"} <button class="text-button" type="button" data-auth-action="${signup ? "login" : "register"}">${signup ? "Sign in" : "Create an account"}</button></p>`}`;
  $("#auth-view").classList.remove("hidden");
  $("#app-view").classList.add("hidden");
  const field = unlock ? $("#auth-password") : $("#auth-username");
  window.setTimeout(() => field?.focus(), 30);
}

async function handleAuthSubmit(event) {
  event.preventDefault();
  const form = event.target;
  if (form.id !== "auth-form") return;
  const mode = form.dataset.mode;
  const values = new FormData(form);
  const password = String(values.get("password") || "");
  const username = String(values.get("username") || "").trim();
  const button = $(".auth-submit", form);
  button.disabled = true;
  button.textContent = "Getting things ready…";
  try {
    if (mode === "register") {
      const identity = await prepareIdentity(password);
      const result = await api("/api/register", { method: "POST", body: { username, password, displayName: values.get("displayName"), publicKey: identity.publicKey, privateBundle: identity.privateBundle, bundleIv: identity.bundleIv, bundleSalt: identity.bundleSalt } });
      await startApp(result.me, identity.privateKey);
    } else if (mode === "login") {
      const result = await api("/api/login", { method: "POST", body: { username, password } });
      const privateKey = await unlockIdentity(password, result.bundle, result.me.publicKey);
      await startApp(result.me, privateKey);
    } else {
      const privateKey = await unlockIdentity(password, state.authBundle, state.me.publicKey);
      await startApp(state.me, privateKey);
    }
  } catch (error) {
    renderAuth(mode, error.message || "Could not sign in.", mode === "unlock" ? state.me : null, state.authBundle);
  }
}

async function startApp(person, privateKey) {
  state.me = person;
  state.privateKey = privateKey;
  state.cryptoCache.clear();
  state.unverifiedPeers.clear();
  state.changedPeerKeys.clear();
  state.active = null;
  state.messages = [];
  state.lastId = 0;
  $("#auth-view").classList.add("hidden");
  $("#app-view").classList.remove("hidden", "chat-open");
  $("#empty-state").classList.remove("hidden");
  $("#active-chat").classList.add("hidden");
  const display = person.displayName || person.handle;
  $("#my-name").textContent = display;
  $("#my-handle").textContent = person.handle;
  $("#my-avatar").textContent = firstLetter(person);
  $("#my-avatar").className = `avatar avatar-me ${avatarTone(person.handle)}`;
  await api("/api/presence", { method: "POST", body: {} }).catch(() => {});
  await loadChats();
  clearInterval(state.pollTimer);
  state.pollTimer = window.setInterval(poll, 3200);
}

function personAvatar(person, classes = "") {
  const wrap = document.createElement("span");
  wrap.className = `avatar-holder ${classes}`.trim();
  const avatar = document.createElement("span");
  avatar.className = `avatar ${avatarTone(person.handle)}`;
  avatar.textContent = firstLetter(person);
  wrap.append(avatar);
  if (person.online) {
    const dot = document.createElement("i");
    dot.className = "online-indicator";
    wrap.append(dot);
  }
  return wrap;
}
function formatTime(seconds) {
  if (!seconds) return "";
  const date = new Date(seconds * 1000);
  const today = new Date();
  if (date.toDateString() === today.toDateString()) return new Intl.DateTimeFormat("en-US", { hour: "2-digit", minute: "2-digit" }).format(date);
  return new Intl.DateTimeFormat("en-US", { day: "numeric", month: "short" }).format(date);
}
function renderChats() {
  const host = $("#chat-list");
  const query = canonical($("#search-input").value);
  const unread = state.chats.reduce((total, chat) => total + Number(chat.unread || 0), 0);
  $("#unread-total").textContent = String(unread);
  $("#unread-total").classList.toggle("hidden", unread === 0);
  const list = state.chats.filter((chat) => {
    const matchesQuery = !query || `${canonical(chat.handle)} ${niceName(chat).toLowerCase()}`.includes(query);
    const matchesFilter = state.filter === "all" || (state.filter === "online" ? chat.online : Number(chat.unread) > 0);
    return matchesQuery && matchesFilter;
  });
  host.replaceChildren();
  if (!list.length) {
    const empty = document.createElement("div");
    empty.className = "chat-list-empty";
    empty.textContent = state.filter === "unread" ? "Unread messages will appear here." : state.filter === "online" ? "No one is online right now." : query ? "No chats found." : "No chats yet. Tap + to start one.";
    host.append(empty);
    return;
  }
  const label = document.createElement("div");
  label.className = "chat-section-label";
  label.textContent = state.filter === "online" ? "ONLINE" : state.filter === "unread" ? "UNREAD" : "RECENT";
  host.append(label);
  list.forEach((chat, index) => {
    const button = document.createElement("button");
    button.className = `chat-card ${state.active && canonical(state.active.handle) === canonical(chat.handle) ? "active" : ""}`;
    button.dataset.handle = chat.handle;
    button.style.animationDelay = `${Math.min(index * 25, 150)}ms`;
    button.append(personAvatar(chat));
    const info = document.createElement("span");
    info.className = "chat-card-info";
    const top = document.createElement("span");
    top.className = "chat-card-top";
    const name = document.createElement("strong");
    name.textContent = niceName(chat);
    const when = document.createElement("time");
    when.textContent = formatTime(chat.lastTime);
    top.append(name, when);
    const bottom = document.createElement("span");
    bottom.className = "chat-card-bottom";
    const preview = document.createElement("span");
    preview.textContent = chat.lastId ? "⌑  Encrypted message" : chat.handle;
    bottom.append(preview);
    if (Number(chat.unread) > 0) {
      const badge = document.createElement("b");
      badge.className = "chat-card-badge";
      badge.textContent = String(chat.unread);
      bottom.append(badge);
    }
    info.append(top, bottom);
    button.append(info);
    host.append(button);
  });
}

async function loadChats() {
  try {
    const result = await api("/api/chats");
    state.chats = result.chats || [];
    state.chats.forEach(trackPeerKey);
    state.chats.forEach((chat) => {
      if (chat.lastSeenOutgoingId) state.messages.forEach((message) => {
        if (message.id <= chat.lastSeenOutgoingId && canonical(message.sender) === canonical(state.me.handle)) message.seen = true;
      });
    });
    renderChats();
  } catch (error) {
    if (error.message.includes("Please log in")) signOutLocal();
  }
}

async function searchDirectory(query, target) {
  if (canonical(query).length < 2) { target.replaceChildren(); return; }
  try {
    const result = await api(`/api/users?q=${encodeURIComponent(query.trim().replace(/^@/, ""))}`);
    target.replaceChildren();
    if (!result.users.length) {
      const empty = document.createElement("div");
      empty.className = "chat-list-empty";
      empty.textContent = "No users found. Check the username and try again.";
      target.append(empty);
      return;
    }
    result.users.forEach((person) => {
      const button = document.createElement("button");
      button.className = `result-row ${target.classList.contains("modal-results") ? "modal-result" : ""}`;
      button.dataset.handle = person.handle;
      button.append(personAvatar(person));
      const copy = document.createElement("span");
      copy.className = "result-copy";
      const title = document.createElement("strong");
      title.textContent = niceName(person);
      const subtitle = document.createElement("small");
      subtitle.textContent = `${person.handle}${person.online ? " · online" : ""}`;
      copy.append(title, subtitle);
      const action = document.createElement("span");
      action.className = "result-action";
      action.textContent = state.chats.some((chat) => canonical(chat.handle) === canonical(person.handle)) ? "›" : "+";
      button.append(copy, action);
      target.append(button);
    });
  } catch (error) { toast(error.message, "error"); }
}

function showModal(content) {
  $("#modal-content").innerHTML = content;
  $("#modal-layer").classList.remove("hidden");
  window.setTimeout(() => $(".modal-input")?.focus(), 35);
}
function closeModal() { $("#modal-layer").classList.add("hidden"); $("#modal-content").replaceChildren(); }
function newChatModal() {
  showModal(`<div class="modal-eyebrow">START A CONVERSATION</div><h2 class="modal-title" id="modal-title">New chat</h2><p class="modal-copy">Find someone by their username. Start typing to see matching people.</p><input class="modal-input" id="directory-input" type="search" placeholder="@username" autocomplete="off"><div class="modal-results" id="directory-results"></div>`);
}
async function openChat(chatOrHandle) {
  const handle = typeof chatOrHandle === "string" ? chatOrHandle : chatOrHandle.handle;
  const existing = state.chats.find((item) => canonical(item.handle) === canonical(handle));
  let chat = existing || (typeof chatOrHandle === "object" ? chatOrHandle : null);
  if (!chat || !chat.publicKey) {
    const result = await api("/api/chats", { method: "POST", body: { username: handle } });
    chat = result.chat;
  }
  trackPeerKey(chat);
  if (!state.chats.some((item) => canonical(item.handle) === canonical(chat.handle))) state.chats.unshift({ ...chat, unread: 0, lastId: 0, lastTime: 0 });
  state.active = chat;
  state.messages = [];
  state.lastId = 0;
  $("#empty-state").classList.add("hidden");
  $("#active-chat").classList.remove("hidden");
  $("#app-view").classList.add("chat-open");
  $("#peer-avatar").textContent = firstLetter(chat);
  $("#peer-avatar").className = `avatar ${avatarTone(chat.handle)}`;
  $("#peer-name").textContent = niceName(chat);
  setPeerStatus(chat);
  $("#messages").replaceChildren();
  renderChats();
  closeModal();
  await fetchMessages(true);
  $("#message-input").focus();
}
function setPeerStatus(chat) {
  const status = $("#peer-status");
  status.textContent = chat.online ? "online" : chat.lastSeen ? `last seen ${formatRelative(chat.lastSeen)}` : "offline";
  status.classList.toggle("online", Boolean(chat.online));
  const keyNeedsAttention = state.unverifiedPeers.has(canonical(chat.handle)) || state.changedPeerKeys.has(canonical(chat.handle));
  $("#key-info").classList.toggle("key-unverified", keyNeedsAttention);
  $("#encryption-label").textContent = state.changedPeerKeys.has(canonical(chat.handle)) ? "KEY CHANGED" : keyNeedsAttention ? "VERIFY KEY" : "ENCRYPTED";
  $("#composer-hint").innerHTML = keyNeedsAttention
    ? `<span class="hint-dot warning"></span> ${state.changedPeerKeys.has(canonical(chat.handle)) ? "Sending paused: verify the safety code" : "Compare the safety code for added confidence"}`
    : `<span class="hint-dot"></span> End-to-end encryption is on`;
}
function trackPeerKey(person) {
  if (!person?.handle || !person.publicKey) return;
  const handle = canonical(person.handle);
  const storageKey = `chatrix-peer-key:${handle}`;
  const verifiedKey = `chatrix-peer-verified:${handle}`;
  const known = localStorage.getItem(storageKey);
  const verified = localStorage.getItem(verifiedKey);
  if (!known) {
    localStorage.setItem(storageKey, person.publicKey);
    state.unverifiedPeers.add(handle);
  } else if (known !== person.publicKey) {
    state.changedPeerKeys.add(handle);
    state.unverifiedPeers.add(handle);
    state.cryptoCache.delete(handle);
  } else if (verified === person.publicKey) {
    state.changedPeerKeys.delete(handle);
    state.unverifiedPeers.delete(handle);
  } else {
    state.unverifiedPeers.add(handle);
  }
}
function formatRelative(seconds) {
  const delta = Math.max(0, Math.floor(Date.now() / 1000 - seconds));
  if (delta < 60) return "just now";
  if (delta < 3600) return `${Math.floor(delta / 60)} min ago`;
  if (delta < 86400) return `${Math.floor(delta / 3600)} hr ago`;
  return formatTime(seconds);
}

async function conversationKey(peer) {
  const handle = canonical(peer.handle);
  if (state.cryptoCache.has(handle)) return state.cryptoCache.get(handle);
  const publicKey = await crypto.subtle.importKey("raw", unb64(peer.publicKey), { name: "ECDH", namedCurve: "P-256" }, false, []);
  const shared = await crypto.subtle.deriveBits({ name: "ECDH", public: publicKey }, state.privateKey, 256);
  const material = await crypto.subtle.importKey("raw", shared, "HKDF", false, ["deriveKey"]);
  const handles = [canonical(state.me.handle), handle].sort();
  const info = enc.encode(`chatrix-v1|@${handles[0]}|@${handles[1]}`);
  const key = await crypto.subtle.deriveKey({ name: "HKDF", hash: "SHA-256", salt: enc.encode("chatrix-message-key-v1"), info }, material, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
  state.cryptoCache.set(handle, key);
  return key;
}
async function encryptMessage(text, peer) {
  const key = await conversationKey(peer);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const handles = [canonical(state.me.handle), canonical(peer.handle)].sort();
  const additionalData = enc.encode(`@${handles[0]}|@${handles[1]}`);
  const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv, additionalData }, key, enc.encode(text));
  return { ciphertext: b64(ciphertext), iv: b64(iv) };
}
async function decryptMessage(message, peer) {
  const key = await conversationKey(peer);
  const handles = [canonical(state.me.handle), canonical(peer.handle)].sort();
  const additionalData = enc.encode(`@${handles[0]}|@${handles[1]}`);
  const clear = await crypto.subtle.decrypt({ name: "AES-GCM", iv: unb64(message.iv), additionalData }, key, unb64(message.ciphertext));
  return dec.decode(clear);
}

async function fetchMessages(initial = false) {
  const peer = state.active;
  if (!peer || state.polling) return;
  state.polling = true;
  const beforeCount = state.messages.length;
  const box = $("#messages");
  const wasNearBottom = box.scrollHeight - box.scrollTop - box.clientHeight < 100;
  try {
    const result = await api(`/api/chats/${encodeURIComponent(canonical(peer.handle))}/messages?after=${initial ? 0 : state.lastId}`);
    for (const message of result.messages || []) {
      try {
        message.cleartext = await decryptMessage(message, peer);
      } catch {
        message.cleartext = "Could not decrypt this message on this device.";
        message.decryptFailed = true;
      }
      state.messages.push(message);
      state.lastId = Math.max(state.lastId, message.id);
    }
    if (state.messages.length !== beforeCount || initial) renderMessages();
    if (state.messages.some((message) => message.sender !== state.me.handle && !message.seen)) {
      await api(`/api/chats/${encodeURIComponent(canonical(peer.handle))}/seen`, { method: "POST", body: {} }).catch(() => {});
      const chat = state.chats.find((item) => canonical(item.handle) === canonical(peer.handle));
      if (chat) chat.unread = 0;
      renderChats();
    }
    if (wasNearBottom || initial) box.scrollTop = box.scrollHeight;
  } catch (error) { if (initial) toast(error.message, "error"); }
  finally { state.polling = false; }
}

function readableDay(seconds) {
  const date = new Date(seconds * 1000);
  const now = new Date();
  if (date.toDateString() === now.toDateString()) return "today";
  const yesterday = new Date(now); yesterday.setDate(now.getDate() - 1);
  if (date.toDateString() === yesterday.toDateString()) return "yesterday";
  return new Intl.DateTimeFormat("en-US", { day: "numeric", month: "long" }).format(date);
}
function addMessageContent(bubble, message) {
  const text = message.cleartext || "";
  if (text.startsWith(FILE_PREFIX)) {
    try {
      const file = JSON.parse(text.slice(FILE_PREFIX.length));
      if (typeof file.name !== "string" || typeof file.data !== "string" || typeof file.type !== "string") throw new Error("invalid file");
      if (SAFE_FILE_TYPES.has(file.type) && file.type.startsWith("image/") && file.data.startsWith(`data:${file.type};base64,`)) {
        const image = document.createElement("img");
        image.className = "message-image";
        image.src = file.data;
        image.alt = file.name;
        image.loading = "lazy";
        bubble.append(image);
      } else if (SAFE_FILE_TYPES.has(file.type) && file.data.startsWith(`data:${file.type};base64,`)) {
        const card = document.createElement("div");
        card.className = "file-card";
        const icon = document.createElement("span"); icon.className = "file-icon"; icon.textContent = "▤";
        const copy = document.createElement("span"); copy.className = "file-copy";
        const name = document.createElement("strong"); name.textContent = file.name;
        const size = document.createElement("small"); size.textContent = file.type || "File";
        copy.append(name, size);
        const link = document.createElement("a"); link.className = "file-download"; link.href = file.data; link.download = file.name; link.textContent = "↓"; link.setAttribute("aria-label", "Download file");
        card.append(icon, copy, link); bubble.append(card);
      }
      return;
    } catch { /* Show malformed attachment as regular text below. */ }
  }
  const textNode = document.createElement("div");
  textNode.className = "message-text";
  textNode.textContent = text;
  bubble.append(textNode);
}
function renderMessages() {
  const host = $("#messages");
  host.replaceChildren();
  if (!state.messages.length) {
    const welcome = document.createElement("div");
    welcome.className = "empty-messages";
    welcome.innerHTML = `<span>⌑</span> This is the start of your story with <strong>${escapeHtml(niceName(state.active))}</strong>.<br>Your messages are encrypted on your device.`;
    host.append(welcome);
    return;
  }
  let lastDay = "";
  for (const message of state.messages) {
    const day = new Date(message.createdAt * 1000).toDateString();
    if (day !== lastDay) {
      const divider = document.createElement("div"); divider.className = "day-divider"; divider.textContent = readableDay(message.createdAt); host.append(divider); lastDay = day;
    }
    const outgoing = canonical(message.sender) === canonical(state.me.handle);
    const row = document.createElement("div"); row.className = `message-row ${outgoing ? "outgoing" : "incoming"}`;
    if (!outgoing) {
      const avatar = document.createElement("span"); avatar.className = `avatar message-avatar ${avatarTone(state.active.handle)}`; avatar.textContent = firstLetter(state.active); row.append(avatar);
    }
    const bubble = document.createElement("div"); bubble.className = "message-bubble";
    addMessageContent(bubble, message);
    const meta = document.createElement("div"); meta.className = "message-meta";
    const time = document.createElement("time"); time.textContent = new Intl.DateTimeFormat("en-US", { hour: "2-digit", minute: "2-digit" }).format(new Date(message.createdAt * 1000)); meta.append(time);
    if (outgoing) { const check = document.createElement("span"); check.className = "message-check"; check.textContent = message.seen ? "✓✓" : "✓"; meta.append(check); }
    bubble.append(meta); row.append(bubble); host.append(row);
  }
}

async function sendText(text) {
  if (!state.active || !text.trim()) return;
  if (state.changedPeerKeys.has(canonical(state.active.handle))) {
    toast("The safety key changed. Compare the new code with your contact before sending.", "error");
    return;
  }
  const trimmed = text.trim();
  const send = $("#send-button");
  send.disabled = true;
  try {
    const encrypted = await encryptMessage(trimmed, state.active);
    const result = await api(`/api/chats/${encodeURIComponent(canonical(state.active.handle))}/messages`, { method: "POST", body: encrypted });
    const message = result.message;
    message.cleartext = trimmed;
    state.messages.push(message);
    state.lastId = message.id;
    const chat = state.chats.find((item) => canonical(item.handle) === canonical(state.active.handle));
    if (chat) { chat.lastId = message.id; chat.lastTime = message.createdAt; chat.lastSender = state.me.handle; }
    renderMessages();
    $("#messages").scrollTop = $("#messages").scrollHeight;
    renderChats();
    $("#message-input").value = "";
    resizeComposer();
  } catch (error) { toast(error.message, "error"); }
  finally { send.disabled = false; $("#message-input").focus(); }
}
function resizeComposer() {
  const input = $("#message-input");
  input.style.height = "auto";
  input.style.height = `${Math.min(input.scrollHeight, 140)}px`;
}
async function sendFile(file) {
  if (!file || !state.active) return;
  if (file.size > 150 * 1024) { toast("Files must be smaller than 150 KB in this version.", "error"); return; }
  if (!SAFE_FILE_TYPES.has(file.type || "application/octet-stream")) { toast("This file type is not supported yet.", "error"); return; }
  try {
    const data = await new Promise((resolve, reject) => {
      const reader = new FileReader(); reader.onload = () => resolve(reader.result); reader.onerror = () => reject(new Error("Could not read the file.")); reader.readAsDataURL(file);
    });
    await sendText(`${FILE_PREFIX}${JSON.stringify({ name: file.name, type: file.type || "application/octet-stream", data })}`);
  } catch (error) { toast(error.message, "error"); }
}

async function showKeyInfo() {
  if (!state.active) return;
  const hash = new Uint8Array(await crypto.subtle.digest("SHA-256", unb64(state.active.publicKey)));
  const fingerprint = [...hash.slice(0, 20)].map((byte) => byte.toString(16).padStart(2, "0").toUpperCase()).join("").match(/.{1,4}/g).join(" ");
  const peerId = canonical(state.active.handle);
  const changed = state.changedPeerKeys.has(peerId);
  const verified = !changed && !state.unverifiedPeers.has(peerId);
  showModal(`<div class="modal-eyebrow">SECURITY DETAILS</div><h2 class="modal-title" id="modal-title">${changed ? "Safety key changed" : "Chat encryption"}</h2><p class="modal-copy">Messages are encrypted in your browser with a key known only to the participants. The server receives and stores ciphertext.</p><div class="modal-eyebrow">SAFETY CODE · ${escapeHtml(state.active.handle)}</div><div class="fingerprint" id="fingerprint-value">${fingerprint}</div><button class="primary-button copy-code" type="button">Copy code</button>${verified ? `<div class="trust-status">✓ Safety code marked as verified on this device.</div>` : `<button class="primary-button verify-code" type="button">I compared the code with my contact</button>`}<ul class="security-list"><li>Compare this code with your contact through another channel to detect a substituted key.</li><li>If the code changed, do not send messages until you have verified it with your contact.</li><li>This first version has not been independently audited and does not provide forward secrecy.</li></ul>`);
}
function showSecurityIntro() {
  showModal(`<div class="modal-eyebrow">HOW SECURITY WORKS</div><h2 class="modal-title" id="modal-title">Your conversations stay private</h2><p class="modal-copy">Your browser creates a unique identity key. The two devices derive a shared chat key, and each message is encrypted with AES-GCM before it is sent. The server stores salted PBKDF2 password hashes; your private key is encrypted with your password.</p><ul class="security-list"><li>The server cannot read message or attachment contents.</li><li>Compare each chat’s safety code in person or through another trusted channel.</li><li>A public launch requires HTTPS, an independent audit, and more safeguards against key substitution.</li></ul>`);
}

async function poll() {
  if (!state.me) return;
  await api("/api/presence", { method: "POST", body: {} }).catch(() => {});
  await loadChats();
  if (state.active) {
    const updated = state.chats.find((chat) => canonical(chat.handle) === canonical(state.active.handle));
    if (updated) { state.active = updated; setPeerStatus(updated); }
    await fetchMessages(false);
  }
}
function signOutLocal() {
  clearInterval(state.pollTimer);
  state.me = null; state.privateKey = null; state.active = null; state.chats = []; state.messages = []; state.cryptoCache.clear();
  $("#app-view").classList.add("hidden");
  renderAuth("login");
}
async function signOut() {
  await api("/api/logout", { method: "POST", body: {} }).catch(() => {});
  signOutLocal();
}

$("#auth-content").addEventListener("submit", handleAuthSubmit);
$("#auth-content").addEventListener("click", async (event) => {
  const action = event.target.closest("[data-auth-action]")?.dataset.authAction;
  if (action === "login" || action === "register") renderAuth(action);
  if (action === "logout") await signOut();
});
$("#security-link").addEventListener("click", (event) => { event.preventDefault(); showSecurityIntro(); });
$("#theme-auth").addEventListener("click", () => setTheme(state.theme === "light" ? "dark" : "light"));
$("#theme-app").addEventListener("click", () => setTheme(state.theme === "light" ? "dark" : "light"));
$("#new-chat").addEventListener("click", newChatModal);
$("#empty-new-chat").addEventListener("click", newChatModal);
$("#chat-list").addEventListener("click", (event) => { const item = event.target.closest("[data-handle]"); if (item) openChat(item.dataset.handle).catch((error) => toast(error.message, "error")); });
$("#chat-list").addEventListener("keydown", (event) => { if (event.key === "Enter") event.target.closest("[data-handle]")?.click(); });
$("#sidebar-results").addEventListener("click", (event) => { const item = event.target.closest("[data-handle]"); if (item) openChat(item.dataset.handle).catch((error) => toast(error.message, "error")); });
$("#search-input").addEventListener("input", (event) => {
  renderChats();
  const value = event.target.value.trim();
  clearTimeout(state.searchTimer);
  if (!value) { $("#sidebar-results").replaceChildren(); return; }
  state.searchTimer = window.setTimeout(() => searchDirectory(value, $("#sidebar-results")), 260);
});
$("#search-input").addEventListener("keydown", (event) => { if (event.key === "Escape") { event.target.value = ""; renderChats(); $("#sidebar-results").replaceChildren(); } });
document.querySelectorAll(".filter").forEach((button) => button.addEventListener("click", () => {
  document.querySelectorAll(".filter").forEach((item) => item.classList.remove("active"));
  button.classList.add("active"); state.filter = button.dataset.filter; renderChats();
}));
$("#composer").addEventListener("submit", (event) => { event.preventDefault(); const input = $("#message-input"); const value = input.value; if (value.trim()) sendText(value); });
$("#message-input").addEventListener("input", resizeComposer);
$("#message-input").addEventListener("keydown", (event) => { if (event.key === "Enter" && !event.shiftKey && !event.isComposing) { event.preventDefault(); $("#composer").requestSubmit(); } });
$("#emoji-button").addEventListener("click", () => { const input = $("#message-input"); const start = input.selectionStart; const end = input.selectionEnd; input.setRangeText(" ✨ ", start, end, "end"); input.focus(); resizeComposer(); });
$("#attach-button").addEventListener("click", () => $("#file-input").click());
$("#file-input").addEventListener("change", (event) => { sendFile(event.target.files?.[0]); event.target.value = ""; });
$("#key-info").addEventListener("click", showKeyInfo);
$("#chat-menu").addEventListener("click", showKeyInfo);
$("#logout").addEventListener("click", signOut);
$("#back-to-list").addEventListener("click", () => $("#app-view").classList.remove("chat-open"));
$("#modal-close").addEventListener("click", closeModal);
$("#modal-layer").addEventListener("click", (event) => { if (event.target === $("#modal-layer")) closeModal(); });
$("#modal-content").addEventListener("input", (event) => {
  if (event.target.id !== "directory-input") return;
  clearTimeout(state.searchTimer);
  state.searchTimer = window.setTimeout(() => searchDirectory(event.target.value, $("#directory-results")), 220);
});
$("#modal-content").addEventListener("click", async (event) => {
  const user = event.target.closest("[data-handle]");
  if (user) { try { await openChat(user.dataset.handle); } catch (error) { toast(error.message, "error"); } return; }
  if (event.target.closest(".copy-code")) {
    try { await navigator.clipboard.writeText($("#fingerprint-value").textContent); toast("Safety code copied.", "success"); }
    catch { toast("Could not copy the safety code.", "error"); }
  }
  if (event.target.closest(".verify-code") && state.active) {
    const handle = canonical(state.active.handle);
    localStorage.setItem(`chatrix-peer-key:${handle}`, state.active.publicKey);
    localStorage.setItem(`chatrix-peer-verified:${handle}`, state.active.publicKey);
    state.unverifiedPeers.delete(handle);
    state.changedPeerKeys.delete(handle);
    state.cryptoCache.delete(handle);
    setPeerStatus(state.active);
    closeModal();
    toast("Safety code saved on this device.", "success");
  }
});
window.addEventListener("keydown", (event) => {
  if (event.key === "Escape") closeModal();
  if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === "k") { event.preventDefault(); $("#search-input").focus(); }
});

async function boot() {
  setTheme(state.theme);
  try {
    const result = await api("/api/me");
    state.me = result.me;
    renderAuth("unlock", "", result.me, result.bundle);
  } catch {
    renderAuth("login");
  }
}
boot();
