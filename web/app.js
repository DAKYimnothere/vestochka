const state = { user: null, active: null, chats: new Map(), token: null, socket: null, peer: null, stream: null, avatarImage: null, avatarRotation: 0, presence: new Map(), typingTimer: null, privateKey: null, pendingIce: [], selectedStoryFile: null, storyPreviewUrl: null, callTimeout: null, mediaRecorder: null, mediaChunks: [], mediaMode: null, mediaTimer: null, isRecording: false, isPaused: false };
const $ = (id) => document.getElementById(id);
const initials = (name) => (name || "?").slice(0, 1).toUpperCase();
const setStatus = (text, error = true) => { $("auth-status").textContent = text; $("auth-status").style.color = error ? "#d46e7b" : "#5b9b7d"; };
async function api(url, options = {}) {
  const headers = {};
  if (!(options.body instanceof FormData)) headers["Content-Type"] = "application/json";
  if (state.token) headers.Authorization = "Bearer " + state.token;
  const response = await fetch(url, {...options, headers: {...headers, ...(options.headers || {})}});
  const body = await response.json().catch(() => ({}));
  if (!response.ok) {
    const detail = Array.isArray(body.detail)
      ? body.detail.map(item => item.msg || "Некорректное значение").join("; ")
      : typeof body.detail === "string" ? body.detail : "Не удалось выполнить запрос";
    throw new Error(detail);
  }
  return body;
}
const SESSION_STORAGE_KEY = "vestochka-session";
function saveSession(username, token) {
  localStorage.setItem(SESSION_STORAGE_KEY, JSON.stringify({username, token}));
}
function clearSession() {
  localStorage.removeItem(SESSION_STORAGE_KEY);
  state.token = null;
  state.privateKey = null;
}
async function restoreSession() {
  const stored = localStorage.getItem(SESSION_STORAGE_KEY);
  if (!stored) return;
  let session;
  try {
    session = JSON.parse(stored);
    if (!session?.username || !session?.token) throw new Error("Некорректная сохранённая сессия");
    state.token = session.token;
    state.privateKey = await loadBrowserPrivateKey(session.username);
    if (!state.privateKey) throw new Error("На этом устройстве отсутствует ключ шифрования");
    const user = await api("/me");
    showMessenger(user);
  } catch (error) {
    clearSession();
    $("auth-status").textContent = "Сессия завершена. Войдите снова, чтобы продолжить.";
  }
}
const bytesToBase64 = bytes => btoa(String.fromCharCode(...new Uint8Array(bytes)));
const base64ToBytes = value => Uint8Array.from(atob(value), char => char.charCodeAt(0));
async function createBrowserKeyPair(username) {
  const pair = await crypto.subtle.generateKey({name: "RSA-OAEP", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256"}, true, ["encrypt", "decrypt"]);
  const privateJwk = await crypto.subtle.exportKey("jwk", pair.privateKey);
  return {publicKey: bytesToBase64(await crypto.subtle.exportKey("spki", pair.publicKey)), privateKey: pair.privateKey};
}
async function loadBrowserPrivateKey(username) {
  const stored = localStorage.getItem(`vestochka-key-${username}`);
  if (!stored) return null;
  try { return await crypto.subtle.importKey("jwk", JSON.parse(stored), {name: "RSA-OAEP", hash: "SHA-256"}, true, ["decrypt"]); }
  catch (_) { return null; }
}
async function saveBrowserPublicKey(username, privateKey) {
  const privateJwk = await crypto.subtle.exportKey("jwk", privateKey);
  const publicJwk = {kty: privateJwk.kty, n: privateJwk.n, e: privateJwk.e, alg: privateJwk.alg, ext: true, key_ops: ["encrypt"]};
  localStorage.setItem(`vestochka-public-key-${username}`, JSON.stringify(publicJwk));
}
async function exportBrowserPublicKey(username) {
  const stored = localStorage.getItem(`vestochka-key-${username}`);
  if (!stored) throw new Error("Ключ шифрования не найден на этом устройстве");
  const privateJwk = JSON.parse(stored);
  const publicJwk = {kty: privateJwk.kty, n: privateJwk.n, e: privateJwk.e, alg: "RSA-OAEP-256", ext: true, key_ops: ["encrypt"]};
  const publicKey = await crypto.subtle.importKey("jwk", publicJwk, {name: "RSA-OAEP", hash: "SHA-256"}, true, ["encrypt"]);
  return bytesToBase64(await crypto.subtle.exportKey("spki", publicKey));
}
async function importOwnPublicKey(username) {
  const stored = localStorage.getItem(`vestochka-key-${username}`);
  if (!stored) throw new Error("Ключ шифрования не найден на этом устройстве");
  const privateJwk = JSON.parse(stored);
  const publicJwk = {kty: privateJwk.kty, n: privateJwk.n, e: privateJwk.e, alg: "RSA-OAEP-256", ext: true, key_ops: ["encrypt"]};
  return crypto.subtle.importKey("jwk", publicJwk, {name: "RSA-OAEP", hash: "SHA-256"}, false, ["encrypt"]);
}
async function importPublicKey(value) {
  let bytes;
  try {
    bytes = /^[0-9a-f]+$/i.test(value) ? Uint8Array.from(value.match(/.{1,2}/g).map(part => parseInt(part, 16))) : base64ToBytes(value);
    const pem = new TextDecoder().decode(bytes);
    if (pem.includes("BEGIN PUBLIC KEY")) bytes = base64ToBytes(pem.replace(/-----[^-]+-----/g, "").replace(/\s/g, ""));
    return await crypto.subtle.importKey("spki", bytes, {name: "RSA-OAEP", hash: "SHA-256"}, false, ["encrypt"]);
  } catch (_) { throw new Error("У собеседника нет корректного ключа шифрования"); }
}
async function encryptMessage(text, username) {
  const recipient = await api(`/get_key/${encodeURIComponent(username)}`);
  const publicKey = await importPublicKey(recipient.public_key);
  const senderPublicKey = await importOwnPublicKey(state.user.username);
  const aesKey = await crypto.subtle.generateKey({name: "AES-GCM", length: 256}, true, ["encrypt", "decrypt"]);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await crypto.subtle.encrypt({name: "AES-GCM", iv}, aesKey, new TextEncoder().encode(text));
  const wrappedKey = await crypto.subtle.encrypt({name: "RSA-OAEP"}, publicKey, await crypto.subtle.exportKey("raw", aesKey));
  const senderWrappedKey = await crypto.subtle.encrypt({name: "RSA-OAEP"}, senderPublicKey, await crypto.subtle.exportKey("raw", aesKey));
  return btoa(JSON.stringify({v: 2, k: bytesToBase64(wrappedKey), sk: bytesToBase64(senderWrappedKey), i: bytesToBase64(iv), d: bytesToBase64(ciphertext)}));
}
async function decryptMessage(value, isMine = false) {
  try {
    if (typeof value !== "string") return "";
    const envelope = JSON.parse(atob(value));
    if (![1, 2].includes(envelope.v) || !state.privateKey) return "[Не удалось расшифровать]";
    const wrappedKey = envelope.v === 2 && isMine && envelope.sk ? envelope.sk : envelope.k;
    const rawKey = await crypto.subtle.decrypt({name: "RSA-OAEP"}, state.privateKey, base64ToBytes(wrappedKey));
    const aesKey = await crypto.subtle.importKey("raw", rawKey, "AES-GCM", false, ["decrypt"]);
    const plaintext = await crypto.subtle.decrypt({name: "AES-GCM", iv: base64ToBytes(envelope.i)}, aesKey, base64ToBytes(envelope.d));
    return new TextDecoder().decode(plaintext);
  } catch (_) {
    // Messages created before E2EE are stored as plain text.
    if (!/^[A-Za-z0-9+/]+=*$/.test(value) || value.length < 80) return value;
    return "[Старое зашифрованное сообщение недоступно]";
  }
}
function showMessenger(user) {
  state.user = user;
  $("auth-view").classList.add("hidden"); $("messenger-view").classList.remove("hidden");
  $("my-name").textContent = user.display_name || `@${user.username}`;
  $("my-id").textContent = `ID ${user.id} · @${user.username}`;
  $("my-avatar").textContent = initials(user.username);
  fillProfile(user); loadStories(); loadSessions(); loadRecentChats();
  applyTheme(user.theme || "light");
  connectRealtime();
  setInterval(refreshActiveChat, 3000);
}
function fillProfile(user) {
  $("profile-name").value = user.display_name || "";
  $("profile-bio").value = user.bio || "";
  $("profile-phone").value = user.phone || "";
  $("profile-avatar").textContent = initials(user.username);
  if (user.avatar_url) {
    $("profile-avatar").style.backgroundImage = `url(${user.avatar_url})`;
    $("my-avatar").style.backgroundImage = `url(${user.avatar_url})`;
    $("profile-avatar").textContent = ""; $("my-avatar").textContent = "";
  }
  $("phone-visibility").value = user.phone_visibility || "nobody";
  $("last-seen-visibility").value = user.last_seen_visibility || "everybody";
  $("theme-setting").value = user.theme || "light";
  $("two-factor").checked = Boolean(user.two_factor_enabled);
}
function applyTheme(theme) {
  document.body.classList.toggle("dark", theme === "dark");
}
function switchTab(tab) {
  document.querySelectorAll(".tab-content").forEach(item => item.classList.add("hidden"));
  $(`${tab}-tab`).classList.remove("hidden");
  document.querySelectorAll(".nav-tab").forEach(item => item.classList.toggle("active", item.dataset.tab === tab));
  if (tab === "settings") loadSessions();
}
async function loadSessions() {
  try {
    const sessions = await api("/me/sessions");
    $("sessions-list").innerHTML = sessions.map(session => `<div class="session-row"><div><strong>${escapeHtml(session.device_name)}</strong><small>Вход: ${new Date(session.created_at).toLocaleString()}</small></div><button data-session="${session.id}">Завершить</button></div>`).join("");
    document.querySelectorAll("[data-session]").forEach(button => button.onclick = async () => { await api(`/me/sessions/${button.dataset.session}`, {method:"DELETE"}); loadSessions(); });
  } catch (error) { $("sessions-list").textContent = error.message; }
}
async function loadStories() {
  try {
    const stories = await api("/me/stories");
    state.storyItems = stories;
    $("stories-list").innerHTML = stories.map(renderStoryCard).join("");
    bindStoryCards($("stories-list"));
  } catch (error) { $("stories-list").textContent = error.message; }
}
function connectRealtime() {
  const protocol = location.protocol === "https:" ? "wss" : "ws";
  const socket = new WebSocket(`${protocol}://${location.host}/ws/${state.user.username}?token=${encodeURIComponent(state.token)}`);
  socket.onmessage = (event) => {
    const data = JSON.parse(event.data);
    if (data.type === "message" && data.from_user === state.active) {
      const messages = state.chats.get(state.active) || [];
      if (messages.some(message => message.sender === data.from_user && message.encrypted_text === data.encrypted_msg && Date.now() - new Date(message.timestamp).getTime() < 10000)) return;
      messages.push({id: data.message_id, sender: data.from_user, encrypted_text: data.encrypted_msg, timestamp: new Date().toISOString(), reply_to_id: data.reply_to_id, reactions: data.reactions || {}, media_url: data.media_url || null, media_type: data.media_type || null});
      state.chats.set(state.active, messages);
      renderMessages(messages);
      markChatRead(data.from_user);
    }
    if (data.type === "message") loadRecentChats();
    if (data.type === "presence") {
      state.presence.set(data.username, data);
      if (data.username === state.active) updateChatStatus(data.username);
      loadRecentChats();
    }
    if (data.type === "typing" || data.type === "recording") {
      if (data.active === false) {
        state.presence.delete(data.from_user);
        if (data.from_user === state.active) updateChatStatus(data.from_user);
        return;
      }
      state.presence.set(data.from_user, {...data, expires_at: Date.now() + 4000});
      if (data.from_user === state.active) updateChatStatus(data.from_user);
      window.setTimeout(() => {
        const current = state.presence.get(data.from_user);
        if (current && current.expires_at <= Date.now()) {
          state.presence.delete(data.from_user);
          if (state.active === data.from_user) updateChatStatus(data.from_user);
        }
      }, 4200);
    }
    if ((data.type === "messages_read" || data.type === "read_receipt") && (data.username || data.from_user) === state.active) {
      const messages = state.chats.get(state.active) || [];
      const ids = new Set(data.message_ids || []);
      messages.forEach(message => {
        if (message.sender === state.user.username && (!ids.size || ids.has(message.id))) message.read_at = data.read_at;
      });
      state.chats.set(state.active, messages);
      renderMessages(messages);
    }
    handleCallSignal(data).catch(error => {
      $("call-status").textContent = "Ошибка звонка: " + error.message;
      window.setTimeout(() => closeCall(false), 1800);
    });
  };
  socket.onclose = (event) => {
    if (state.socket !== socket) return;
    if (event.code === 1008) {
      state.socket = null;
      showFeature("Сессия истекла. Войдите снова.");
      return;
    }
    setTimeout(() => {
      if (state.user && state.token && state.socket === socket) connectRealtime();
    }, 2000);
  };
  state.socket = socket;
}
function updateChatStatus(username) {
  const presence = state.presence.get(username);
  if (presence?.expires_at > Date.now()) {
    $("chat-status").textContent = presence.type === "recording" ? "Записывает голосовое сообщение..." : "Печатает...";
    return;
  }
  if (presence?.online) {
    $("chat-status").textContent = "В сети";
    return;
  }
  $("chat-status").textContent = presence?.status_text || "Был недавно";
}
function sendPresence(type, active) {
  if (state.socket?.readyState === WebSocket.OPEN && state.active) {
    state.socket.send(JSON.stringify({type, to_user: state.active, active}));
  }
}
async function refreshActiveChat() {
  if (!state.active || document.hidden) return;
  try {
    const messages = await api(`/history/${state.user.username}/${state.active}`);
    const current = state.chats.get(state.active) || [];
    if (messages.length !== current.length || messages.at(-1)?.timestamp !== current.at(-1)?.timestamp) {
      state.chats.set(state.active, messages);
      renderMessages(messages);
    }
  } catch (error) {
    showFeature("Не удалось обновить сообщения: " + error.message);
  }
}
function sendSignal(payload) {
  if (state.socket?.readyState !== WebSocket.OPEN) return false;
  state.socket.send(JSON.stringify({...payload, to_user: state.active}));
  return true;
}
async function openCall(kind, incomingOffer = null, fromUser = null) {
  if (!state.active && !fromUser) return showFeature("Сначала выбери контакт.");
  if (fromUser) state.active = fromUser;
  try {
    state.stream = await navigator.mediaDevices.getUserMedia({audio: true, video: kind === "video"});
  } catch (error) {
    showFeature(error.name === "NotAllowedError" ? "Разреши доступ к камере и микрофону в браузере." : "Камера или микрофон недоступны на этом устройстве.");
    return;
  }
  $("call-overlay").classList.remove("hidden");
  $("call-title").textContent = `${kind === "video" ? "Видеозвонок" : "Аудиозвонок"} · @${state.active}`;
  $("call-status").textContent = incomingOffer ? "Входящий звонок принят…" : "Вызов отправлен…";
  $("call-placeholder").textContent = kind === "video" ? "Ожидание видео…" : "Ожидание собеседника…";
  $("local-video").srcObject = state.stream;
  if (!incomingOffer) state.pendingIce = [];
  state.peer = new RTCPeerConnection({iceServers: [{urls: "stun:stun.l.google.com:19302"}, {urls: "stun:stun1.l.google.com:19302"}]});
  state.stream.getTracks().forEach(track => state.peer.addTrack(track, state.stream));
  state.peer.ontrack = event => { $("remote-video").srcObject = event.streams[0]; };
  state.peer.onicecandidate = event => { if (event.candidate) sendSignal({type: "ice_candidate", candidate: event.candidate}); };
  state.peer.onconnectionstatechange = () => {
    const status = state.peer?.connectionState;
    $("call-status").textContent = status === "connected" ? "Соединение установлено" : status === "failed" ? "Не удалось установить соединение" : status === "disconnected" ? "Соединение прервано" : "Подключение…";
    $("call-placeholder").classList.toggle("hidden", status === "connected");
    if (status === "failed" || status === "disconnected") window.setTimeout(() => closeCall(false), 1800);
  };
  clearTimeout(state.callTimeout);
  state.callTimeout = window.setTimeout(() => {
    if (state.peer && state.peer.connectionState !== "connected") {
      $("call-status").textContent = "Собеседник не ответил";
      window.setTimeout(() => closeCall(), 1800);
    }
  }, 30000);
  if (incomingOffer) {
    await state.peer.setRemoteDescription(incomingOffer);
    for (const candidate of state.pendingIce) await state.peer.addIceCandidate(candidate);
    state.pendingIce = [];
    const answer = await state.peer.createAnswer();
    await state.peer.setLocalDescription(answer);
    sendSignal({type: "call_answer", sdp: answer});
  } else {
    const offer = await state.peer.createOffer();
    await state.peer.setLocalDescription(offer);
    if (!sendSignal({type: "call_offer", sdp: offer, kind})) {
      $("call-status").textContent = "Нет связи с сервером";
      window.setTimeout(() => closeCall(false), 1800);
    }
  }
}
async function handleCallSignal(data) {
  if (data.type === "call_offer") {
    if (!confirm(`Входящий звонок от @${data.from_user}. Принять?`)) return;
    await openCall(data.kind || "video", data.sdp, data.from_user);
  } else if (data.type === "call_unavailable") {
    $("call-status").textContent = "Собеседник сейчас не в сети";
    window.setTimeout(() => closeCall(false), 1800);
  } else if (data.type === "call_answer" && state.peer) {
    await state.peer.setRemoteDescription(data.sdp);
    for (const candidate of state.pendingIce) await state.peer.addIceCandidate(candidate);
    state.pendingIce = [];
  } else if (data.type === "ice_candidate" && data.candidate) {
    if (state.peer?.remoteDescription) await state.peer.addIceCandidate(data.candidate);
    else state.pendingIce.push(data.candidate);
  } else if (data.type === "call_end") {
    closeCall(false);
  }
}
function closeCall(send = true) {
  if (send) sendSignal({type: "call_end"});
  clearTimeout(state.callTimeout);
  state.peer?.close(); state.stream?.getTracks().forEach(track => track.stop());
  state.peer = null; state.stream = null; state.pendingIce = []; $("remote-video").srcObject = null; $("local-video").srcObject = null; $("call-placeholder").classList.remove("hidden"); $("call-overlay").classList.add("hidden");
}
async function authenticate(register = false) {
  const username = $("username").value.trim(), password = $("password").value;
  try {
    if (register && password.length < 12) throw new Error("Пароль должен содержать минимум 12 символов");
    const privateKey = register ? null : await loadBrowserPrivateKey(username);
    if (!register && !privateKey) throw new Error("Ключ шифрования не найден на этом устройстве");
    const keyData = register ? await createBrowserKeyPair(username) : {privateKey};
    if (register) {
      const privateJwk = await crypto.subtle.exportKey("jwk", keyData.privateKey);
      localStorage.setItem(`vestochka-key-${username}`, JSON.stringify(privateJwk));
      const publicJwk = await crypto.subtle.exportKey("jwk", await crypto.subtle.importKey("spki", base64ToBytes(keyData.publicKey), {name: "RSA-OAEP", hash: "SHA-256"}, true, ["encrypt"]));
      localStorage.setItem(`vestochka-public-key-${username}`, JSON.stringify(publicJwk));
    } else if (!localStorage.getItem(`vestochka-public-key-${username}`)) await saveBrowserPublicKey(username, keyData.privateKey);
    const publicKey = register ? keyData.publicKey : await exportBrowserPublicKey(username);
    const result = await api(register ? "/register" : "/login", {method: "POST", body: JSON.stringify({username, password, public_key: publicKey})});
    state.token = result.token;
    state.privateKey = keyData.privateKey;
    saveSession(username, result.token);
    showMessenger(result.user);
  } catch (error) {
    setStatus(error.message === "Taken" ? "Этот username уже занят. Войдите или выберите другой." : error.message);
  }
}
function renderSearch(users) {
  $("search-results").innerHTML = users.map(user => `<div class="result" data-username="${user.username}"><div class="avatar result-avatar" style="${user.avatar_url ? `background-image:url('${user.avatar_url}')` : ""}">${user.avatar_url ? "" : initials(user.username)}</div><div class="result-info"><strong>${escapeHtml(user.display_name || "Пользователь")}</strong><small>@${user.username} · ID ${user.id}</small></div><button class="result-action profile-action" title="Открыть профиль">◉</button><button class="result-action chat-action" title="Написать">➤</button></div>`).join("");
  document.querySelectorAll(".result").forEach(el => {
    el.querySelector(".profile-action").onclick = (event) => { event.stopPropagation(); openPublicProfile(el.dataset.username); };
    el.querySelector(".chat-action").onclick = (event) => { event.stopPropagation(); openChat(el.dataset.username); };
    el.querySelector(".result-info").onclick = () => openChat(el.dataset.username);
  });
}
function renderRecentChats(chats) {
  const list = $("chat-list");
  list.innerHTML = chats.length ? chats.map(chat => `<div class="chat-item${state.active === chat.username ? " active" : ""}" data-username="${escapeHtml(chat.username)}"><div class="avatar" style="${chat.avatar_url ? `background-image:url('${chat.avatar_url}')` : ""}">${chat.avatar_url ? "" : initials(chat.username)}</div><div class="result-info"><strong>${escapeHtml(chat.display_name || chat.username)}</strong><small>${escapeHtml(chat.last_message || "")}</small></div>${chat.unread_count ? `<span class="unread-badge">${chat.unread_count}</span>` : ""}</div>`).join("") : `<p class="muted">Здесь появятся ваши диалоги.</p>`;
  list.querySelectorAll(".chat-item").forEach(item => item.onclick = () => openChat(item.dataset.username));
}
async function loadRecentChats() {
  try {
    const chats = await api("/recent-chats");
    chats.forEach(chat => state.presence.set(chat.username, chat));
    renderRecentChats(chats);
  }
  catch (error) { $("chat-list").innerHTML = `<p class="muted">${escapeHtml(error.message)}</p>`; }
}
async function openPublicProfile(username) {
  try {
    const profile = await api(`/public-profile/${encodeURIComponent(username)}`);
    $("public-avatar").style.backgroundImage = profile.avatar_url ? `url(${profile.avatar_url})` : "";
    $("public-avatar").textContent = profile.avatar_url ? "" : initials(profile.username);
    $("public-username").textContent = `@${profile.username}`;
    $("public-name").textContent = profile.display_name || profile.username;
    $("public-id").textContent = `Постоянный ID: ${profile.id} · ${profile.online ? "в сети" : "не в сети"}`;
    $("public-bio").textContent = profile.bio || "Пользователь пока ничего не написал о себе.";
    $("public-phone").textContent = profile.phone ? `Телефон: ${profile.phone}` : "";
    $("public-message").classList.toggle("hidden", profile.blocked);
    $("public-contact").classList.toggle("hidden", profile.blocked);
    $("public-block").classList.remove("hidden");
    $("public-delete-chat").classList.toggle("hidden", profile.blocked);
    $("public-contact").textContent = profile.contact ? "Убрать из контактов" : "Добавить в контакты";
    $("public-block").textContent = profile.blocked ? "Разблокировать" : "Заблокировать";
    state.storyItems = profile.stories;
    $("public-stories").innerHTML = profile.stories.length ? profile.stories.map(renderStoryCard).join("") : `<p class="muted">Активных stories пока нет.</p>`;
    bindStoryCards($("public-stories"));
    $("public-message").onclick = () => { $("public-profile-modal").classList.add("hidden"); openChat(profile.username); };
    $("public-contact").onclick = async () => {
      try { const result = await api(`/users/${encodeURIComponent(profile.username)}/contact`, {method: profile.contact ? "DELETE" : "POST"}); profile.contact = result.contact; $("public-contact").textContent = profile.contact ? "Убрать из контактов" : "Добавить в контакты"; showFeature(profile.contact ? "Добавлено в контакты." : "Удалено из контактов."); } catch (error) { showFeature(error.message); }
    };
    $("public-block").onclick = async () => {
      const blocked = !profile.blocked;
      try { await api(`/users/${encodeURIComponent(profile.username)}/block`, {method: blocked ? "POST" : "DELETE"}); profile.blocked = blocked; $("public-block").textContent = blocked ? "Разблокировать" : "Заблокировать"; $("public-message").classList.toggle("hidden", blocked); $("public-contact").classList.toggle("hidden", blocked); $("public-delete-chat").classList.remove("hidden"); showFeature(blocked ? "Пользователь заблокирован." : "Пользователь разблокирован."); } catch (error) { showFeature(error.message); }
    };
    $("public-delete-chat").onclick = async () => {
      const deleteForAll = window.confirm("Удалить чат у обоих пользователей? Нажмите Отмена, чтобы удалить только у себя.");
      try { await api(`/chats/${encodeURIComponent(profile.username)}/${deleteForAll ? "all" : "me"}`, {method:"DELETE"}); $("public-profile-modal").classList.add("hidden"); if (state.active === profile.username) { state.chats.delete(profile.username); renderMessages([]); } loadRecentChats(); showFeature(deleteForAll ? "Чат удалён у всех." : "Чат удалён у вас."); } catch (error) { showFeature(error.message); }
    };
    $("public-profile-modal").classList.remove("hidden");
  } catch (error) { showFeature(error.message); }
}
function renderStoryCard(story) {
  let likes = story.likes;
  if (typeof likes === "string") { try { likes = JSON.parse(likes); } catch (_) { likes = []; } }
  likes = Array.isArray(likes) ? likes : [];
  return `<article class="story-card" data-story-id="${story.id}"><button class="story-open" title="Открыть story">${story.media_type === "video" ? `<video src="${story.media_url}" muted></video>` : `<img src="${story.media_url}" alt="Story">`}</button><div class="story-card-footer"><p>${escapeHtml(story.caption || "")}${story.music_name ? `<br>♫ ${escapeHtml(story.music_name)}` : ""}</p><button class="story-card-like" title="Нравится">♡ ${likes.length}</button></div></article>`;
}
function bindStoryCards(container) {
  container.querySelectorAll(".story-card").forEach(card => {
    const story = (state.storyItems || []).find(item => String(item.id) === card.dataset.storyId);
    card.querySelector(".story-open").onclick = () => openStoryViewer(story);
    card.querySelector(".story-card-like").onclick = event => { event.stopPropagation(); reactToStory(story); };
  });
}
function openStoryViewer(story) {
  if (!story) return;
  state.activeStory = story;
  $("story-viewer-media").innerHTML = story.media_type === "video" ? `<video src="${story.media_url}" controls autoplay></video>` : `<img src="${story.media_url}" alt="Story">`;
  $("story-viewer-caption").textContent = story.caption || "";
  let likes = story.likes; if (typeof likes === "string") { try { likes = JSON.parse(likes); } catch (_) { likes = []; } }
  $("story-like-count").textContent = Array.isArray(likes) ? likes.length : 0;
  $("story-viewer").classList.remove("hidden");
}
async function reactToStory(story) {
  if (!story) return;
  let likes = typeof story.likes === "string" ? JSON.parse(story.likes || "[]") : (story.likes || []);
  const liked = !likes.includes(state.user.username);
  try { const result = await api(`/stories/${story.id}/reaction`, {method:"POST", body:JSON.stringify({liked})}); story.likes = likes.filter(name => name !== state.user.username); if (liked) story.likes.push(state.user.username); $("story-like-count").textContent = result.count; showFeature(liked ? "Лайк поставлен." : "Лайк убран."); } catch (error) { showFeature(error.message); }
}
async function searchUsers(query) {
  if (query.length < 3) { $("search-results").innerHTML = ""; return; }
  try { renderSearch(await api(`/users/search?q=${encodeURIComponent(query)}`)); } catch (error) { $("search-results").textContent = error.message; }
}
async function renderMessages(messages) {
  const box = $("messages");
  const decrypted = await Promise.all(messages.map(message => decryptMessage(message.encrypted_text, message.sender === state.user.username)));
  box.innerHTML = messages.length ? messages.map((message, index) => {
    const mine = message.sender === state.user.username;
    const ticks = mine ? `<span class="message-ticks ${message.read_at ? "read" : ""}" title="${message.read_at ? "Прочитано" : "Отправлено"}">${message.read_at ? "✓✓" : "✓"}</span>` : "";
    const reactions = Object.entries(message.reactions || {}).filter(([, users]) => users.length).map(([emoji, users]) => `<button class="reaction-chip" data-emoji="${emoji}">${emoji} ${users.length}</button>`).join("");
    const replyMessage = message.reply_to_id ? messages.find(item => item.id === message.reply_to_id) : null;
    const replyIndex = replyMessage ? messages.indexOf(replyMessage) : -1;
    const reply = replyMessage ? `<small class="reply-reference">${escapeHtml((decrypted[replyIndex] || (message.media_type === 'audio' ? 'Голосовое сообщение' : message.media_type === 'video' ? 'Кружочек' : 'Сообщение')).slice(0, 120))}</small>` : "";
    const mediaMarkup = message.media_url ? (message.media_type === 'audio' ? `<div class="audio-player"><audio class="audio-source" preload="metadata" src="${message.media_url}"></audio><button class="audio-play" type="button" aria-label="Воспроизвести голосовое сообщение"><span>▶</span></button><div class="audio-details"><input class="audio-progress" type="range" min="0" max="100" value="0" step="0.1" aria-label="Позиция голосового сообщения"><div class="audio-meta"><span class="audio-label">Голосовое</span><span class="audio-time">0:00</span></div></div></div>` : message.media_type === 'image' ? `<img loading="lazy" class="media-message image-message" src="${message.media_url}" alt="Изображение">` : message.media_type === 'file' ? `<a class="file-message" href="${message.media_url}" target="_blank" rel="noopener">↧ <span>Открыть файл</span></a>` : `<video controls playsinline class="media-message video-circle" src="${message.media_url}"></video>`) : "";
    const textMarkup = message.media_url ? "" : `<div class="message-text">${escapeHtml(decrypted[index])}</div>`;
    return `<div class="message ${mine ? "mine" : ""}" data-message-id="${message.id || ""}">${reply}${mediaMarkup || textMarkup}<div class="message-tools"><button class="message-action reply-action" title="Ответить">↩</button><button class="message-action reaction-action" title="Реакция">😊</button>${reactions}</div><time>${new Date(message.timestamp).toLocaleTimeString([], {hour:"2-digit", minute:"2-digit"})} ${ticks}</time></div>`;
  }).join("") : `<div class="empty-state"><span>✦</span><h2>Первое сообщение</h2><p>Добавь немного тепла в этот чат.</p></div>`;
  box.querySelectorAll(".reply-action").forEach(button => button.onclick = () => { const message = messages.find(item => String(item.id) === button.closest(".message").dataset.messageId); beginReply(message, decrypted[messages.indexOf(message)]); });
  box.querySelectorAll(".reaction-action").forEach(button => button.onclick = () => chooseReaction(button.closest(".message").dataset.messageId));
  bindAudioPlayers(box);
  box.scrollTop = box.scrollHeight;
}
function formatAudioTime(seconds) {
  if (!Number.isFinite(seconds)) return "0:00";
  return `${Math.floor(seconds / 60)}:${String(Math.floor(seconds % 60)).padStart(2, "0")}`;
}
function bindAudioPlayers(container) {
  container.querySelectorAll(".audio-player").forEach(player => {
    const audio = player.querySelector(".audio-source");
    const button = player.querySelector(".audio-play");
    const progress = player.querySelector(".audio-progress");
    const time = player.querySelector(".audio-time");
    const updateProgress = () => {
      const percent = audio.duration ? (audio.currentTime / audio.duration) * 100 : 0;
      progress.value = percent;
      time.textContent = `${formatAudioTime(audio.currentTime)} / ${formatAudioTime(audio.duration)}`;
      player.style.setProperty("--audio-progress", `${percent}%`);
    };
    button.onclick = async () => {
      if (audio.paused) {
        document.querySelectorAll(".audio-source").forEach(other => { if (other !== audio) other.pause(); });
        await audio.play();
      } else audio.pause();
    };
    audio.onloadedmetadata = updateProgress;
    audio.ontimeupdate = updateProgress;
    audio.onplay = () => { button.classList.add("playing"); button.querySelector("span").textContent = "Ⅱ"; };
    audio.onpause = () => { button.classList.remove("playing"); button.querySelector("span").textContent = "▶"; };
    audio.onended = () => { progress.value = 0; audio.currentTime = 0; updateProgress(); };
    progress.oninput = () => { if (audio.duration) audio.currentTime = (Number(progress.value) / 100) * audio.duration; };
    updateProgress();
  });
}
function beginReply(message, content) { if (!message) return; state.replyTo = message; $("reply-label").textContent = `Ответ: ${(content || "Сообщение").slice(0, 120)}`; $("reply-bar").classList.remove("hidden"); $("message-input").focus(); }
function chooseReaction(messageId) { state.reactionMessageId = Number(messageId); $("emoji-picker").classList.remove("hidden"); }
async function reactToMessage(messageId, emoji) { try { const result = await api(`/messages/${state.user.username}/${messageId}/reaction`, {method:"POST", body:JSON.stringify({emoji})}); const messages = state.chats.get(state.active) || []; const message = messages.find(item => item.id === messageId); if (message) message.reactions = result.reactions; renderMessages(messages); } catch (error) { showFeature(error.message); } }
function escapeHtml(value) { return value.replace(/[&<>"']/g, char => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#039;"}[char])); }
async function openChat(username) {
  state.active = username; $("chat-name").textContent = `@${username}`; $("chat-status").textContent = "В сети · защищённый разговор";
  $("messenger-view").classList.add("mobile-chat-open");
  $("chat-avatar").textContent = initials(username); $("message-input").disabled = false; $("send-btn").disabled = false;
  document.querySelector(".conversation").classList.add("chat-ready");
  updateChatStatus(username);
  loadRecentChats();
  markChatRead(username);
  try { const messages = await api(`/history/${state.user.username}/${username}`); state.chats.set(username, messages); renderMessages(messages); markChatRead(username); } catch (error) { $("feature-note").textContent = error.message; }
  $("feature-note").textContent = "Можно начать с сообщения, AI-подсказки или звонка.";
}
function closeMobileChat() { $("messenger-view").classList.remove("mobile-chat-open"); }
async function markChatRead(username) {
  try { await api(`/chats/${username}/read`, {method:"POST"}); loadRecentChats(); }
  catch (error) { showFeature("Не удалось обновить статус прочтения: " + error.message); }
}
async function sendMessage() {
  const input = $("message-input"), text = input.value.trim();
  if (!text || !state.active) return;
  try { const encryptedText = await encryptMessage(text, state.active); const result = await api(`/messages/${state.user.username}`, {method: "POST", body: JSON.stringify({to_user: state.active, text: encryptedText, reply_to_id: state.replyTo?.id || null})}); input.value = ""; state.replyTo = null; $("reply-bar").classList.add("hidden"); const messages = state.chats.get(state.active) || []; messages.push({id: result.id, sender: state.user.username, encrypted_text: encryptedText, timestamp: result.timestamp, reply_to_id: result.reply_to_id, reactions: {}}); state.chats.set(state.active, messages); renderMessages(messages); loadRecentChats(); } catch (error) { $("feature-note").textContent = error.message; }
}

function getRecordingMimeType(mediaType) {
  const candidates = mediaType === "video"
    ? ["video/webm;codecs=vp9,opus", "video/webm;codecs=vp8,opus", "video/webm"]
    : ["audio/webm;codecs=opus", "audio/webm", "audio/ogg;codecs=opus"];
  return candidates.find(type => MediaRecorder.isTypeSupported(type)) || "";
}
async function sendMediaMessage(mediaType) {
  if (!state.active) return showFeature("Сначала выбери контакт.");
  if (!navigator.mediaDevices?.getUserMedia) return showFeature("Запись недоступна в этом браузере.");
  let stream;
  try {
    stream = await navigator.mediaDevices.getUserMedia({ audio: true, video: mediaType === "video" });
    const mimeType = getRecordingMimeType(mediaType);
    const recorder = new MediaRecorder(stream, mimeType ? {mimeType} : undefined);
    state.mediaRecorder = recorder;
    state.mediaChunks = [];
    state.mediaMode = mediaType;
    state.isPaused = false;
    if (mediaType === "video") {
      const preview = $("recording-preview");
      preview.srcObject = stream;
      $("recording-title").textContent = "Запись кружочка";
      $("recording-overlay").classList.remove("hidden");
    } else {
      $("recording-title").textContent = "Запись голосового";
      $("recording-preview").srcObject = null;
      $("recording-overlay").classList.remove("hidden");
    }
    $("recording-overlay").classList.toggle("recording-audio", mediaType === "audio");
    recorder.ondataavailable = (event) => { if (event.data.size) state.mediaChunks.push(event.data); };
    recorder.onstop = async () => {
      const blob = new Blob(state.mediaChunks, {type: recorder.mimeType || mimeType || (mediaType === "video" ? "video/webm" : "audio/webm")});
      if (!state.discardMedia) {
        const form = new FormData();
        form.append('file', blob, mediaType === 'video' ? 'circle.webm' : 'voice.webm');
        form.append('to_user', state.active);
        form.append('media_type', mediaType);
        if (state.replyTo?.id) form.append('reply_to_id', String(state.replyTo.id));
        try {
          const result = await api(`/messages/${state.user.username}/media?to_user=${encodeURIComponent(state.active)}&media_type=${mediaType}${state.replyTo?.id ? `&reply_to_id=${state.replyTo.id}` : ''}`, {method: 'POST', body: form});
          const messages = state.chats.get(state.active) || [];
          messages.push({id: result.id, sender: state.user.username, encrypted_text: '', timestamp: result.timestamp, reply_to_id: result.reply_to_id, reactions: {}, media_url: result.media_url, media_type: result.media_type});
          state.chats.set(state.active, messages);
          renderMessages(messages);
          loadRecentChats();
          showFeature(mediaType === 'video' ? 'Кружочек отправлен.' : 'Голосовое сообщение отправлено.');
        } catch (error) { showFeature(error.message); }
      }
      stream.getTracks().forEach(track => track.stop());
      $("recording-preview").srcObject = null;
      $("recording-overlay").classList.add("hidden");
      state.isRecording = false;
      state.isPaused = false;
      state.discardMedia = false;
      $(mediaType === 'video' ? 'video-record-btn' : 'voice-record-btn').classList.remove('recording');
      $("recording-status").textContent = "";
      $("pause-recording").textContent = "Пауза";
      clearInterval(state.mediaTimer);
      state.replyTo = null;
      $("reply-bar").classList.add("hidden");
    };
    recorder.start();
    state.isRecording = true;
    const button = $(mediaType === 'video' ? 'video-record-btn' : 'voice-record-btn');
    button.classList.add('recording');
    const startedAt = Date.now();
    $("recording-status").textContent = "00:00";
    $("recording-overlay-status").textContent = "00:00";
    clearInterval(state.mediaTimer);
    state.mediaTimer = setInterval(() => {
      const elapsed = Math.floor((Date.now() - startedAt) / 1000);
      const elapsedText = `${String(Math.floor(elapsed / 60)).padStart(2, "0")}:${String(elapsed % 60).padStart(2, "0")}`;
      $("recording-status").textContent = elapsedText;
      $("recording-overlay-status").textContent = elapsedText;
    }, 250);
    state.mediaTimeout = setTimeout(() => {
      if (state.mediaRecorder && state.isRecording) {
        state.mediaRecorder.stop();
      }
    }, mediaType === 'video' ? 15000 : 45000);
    showFeature(mediaType === 'video' ? 'Запись кружочка…' : 'Запись голосового…');
  } catch (error) {
    stream?.getTracks().forEach(track => track.stop());
    state.mediaRecorder = null;
    state.isRecording = false;
    $(mediaType === 'video' ? 'video-record-btn' : 'voice-record-btn').classList.remove('recording');
    $("recording-status").textContent = "";
    showFeature(error.message || "Не удалось начать запись.");
  }
}

function stopMediaRecording(discard = false) {
  if (state.mediaRecorder && state.isRecording) {
    state.discardMedia = discard;
    state.mediaRecorder.stop();
    state.isRecording = false;
    clearTimeout(state.mediaTimeout);
    $(state.mediaMode === 'video' ? 'video-record-btn' : 'voice-record-btn').classList.remove('recording');
  }
}
function toggleMediaPause() {
  const recorder = state.mediaRecorder;
  if (!recorder || !state.isRecording) return;
  if (recorder.state === "recording") {
    recorder.pause();
    state.isPaused = true;
    $("pause-recording").textContent = "Продолжить";
    $("recording-overlay").classList.add("recording-paused");
    showFeature("Запись приостановлена.");
  } else if (recorder.state === "paused") {
    recorder.resume();
    state.isPaused = false;
    $("pause-recording").textContent = "Пауза";
    $("recording-overlay").classList.remove("recording-paused");
    showFeature("Запись продолжается.");
  }
}
async function uploadChatFile(file) {
  if (!file || !state.active) return;
  const kind = file.type.startsWith("image/") ? "image" : file.type.startsWith("video/") ? "video" : file.type.startsWith("audio/") ? "audio" : "file";
  if (file.size > 16 * 1024 * 1024) return showFeature("Файл слишком большой. Максимум — 16 МБ.");
  const form = new FormData();
  form.append("file", file);
  form.append("to_user", state.active);
  form.append("media_type", kind);
  try {
    const result = await api(`/messages/${state.user.username}/media?to_user=${encodeURIComponent(state.active)}&media_type=${kind}`, {method:"POST", body:form});
    const messages = state.chats.get(state.active) || [];
    messages.push({id: result.id, sender: state.user.username, encrypted_text: "", timestamp: result.timestamp, reply_to_id: result.reply_to_id, reactions: {}, media_url: result.media_url, media_type: result.media_type});
    state.chats.set(state.active, messages);
    renderMessages(messages); loadRecentChats(); showFeature("Файл отправлен.");
  } catch (error) { showFeature(error.message); }
}
function showFeature(text) {
  $("feature-note").textContent = text;
  const toast = $("action-toast");
  toast.textContent = text;
  clearTimeout(showFeature.timer);
  showFeature.timer = setTimeout(() => { toast.textContent = ""; }, 7000);
}
$("auth-form").onsubmit = (event) => { event.preventDefault(); authenticate(false); };
$("register-btn").onclick = () => authenticate(true);
$("search-input").oninput = (event) => searchUsers(event.target.value.trim());
$("send-btn").onclick = sendMessage; $("message-input").onkeydown = (event) => { if (event.key === "Enter") sendMessage(); };
$("message-input").oninput = () => {
  sendPresence("typing", true);
  clearTimeout(state.typingTimer);
  state.typingTimer = setTimeout(() => sendPresence("typing", false), 1200);
};
$("logout-btn").onclick = () => { clearSession(); location.reload(); };
$("voice-record-btn").onclick = () => {
  if (state.isRecording) {
    stopMediaRecording();
    return;
  }
  sendMediaMessage("audio");
};
$("video-record-btn").onclick = () => {
  if (state.isRecording) {
    stopMediaRecording();
    return;
  }
  sendMediaMessage("video");
};
$("mobile-back-btn").onclick = closeMobileChat;
$("stop-recording").onclick = () => stopMediaRecording(false);
$("cancel-recording").onclick = () => stopMediaRecording(true);
$("pause-recording").onclick = toggleMediaPause;
$("media-btn").onclick = () => $("chat-file").click();
$("chat-file").onchange = (event) => { uploadChatFile(event.target.files[0]); event.target.value = ""; };

document.querySelectorAll("[data-tab]").forEach(button => button.onclick = () => switchTab(button.dataset.tab));
$("save-profile").onclick = async () => {
  try {
    const updated = await api(`/profile/${state.user.username}/update`, {method:"POST", body: JSON.stringify({display_name:$("profile-name").value, bio:$("profile-bio").value, phone:$("profile-phone").value})});
    state.user = {...state.user, ...(updated.user || {})};
    $("my-name").textContent = state.user.display_name || `@${state.user.username}`;
    showFeature("Профиль сохранён.");
  } catch (error) { showFeature(error.message); }
};
$("avatar-file").onchange = async (event) => {
  if (!event.target.files[0]) return;
  const image = new Image();
  image.onload = () => {
    state.avatarImage = image; state.avatarRotation = 0; $("avatar-zoom").value = "1"; drawAvatarPreview(); $("avatar-editor").classList.remove("hidden");
  };
  image.onerror = () => showFeature("Не удалось открыть изображение.");
  image.src = URL.createObjectURL(event.target.files[0]);
};
$("avatar-zoom").oninput = drawAvatarPreview;
$("rotate-avatar").onclick = () => { state.avatarRotation = (state.avatarRotation + 90) % 360; drawAvatarPreview(); };
$("close-avatar-editor").onclick = () => $("avatar-editor").classList.add("hidden");
$("save-avatar").onclick = () => {
  $("avatar-canvas").toBlob(async blob => {
    const form = new FormData(); form.append("file", blob, "avatar.png");
    try {
      const result = await api("/me/avatar", {method:"POST", body:form});
      $("profile-avatar").style.backgroundImage = `url(${result.avatar_url})`;
      $("profile-avatar").textContent = "";
      $("my-avatar").style.backgroundImage = `url(${result.avatar_url})`;
      $("my-avatar").textContent = "";
      $("avatar-editor").classList.add("hidden");
      showFeature("Аватар обновлён.");
    } catch (error) { showFeature(error.message); }
  }, "image/png");
};
function drawAvatarPreview() {
  const canvas = $("avatar-canvas"), context = canvas.getContext("2d"), image = state.avatarImage;
  if (!image) return;
  const zoom = Number($("avatar-zoom").value);
  const side = Math.min(image.width, image.height) / zoom;
  context.clearRect(0, 0, 320, 320);
  context.save(); context.translate(160, 160); context.rotate(state.avatarRotation * Math.PI / 180);
  const scale = 320 / side;
  context.drawImage(image, -image.width * scale / 2, -image.height * scale / 2, image.width * scale, image.height * scale);
  context.restore();
}
$("choose-story").onclick = () => $("story-file").click();
$("story-file").onchange = (event) => {
  state.selectedStoryFile = event.target.files[0] || null;
  $("publish-story").disabled = !state.selectedStoryFile;
  if (!state.selectedStoryFile) return;
  if (state.storyPreviewUrl) URL.revokeObjectURL(state.storyPreviewUrl);
  state.storyPreviewUrl = URL.createObjectURL(state.selectedStoryFile);
  const preview = $("story-preview");
  const isVideo = state.selectedStoryFile.type.startsWith("video/");
  preview.innerHTML = isVideo ? `<video src="${state.storyPreviewUrl}" controls></video>` : `<img src="${state.storyPreviewUrl}" alt="Предпросмотр story">`;
  preview.classList.remove("hidden");
  $("story-status").textContent = `Файл выбран: ${state.selectedStoryFile.name}`;
};
$("publish-story").onclick = async () => {
  if (!state.selectedStoryFile) return $("story-status").textContent = "Сначала выберите фото или видео.";
  $("publish-story").disabled = true;
  $("choose-story").disabled = true;
  $("story-status").textContent = "Загрузка story…";
  const form = new FormData(); form.append("file", state.selectedStoryFile); form.append("caption", $("story-caption").value); form.append("music_name", $("story-music").value);
  try { await api("/me/stories/upload", {method:"POST", body:form, headers:{}}); if (state.storyPreviewUrl) URL.revokeObjectURL(state.storyPreviewUrl); state.storyPreviewUrl = null; state.selectedStoryFile = null; $("story-file").value = ""; $("story-preview").classList.add("hidden"); $("story-status").textContent = "Story успешно опубликована на 24 часа."; $("story-caption").value = ""; $("story-music").value = ""; loadStories(); showFeature("Story успешно опубликована."); } catch (error) { $("publish-story").disabled = false; $("story-status").textContent = `Не удалось опубликовать: ${error.message}`; showFeature(error.message); }
  $("choose-story").disabled = false;
};
$("close-public-profile").onclick = () => $("public-profile-modal").classList.add("hidden");
$("cancel-reply").onclick = () => { state.replyTo = null; $("reply-bar").classList.add("hidden"); };
$("emoji-picker").querySelectorAll("[data-emoji]").forEach(button => button.onclick = () => { reactToMessage(state.reactionMessageId, button.dataset.emoji); $("emoji-picker").classList.add("hidden"); });
$("close-story-viewer").onclick = () => { $("story-viewer").classList.add("hidden"); $("story-viewer-media").innerHTML = ""; };
$("story-like").onclick = () => reactToStory(state.activeStory);
$("public-profile-modal").onclick = (event) => {
  if (event.target === $("public-profile-modal")) $("public-profile-modal").classList.add("hidden");
};
$("save-settings").onclick = async () => {
  try { await api(`/profile/${state.user.username}/update`, {method:"POST", body:JSON.stringify({theme:$("theme-setting").value, phone_visibility:$("phone-visibility").value, last_seen_visibility:$("last-seen-visibility").value, two_factor_enabled:$("two-factor").checked})}); applyTheme($("theme-setting").value); showFeature("Настройки сохранены."); } catch (error) { showFeature(error.message); }
};
$("ai-btn").onclick = $("ai-card-btn").onclick = async () => {
  if (!state.active) return showFeature("Сначала выбери контакт.");
  const prompt = window.prompt("Что спросить у Vesto AI?", "Придумай идею для нашего разговора");
  if (!prompt) return;
  showFeature("Vesto AI думает...");
  try {
    const result = await api(`/ai/${state.user.username}`, {method: "POST", body: JSON.stringify({prompt})});
    showFeature(result.answer);
  } catch (error) { showFeature(error.message); }
};
$("chat-avatar").onclick = () => { if (state.active) openPublicProfile(state.active); };
$("chat-heading").onclick = () => { if (state.active) openPublicProfile(state.active); };
document.querySelector(".header-actions").onclick = event => event.stopPropagation();
document.querySelectorAll(".call-btn").forEach(button => button.onclick = () => openCall(button.dataset.kind));
$("end-call").onclick = () => closeCall();
restoreSession();
