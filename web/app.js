const state = { user: null, active: null, chats: new Map(), token: null, socket: null, peer: null, stream: null, avatarImage: null, avatarRotation: 0, presence: new Map(), typingTimer: null };
const $ = (id) => document.getElementById(id);
const initials = (name) => (name || "?").slice(0, 1).toUpperCase();
const setStatus = (text, error = true) => { $("auth-status").textContent = text; $("auth-status").style.color = error ? "#d46e7b" : "#5b9b7d"; };
async function api(url, options = {}) {
  const headers = {};
  if (!(options.body instanceof FormData)) headers["Content-Type"] = "application/json";
  if (state.token) headers.Authorization = "Bearer " + state.token;
  const response = await fetch(url, {...options, headers: {...headers, ...(options.headers || {})}});
  const body = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(body.detail || "Не удалось выполнить запрос");
  return body;
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
    $("stories-list").innerHTML = stories.map(renderStoryCard).join("");
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
      messages.push({sender: data.from_user, encrypted_text: data.encrypted_msg, timestamp: new Date().toISOString()});
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
    handleCallSignal(data);
  };
  socket.onclose = () => setTimeout(connectRealtime, 2000);
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
  if (state.socket?.readyState === WebSocket.OPEN) state.socket.send(JSON.stringify({...payload, to_user: state.active}));
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
  $("local-video").srcObject = state.stream;
  state.peer = new RTCPeerConnection({iceServers: [{urls: "stun:stun.l.google.com:19302"}]});
  state.stream.getTracks().forEach(track => state.peer.addTrack(track, state.stream));
  state.peer.ontrack = event => { $("remote-video").srcObject = event.streams[0]; };
  state.peer.onicecandidate = event => { if (event.candidate) sendSignal({type: "ice_candidate", candidate: event.candidate}); };
  if (incomingOffer) {
    await state.peer.setRemoteDescription(incomingOffer);
    const answer = await state.peer.createAnswer();
    await state.peer.setLocalDescription(answer);
    sendSignal({type: "call_answer", sdp: answer});
  } else {
    const offer = await state.peer.createOffer();
    await state.peer.setLocalDescription(offer);
    sendSignal({type: "call_offer", sdp: offer, kind});
  }
}
async function handleCallSignal(data) {
  if (data.type === "call_offer") {
    if (!confirm(`Входящий звонок от @${data.from_user}. Принять?`)) return;
    await openCall(data.kind || "video", data.sdp, data.from_user);
  } else if (data.type === "call_answer" && state.peer) {
    await state.peer.setRemoteDescription(data.sdp);
  } else if (data.type === "ice_candidate" && state.peer && data.candidate) {
    await state.peer.addIceCandidate(data.candidate);
  } else if (data.type === "call_end") {
    closeCall(false);
  }
}
function closeCall(send = true) {
  if (send) sendSignal({type: "call_end"});
  state.peer?.close(); state.stream?.getTracks().forEach(track => track.stop());
  state.peer = null; state.stream = null; $("remote-video").srcObject = null; $("local-video").srcObject = null; $("call-overlay").classList.add("hidden");
}
async function authenticate(register = false) {
  const username = $("username").value.trim(), password = $("password").value;
  try {
    const result = await api(register ? "/register" : "/login", {method: "POST", body: JSON.stringify({username, password, public_key: ""})});
    state.token = result.token;
    showMessenger(result.user);
  } catch (error) { setStatus(error.message); }
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
    $("public-stories").innerHTML = profile.stories.length ? profile.stories.map(renderStoryCard).join("") : `<p class="muted">Активных stories пока нет.</p>`;
    $("public-message").onclick = () => { $("public-profile-modal").classList.add("hidden"); openChat(profile.username); };
    $("public-profile-modal").classList.remove("hidden");
  } catch (error) { showFeature(error.message); }
}
function renderStoryCard(story) {
  return `<article class="story-card">${story.media_type === "video" ? `<video src="${story.media_url}" controls></video>` : `<img src="${story.media_url}" alt="Story">`}<p>${escapeHtml(story.caption || "")}${story.music_name ? `<br>♫ ${escapeHtml(story.music_name)}` : ""}</p></article>`;
}
async function searchUsers(query) {
  if (query.length < 3) { $("search-results").innerHTML = ""; return; }
  try { renderSearch(await api(`/users/search?q=${encodeURIComponent(query)}`)); } catch (error) { $("search-results").textContent = error.message; }
}
function renderMessages(messages) {
  const box = $("messages");
  box.innerHTML = messages.length ? messages.map(message => {
    const mine = message.sender === state.user.username;
    const ticks = mine ? `<span class="message-ticks ${message.read_at ? "read" : ""}" title="${message.read_at ? "Прочитано" : "Отправлено"}">${message.read_at ? "✓✓" : "✓"}</span>` : "";
    return `<div class="message ${mine ? "mine" : ""}"><div class="message-text">${escapeHtml(message.encrypted_text)}</div><time>${new Date(message.timestamp).toLocaleTimeString([], {hour:"2-digit", minute:"2-digit"})} ${ticks}</time></div>`;
  }).join("") : `<div class="empty-state"><span>✦</span><h2>Первое сообщение</h2><p>Добавь немного тепла в этот чат.</p></div>`;
  box.scrollTop = box.scrollHeight;
}
function escapeHtml(value) { return value.replace(/[&<>"']/g, char => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#039;"}[char])); }
async function openChat(username) {
  state.active = username; $("chat-name").textContent = `@${username}`; $("chat-status").textContent = "В сети · защищённый разговор";
  $("chat-avatar").textContent = initials(username); $("message-input").disabled = false; $("send-btn").disabled = false;
  document.querySelector(".conversation").classList.add("chat-ready");
  updateChatStatus(username);
  loadRecentChats();
  markChatRead(username);
  try { const messages = await api(`/history/${state.user.username}/${username}`); state.chats.set(username, messages); renderMessages(messages); markChatRead(username); } catch (error) { $("feature-note").textContent = error.message; }
  $("feature-note").textContent = "Можно начать с сообщения, AI-подсказки или звонка.";
}
async function markChatRead(username) {
  try { await api(`/chats/${username}/read`, {method:"POST"}); loadRecentChats(); }
  catch (error) { showFeature("Не удалось обновить статус прочтения: " + error.message); }
}
async function sendMessage() {
  const input = $("message-input"), text = input.value.trim();
  if (!text || !state.active) return;
  try { await api(`/messages/${state.user.username}`, {method: "POST", body: JSON.stringify({to_user: state.active, text})}); input.value = ""; const messages = state.chats.get(state.active) || []; messages.push({sender: state.user.username, encrypted_text: text, timestamp: new Date().toISOString()}); state.chats.set(state.active, messages); renderMessages(messages); loadRecentChats(); } catch (error) { $("feature-note").textContent = error.message; }
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
$("logout-btn").onclick = () => location.reload();
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
$("publish-story").onclick = () => $("story-file").click();
$("story-file").onchange = async (event) => {
  if (!event.target.files[0]) return;
  const form = new FormData(); form.append("file", event.target.files[0]); form.append("caption", $("story-caption").value); form.append("music_name", $("story-music").value);
  try { await api("/me/stories/upload", {method:"POST", body:form, headers:{}}); $("story-caption").value = ""; $("story-music").value = ""; loadStories(); showFeature("Story опубликована на 24 часа."); } catch (error) { showFeature(error.message); }
};
$("close-public-profile").onclick = () => $("public-profile-modal").classList.add("hidden");
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
$("media-btn").onclick = $("media-card-btn").onclick = () => showFeature("Circle FX: здесь появится студия видеосообщений — музыка, фильтры и эффекты.");
document.querySelectorAll(".call-btn").forEach(button => button.onclick = () => openCall(button.dataset.kind));
$("end-call").onclick = () => closeCall();
