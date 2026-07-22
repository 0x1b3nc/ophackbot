(() => {
  const messagesEl = document.getElementById("messages");
  const emptyEl = document.getElementById("empty");
  const promptEl = document.getElementById("prompt");
  const sendBtn = document.getElementById("send");
  const clearBtn = document.getElementById("clear-chat");
  const targetEl = document.getElementById("target");
  const providerEl = document.getElementById("provider");
  const setTargetBtn = document.getElementById("set-target");
  const setProviderBtn = document.getElementById("set-provider");
  const headerSub = document.getElementById("header-sub");
  const stMode = document.getElementById("st-mode");
  const stTarget = document.getElementById("st-target");
  const stYolo = document.getElementById("st-yolo");

  let running = false;
  let abortCtrl = null;

  function hideEmpty() {
    if (emptyEl) emptyEl.style.display = "none";
  }

  function showEmptyIfNeeded() {
    if (!messagesEl.querySelector(".bubble") && emptyEl) {
      emptyEl.style.display = "";
    }
  }

  function escapeHtml(s) {
    return String(s)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  function lightMarkdown(text) {
    let html = escapeHtml(text);
    html = html.replace(/```([\s\S]*?)```/g, (_, code) => `<pre><code>${code}</code></pre>`);
    html = html.replace(/`([^`]+)`/g, "<code>$1</code>");
    html = html.replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>");
    return html;
  }

  function appendBubble(role, content, opts = {}) {
    hideEmpty();
    const div = document.createElement("div");
    div.className = `bubble ${role}`;
    if (role === "assistant") {
      div.innerHTML = `<div class="body markdown-body">${lightMarkdown(content)}</div>`;
    } else if (role === "status") {
      const spin = opts.kind === "running" ? '<span class="running-dot"></span>' : "";
      div.innerHTML = `${spin}<span>${escapeHtml(content)}</span>`;
      if (opts.kind === "running") div.dataset.running = "1";
    } else {
      div.textContent = content;
    }
    messagesEl.appendChild(div);
    messagesEl.scrollTop = messagesEl.scrollHeight;
    return div;
  }

  function clearRunningStatus() {
    messagesEl.querySelectorAll('.bubble.status[data-running="1"]').forEach((el) => el.remove());
  }

  function setRunning(on) {
    running = on;
    promptEl.disabled = on;
    updateSendEnabled();
    if (on) {
      sendBtn.classList.add("stop");
      sendBtn.disabled = false;
      sendBtn.setAttribute("aria-label", "Stop");
      sendBtn.innerHTML =
        '<svg width="14" height="14" viewBox="0 0 14 14" fill="none"><rect x="3" y="3" width="8" height="8" rx="1.5" fill="currentColor"/></svg>';
    } else {
      sendBtn.classList.remove("stop");
      sendBtn.setAttribute("aria-label", "Send");
      sendBtn.innerHTML =
        '<svg width="16" height="16" viewBox="0 0 16 16" fill="none"><path d="M8 12V4M8 4L4 8M8 4L12 8" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg>';
      updateSendEnabled();
    }
  }

  function updateSendEnabled() {
    if (running) return;
    sendBtn.disabled = !promptEl.value.trim();
  }

  function resizePrompt() {
    promptEl.style.height = "auto";
    promptEl.style.height = `${Math.min(promptEl.scrollHeight, 160)}px`;
  }

  async function refreshStatus() {
    try {
      const res = await fetch("/api/status");
      const data = await res.json();
      stMode.textContent = data.label || data.mode || "—";
      stTarget.textContent = data.target || "—";
      stYolo.textContent = data.yolo ? "on" : "off";
      headerSub.textContent = `${data.label || data.mode} · effort ${data.effort || "auto"}`;
      if (data.target && !targetEl.value) targetEl.value = data.target;
    } catch {
      stMode.textContent = "offline?";
    }
  }

  async function postJson(url, body) {
    const res = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(data.error || res.statusText);
    return data;
  }

  async function sendPrompt() {
    const prompt = promptEl.value.trim();
    if (!prompt || running) return;
    promptEl.value = "";
    resizePrompt();
    updateSendEnabled();
    setRunning(true);
    abortCtrl = new AbortController();

    try {
      const res = await fetch("/api/chat", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          prompt,
          target: targetEl.value.trim() || undefined,
        }),
        signal: abortCtrl.signal,
      });
      if (!res.ok || !res.body) {
        const err = await res.text();
        appendBubble("assistant", `Error: ${err || res.status}`);
        return;
      }

      const reader = res.body.getReader();
      const decoder = new TextDecoder();
      let buf = "";
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        buf += decoder.decode(value, { stream: true });
        const parts = buf.split("\n\n");
        buf = parts.pop() || "";
        for (const part of parts) {
          const line = part
            .split("\n")
            .find((l) => l.startsWith("data: "));
          if (!line) continue;
          let msg;
          try {
            msg = JSON.parse(line.slice(6));
          } catch {
            continue;
          }
          if (msg.type === "close") continue;
          if (msg.role === "user") {
            appendBubble("user", msg.content || "");
          } else if (msg.role === "status") {
            clearRunningStatus();
            appendBubble("status", msg.content || "", { kind: msg.kind });
          } else if (msg.role === "assistant") {
            clearRunningStatus();
            appendBubble("assistant", msg.content || "");
          }
        }
      }
    } catch (err) {
      if (err.name !== "AbortError") {
        appendBubble("assistant", `Error: ${err.message || err}`);
      } else {
        clearRunningStatus();
        appendBubble("status", "stopped", { kind: "done" });
      }
    } finally {
      abortCtrl = null;
      setRunning(false);
      refreshStatus();
      promptEl.focus();
    }
  }

  sendBtn.addEventListener("click", () => {
    if (running && abortCtrl) {
      abortCtrl.abort();
      return;
    }
    sendPrompt();
  });

  promptEl.addEventListener("input", () => {
    resizePrompt();
    updateSendEnabled();
  });

  promptEl.addEventListener("keydown", (e) => {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      if (!running) sendPrompt();
    }
  });

  clearBtn.addEventListener("click", () => {
    messagesEl.querySelectorAll(".bubble").forEach((el) => el.remove());
    showEmptyIfNeeded();
  });

  setTargetBtn.addEventListener("click", async () => {
    const target = targetEl.value.trim();
    if (!target) return;
    try {
      await postJson("/api/target", { target });
      await refreshStatus();
    } catch (err) {
      appendBubble("assistant", `Target error: ${err.message}`);
    }
  });

  setProviderBtn.addEventListener("click", async () => {
    const provider = providerEl.value.trim();
    if (!provider) return;
    try {
      await postJson("/api/provider", { provider });
      await refreshStatus();
    } catch (err) {
      appendBubble("assistant", `Provider error: ${err.message}`);
    }
  });

  refreshStatus();
  updateSendEnabled();
  promptEl.focus();
})();
