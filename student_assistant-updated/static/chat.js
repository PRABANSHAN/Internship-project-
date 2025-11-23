const form = document.getElementById('chat-form');
const msgInput = document.getElementById('msg');
const messages = document.getElementById('messages');

function appendMessage(who, text, timestamp=null, isPlaceholder=false) {
  const div = document.createElement('div');
  div.className = 'message ' + who + (isPlaceholder ? ' placeholder' : '');
  const content = document.createElement('div');
  content.className = 'message-content';
  content.textContent = text;
  const meta = document.createElement('div');
  meta.className = 'message-meta';
  if (timestamp) {
    meta.textContent = timestamp;
  } else {
    const now = new Date();
    meta.textContent = now.toLocaleTimeString();
  }
  div.appendChild(content);
  div.appendChild(meta);
  messages.appendChild(div);
  messages.scrollTop = messages.scrollHeight;
}

form.addEventListener('submit', async (e) => {
  e.preventDefault();
  const text = msgInput.value.trim();
  if (!text) return;
  appendMessage('user', text);
  msgInput.value = '';
  const placeholder = 'Thinking...';
  appendMessage('bot', placeholder, null, true);
  try {
    const res = await fetch('/api/chat', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({message: text})
    });
    const data = await res.json();
    // remove the placeholder and set reply
    const placeholders = document.getElementsByClassName('placeholder');
    if (placeholders.length) {
      const el = placeholders[placeholders.length - 1];
      // update message content
      const content = el.querySelector('.message-content');
      const meta = el.querySelector('.message-meta');
      if (data.error) content.textContent = 'Error: ' + data.error;
      else content.textContent = data.reply || 'No reply';
      // remove placeholder marker
      el.classList.remove('placeholder');
      // update timestamp (use server timestamp if returned)
      if (data.timestamp) meta.textContent = data.timestamp;
      else meta.textContent = new Date().toLocaleTimeString();
    }
  } catch (err) {
    appendMessage('bot', 'Error: ' + err.message);
  }
});

// Load recent history on page load
window.addEventListener('DOMContentLoaded', async () => {
  try {
    const res = await fetch('/api/history');
    if (!res.ok) return;
    const data = await res.json();
    if (!data || !Array.isArray(data.messages)) return;
    // messages are returned newest-first; render oldest-first
    const msgs = data.messages.slice().reverse();
    for (const m of msgs) {
      appendMessage(m.role === 'user' ? 'user' : 'bot', m.content, m.created_at || null);
    }
  } catch (e) {
    // ignore history load errors
  }
});
