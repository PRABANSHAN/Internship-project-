const form = document.getElementById('chat-form');
const msgInput = document.getElementById('msg');
const messages = document.getElementById('messages');

function appendMessage(who, text) {
  const div = document.createElement('div');
  div.className = 'message ' + who;
  div.textContent = text;
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
  appendMessage('bot', placeholder);
  try {
    const res = await fetch('/api/chat', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({message: text})
    });
    const data = await res.json();
    // remove the placeholder and set reply
    const placeholders = document.getElementsByClassName('bot');
    if (placeholders.length) {
      const el = placeholders[placeholders.length - 1];
      if (data.error) el.textContent = 'Error: ' + data.error;
      else el.textContent = data.reply || 'No reply';
    }
  } catch (err) {
    appendMessage('bot', 'Error: ' + err.message);
  }
});
