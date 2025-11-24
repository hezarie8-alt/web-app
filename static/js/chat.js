document.addEventListener('DOMContentLoaded', () => {
    // اتصال به Socket.IO
    const socket = io();
    const currentUserId = {{ current_user.id }};
    const otherUserId = {{ other_user.id }};
    const roomName = `chat-${Math.min(currentUserId, otherUserId)}-${Math.max(currentUserId, otherUserId)}`;
    
    // پیوستن به اتاق چت
    socket.emit('join_chat', { other_user_id: otherUserId });
    
    // اسکرول به پایین پیام‌ها
    function scrollToBottom() {
        const chatMessages = document.getElementById('chat-messages');
        chatMessages.scrollTop = chatMessages.scrollHeight;
    }
    
    // اسکرول اولیه به پایین
    scrollToBottom();
    
    // مدیریت ارسال فرم
    const messageForm = document.getElementById('message-form');
    const messageInput = document.getElementById('message-input');
    
    messageForm.addEventListener('submit', (e) => {
        e.preventDefault();
        
        const content = messageInput.value.trim();
        if (content) {
            // ارسال پیام از طریق Socket.IO برای نمایش آنی
            socket.emit('send_message', {
                other_user_id: otherUserId,
                content: content
            });
            
            // ایجاد و نمایش پیام فوری در رابط کاربری
            const chatMessages = document.getElementById('chat-messages');
            const messageDiv = document.createElement('div');
            messageDiv.className = 'message sent';
            
            const now = new Date();
            const timeString = now.getHours().toString().padStart(2, '0') + ':' + 
                             now.getMinutes().toString().padStart(2, '0');
            
            messageDiv.innerHTML = `
                <div class="message-content">
                    <div class="message-text">${content}</div>
                    <div class="message-time">${timeString}</div>
                </div>
            `;
            
            chatMessages.appendChild(messageDiv);
            
            // پاک کردن ورودی
            messageInput.value = '';
            
            // اسکرول به پایین برای نمایش پیام جدید
            scrollToBottom();
            
            // ارسال به سرور برای ذخیره در دیتابیس (بک‌آپ)
            fetch(`/send_message/${otherUserId}`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                },
                body: `content=${encodeURIComponent(content)}`
            })
            .catch(error => console.error('خطا در ارسال پیام:', error));
        }
    });
    
    // مدیریت پیام‌های جدید از Socket.IO
    socket.on('new_message', (data) => {
        if (data.sender_id == otherUserId || data.sender_id == currentUserId) {
            const chatMessages = document.getElementById('chat-messages');
            const typingIndicator = document.getElementById('typing-indicator');
            
            // مخفی کردن نشانگر تایپ کردن در صورت نمایش
            if (typingIndicator.style.display !== 'none') {
                typingIndicator.style.display = 'none';
            }
            
            // ایجاد عنصر پیام
            const messageDiv = document.createElement('div');
            messageDiv.className = data.sender_id == currentUserId ? 'message sent' : 'message received';
            
            if (data.sender_id != currentUserId) {
                messageDiv.innerHTML = `
                    <div class="message-avatar">${data.sender_name[0]}</div>
                    <div class="message-content">
                        <div class="message-text">${data.content}</div>
                        <div class="message-time">${data.timestamp}</div>
                    </div>
                `;
            } else {
                messageDiv.innerHTML = `
                    <div class="message-content">
                        <div class="message-text">${data.content}</div>
                        <div class="message-time">${data.timestamp}</div>
                    </div>
                `;
            }
            
            // اضافه کردن پیام به چت
            chatMessages.appendChild(messageDiv);
            
            // اسکرول به پایین
            scrollToBottom();
        }
    });
    
    // مدیریت پیام‌های وضعیت
    socket.on('status_message', (data) => {
        if (data.type === 'join') {
            // می‌توانید در صورت تمایل اعلان نمایش دهید
            console.log(`${data.msg}`);
        }
    });
    
    // مدیریت نشانگر تایپ کردن
    let typingTimer;
    messageInput.addEventListener('input', () => {
        // پاک کردن تایمر موجود
        clearTimeout(typingTimer);
        
        // ارسال رویداد تایپ کردن
        socket.emit('typing', { room: roomName });
        
        // تنظیم تایمر برای متوقف کردن نشانگر تایپ کردن
        typingTimer = setTimeout(() => {
            socket.emit('stop_typing', { room: roomName });
        }, 1000);
    });
    
    // مدیریت نشانگر تایپ کردن از کاربر دیگر
    socket.on('typing', (data) => {
        if (data.user_id == otherUserId) {
            const typingIndicator = document.getElementById('typing-indicator');
            typingIndicator.style.display = 'flex';
            scrollToBottom();
        }
    });
    
    socket.on('stop_typing', (data) => {
        if (data.user_id == otherUserId) {
            const typingIndicator = document.getElementById('typing-indicator');
            typingIndicator.style.display = 'none';
        }
    });
});