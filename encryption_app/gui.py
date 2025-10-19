import tkinter as tk
from tkinter import messagebox, filedialog, ttk
from database import (
    register_user,
    get_user,
    get_chat_messages,
    get_user_keys,
    save_message,
    get_all_users,
    get_chat_list
)
from crypto import crypto_manager
import os
from datetime import datetime
import pytz

current_user = None
selected_chat = None

def get_moscow_time():
    moscow_tz = pytz.timezone('Europe/Moscow')
    utc_time = datetime.now(pytz.UTC)
    return utc_time.astimezone(moscow_tz)

def login_window():
    def on_login():
        global current_user
        username = entry_username.get()
        password = entry_password.get()
        user = get_user(username)
        if user and user[2] == password:  # Проверяем пароль
            current_user = username
            root.destroy()
            main_window()
        else:
            messagebox.showerror("Ошибка", "Неверное имя пользователя или пароль.")

    def on_register():
        username = entry_username.get()
        password = entry_password.get()
        if username and password:
            if register_user(username, password):  # Исправлен вызов функции
                messagebox.showinfo("Успех", "Регистрация прошла успешно!")
            else:
                messagebox.showerror("Ошибка", "Имя пользователя уже занято.")
        else:
            messagebox.showerror("Ошибка", "Пожалуйста, введите имя пользователя и пароль.")

    # Создание окна входа/регистрации
    root = tk.Tk()
    root.title("Вход/Регистрация")

    tk.Label(root, text="Имя пользователя").grid(row=0, column=0)
    entry_username = tk.Entry(root)
    entry_username.grid(row=0, column=1)

    tk.Label(root, text="Пароль").grid(row=1, column=0)
    entry_password = tk.Entry(root, show="*")
    entry_password.grid(row=1, column=1)

    tk.Button(root, text="Войти", command=on_login).grid(row=2, column=0)
    tk.Button(root, text="Зарегистрироваться", command=on_register).grid(row=2, column=1)

    root.mainloop()

def main_window():
    def send_message():
        global selected_chat
        if not selected_chat:
            messagebox.showerror("Ошибка", "Пожалуйста, выберите чат")
            return

        message = entry_message.get()
        if not message:
            return

        try:
            # Сначала показываем сообщение в истории чата
            time_str = get_moscow_time().strftime("%H:%M")
            chat_content.insert(tk.END, f"\n{time_str} ", "time_right")
            chat_content.insert(tk.END, f"Вы: {message}\n", "msg_right")
            chat_content.see(tk.END)

            # Для получателя шифруем сообщение
            public_key, _ = get_user_keys(selected_chat)
            if not public_key:
                messagebox.showerror("Ошибка", "Не удалось получить ключ получателя")
                return

            # Шифруем сообщение для получателя
            encrypted_data = crypto_manager.encrypt_message(message.encode('utf-8'), public_key)

            # Сохраняем зашифрованное сообщение для получателя с исходным текстом
            save_message(current_user, selected_chat, encrypted_data, original_content=message)

            entry_message.delete(0, tk.END)
            refresh_chat_list()
        except Exception as e:
            messagebox.showerror("Ошибка", f"Ошибка при отправке сообщения: {str(e)}")

    def send_file():
        global selected_chat
        if not selected_chat:
            messagebox.showerror("Ошибка", "Пожалуйста, выберите чат")
            return

        file_path = filedialog.askopenfilename()
        if file_path:
            try:
                filename = os.path.basename(file_path)
                # Сначала показываем информацию о файле в истории чата
                time_str = get_moscow_time().strftime("%H:%M")
                chat_content.insert(tk.END, f"\n{time_str} ", "time_right")
                chat_content.insert(tk.END, 
                    f"Вы: Файл: {filename} [Отправлено]\n", 
                    "msg_right")
                chat_content.see(tk.END)
                # Затем шифруем и отправляем в базу
                with open(file_path, 'rb') as file:
                    file_data = file.read()
                
                public_key, _ = get_user_keys(selected_chat)
                if not public_key:
                    messagebox.showerror("Ошибка", "Не удалось получить ключ получателя")
                    return

                encrypted_data = crypto_manager.encrypt_message(file_data, public_key)
                save_message(current_user, selected_chat, encrypted_data, 
                           is_file=True, filename=filename)
                
                refresh_chat_list()
            except Exception as e:
                messagebox.showerror("Ошибка", f"Ошибка при отправке файла: {str(e)}")

    def save_received_file(filename, decrypted_data):
        save_path = filedialog.asksaveasfilename(
            defaultextension=".*",
            initialfile=filename
        )
        if save_path:
            try:
                with open(save_path, 'wb') as file:
                    file.write(decrypted_data)
                messagebox.showinfo("Успех", f"Файл сохранен как {save_path}")
            except Exception as e:
                messagebox.showerror("Ошибка", f"Ошибка при сохранении файла: {str(e)}")

    def update_chat_header():
        if selected_chat:
            chat_title.config(text=f"Чат с {selected_chat}")
        else:
            chat_title.config(text="")

    def refresh_chat():
        global selected_chat
        if not selected_chat:
            return

        update_chat_header()
        chat_content.delete(1.0, tk.END)
        messages = get_chat_messages(current_user, selected_chat)

        for message in messages:
            try:
                # Конвертируем время в московское
                timestamp = datetime.fromisoformat(message['timestamp'])
                if not timestamp.tzinfo:
                    timestamp = pytz.UTC.localize(timestamp)
                moscow_time = timestamp.astimezone(pytz.timezone('Europe/Moscow'))
                time_str = moscow_time.strftime("%H:%M")

                align = "right" if message['sender'] == current_user else "left"

                if message['sender'] == current_user:
                    # Для отправленных сообщений используем исходный текст, если он есть
                    if message['is_file']:
                        chat_content.insert(tk.END, f"\n{time_str} ", f"time_{align}")
                        chat_content.insert(tk.END,
                                            f"Вы: Файл: {message['filename']} [Отправлено]\n",
                                            f"msg_{align}")
                    else:
                        # Используем original_content, если доступно
                        original_text = message.get('original_content', '[сообщение не доступно]')
                        chat_content.insert(tk.END, f"\n{time_str} ", f"time_{align}")
                        chat_content.insert(tk.END,
                                            f"Вы: {original_text}\n",
                                            f"msg_{align}")
                else:
                    # Для полученных сообщений расшифровываем
                    _, private_key = get_user_keys(current_user)
                    if not private_key:
                        chat_content.insert(tk.END, "[не удалось получить ключ]\n")
                        continue

                    try:
                        # Расшифровываем сообщение
                        decrypted_data = crypto_manager.decrypt_message(
                            message['encrypted_data'],
                            private_key
                        )

                        if message['is_file']:
                            chat_content.insert(tk.END, f"\n{time_str} ", f"time_{align}")
                            chat_content.insert(tk.END,
                                                f"{message['sender']}: Файл: {message['filename']} [Нажмите для сохранения]\n",
                                                f"msg_{align}")

                            def save_handler(event, decrypted_file=decrypted_data,
                                             f_name=message['filename']):
                                save_received_file(f_name, decrypted_file)

                            chat_content.tag_add("clickable", "end-2c linestart", "end-1c")
                            chat_content.tag_bind("clickable", "<Button-1>", save_handler)
                        else:
                            chat_content.insert(tk.END, f"\n{time_str} ", f"time_{align}")
                            chat_content.insert(tk.END,
                                                f"{message['sender']}: {decrypted_data.decode('utf-8', errors='replace')}\n",
                                                f"msg_{align}")
                    except Exception as e:
                        chat_content.insert(tk.END, f"\n{time_str} ", f"time_{align}")
                        chat_content.insert(tk.END,
                                            f"[ошибка расшифровки сообщения: {str(e)}]\n",
                                            f"msg_{align}")

            except Exception as e:
                chat_content.insert(tk.END, f"[ошибка обработки сообщения: {str(e)}]\n")

        # Настраиваем теги для выравнивания
        chat_content.tag_configure("msg_left", justify="left")
        chat_content.tag_configure("msg_right", justify="right")
        chat_content.tag_configure("time_left", justify="left")
        chat_content.tag_configure("time_right", justify="right")

        chat_content.see(tk.END)

    def on_chat_selected(event):
        global selected_chat
        selection = chat_list.selection()
        if selection:
            item = chat_list.item(selection[0])
            selected_chat = item['values'][0]
            update_chat_header()
            refresh_chat()

    def refresh_chat_list():
        # Сохраняем текущее выделение
        current_selection = None
        if chat_list.selection():
            current_selection = chat_list.item(chat_list.selection()[0])['values'][0]

        # Очищаем список
        for item in chat_list.get_children():
            chat_list.delete(item)

        # Получаем список чатов с последними сообщениями
        chats = get_chat_list(current_user)

        for chat in chats:
            try:
                # Конвертируем время в московское
                timestamp = datetime.fromisoformat(chat['timestamp'])
                if not timestamp.tzinfo:
                    timestamp = pytz.UTC.localize(timestamp)
                moscow_time = timestamp.astimezone(pytz.timezone('Europe/Moscow'))
                time_str = moscow_time.strftime("%H:%M")

                if chat['sender'] == current_user:
                    # Для отправленных сообщений показываем оригинальный текст
                    if chat['is_file']:
                        preview = f"📎 {chat['filename']}"
                    else:
                        # Используем original_content, если доступно
                        if chat['original_content']:
                            preview = chat['original_content'][:50] + "..." if len(chat['original_content']) > 50 else chat['original_content']
                        else:
                            # Если нет original_content, пытаемся расшифровать
                            _, private_key = get_user_keys(current_user)
                            if private_key:
                                try:
                                    decrypted = crypto_manager.decrypt_message(chat['encrypted_data'], private_key)
                                    preview = decrypted.decode('utf-8', errors='replace')[:50] + "..." if len(decrypted) > 50 else decrypted.decode('utf-8', errors='replace')
                                except Exception as e:
                                    preview = "[ошибка расшифровки сообщения]"
                            else:
                                preview = "[сообщение недоступно]"
                else:
                    # Для полученных сообщений расшифровываем
                    _, private_key = get_user_keys(current_user)
                    if not private_key:
                        chat_list.insert("", "end",
                            values=(chat['chat_with'], "[не удалось получить ключ]", time_str))
                        continue

                    try:
                        # Расшифровываем сообщение
                        decrypted_data = crypto_manager.decrypt_message(
                            chat['encrypted_data'],
                            private_key
                        )

                        if chat['is_file']:
                            preview = f"📎 {chat['filename']}"
                        else:
                            preview = decrypted_data.decode('utf-8', errors='replace')[:50] + "..." if len(decrypted_data) > 50 else decrypted_data.decode('utf-8', errors='replace')

                    except Exception as e:
                        preview = f"[ошибка расшифровки: {str(e)}]"

                chat_list.insert("", "end",
                    values=(chat['chat_with'], preview, time_str))
            except Exception as e:
                chat_list.insert("", "end",
                    values=(chat['chat_with'], f"[ошибка обработки сообщения: {str(e)}]", ""))

        # Восстанавливаем выделение
        if current_selection:
            for item in chat_list.get_children():
                if chat_list.item(item)['values'][0] == current_selection:
                    chat_list.selection_set(item)
                    break

    def start_new_chat():
        def search_users():
            search_query = search_entry.get().lower()
            users_list.delete(0, tk.END)
            all_users = get_all_users()
            for user in all_users:
                if user != current_user and search_query in user.lower():
                    users_list.insert(tk.END, user)

        def select_user():
            selection = users_list.curselection()
            if selection:
                selected_user = users_list.get(selection[0])
                search_window.destroy()
                global selected_chat
                selected_chat = selected_user
                refresh_chat()
                refresh_chat_list()

        # Создаем окно поиска
        search_window = tk.Toplevel()
        search_window.title("Новый чат")
        search_window.geometry("300x400")
        
        # Поле поиска
        search_frame = ttk.Frame(search_window)
        search_frame.pack(fill=tk.X, padx=5, pady=5)
        
        search_entry = ttk.Entry(search_frame)
        search_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        ttk.Button(search_frame, text="🔍", command=search_users).pack(side=tk.LEFT, padx=2)
        
        # Список пользователей
        users_list = tk.Listbox(search_window)
        users_list.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Кнопка выбора пользователя
        ttk.Button(search_window, text="Начать чат", command=select_user).pack(pady=5)
        
        # Заполняем список всеми пользователями изначально
        search_users()
        
        # Делаем окно модальным
        search_window.transient(root)
        search_window.grab_set()
        search_window.focus_set()

    # Создание главного окна
    root = tk.Tk()
    root.title(f"Мессенджер - {current_user}")
    root.geometry("800x600")

    # Создаем фреймы
    left_frame = ttk.Frame(root)
    left_frame.pack(side=tk.LEFT, fill=tk.Y, padx=5, pady=5)
    
    right_frame = ttk.Frame(root)
    right_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5, pady=5)

    # Добавляем кнопку нового чата и поиск в верхней части левого фрейма
    top_frame = ttk.Frame(left_frame)
    top_frame.pack(fill=tk.X, pady=(0, 5))
    
    ttk.Button(top_frame, text="✏️ Новый чат", command=start_new_chat).pack(fill=tk.X)
    
    # Добавляем заголовок чата
    chat_header = ttk.Frame(right_frame)
    chat_header.pack(fill=tk.X, pady=(0, 5))
    
    chat_title = ttk.Label(chat_header, text="", font=("Arial", 12, "bold"))
    chat_title.pack(side=tk.LEFT, padx=5)

    # Список чатов (слева)
    chat_list = ttk.Treeview(left_frame, columns=("user", "preview", "time"), show="headings", height=20)
    chat_list.heading("user", text="Пользователь")
    chat_list.heading("preview", text="Последнее сообщение")
    chat_list.heading("time", text="Время")
    
    chat_list.column("user", width=100)
    chat_list.column("preview", width=200)
    chat_list.column("time", width=50)
    
    chat_list.pack(fill=tk.BOTH, expand=True)
    chat_list.bind("<<TreeviewSelect>>", on_chat_selected)

    # Область чата (справа)
    chat_content = tk.Text(right_frame, wrap=tk.WORD)
    chat_content.pack(fill=tk.BOTH, expand=True)
    
    # Панель ввода сообщения
    input_frame = ttk.Frame(right_frame)
    input_frame.pack(fill=tk.X, pady=5)
    
    entry_message = ttk.Entry(input_frame)
    entry_message.pack(side=tk.LEFT, fill=tk.X, expand=True)
    
    ttk.Button(input_frame, text="📎", command=send_file).pack(side=tk.LEFT, padx=2)
    ttk.Button(input_frame, text="Отправить", command=send_message).pack(side=tk.LEFT, padx=2)

    # Инициализация
    refresh_chat_list()

    # Запускаем периодическое обновление
    def periodic_refresh():
        refresh_chat_list()
        root.after(5000, periodic_refresh)  # Обновление каждые 5 секунд
    
    periodic_refresh()
    root.mainloop()

if __name__ == "__main__":
    print("Запуск графического интерфейса...")
    login_window()