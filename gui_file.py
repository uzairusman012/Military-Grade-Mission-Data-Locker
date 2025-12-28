import customtkinter as ctk
from tkinter import messagebox, Canvas
import os
import json
from datetime import datetime
import pyotp
import random
import math
from argon2 import PasswordHasher
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hmac

# Initialize password hasher
ph = PasswordHasher()

# ===================== BACKEND FUNCTIONS =====================

def derive_key(password, salt=b'my_fixed_salt'):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    return kdf.derive(password.encode())

def generate_totp_code(secret):
    totp = pyotp.TOTP(secret)
    return totp.now()

def log_action(username, action, filename, success):
    os.makedirs("logs", exist_ok=True)
    log_entry = {
        "timestamp": datetime.now().isoformat(),
        "username": username or "ANONYMOUS",
        "action": action,
        "filename": filename,
        "success": success
    }
    with open("logs/audit.log", "a") as f:
        f.write(json.dumps(log_entry) + "\n")

def encrypt_file(file_path, key, username):
    try:
        with open(file_path, "rb") as f:
            original_data = f.read()
        
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        
        while len(original_data) % 16 != 0:
            original_data += b' '
        
        encrypted_data = encryptor.update(original_data) + encryptor.finalize()
        
        h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
        h.update(iv + encrypted_data)
        hmac_value = h.finalize()
        
        encrypted_filename = f"storage/encrypted_{os.path.basename(file_path)}"
        with open(encrypted_filename, "wb") as f:
            f.write(iv + encrypted_data + hmac_value)
        
        log_action(username, "encrypt", file_path, True)
        return True, encrypted_filename
    except Exception as e:
        log_action(username, "encrypt", file_path, False)
        return False, str(e)

def decrypt_file(encrypted_path, key, username):
    try:
        with open(encrypted_path, "rb") as f:
            data = f.read()
        
        iv = data[:16]
        hmac_value = data[-32:]
        encrypted_data = data[16:-32]
        
        h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
        h.update(iv + encrypted_data)
        h.verify(hmac_value)
        
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        
        decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()
        decrypted_data = decrypted_data.rstrip(b' ')
        
        output_filename = f"decrypted_{os.path.basename(encrypted_path)[10:]}"
        with open(output_filename, "wb") as f:
            f.write(decrypted_data)
        
        log_action(username, "decrypt", encrypted_path, True)
        return True, output_filename, decrypted_data
    except Exception as e:
        log_action(username, "decrypt", encrypted_path, False)
        return False, str(e), None

PERMISSIONS = {
    "Commander": {"encrypt": True, "decrypt": True, "delete": True},
    "Pilot": {"encrypt": False, "decrypt": True, "delete": False},
    "Analyst": {"encrypt": False, "decrypt": True, "delete": False},
    "Technician": {"encrypt": False, "decrypt": False, "delete": False},
}

def check_permission(role, action):
    return PERMISSIONS.get(role, {}).get(action, False)

# ===================== ANIMATION HELPERS =====================

def animate_fade_in(widget, start_alpha=0.0, end_alpha=1.0, steps=10, delay=20):
    """Fade in animation for widgets"""
    def fade_step(current_step):
        if current_step <= steps:
            alpha = start_alpha + (end_alpha - start_alpha) * (current_step / steps)
            try:
                widget.attributes('-alpha', alpha)
                widget.after(delay, lambda: fade_step(current_step + 1))
            except:
                pass
    
    try:
        widget.attributes('-alpha', start_alpha)
        fade_step(0)
    except:
        pass

def animate_slide_in(window, direction='down', distance=30, steps=12, delay=15):
    """Slide in animation for windows"""
    def slide_step(current_step):
        if current_step <= steps:
            try:
                progress = current_step / steps
                # Ease-out effect
                progress = 1 - (1 - progress) ** 3
                
                if direction == 'down':
                    offset = int(distance * (1 - progress))
                    window.geometry(f"+{start_x}+{start_y + offset}")
                elif direction == 'up':
                    offset = int(distance * (1 - progress))
                    window.geometry(f"+{start_x}+{start_y - offset}")
                
                window.after(delay, lambda: slide_step(current_step + 1))
            except:
                pass
    
    try:
        window.update_idletasks()
        start_x = window.winfo_x()
        start_y = window.winfo_y()
        
        if direction == 'down':
            window.geometry(f"+{start_x}+{start_y - distance}")
        elif direction == 'up':
            window.geometry(f"+{start_x}+{start_y + distance}")
        
        window.after(10, lambda: slide_step(0))
    except:
        pass

# ===================== OPTIMIZED ANIMATED BACKGROUND =====================

class OptimizedBackground:
    def __init__(self, canvas, width, height):
        self.canvas = canvas
        self.width = width
        self.height = height
        self.particles = []
        self.lines = []
        self.is_animating = True
        self.init_particles()
        self.animate()
    
    def init_particles(self):
        for _ in range(40):
            x = random.randint(0, self.width)
            y = random.randint(0, self.height)
            vx = random.uniform(-0.3, 0.3)
            vy = random.uniform(-0.3, 0.3)
            size = random.randint(2, 3)
            self.particles.append({
                'x': x, 'y': y, 'vx': vx, 'vy': vy,
                'size': size,
                'id': self.canvas.create_oval(x, y, x+size, y+size, 
                                              fill='#00ff00', outline='', tags='particle')
            })
    
    def animate(self):
        if not self.is_animating:
            return
            
        for p in self.particles:
            p['x'] += p['vx']
            p['y'] += p['vy']
            
            if p['x'] < 0 or p['x'] > self.width:
                p['vx'] *= -1
            if p['y'] < 0 or p['y'] > self.height:
                p['vy'] *= -1
            
            self.canvas.coords(p['id'], p['x'], p['y'], 
                             p['x']+p['size'], p['y']+p['size'])
        
        self.canvas.delete('line')
        
        for i, p1 in enumerate(self.particles):
            for p2 in self.particles[i+1:i+5]:
                dist = math.sqrt((p1['x']-p2['x'])**2 + (p1['y']-p2['y'])**2)
                if dist < 120:
                    opacity = int((1 - dist/120) * 40)
                    color = f'#{0:02x}{opacity:02x}{0:02x}'
                    self.canvas.create_line(
                        p1['x'], p1['y'], p2['x'], p2['y'],
                        fill=color, width=1, tags='line'
                    )
        
        if self.is_animating:
            self.canvas.after(50, self.animate)
    
    def resize(self, width, height):
        self.width = width
        self.height = height
    
    def stop(self):
        self.is_animating = False

# ===================== SELECTABLE CODE DISPLAY =====================

class SelectableCodeDisplay(ctk.CTkTextbox):
    """A selectable and copyable code display widget"""
    def __init__(self, master, code_text="", **kwargs):
        default_kwargs = {
            'font': ("Courier", 24, "bold"),
            'fg_color': "transparent",
            'border_width': 0,
            'height': 60,
            'wrap': "none"
        }
        default_kwargs.update(kwargs)
        
        super().__init__(master, **default_kwargs)
        
        if code_text:
            self.insert("1.0", code_text)
        
        self.configure(state="disabled")
        
        # Enable selection
        self.bind('<Button-1>', lambda e: self.configure(state="normal"))
        self.bind('<ButtonRelease-1>', lambda e: self.after(10, lambda: self.configure(state="disabled")))
        
        # Context menu
        self.bind('<Button-3>', self.show_context_menu)
    
    def show_context_menu(self, event):
        """Show right-click context menu"""
        menu = ctk.CTkToplevel(self)
        menu.overrideredirect(True)
        menu.geometry(f"+{event.x_root}+{event.y_root}")
        
        copy_btn = ctk.CTkButton(menu, text="📋 Copy", width=120, height=35,
                                command=lambda: [self.copy_to_clipboard(), menu.destroy()],
                                fg_color="#2d6a3e", hover_color="#1a472a")
        copy_btn.pack(padx=5, pady=5)
        
        menu.bind('<FocusOut>', lambda e: menu.destroy())
        menu.focus_set()
    
    def copy_to_clipboard(self):
        """Copy content to clipboard"""
        try:
            text = self.get("1.0", "end-1c")
            self.master.clipboard_clear()
            self.master.clipboard_append(text)
            
            original_fg = self.cget("fg_color")
            self.configure(fg_color="#1a472a")
            self.after(300, lambda: self.configure(fg_color=original_fg))
        except:
            pass
    
    def update_code(self, new_code):
        """Update the displayed code"""
        self.configure(state="normal")
        self.delete("1.0", "end")
        self.insert("1.0", new_code)
        self.configure(state="disabled")

# ===================== SMOOTH ANIMATED BUTTON =====================

class SmoothButton(ctk.CTkButton):
    def __init__(self, master, **kwargs):
        super().__init__(master, **kwargs)
        self.bind('<Enter>', self.on_enter)
        self.bind('<Leave>', self.on_leave)
    
    def on_enter(self, e):
        self.configure(cursor="hand2")
    
    def on_leave(self, e):
        self.configure(cursor="")

# ===================== LOADING ANIMATION =====================

class LoadingAnimation:
    def __init__(self, parent, text="Processing..."):
        self.window = ctk.CTkToplevel(parent)
        self.window.title("")
        self.window.geometry("300x150")
        self.window.resizable(False, False)
        self.window.transient(parent)
        self.window.grab_set()
        
        self.window.update_idletasks()
        x = (self.window.winfo_screenwidth() // 2) - 150
        y = (self.window.winfo_screenheight() // 2) - 75
        self.window.geometry(f"+{x}+{y}")
        
        animate_fade_in(self.window, 0.0, 1.0, steps=8, delay=15)
        
        self.label = ctk.CTkLabel(self.window, text=text, 
                                 font=("Arial", 16, "bold"))
        self.label.pack(pady=30)
        
        self.progress = ctk.CTkProgressBar(self.window, width=250)
        self.progress.pack(pady=20)
        self.progress.set(0)
        
        self.animate_progress()
    
    def animate_progress(self):
        current = self.progress.get()
        if current < 1:
            self.progress.set(current + 0.1)
            self.window.after(50, self.animate_progress)
    
    def close(self):
        self.window.destroy()

# ===================== GUI APPLICATION =====================

class MilitaryDataLockerGUI:
    def __init__(self):
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("green")
        
        self.window = ctk.CTk()
        self.window.title("🔐 Military Grade Mission Data Locker")
        
        screen_width = self.window.winfo_screenwidth()
        screen_height = self.window.winfo_screenheight()
        
        window_width = int(screen_width * 0.8)
        window_height = int(screen_height * 0.8)
        
        x = (screen_width - window_width) // 2
        y = (screen_height - window_height) // 2
        
        self.window.geometry(f"{window_width}x{window_height}+{x}+{y}")
        self.window.minsize(1000, 700)
        
        self.logged_in_user = None
        self.current_frame = None
        self.background_canvas = None
        self.animated_bg = None
        
        os.makedirs("users", exist_ok=True)
        os.makedirs("mission_files", exist_ok=True)
        os.makedirs("storage", exist_ok=True)
        os.makedirs("logs", exist_ok=True)
        
        self.window.bind('<Configure>', self.on_resize)
        
        self.show_login_screen()
    
    def on_resize(self, event):
        if self.animated_bg and event.widget == self.window:
            width = event.width
            height = event.height
            if self.background_canvas:
                self.animated_bg.resize(width, height)
    
    def create_animated_background(self, parent):
        if self.background_canvas:
            try:
                self.animated_bg.stop()
            except:
                pass
            self.background_canvas.destroy()
        
        self.background_canvas = Canvas(parent, bg='#0a0a0a', highlightthickness=0)
        self.background_canvas.place(x=0, y=0, relwidth=1, relheight=1)
        
        width = parent.winfo_width() or 1000
        height = parent.winfo_height() or 700
        
        self.animated_bg = OptimizedBackground(self.background_canvas, width, height)
    
    def clear_frame(self):
        if self.animated_bg:
            self.animated_bg.stop()
            self.animated_bg = None
        
        if self.background_canvas:
            self.background_canvas.destroy()
            self.background_canvas = None
        
        if self.current_frame:
            self.current_frame.destroy()
            self.current_frame = None
    
    def show_login_screen(self):
        self.clear_frame()
        
        self.current_frame = ctk.CTkFrame(self.window, fg_color="#0a0a0a")
        self.current_frame.pack(fill="both", expand=True)
        
        self.create_animated_background(self.current_frame)
        self.window.update_idletasks()
        
        # Scrollable container
        scroll_container = ctk.CTkScrollableFrame(self.current_frame, fg_color="transparent")
        scroll_container.pack(fill="both", expand=True, padx=50, pady=50)
        
        content = ctk.CTkFrame(scroll_container, fg_color="#1a1a1a", 
                           corner_radius=20, border_width=2, border_color="#2d6a3e")
        content.pack(pady=20, padx=20, fill="both", expand=True)
        content.pack_configure(ipadx=50, ipady=30)
        
        # Header
        title = ctk.CTkLabel(content, text="🔐 MILITARY GRADE", 
                         font=("Arial Black", 28, "bold"), text_color="#00ff00")
        title.pack(pady=(25, 5))

        subtitle = ctk.CTkLabel(content, text="MISSION DATA LOCKER", 
                               font=("Arial Black", 32, "bold"))
        subtitle.pack(pady=5)
        
        security_label = ctk.CTkLabel(content, text="━━━ SECURE AUTHENTICATION REQUIRED ━━━", 
                                     font=("Courier", 13), text_color="#00ff00")
        security_label.pack(pady=12)
        
        # Login Form
        form_frame = ctk.CTkFrame(content, fg_color="transparent")
        form_frame.pack(pady=15, padx=50, fill="both", expand=True)
        
        ctk.CTkLabel(form_frame, text="🔑 SYSTEM LOGIN", 
                    font=("Arial", 22, "bold")).pack(pady=12)
        
        # Username
        user_frame = ctk.CTkFrame(form_frame, fg_color="#2a2a2a", corner_radius=10)
        user_frame.pack(pady=8, fill="x")
        
        ctk.CTkLabel(user_frame, text="👤", font=("Arial", 20)).pack(side="left", padx=12)
        self.login_username = ctk.CTkEntry(user_frame, placeholder_text="Username",
                                           font=("Arial", 14), border_width=0,
                                           fg_color="transparent", height=40)
        self.login_username.pack(side="left", fill="both", expand=True, padx=5, pady=10)
        
        # Password
        pass_frame = ctk.CTkFrame(form_frame, fg_color="#2a2a2a", corner_radius=10)
        pass_frame.pack(pady=8, fill="x")
        
        ctk.CTkLabel(pass_frame, text="🔒", font=("Arial", 20)).pack(side="left", padx=12)
        self.login_password = ctk.CTkEntry(pass_frame, placeholder_text="Password",
                                           show="●", font=("Arial", 14), border_width=0,
                                           fg_color="transparent", height=40)
        self.login_password.pack(side="left", fill="both", expand=True, padx=5, pady=10)
        
        # TOTP
        totp_frame = ctk.CTkFrame(form_frame, fg_color="#2a2a2a", corner_radius=10)
        totp_frame.pack(pady=8, fill="x")
        
        ctk.CTkLabel(totp_frame, text="🔐", font=("Arial", 20)).pack(side="left", padx=12)
        self.login_totp = ctk.CTkEntry(totp_frame, placeholder_text="2FA Code (6 digits)",
                                       font=("Arial", 14), border_width=0,
                                       fg_color="transparent", height=40)
        self.login_totp.pack(side="left", fill="both", expand=True, padx=5, pady=10)
        
        # Buttons
        btn_frame = ctk.CTkFrame(form_frame, fg_color="transparent")
        btn_frame.pack(pady=20)
        
        SmoothButton(btn_frame, text="🚀 ACCESS SYSTEM", 
                     command=self.login_user,
                     width=200, height=50, font=("Arial", 15, "bold"),
                     fg_color="#2d6a3e", hover_color="#1a472a",
                     corner_radius=12).pack(side="left", padx=8)
        
        SmoothButton(btn_frame, text="📝 NEW USER", 
                     command=self.show_register_screen,
                     width=200, height=50, font=("Arial", 15, "bold"),
                     fg_color="#4a4a4a", hover_color="#2d2d2d",
                     corner_radius=12).pack(side="left", padx=8)
        
        # TOTP Generator
        totp_gen_frame = ctk.CTkFrame(form_frame, fg_color="transparent")
        totp_gen_frame.pack(pady=8)
        
        SmoothButton(totp_gen_frame, text="🔑 Generate 2FA Code", 
                     command=self.show_pre_login_totp_generator,
                     width=420, height=40, font=("Arial", 13, "bold"),
                     fg_color="#6a2d6a", hover_color="#4a1a4a",
                     corner_radius=10).pack()
        
        ctk.CTkLabel(totp_gen_frame, text="(Need a 2FA code for login? Click here)", 
                    font=("Arial", 10), text_color="gray").pack(pady=(3,0))
        
        # Footer
        ctk.CTkLabel(content, text="⚠️ Unauthorized access is prohibited",
                    font=("Courier", 11), text_color="#ff6b6b").pack(side="bottom", pady=15)
    
    def show_register_screen(self):
        self.clear_frame()
        
        self.current_frame = ctk.CTkFrame(self.window, fg_color="#0a0a0a")
        self.current_frame.pack(fill="both", expand=True)
        
        self.create_animated_background(self.current_frame)
        self.window.update_idletasks()
        
        scroll_container = ctk.CTkScrollableFrame(self.current_frame, fg_color="transparent")
        scroll_container.pack(fill="both", expand=True, padx=50, pady=50)
        
        content = ctk.CTkFrame(scroll_container, fg_color="#1a1a1a", corner_radius=20,
                              border_width=2, border_color="#2d6a3e")
        content.pack(pady=20, padx=20, fill="both", expand=True)
        content.pack_configure(ipadx=50, ipady=30)
        
        # Header
        header = ctk.CTkFrame(content, fg_color="#1a472a", corner_radius=15)
        header.pack(fill="x", padx=30, pady=25)
        
        ctk.CTkLabel(header, text="📝 NEW USER REGISTRATION", 
                    font=("Arial Black", 24, "bold"),
                    text_color="#00ff00").pack(pady=15)
        
        ctk.CTkLabel(header, text="━━━ CREATE SECURE CREDENTIALS ━━━", 
                    font=("Courier", 11), text_color="#00ff00").pack(pady=(0,12))
        
        form_frame = ctk.CTkFrame(content, fg_color="transparent")
        form_frame.pack(pady=20, padx=50, fill="both", expand=True)
        
        # Username
        user_frame = ctk.CTkFrame(form_frame, fg_color="#2a2a2a", corner_radius=10)
        user_frame.pack(pady=10, fill="x")
        
        ctk.CTkLabel(user_frame, text="👤 USERNAME:", 
                    font=("Arial", 13, "bold")).pack(anchor="w", padx=15, pady=(10,0))
        self.reg_username = ctk.CTkEntry(user_frame, placeholder_text="Enter unique username",
                                        font=("Arial", 13), border_width=0,
                                        fg_color="transparent", height=38)
        self.reg_username.pack(fill="x", padx=15, pady=(5,12))
        
        # Password
        pass_frame = ctk.CTkFrame(form_frame, fg_color="#2a2a2a", corner_radius=10)
        pass_frame.pack(pady=10, fill="x")
        
        ctk.CTkLabel(pass_frame, text="🔒 PASSWORD:", 
                    font=("Arial", 13, "bold")).pack(anchor="w", padx=15, pady=(10,0))
        self.reg_password = ctk.CTkEntry(pass_frame, placeholder_text="Strong password required",
                                        show="●", font=("Arial", 13), border_width=0,
                                        fg_color="transparent", height=38)
        self.reg_password.pack(fill="x", padx=15, pady=(5,12))
        
        # Role
        role_frame = ctk.CTkFrame(form_frame, fg_color="#2a2a2a", corner_radius=10)
        role_frame.pack(pady=10, fill="x")
        
        ctk.CTkLabel(role_frame, text="🎖️ SECURITY CLEARANCE:", 
                    font=("Arial", 13, "bold")).pack(anchor="w", padx=15, pady=(10,0))
        self.reg_role = ctk.CTkComboBox(role_frame,
                                        values=["Commander", "Pilot", "Analyst", "Technician"],
                                        font=("Arial", 13), border_width=0,
                                        fg_color="#1a1a1a", button_color="#2d6a3e",
                                        button_hover_color="#1a472a", height=38,
                                        state="readonly")
        self.reg_role.set("Select Clearance Level")
        self.reg_role.pack(fill="x", padx=15, pady=(5,12))
        
        # Buttons
        btn_frame = ctk.CTkFrame(form_frame, fg_color="transparent")
        btn_frame.pack(pady=25)
        
        SmoothButton(btn_frame, text="✅ CREATE ACCOUNT", 
                      command=self.register_user,
                      width=200, height=50, font=("Arial", 14, "bold"),
                      fg_color="#2d6a3e", hover_color="#1a472a",
                      corner_radius=12).pack(side="left", padx=8)
        
        SmoothButton(btn_frame, text="⬅️ BACK TO LOGIN", 
                      command=self.show_login_screen,
                      width=200, height=50, font=("Arial", 14, "bold"),
                      fg_color="#4a4a4a", hover_color="#2d2d2d",
                      corner_radius=12).pack(side="left", padx=8)
    
    def register_user(self):
        username = self.reg_username.get().strip()
        password = self.reg_password.get()
        role = self.reg_role.get()
        
        if not username or not password or role == "Select Clearance Level":
            messagebox.showerror("❌ Error", "All fields are required!")
            return
        
        if os.path.exists(f"users/{username}.json"):
            messagebox.showerror("❌ Error", "Username already exists!")
            return
        
        loading = LoadingAnimation(self.window, "Creating secure account...")
        self.window.update()
        
        try:
            password_hash = ph.hash(password)
            totp_secret = pyotp.random_base32()
            
            user_data = {
                "username": username,
                "role": role,
                "password_hash": password_hash,
                "totp_secret": totp_secret
            }
            
            with open(f"users/{username}.json", "w") as f:
                json.dump(user_data, f)
            
            loading.close()
            
            # Show TOTP secret
            result_window = ctk.CTkToplevel(self.window)
            result_window.title("✅ Registration Successful")
            result_window.geometry("650x600")
            result_window.resizable(False, False)
            result_window.grab_set()
            
            result_window.update_idletasks()
            x = (result_window.winfo_screenwidth() // 2) - 325
            y = (result_window.winfo_screenheight() // 2) - 300
            result_window.geometry(f"+{x}+{y}")
            
            animate_fade_in(result_window)
            animate_slide_in(result_window, 'down', 30)
            
            # Header
            header = ctk.CTkFrame(result_window, fg_color="#1a472a", corner_radius=0)
            header.pack(fill="x")
            
            ctk.CTkLabel(header, text="✅ ACCOUNT CREATED!", 
                        font=("Arial Black", 22, "bold"),
                        text_color="#00ff00").pack(pady=25)
            
            info_frame = ctk.CTkFrame(result_window, fg_color="#2a2a2a")
            info_frame.pack(pady=25, padx=35, fill="both", expand=True)
            
            # User info
            info_box = ctk.CTkFrame(info_frame, fg_color="#1a1a1a", corner_radius=10)
            info_box.pack(pady=15, padx=25, fill="x")
            
            ctk.CTkLabel(info_box, text=f"👤 Username: {username}", 
                        font=("Arial", 15, "bold"), anchor="w").pack(pady=10, padx=18, fill="x")
            ctk.CTkLabel(info_box, text=f"🎖️ Role: {role}", 
                        font=("Arial", 15, "bold"), anchor="w").pack(pady=10, padx=18, fill="x")
            
            # TOTP Secret - SELECTABLE
            ctk.CTkLabel(info_frame, text="⚠️ SAVE YOUR 2FA SECRET", 
                        font=("Arial", 16, "bold"), text_color="#ff6b6b").pack(pady=15)
            
            ctk.CTkLabel(info_frame, text="(Select and copy with Ctrl+C or right-click)", 
                        font=("Arial", 11), text_color="gray").pack(pady=3)
            
            secret_box = ctk.CTkFrame(info_frame, fg_color="#1a472a", corner_radius=10)
            secret_box.pack(pady=10, padx=25, fill="x")
            
            secret_display = SelectableCodeDisplay(secret_box, code_text=totp_secret,
                                                   font=("Courier", 16, "bold"), height=50)
            secret_display.pack(pady=15, padx=20, fill="x")
            
            # Current TOTP - SELECTABLE
            current_code = generate_totp_code(totp_secret)
            
            code_frame = ctk.CTkFrame(info_frame, fg_color="#1a1a1a", corner_radius=10)
            code_frame.pack(pady=10, padx=25, fill="x")
            
            ctk.CTkLabel(code_frame, text="🔐 Current Login Code", 
                        font=("Arial", 13)).pack(pady=(12,5))
            
            code_display = SelectableCodeDisplay(code_frame, code_text=current_code,
                                                 font=("Arial", 28, "bold"), height=50)
            code_display.pack(pady=(0,15), padx=20, fill="x")
            
            SmoothButton(result_window, text="🎯 PROCEED TO LOGIN", 
                         command=lambda: [result_window.destroy(), self.show_login_screen()],
                         width=280, height=55, font=("Arial", 15, "bold"),
                         fg_color="#2d6a3e", hover_color="#1a472a",
                         corner_radius=12).pack(pady=25)
            
        except Exception as e:
            if 'loading' in locals():
                loading.close()
            messagebox.showerror("❌ Error", f"Registration failed: {str(e)}")
    
    def login_user(self):
        username = self.login_username.get().strip()
        password = self.login_password.get()
        totp_code = self.login_totp.get().strip()
        
        if not username or not password or not totp_code:
            messagebox.showerror("❌ Error", "All fields are required!")
            return
        
        loading = LoadingAnimation(self.window, "Authenticating...")
        self.window.update()
        
        try:
            with open(f"users/{username}.json", "r") as f:
                user_data = json.load(f)
            
            ph.verify(user_data["password_hash"], password)
            
            totp = pyotp.TOTP(user_data["totp_secret"])
            if not totp.verify(totp_code, valid_window=1):
                loading.close()
                messagebox.showerror("❌ Error", "Invalid 2FA code!")
                log_action(username, "login", "system", False)
                return
            
            loading.close()
            
            self.logged_in_user = user_data
            log_action(username, "login", "system", True)
            
            # Success message
            success_window = ctk.CTkToplevel(self.window)
            success_window.title("✅ Access Granted")
            success_window.geometry("450x300")
            success_window.resizable(False, False)
            success_window.transient(self.window)
            
            success_window.update_idletasks()
            x = (success_window.winfo_screenwidth() // 2) - 225
            y = (success_window.winfo_screenheight() // 2) - 150
            success_window.geometry(f"+{x}+{y}")
            
            animate_fade_in(success_window)
            animate_slide_in(success_window, 'down', 30)
            
            ctk.CTkFrame(success_window, fg_color="#2d6a3e", height=12).pack(fill="x")
            
            ctk.CTkLabel(success_window, text="✅", 
                        font=("Arial", 70)).pack(pady=25)
            ctk.CTkLabel(success_window, text="ACCESS GRANTED", 
                        font=("Arial Black", 22, "bold"),
                        text_color="#00ff00").pack(pady=12)
            ctk.CTkLabel(success_window, text=f"Welcome, {username}!", 
                        font=("Arial", 16)).pack(pady=8)
            ctk.CTkLabel(success_window, text=f"Clearance: {user_data['role']}", 
                        font=("Arial", 14, "bold")).pack(pady=8)
            
            def proceed():
                success_window.destroy()
                self.show_dashboard()
            
            success_window.after(2000, proceed)
            
        except FileNotFoundError:
            loading.close()
            messagebox.showerror("❌ Error", "User not found!")
            log_action(username, "login", "system", False)
        except Exception as e:
            loading.close()
            messagebox.showerror("❌ Error", "Authentication failed!")
            log_action(username, "login", "system", False)
    
    def show_dashboard(self):
        self.clear_frame()
        
        self.current_frame = ctk.CTkFrame(self.window, fg_color="#0a0a0a")
        self.current_frame.pack(fill="both", expand=True)
        
        self.create_animated_background(self.current_frame)
        self.window.update_idletasks()
        
        main_container = ctk.CTkFrame(self.current_frame, fg_color="transparent")
        main_container.pack(fill="both", expand=True, padx=30, pady=30)
        
        # Header
        header = ctk.CTkFrame(main_container, fg_color="#1a472a", corner_radius=15, height=110)
        header.pack(fill="x", pady=(0, 25))
        header.pack_propagate(False)
        
        header_content = ctk.CTkFrame(header, fg_color="transparent")
        header_content.pack(fill="both", expand=True, padx=35, pady=18)
        
        title_frame = ctk.CTkFrame(header_content, fg_color="transparent")
        title_frame.pack(side="left", fill="y")
        
        ctk.CTkLabel(title_frame, text="🎯 MISSION CONTROL CENTER", 
                    font=("Arial Black", 32, "bold"),
                    text_color="#00ff00").pack(anchor="w")
        
        ctk.CTkLabel(title_frame, text="━━━ SECURE OPERATIONS DASHBOARD ━━━", 
                    font=("Courier", 12), text_color="#00ff00").pack(anchor="w", pady=(8,0))
        
        user_frame = ctk.CTkFrame(header_content, fg_color="#2a2a2a", corner_radius=12)
        user_frame.pack(side="right", padx=12)
        
        ctk.CTkLabel(user_frame, 
                    text=f"👤 {self.logged_in_user['username']}", 
                    font=("Arial", 16, "bold")).pack(side="top", padx=25, pady=(12,3))
        
        ctk.CTkLabel(user_frame, 
                    text=f"🎖️ {self.logged_in_user['role']}", 
                    font=("Arial", 13), text_color="#00ff00").pack(side="top", padx=25, pady=(0,12))
        
        # Content area
        content = ctk.CTkFrame(main_container, fg_color="transparent")
        content.pack(fill="both", expand=True)
        
        # Left panel
        left_panel = ctk.CTkFrame(content, fg_color="#1a1a1a", corner_radius=15)
        left_panel.pack(side="left", fill="both", expand=True, padx=(0, 12))
        
        ops_header = ctk.CTkFrame(left_panel, fg_color="#2a2a2a", corner_radius=12)
        ops_header.pack(fill="x", padx=18, pady=18)
        
        ctk.CTkLabel(ops_header, text="⚡ ACTIVE OPERATIONS", 
                    font=("Arial Black", 22, "bold")).pack(pady=15)
        
        ops_scroll = ctk.CTkScrollableFrame(left_panel, fg_color="transparent")
        ops_scroll.pack(fill="both", expand=True, padx=18, pady=(0,18))
        
        # Operations buttons
        operations = []
        
        if check_permission(self.logged_in_user['role'], 'encrypt'):
            operations.append(("📝", "CREATE & ENCRYPT FILE", "Generate and secure mission files",
                             "#2d6a3e", "#1a472a", self.show_encrypt_screen))
        
        if check_permission(self.logged_in_user['role'], 'decrypt'):
            operations.append(("🔓", "DECRYPT FILE", "Access encrypted mission data",
                             "#4a6a8a", "#2d4a6a", self.show_decrypt_screen))
        
        operations.extend([
            ("📊", "AUDIT LOGS", "Review system activity logs",
             "#6a4a2d", "#4a2d1a", self.show_audit_logs),
            ("🔑", "TOTP GENERATOR", "Generate 2FA authentication codes",
             "#6a2d6a", "#4a1a4a", self.show_totp_generator)
        ])
        
        for icon, title, desc, fg, hover, cmd in operations:
            btn_container = ctk.CTkFrame(ops_scroll, fg_color="#2a2a2a", corner_radius=12)
            btn_container.pack(fill="x", pady=10)
            
            icon_label = ctk.CTkLabel(btn_container, text=icon, font=("Arial", 35))
            icon_label.pack(side="left", padx=20, pady=18)
            
            text_frame = ctk.CTkFrame(btn_container, fg_color="transparent")
            text_frame.pack(side="left", fill="x", expand=True, pady=18)
            
            ctk.CTkLabel(text_frame, text=title, 
                        font=("Arial", 15, "bold"), anchor="w").pack(anchor="w")
            ctk.CTkLabel(text_frame, text=desc, 
                        font=("Arial", 11), text_color="gray", anchor="w").pack(anchor="w", pady=(3,0))
            
            SmoothButton(btn_container, text="LAUNCH ➤",
                          command=cmd,
                          width=130, height=50, font=("Arial", 13, "bold"),
                          fg_color=fg, hover_color=hover,
                          corner_radius=10).pack(side="right", padx=18, pady=12)
        
        # Right panel
        right_panel = ctk.CTkFrame(content, fg_color="#1a1a1a", corner_radius=15)
        right_panel.pack(side="right", fill="both", expand=True, padx=(12, 0))
        
        info_header = ctk.CTkFrame(right_panel, fg_color="#2a2a2a", corner_radius=12)
        info_header.pack(fill="x", padx=18, pady=18)
        
        ctk.CTkLabel(info_header, text="📋 SYSTEM STATUS", 
                    font=("Arial Black", 22, "bold")).pack(pady=15)
        
        info_scroll = ctk.CTkScrollableFrame(right_panel, fg_color="transparent")
        info_scroll.pack(fill="both", expand=True, padx=18, pady=(0,18))
        
        # Permissions
        perm_box = ctk.CTkFrame(info_scroll, fg_color="#2a2a2a", corner_radius=12)
        perm_box.pack(fill="x", pady=12)
        
        ctk.CTkLabel(perm_box, text="🔐 CLEARANCE PERMISSIONS", 
                    font=("Arial", 16, "bold")).pack(pady=15, padx=18, anchor="w")
        
        perms = PERMISSIONS.get(self.logged_in_user['role'], {})
        for action, allowed in perms.items():
            perm_item = ctk.CTkFrame(perm_box, fg_color="#1a1a1a", corner_radius=8)
            perm_item.pack(fill="x", padx=18, pady=6)
            
            status = "✅ GRANTED" if allowed else "❌ DENIED"
            color = "#00ff00" if allowed else "#ff6b6b"
            
            ctk.CTkLabel(perm_item, text=action.upper(), 
                        font=("Arial", 13, "bold"), anchor="w").pack(side="left", padx=12, pady=10)
            ctk.CTkLabel(perm_item, text=status, 
                        font=("Arial", 12, "bold"), text_color=color).pack(side="right", padx=12, pady=10)
        
        perm_box.pack_configure(pady=(0,12))
        
        # Storage stats
        sys_box = ctk.CTkFrame(info_scroll, fg_color="#2a2a2a", corner_radius=12)
        sys_box.pack(fill="x", pady=12)
        
        ctk.CTkLabel(sys_box, text="📂 STORAGE STATUS", 
                    font=("Arial", 16, "bold")).pack(pady=15, padx=18, anchor="w")
        
        try:
            encrypted_files = len([f for f in os.listdir("storage") if f.startswith("encrypted_")])
            mission_files = len([f for f in os.listdir("mission_files")])
            total_users = len([f for f in os.listdir("users") if f.endswith(".json")])
        except:
            encrypted_files = mission_files = total_users = 0
        
        stats = [
            ("🔒 Encrypted Files", encrypted_files, "#2d6a3e"),
            ("📝 Mission Files", mission_files, "#4a6a8a"),
            ("👥 Total Users", total_users, "#6a4a2d")
        ]
        
        for label, value, color in stats:
            stat_item = ctk.CTkFrame(sys_box, fg_color=color, corner_radius=8)
            stat_item.pack(fill="x", padx=18, pady=6)
            
            ctk.CTkLabel(stat_item, text=label, 
                        font=("Arial", 12), anchor="w").pack(side="left", padx=12, pady=10)
            ctk.CTkLabel(stat_item, text=str(value), 
                        font=("Arial", 18, "bold")).pack(side="right", padx=12, pady=10)
        
        # Security status
        security_box = ctk.CTkFrame(info_scroll, fg_color="#1a472a", corner_radius=12)
        security_box.pack(fill="x", pady=12)
        
        ctk.CTkLabel(security_box, text="🛡️ SECURITY: ACTIVE", 
                    font=("Arial", 14, "bold"), text_color="#00ff00").pack(pady=12)
        ctk.CTkLabel(security_box, text="All systems operational", 
                    font=("Arial", 11)).pack(pady=(0,12))
        
        # Logout
        SmoothButton(main_container, text="🚪 TERMINATE SESSION", 
                      command=self.logout,
                      width=280, height=55, font=("Arial", 16, "bold"),
                      fg_color="#8a2d2d", hover_color="#6a1a1a",
                      corner_radius=12).pack(pady=18)
    
    def show_encrypt_screen(self):
        encrypt_window = ctk.CTkToplevel(self.window)
        encrypt_window.title("📝 Create & Encrypt Mission File")
        
        # Get screen dimensions and set window size to 85% of screen height
        screen_height = encrypt_window.winfo_screenheight()
        window_height = int(screen_height * 0.85)
        encrypt_window.geometry(f"850x{window_height}")
        encrypt_window.grab_set()
        
        animate_fade_in(encrypt_window)
        animate_slide_in(encrypt_window, 'down', 30)
        
        # Header - Fixed at top
        header = ctk.CTkFrame(encrypt_window, fg_color="#1a472a", corner_radius=0)
        header.pack(fill="x", side="top")
        
        ctk.CTkLabel(header, text="📝 CREATE & ENCRYPT MISSION FILE", 
                    font=("Arial Black", 22, "bold"),
                    text_color="#00ff00").pack(pady=20)
        
        ctk.CTkLabel(header, text="━━━ SECURE FILE GENERATION ━━━", 
                    font=("Courier", 11), text_color="#00ff00").pack(pady=(0,15))
        
        # Scrollable content area
        scroll_content = ctk.CTkScrollableFrame(encrypt_window, fg_color="#2a2a2a")
        scroll_content.pack(fill="both", expand=True, padx=25, pady=(15,0))
        
        # Filename
        file_frame = ctk.CTkFrame(scroll_content, fg_color="#1a1a1a", corner_radius=12)
        file_frame.pack(fill="x", pady=10)
        
        ctk.CTkLabel(file_frame, text="📄 FILENAME:", 
                    font=("Arial", 13, "bold")).pack(anchor="w", padx=18, pady=(12,5))
        filename_entry = ctk.CTkEntry(file_frame, placeholder_text="mission_report.txt",
                                     font=("Arial", 13), border_width=0,
                                     fg_color="#2a2a2a", height=40)
        filename_entry.pack(fill="x", padx=18, pady=(0,12))
        filename_entry.insert(0, "mission_file.txt")
        
        # Content
        content_frame = ctk.CTkFrame(scroll_content, fg_color="#1a1a1a", corner_radius=12)
        content_frame.pack(fill="x", pady=10)
        
        ctk.CTkLabel(content_frame, text="📋 MISSION CONTENT:", 
                    font=("Arial", 13, "bold")).pack(anchor="w", padx=18, pady=(12,5))
        
        content_text = ctk.CTkTextbox(content_frame, font=("Consolas", 12),
                                     border_width=0, fg_color="#2a2a2a",
                                     wrap="word", height=250, 
                                     text_color="#00ff00",
                                     state="normal")
        content_text.pack(fill="x", padx=18, pady=(0,12))
        
        # Password
        pass_frame = ctk.CTkFrame(scroll_content, fg_color="#1a1a1a", corner_radius=12)
        pass_frame.pack(fill="x", pady=10)
        
        ctk.CTkLabel(pass_frame, text="🔒 ENCRYPTION PASSWORD:", 
                    font=("Arial", 13, "bold")).pack(anchor="w", padx=18, pady=(12,5))
        password_entry = ctk.CTkEntry(pass_frame, placeholder_text="Strong password",
                                     show="●", font=("Arial", 13), border_width=0,
                                     fg_color="#2a2a2a", height=40)
        password_entry.pack(fill="x", padx=18, pady=(0,12))
        
        # Info box
        info_frame = ctk.CTkFrame(scroll_content, fg_color="#1a472a", corner_radius=12)
        info_frame.pack(fill="x", pady=10)
        
        ctk.CTkLabel(info_frame, text="ℹ️ Enter your mission data and choose a strong password", 
                    font=("Arial", 11), wraplength=750).pack(pady=12, padx=18)
        
        def perform_encrypt():
            filename = filename_entry.get().strip()
            content_val = content_text.get("0.0", "end-1c").strip()  # Use 0.0 and strip whitespace
            password = password_entry.get()
            
            if not filename or not content_val or not password:
                messagebox.showerror("❌ Error", "All fields are required!")
                return
            
            loading = LoadingAnimation(encrypt_window, "Encrypting file...")
            encrypt_window.update()
            
            try:
                filepath = f"mission_files/{filename}"
                with open(filepath, "w", encoding='utf-8') as f:
                    f.write(content_val)
                
                key = derive_key(password)
                success, result = encrypt_file(filepath, key, self.logged_in_user['username'])
                
                loading.close()
                
                if success:
                    messagebox.showinfo("✅ Success", 
                                      f"File encrypted successfully!\n\nSaved to:\n{result}")
                    encrypt_window.destroy()
                else:
                    messagebox.showerror("❌ Error", f"Encryption failed:\n{result}")
            except Exception as e:
                loading.close()
                messagebox.showerror("❌ Error", f"Error: {str(e)}")
        
        # Buttons - Fixed at bottom
        btn_frame = ctk.CTkFrame(encrypt_window, fg_color="#2a2a2a")
        btn_frame.pack(fill="x", side="bottom", padx=25, pady=20)
        
        SmoothButton(btn_frame, text="🔒 ENCRYPT NOW", 
                      command=perform_encrypt,
                      width=220, height=50, font=("Arial", 14, "bold"),
                      fg_color="#2d6a3e", hover_color="#1a472a",
                      corner_radius=12).pack(side="left", padx=10, pady=12)
        
        SmoothButton(btn_frame, text="⬅️ BACK", 
                      command=encrypt_window.destroy,
                      width=170, height=50, font=("Arial", 14, "bold"),
                      fg_color="#4a4a4a", hover_color="#2d2d2d",
                      corner_radius=12).pack(side="right", padx=10, pady=12)
    
    def show_decrypt_screen(self):
        decrypt_window = ctk.CTkToplevel(self.window)
        decrypt_window.title("🔓 Decrypt File")
        
        # Get screen dimensions
        screen_height = decrypt_window.winfo_screenheight()
        window_height = int(screen_height * 0.85)
        decrypt_window.geometry(f"850x{window_height}")
        decrypt_window.grab_set()
        
        animate_fade_in(decrypt_window)
        animate_slide_in(decrypt_window, 'down', 30)
        
        # Header - Fixed at top
        header = ctk.CTkFrame(decrypt_window, fg_color="#1a472a", corner_radius=0)
        header.pack(fill="x", side="top")
        
        ctk.CTkLabel(header, text="🔓 DECRYPT MISSION FILE", 
                    font=("Arial Black", 22, "bold"),
                    text_color="#00ff00").pack(pady=20)
        
        ctk.CTkLabel(header, text="━━━ SECURE FILE ACCESS ━━━", 
                    font=("Courier", 11), text_color="#00ff00").pack(pady=(0,15))
        
        # Scrollable content
        scroll_content = ctk.CTkScrollableFrame(decrypt_window, fg_color="#2a2a2a")
        scroll_content.pack(fill="both", expand=True, padx=25, pady=(15,0))
        
        # File selection
        file_frame = ctk.CTkFrame(scroll_content, fg_color="#1a1a1a", corner_radius=12)
        file_frame.pack(fill="x", pady=10)
        
        ctk.CTkLabel(file_frame, text="📂 SELECT ENCRYPTED FILE:", 
                    font=("Arial", 13, "bold")).pack(anchor="w", padx=18, pady=(12,5))
        
        select_frame = ctk.CTkFrame(file_frame, fg_color="transparent")
        select_frame.pack(fill="x", padx=18, pady=(0,12))
        
        file_entry = ctk.CTkEntry(select_frame, placeholder_text="No file selected",
                                 font=("Arial", 13), border_width=0,
                                 fg_color="#2a2a2a", height=40)
        file_entry.pack(side="left", fill="x", expand=True, padx=(0,12))
        
        def browse_file():
            try:
                encrypted_files = [f for f in os.listdir("storage") if f.startswith("encrypted_")]
            except:
                encrypted_files = []
            
            if not encrypted_files:
                messagebox.showinfo("ℹ️ Info", "No encrypted files found in storage!")
                return
            
            select_window = ctk.CTkToplevel(decrypt_window)
            select_window.title("📂 Select File")
            select_window.geometry("650x550")
            select_window.grab_set()
            
            animate_fade_in(select_window)
            animate_slide_in(select_window, 'down', 20)
            
            header_sel = ctk.CTkFrame(select_window, fg_color="#1a472a")
            header_sel.pack(fill="x")
            
            ctk.CTkLabel(header_sel, text="📂 SELECT FILE TO DECRYPT", 
                        font=("Arial", 20, "bold")).pack(pady=18)
            
            listbox_frame = ctk.CTkScrollableFrame(select_window, fg_color="#2a2a2a")
            listbox_frame.pack(fill="both", expand=True, padx=25, pady=25)
            
            selected_file = ctk.StringVar()
            
            for file in encrypted_files:
                file_item = ctk.CTkFrame(listbox_frame, fg_color="#1a1a1a", corner_radius=10)
                file_item.pack(fill="x", pady=6, padx=12)
                
                radio = ctk.CTkRadioButton(file_item, text="", variable=selected_file, 
                                          value=file)
                radio.pack(side="left", padx=12, pady=12)
                
                ctk.CTkLabel(file_item, text=file, font=("Consolas", 12), 
                            anchor="w").pack(side="left", fill="x", expand=True, pady=12)
            
            def confirm_selection():
                if selected_file.get():
                    file_entry.delete(0, "end")
                    file_entry.insert(0, selected_file.get())
                    select_window.destroy()
                else:
                    messagebox.showwarning("⚠️ Warning", "Please select a file!")
            
            SmoothButton(select_window, text="✅ SELECT", 
                         command=confirm_selection,
                         width=220, height=50, font=("Arial", 14, "bold"),
                         fg_color="#2d6a3e", hover_color="#1a472a",
                         corner_radius=12).pack(pady=18)
        
        SmoothButton(select_frame, text="📁 BROWSE",
                      command=browse_file,
                      width=130, height=40, font=("Arial", 13, "bold"),
                      fg_color="#4a6a8a", hover_color="#2d4a6a",
                      corner_radius=10).pack(side="left")
        
        # Password
        pass_frame = ctk.CTkFrame(scroll_content, fg_color="#1a1a1a", corner_radius=12)
        pass_frame.pack(fill="x", pady=10)
        
        ctk.CTkLabel(pass_frame, text="🔒 DECRYPTION PASSWORD:", 
                    font=("Arial", 13, "bold")).pack(anchor="w", padx=18, pady=(12,5))
        password_entry = ctk.CTkEntry(pass_frame, placeholder_text="Enter password",
                                     show="●", font=("Arial", 13), border_width=0,
                                     fg_color="#2a2a2a", height=40)
        password_entry.pack(fill="x", padx=18, pady=(0,12))
        
        # Info message
        info_frame = ctk.CTkFrame(scroll_content, fg_color="#1a472a", corner_radius=12)
        info_frame.pack(fill="x", pady=10)
        
        ctk.CTkLabel(info_frame, text="ℹ️ After decryption, content will be displayed in a new window", 
                    font=("Arial", 11), wraplength=750).pack(pady=12, padx=18)
        
        def perform_decrypt():
            filename = file_entry.get().strip()
            password = password_entry.get()
            
            if not filename or not password:
                messagebox.showerror("❌ Error", "Please select a file and enter password!")
                return
            
            loading = LoadingAnimation(decrypt_window, "Decrypting file...")
            decrypt_window.update()
            
            try:
                encrypted_path = f"storage/{filename}"
                if not os.path.exists(encrypted_path):
                    loading.close()
                    messagebox.showerror("❌ Error", f"File not found: {filename}")
                    return
                
                key = derive_key(password)
                success, result, data = decrypt_file(encrypted_path, key, 
                                                    self.logged_in_user['username'])
                
                loading.close()
                
                if success and data:
                    # Decode the data
                    decoded_text = data.decode('utf-8', errors='ignore')
                    
                    # Close the decrypt window
                    decrypt_window.destroy()
                    
                    # Create NEW window to show decrypted content
                    content_window = ctk.CTkToplevel(self.window)
                    content_window.title("📄 Decrypted File Content")
                    
                    screen_height = content_window.winfo_screenheight()
                    window_height = int(screen_height * 0.85)
                    content_window.geometry(f"900x{window_height}")
                    content_window.grab_set()
                    
                    animate_fade_in(content_window)
                    animate_slide_in(content_window, 'down', 30)
                    
                    # Header
                    header = ctk.CTkFrame(content_window, fg_color="#1a472a", corner_radius=0)
                    header.pack(fill="x", side="top")
                    
                    ctk.CTkLabel(header, text="📄 DECRYPTED FILE CONTENT", 
                                font=("Arial Black", 22, "bold"),
                                text_color="#00ff00").pack(pady=20)
                    
                    ctk.CTkLabel(header, text=f"━━━ {filename} ━━━", 
                                font=("Courier", 12), text_color="#00ff00").pack(pady=(0,15))
                    
                    # Info bar
                    info_bar = ctk.CTkFrame(content_window, fg_color="#2a2a2a")
                    info_bar.pack(fill="x", padx=25, pady=(15,0))
                    
                    ctk.CTkLabel(info_bar, text=f"📊 Size: {len(decoded_text)} characters  |  💾 Saved as: {result}", 
                                font=("Arial", 11)).pack(pady=10)
                    
                    # Content display with scrollbar
                    content_frame = ctk.CTkFrame(content_window, fg_color="#1a1a1a", corner_radius=12)
                    content_frame.pack(fill="both", expand=True, padx=25, pady=15)
                    
                    # Textbox with content
                    content_display = ctk.CTkTextbox(content_frame, 
                                                    font=("Consolas", 13),
                                                    border_width=2, 
                                                    border_color="#00ff00",
                                                    fg_color="#0a0a0a",
                                                    wrap="word",
                                                    text_color="#00ff00",
                                                    state="normal")
                    content_display.pack(fill="both", expand=True, padx=15, pady=15)
                    
                    # Insert content
                    content_display.insert("1.0", decoded_text)
                    content_display.see("1.0")
                    
                    # Buttons at bottom
                    btn_frame = ctk.CTkFrame(content_window, fg_color="#2a2a2a")
                    btn_frame.pack(fill="x", side="bottom", padx=25, pady=20)
                    
                    def copy_content():
                        content_window.clipboard_clear()
                        content_window.clipboard_append(decoded_text)
                        messagebox.showinfo("✅ Copied", "Content copied to clipboard!")
                    
                    SmoothButton(btn_frame, text="📋 COPY TO CLIPBOARD", 
                                command=copy_content,
                                width=220, height=50, font=("Arial", 14, "bold"),
                                fg_color="#2d6a3e", hover_color="#1a472a",
                                corner_radius=12).pack(side="left", padx=10, pady=12)
                    
                    SmoothButton(btn_frame, text="⬅️ BACK TO DASHBOARD", 
                                command=content_window.destroy,
                                width=220, height=50, font=("Arial", 14, "bold"),
                                fg_color="#4a4a4a", hover_color="#2d2d2d",
                                corner_radius=12).pack(side="right", padx=10, pady=12)
                    
                else:
                    messagebox.showerror("❌ Error", f"Decryption failed:\n{result if not success else 'No data returned'}")
            except Exception as e:
                loading.close()
                import traceback
                traceback.print_exc()
                messagebox.showerror("❌ Error", f"Error: {str(e)}")
        
        # Buttons - Fixed at bottom
        btn_frame = ctk.CTkFrame(decrypt_window, fg_color="#2a2a2a")
        btn_frame.pack(fill="x", side="bottom", padx=25, pady=20)
        
        SmoothButton(btn_frame, text="🔓 DECRYPT NOW", 
                      command=perform_decrypt,
                      width=220, height=50, font=("Arial", 14, "bold"),
                      fg_color="#4a6a8a", hover_color="#2d4a6a",
                      corner_radius=12).pack(side="left", padx=10, pady=12)
        
        SmoothButton(btn_frame, text="⬅️ BACK", 
                      command=decrypt_window.destroy,
                      width=170, height=50, font=("Arial", 14, "bold"),
                      fg_color="#4a4a4a", hover_color="#2d2d2d",
                      corner_radius=12).pack(side="right", padx=10, pady=12)
    
    def show_audit_logs(self):
        log_window = ctk.CTkToplevel(self.window)
        log_window.title("📊 Audit Logs")
        log_window.geometry("1100x750")
        log_window.grab_set()
        
        animate_fade_in(log_window)
        animate_slide_in(log_window, 'down', 30)
        
        # Header
        header = ctk.CTkFrame(log_window, fg_color="#1a472a", corner_radius=0)
        header.pack(fill="x")
        
        ctk.CTkLabel(header, text="📊 SYSTEM AUDIT LOGS", 
                    font=("Arial Black", 24, "bold"),
                    text_color="#00ff00").pack(pady=25)
        
        ctk.CTkLabel(header, text="━━━ SECURITY ACTIVITY MONITOR ━━━", 
                    font=("Courier", 12), text_color="#00ff00").pack(pady=(0,20))
        
        # Log display
        log_frame = ctk.CTkScrollableFrame(log_window, fg_color="#2a2a2a")
        log_frame.pack(fill="both", expand=True, padx=25, pady=25)
        
        try:
            if os.path.exists("logs/audit.log"):
                with open("logs/audit.log", "r") as f:
                    logs = f.readlines()
                
                for log_line in reversed(logs[-100:]):
                    try:
                        log_data = json.loads(log_line)
                        
                        log_entry_frame = ctk.CTkFrame(log_frame, fg_color="#1a1a1a", 
                                                      corner_radius=10)
                        log_entry_frame.pack(fill="x", pady=6, padx=12)
                        
                        status_color = "#00ff00" if log_data["success"] else "#ff6b6b"
                        status_icon = "✅" if log_data["success"] else "❌"
                        
                        # Time
                        time_str = log_data['timestamp'][:19].replace('T', ' ')
                        ctk.CTkLabel(log_entry_frame, text=time_str, 
                                    font=("Consolas", 11), width=160,
                                    anchor="w").pack(side="left", padx=12, pady=12)
                        
                        # Status
                        ctk.CTkLabel(log_entry_frame, text=status_icon, 
                                    font=("Arial", 16), width=35).pack(side="left", padx=6, pady=12)
                        
                        # User
                        ctk.CTkLabel(log_entry_frame, text=log_data['username'], 
                                    font=("Consolas", 12, "bold"), width=130,
                                    anchor="w").pack(side="left", padx=6, pady=12)
                        
                        # Action
                        action_label = ctk.CTkLabel(log_entry_frame, 
                                                   text=log_data['action'].upper(), 
                                                   font=("Consolas", 12, "bold"),
                                                   text_color=status_color,
                                                   width=110)
                        action_label.pack(side="left", padx=12, pady=12)
                        
                        # Filename
                        filename = log_data['filename']
                        if len(filename) > 50:
                            filename = "..." + filename[-47:]
                        
                        ctk.CTkLabel(log_entry_frame, text=filename, 
                                    font=("Consolas", 11),
                                    anchor="w").pack(side="left", fill="x", expand=True, 
                                                    padx=12, pady=12)
                    except:
                        continue
            else:
                ctk.CTkLabel(log_frame, text="📭 No logs found", 
                            font=("Arial", 18, "bold")).pack(pady=80)
        except Exception as e:
            ctk.CTkLabel(log_frame, text=f"❌ Error loading logs: {str(e)}", 
                        font=("Arial", 15)).pack(pady=80)
        
        # Back button
        SmoothButton(log_window, text="⬅️ BACK TO DASHBOARD", 
                      command=log_window.destroy,
                      width=280, height=55, font=("Arial", 16, "bold"),
                      fg_color="#4a4a4a", hover_color="#2d2d2d",
                      corner_radius=12).pack(pady=25)
    
    def show_pre_login_totp_generator(self):
        """TOTP generator for pre-login - Compact size"""
        totp_window = ctk.CTkToplevel(self.window)
        totp_window.title("🔑 TOTP Code Generator")
        totp_window.geometry("600x700")
        totp_window.resizable(False, False)
        totp_window.grab_set()
        
        totp_window.update_idletasks()
        x = (totp_window.winfo_screenwidth() // 2) - 300
        y = (totp_window.winfo_screenheight() // 2) - 350
        totp_window.geometry(f"+{x}+{y}")
        
        animate_fade_in(totp_window)
        animate_slide_in(totp_window, 'down', 30)
        
        # Header
        header = ctk.CTkFrame(totp_window, fg_color="#1a472a", corner_radius=0)
        header.pack(fill="x")
        
        ctk.CTkLabel(header, text="🔑 GENERATE 2FA CODE", 
                    font=("Arial Black", 22, "bold"),
                    text_color="#00ff00").pack(pady=20)
        
        ctk.CTkLabel(header, text="━━━ ENTER YOUR TOTP SECRET ━━━", 
                    font=("Courier", 11), text_color="#00ff00").pack(pady=(0,15))
        
        content = ctk.CTkFrame(totp_window, fg_color="#2a2a2a")
        content.pack(fill="both", expand=True, padx=25, pady=20)
        
        # Info message
        info_frame = ctk.CTkFrame(content, fg_color="#1a1a1a", corner_radius=12)
        info_frame.pack(fill="x", pady=10)
        
        ctk.CTkLabel(info_frame, text="ℹ️ Enter the TOTP secret from registration", 
                    font=("Arial", 11), wraplength=500).pack(pady=12, padx=18)
        
        # Secret input
        secret_frame = ctk.CTkFrame(content, fg_color="#1a1a1a", corner_radius=12)
        secret_frame.pack(fill="x", pady=10)
        
        ctk.CTkLabel(secret_frame, text="🔐 YOUR TOTP SECRET:", 
                    font=("Arial", 13, "bold")).pack(pady=(15,5))
        
        secret_entry = ctk.CTkEntry(secret_frame, font=("Courier", 14, "bold"),
                                   justify="center", fg_color="#2a2a2a",
                                   border_width=0, height=45, placeholder_text="Enter your secret key")
        secret_entry.pack(fill="x", padx=20, pady=(0,15))
        
        # Generate button - MOVED HERE for better visibility
        is_generating = {"active": False}
        
        def update_code():
            if not is_generating["active"]:
                return
                
            try:
                secret = secret_entry.get().strip()
                if not secret:
                    return
                    
                code = generate_totp_code(secret)
                code_display.update_code(code)
                
                import time
                remaining = 30 - (int(time.time()) % 30)
                progress.set(remaining / 30)
                timer_label.configure(text=f"Time remaining: {remaining}s")
                
                totp_window.after(1000, update_code)
            except Exception as e:
                code_display.update_code("ERROR")
                timer_label.configure(text="Invalid secret key")
                is_generating["active"] = False
        
        def start_generation():
            secret = secret_entry.get().strip()
            if not secret:
                messagebox.showwarning("⚠️ Warning", "Please enter your TOTP secret!")
                return
            
            is_generating["active"] = True
            timer_label.configure(text="Generating codes...")
            update_code()
        
        SmoothButton(content, text="🔑 GENERATE CODE", 
                     command=start_generation,
                     width=300, height=50, font=("Arial", 15, "bold"),
                     fg_color="#2d6a3e", hover_color="#1a472a",
                     corner_radius=12).pack(pady=15)
        
        # Code display
        code_frame = ctk.CTkFrame(content, fg_color="#1a472a", corner_radius=15)
        code_frame.pack(fill="x", pady=15, padx=15)
        
        ctk.CTkLabel(code_frame, text="CURRENT LOGIN CODE", 
                    font=("Arial", 13, "bold")).pack(pady=(18,8))
        
        code_display = SelectableCodeDisplay(code_frame, code_text="------",
                                             font=("Arial", 42, "bold"), 
                                             height=65,
                                             text_color="#00ff00")
        code_display.pack(pady=(5,18), padx=20, fill="x")
        
        # Timer bar
        timer_frame = ctk.CTkFrame(content, fg_color="#1a1a1a", corner_radius=12)
        timer_frame.pack(fill="x", pady=10, padx=15)
        
        timer_label = ctk.CTkLabel(timer_frame, text="Enter secret and click 'Generate Code'", 
                                  font=("Arial", 11))
        timer_label.pack(pady=(12,8))
        
        progress = ctk.CTkProgressBar(timer_frame, width=500)
        progress.pack(pady=(0,12), padx=20)
        progress.set(0)
        
        # Close button
        def close_window():
            is_generating["active"] = False
            totp_window.destroy()
        
        SmoothButton(totp_window, text="⬅️ BACK TO LOGIN", 
                      command=close_window,
                      width=250, height=45, font=("Arial", 13, "bold"),
                      fg_color="#4a4a4a", hover_color="#2d2d2d",
                      corner_radius=12).pack(pady=(0,20))
    
    def show_totp_generator(self):
        """Post-login TOTP generator"""
        totp_window = ctk.CTkToplevel(self.window)
        totp_window.title("🔑 TOTP Generator")
        totp_window.geometry("600x550")
        totp_window.resizable(False, False)
        totp_window.grab_set()
        
        totp_window.update_idletasks()
        x = (totp_window.winfo_screenwidth() // 2) - 300
        y = (totp_window.winfo_screenheight() // 2) - 275
        totp_window.geometry(f"+{x}+{y}")
        
        animate_fade_in(totp_window)
        animate_slide_in(totp_window, 'down', 30)
        
        # Header
        header = ctk.CTkFrame(totp_window, fg_color="#1a472a", corner_radius=0)
        header.pack(fill="x")
        
        ctk.CTkLabel(header, text="🔑 TOTP CODE GENERATOR", 
                    font=("Arial Black", 22, "bold"),
                    text_color="#00ff00").pack(pady=25)
        
        ctk.CTkLabel(header, text="━━━ 2FA AUTHENTICATION ━━━", 
                    font=("Courier", 12), text_color="#00ff00").pack(pady=(0,20))
        
        content = ctk.CTkFrame(totp_window, fg_color="#2a2a2a")
        content.pack(fill="both", expand=True, padx=25, pady=25)
        
        # Secret display
        secret_frame = ctk.CTkFrame(content, fg_color="#1a1a1a", corner_radius=12)
        secret_frame.pack(fill="x", pady=18)
        
        ctk.CTkLabel(secret_frame, text="🔐 YOUR TOTP SECRET:", 
                    font=("Arial", 14, "bold")).pack(pady=(18,8))
        
        secret_display = SelectableCodeDisplay(secret_frame, 
                                               code_text=self.logged_in_user['totp_secret'],
                                               font=("Courier", 14, "bold"), height=50)
        secret_display.pack(fill="x", padx=25, pady=(0,18))
        
        # Code display
        code_frame = ctk.CTkFrame(content, fg_color="#1a472a", corner_radius=15)
        code_frame.pack(fill="x", pady=25, padx=25)
        
        ctk.CTkLabel(code_frame, text="CURRENT LOGIN CODE", 
                    font=("Arial", 13)).pack(pady=(25,8))
        
        code_display = SelectableCodeDisplay(code_frame, code_text="",
                                             font=("Arial", 48, "bold"), height=70)
        code_display.pack(pady=(8,25), padx=20, fill="x")
        
        # Timer bar
        timer_frame = ctk.CTkFrame(content, fg_color="#1a1a1a", corner_radius=12)
        timer_frame.pack(fill="x", pady=12)
        
        timer_label = ctk.CTkLabel(timer_frame, text="Time remaining:", 
                                  font=("Arial", 12))
        timer_label.pack(pady=(12,8))
        
        progress = ctk.CTkProgressBar(timer_frame, width=450)
        progress.pack(pady=(0,12))
        
        def update_code():
            try:
                code = generate_totp_code(self.logged_in_user['totp_secret'])
                code_display.update_code(code)
                
                import time
                remaining = 30 - (int(time.time()) % 30)
                progress.set(remaining / 30)
                timer_label.configure(text=f"Time remaining: {remaining}s")
                
                totp_window.after(1000, update_code)
            except:
                pass
        
        update_code()
        
        # Info
        info_frame = ctk.CTkFrame(content, fg_color="#1a1a1a", corner_radius=12)
        info_frame.pack(fill="x", pady=12)
        
        ctk.CTkLabel(info_frame, text="ℹ️ Code refreshes every 30 seconds | Select & copy with Ctrl+C", 
                    font=("Arial", 11), text_color="gray").pack(pady=15)
        
        # Back button
        SmoothButton(totp_window, text="⬅️ BACK TO DASHBOARD", 
                      command=totp_window.destroy,
                      width=280, height=55, font=("Arial", 16, "bold"),
                      fg_color="#4a4a4a", hover_color="#2d2d2d",
                      corner_radius=12).pack(pady=25)
    
    def logout(self):
        if self.logged_in_user:
            log_action(self.logged_in_user['username'], "logout", "system", True)
        
        confirm = messagebox.askyesno("🚪 Logout", 
                                     "Are you sure you want to terminate your session?")
        if confirm:
            self.logged_in_user = None
            messagebox.showinfo("✅ Logged Out", 
                              "Session terminated successfully!\n\nSee you next time, Agent.")
            self.show_login_screen()
    
    def run(self):
        self.window.mainloop()

# ===================== MAIN EXECUTION =====================

if __name__ == "__main__":
    app = MilitaryDataLockerGUI()
    app.run()