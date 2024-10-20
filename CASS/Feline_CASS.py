import tkinter as tk
from tkinter import ttk, scrolledtext
from PIL import Image, ImageTk
import time
import threading
import socket
import psutil
import ssl
import os
import subprocess
import hashlib
from tqdm import tqdm

#Port Scanner
def port_scanner():
    open_ports = []
    for port in tqdm(range(1, 51), desc="Scanning Ports", leave=False):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.1)
        result = sock.connect_ex(('localhost', port))
        if result == 0:
            open_ports.append(port)
        sock.close()
    
    if open_ports:
        return f"Open ports: {open_ports}\nSuggestion: Review the security of these ports to prevent unauthorized access! Open ports can be exploited by attackers to gain entry into your system.\n"
    else:
        return "No open ports found.\nSuggestion: Ensure your firewall is properly configured and consider closing unnecessary ports to enhance security.\n"

#keyloggers
def detect_keyloggers():
    suspicious_processes = []
    keylogger_signatures = ['keylog', 'spy', 'capture']
    
    for proc in psutil.process_iter(['pid', 'name']):
        for signature in keylogger_signatures:
            if signature in proc.info['name'].lower():
                suspicious_processes.append(proc.info['name'])
    
    if suspicious_processes:
        return f"Potential keyloggers found: {suspicious_processes}\nSuggestion: Investigate these processes immediately to safeguard your information!\n"
    else:
        return "No keyloggers detected.\nSuggestion: Continue to monitor your system regularly for any unusual activity.\n"

#SSL/TLS strength
def ssl_tsl(hostname):
    try:
        context = ssl.create_default_context()
        conn = context.wrap_socket(socket.socket(socket.AF_INET), server_hostname=hostname)
        conn.settimeout(2)
        conn.connect((hostname, 443))
        return "SSL/TLS cipher appears strong.\nSuggestion: Regularly update your SSL certificates and monitor your encryption protocols to ensure secure communications.\n"
    except Exception as e:
        return f"SSL/TLS check failed: {e}\nSuggestion: Check your server configuration for vulnerabilities and ensure that you are using strong encryption standards.\n"

#File Permission
def file_permission(directory):
    insecure_files = []
    for root, dirs, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            if os.access(file_path, os.W_OK):
                insecure_files.append(file_path)
                if len(insecure_files) >= 5:
                    break
        if len(insecure_files) >= 5:
            break
    
    if insecure_files:
        return f"Insecure files found: {insecure_files}\nSuggestion: Secure these files to prevent unauthorized access, as they may contain sensitive information!\n"
    else:
        return "No file permission issues found.\nSuggestion: Ensure that your files have appropriate access controls to protect sensitive data.\n"

#software vulnerabilities
def software_vul():
    vulnerable_software = []
    installed_software = subprocess.getoutput('powershell "Get-ItemProperty HKLM:\\Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* | Select-Object DisplayName, DisplayVersion"').splitlines()
    
    for software in installed_software:
        if "vulnerableversion" in software.lower():
            vulnerable_software.append(software)
            if len(vulnerable_software) >= 5:
                break
    
    if vulnerable_software:
        return f"Vulnerable software found: {vulnerable_software}\nSuggestion: Update these applications to the latest versions to prevent security risks!\n"
    else:
        return "No vulnerable software found.\nSuggestion: Keep all software updated regularly to mitigate potential security issues.\n"

#system integrity
def system_integrity():
    critical_files = ["C:\\Windows\\System32\\cmd.exe", "C:\\Windows\\System32\\notepad.exe"]
    integrity_results = ""
    
    for file in critical_files:
        if os.path.exists(file):
            with open(file, "rb") as f:
                file_hash = hashlib.md5(f.read()).hexdigest()
                integrity_results += f"{file} hash: {file_hash}\n"
        else:
            integrity_results += f"File {file} does not exist!\n"
    
    return integrity_results or "No critical files found.\nSuggestion: Ensure that your system files are intact to prevent system vulnerabilities.\n"

def display_results(results):
    output_text.delete(1.0, tk.END)
    output_text.insert(tk.END, results)
    progress_bar.stop()
    output_frame.pack(pady=10, fill=tk.BOTH, expand=True)

def run_thread(tool_function):
    progress_bar.start()
    threading.Thread(target=lambda: display_results(tool_function())).start()

def resize_image(image_path, size):
    image = Image.open(image_path)
    return ImageTk.PhotoImage(image.resize(size, Image.LANCZOS))

root = tk.Tk()
root.title("Cyber Attack Simulation System - Feline")
root.geometry("1000x800")
root.configure(bg='gray17')

tittle_photo = resize_image("src/img/tittle.png", (800, 120))
tittle_img = tk.Label(root, image=tittle_photo, bd=0, bg='gray17')
tittle_img.pack(pady=10)

middle_frame = tk.Frame(root, bg='gray17')
middle_frame.pack(pady=10)

button_images = [
    resize_image("src/img/ps.png", (300, 100)), 
    resize_image("src/img/keylogger.png", (300, 100)),
    resize_image("src/img/ssl.png", (300, 100)),
    resize_image("src/img/file.png", (300, 100)),
    resize_image("src/img/software.png", (300, 100)),
    resize_image("src/img/system.png", (300, 100)),
]

left_btnframe = tk.Frame(middle_frame, bg='gray17')
left_btnframe.pack(side=tk.LEFT) 

btn1 = tk.Button(left_btnframe, image=button_images[0], bd=0, command=lambda: run_thread(port_scanner), bg='gray17')
btn1.pack(pady=5)

btn2 = tk.Button(left_btnframe, image=button_images[1], bd=0, command=lambda: run_thread(detect_keyloggers), bg='gray17')
btn2.pack(pady=5)

btn3 = tk.Button(left_btnframe, image=button_images[2], bd=0, command=lambda: run_thread(lambda: ssl_tsl("google.com")), bg='gray17')
btn3.pack(pady=5)

robot_photo = resize_image("src/img/robot1.png", (220, 300)) 
robot_image_label = tk.Label(middle_frame, image=robot_photo, bd=0, bg='gray17')
robot_image_label.pack(side=tk.LEFT, padx=40)

right_btnframe = tk.Frame(middle_frame, bg='gray17')
right_btnframe.pack(side=tk.LEFT) 

btn4 = tk.Button(right_btnframe, image=button_images[3], bd=0, command=lambda: run_thread(lambda: file_permission("C:\\Users")), bg='gray17')
btn4.pack(pady=5)

btn5 = tk.Button(right_btnframe, image=button_images[4], bd=0, command=lambda: run_thread(software_vul), bg='gray17')
btn5.pack(pady=5)

btn6 = tk.Button(right_btnframe, image=button_images[5], bd=0, command=lambda: run_thread(system_integrity), bg='gray17')
btn6.pack(pady=5)

progress_bar = ttk.Progressbar(root, mode='indeterminate')
progress_bar.pack(pady=10, fill=tk.X, padx=200)

output_frame = tk.Frame(root, bg='gray17')
output_text = scrolledtext.ScrolledText(output_frame, width=80, height=20, bg='white', fg='black', wrap=tk.WORD, bd=1)
output_text.pack(padx=10, pady=10)

end_photo = resize_image("src/img/feline.png", (350, 100))
end_imageLabel = tk.Label(root, image=end_photo, bd=0, bg='gray17')
end_imageLabel.pack(side=tk.BOTTOM, pady=10)

root.mainloop()
