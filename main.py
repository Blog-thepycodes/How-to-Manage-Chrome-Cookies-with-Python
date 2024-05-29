import os
import json
import base64
import sqlite3
import shutil
from datetime import datetime, timedelta
import win32crypt  # pip install pypiwin32
from Cryptodome.Cipher import AES  # pip install pycryptodome
import tkinter as tk
from tkinter import messagebox, ttk
 
 
def chrome_time_to_datetime(chrome_time):
   """Convert Chrome time format to a datetime object."""
   if chrome_time and chrome_time != 86400000000:
       return datetime(1601, 1, 1) + timedelta(microseconds=chrome_time)
   return None
 
 
def fetch_encryption_key():
   """Retrieve the encryption key used by Chrome."""
   state_path = os.path.join(os.environ["USERPROFILE"], "AppData", "Local", "Google", "Chrome", "User Data", "Local State")
   try:
       with open(state_path, "r", encoding="utf-8") as file:
           state_data = json.load(file)
       encrypted_key = base64.b64decode(state_data["os_crypt"]["encrypted_key"])[5:]
       return win32crypt.CryptUnprotectData(encrypted_key, None, None, None, 0)[1]
   except Exception as e:
       print(f"Failed to get encryption key: {e}")
       return None
 
 
def decrypt_cookie_value(encrypted_value, key):
   """Unveil the encrypted cookie content with the given encryption key."""
   try:
       iv, encrypted_value = encrypted_value[3:15], encrypted_value[15:]
       cipher = AES.new(key, AES.MODE_GCM, iv)
       return cipher.decrypt(encrypted_value)[:-16].decode()
   except Exception as e:
       print(f"Decryption error: {e}")
       return ""
 
 
def retrieve_cookies():
   """Extract cookies from Chrome's database."""
   db_path = os.path.join(os.environ["USERPROFILE"], "AppData", "Local", "Google", "Chrome", "User Data", "Default", "Network", "Cookies")
   temp_db_path = "Temp_Cookies.db"
   if not os.path.isfile(temp_db_path):
       try:
           shutil.copyfile(db_path, temp_db_path)
       except PermissionError as e:
           messagebox.showerror("Permission Error", f"Failed to copy cookies database: {e}")
           return []
 
 
   conn = sqlite3.connect(temp_db_path)
   conn.text_factory = lambda b: b.decode(errors="ignore")
   cursor = conn.cursor()
   cursor.execute("SELECT host_key, name, value, creation_utc, last_access_utc, expires_utc, encrypted_value FROM cookies")
   key = fetch_encryption_key()
   if key is None:
       messagebox.showerror("Error", "Failed to retrieve encryption key.")
       return []
 
 
   cookies_data = []
   for host, name, value, creation_time, last_access, expiry, encrypted_value in cursor.fetchall():
       decrypted_value = decrypt_cookie_value(encrypted_value, key) if not value else value
       cookies_data.append((host, name, decrypted_value, chrome_time_to_datetime(creation_time), chrome_time_to_datetime(last_access), chrome_time_to_datetime(expiry)))
       cursor.execute("UPDATE cookies SET value = ?, has_expires = 1, expires_utc = 99999999999999999, is_persistent = 1, is_secure = 0 WHERE host_key = ? AND name = ?", (decrypted_value, host, name))
   conn.commit()
   conn.close()
   return cookies_data
 
 
def delete_selected_cookies(selected_cookies):
   """Delete selected cookies from Chrome's database."""
   db_path = os.path.join(os.environ["USERPROFILE"], "AppData", "Local", "Google", "Chrome", "User Data", "Default", "Network", "Cookies")
   temp_db_path = "Temp_Cookies.db"
   try:
       shutil.copyfile(db_path, temp_db_path)
   except PermissionError as e:
       messagebox.showerror("Permission Error", f"Failed to copy cookies database: {e}")
       return
 
 
   conn = sqlite3.connect(temp_db_path)
   cursor = conn.cursor()
   for cookie in selected_cookies:
       cursor.execute("DELETE FROM cookies WHERE host_key = ? AND name = ?", (cookie[0], cookie[1]))
   conn.commit()
   conn.close()
 
 
   try:
       shutil.copyfile(temp_db_path, db_path)
   except PermissionError as e:
       messagebox.showerror("Permission Error", f"Failed to update cookies database: {e}")
       return
   messagebox.showinfo("Info", "Selected cookies have been deleted.")
 
 
def delete_all_cookies():
   """Delete all cookies from Chrome's database."""
   db_path = os.path.join(os.environ["USERPROFILE"], "AppData", "Local", "Google", "Chrome", "User Data", "Default", "Network", "Cookies")
   temp_db_path = "Temp_Cookies.db"
   try:
       shutil.copyfile(db_path, temp_db_path)
   except PermissionError as e:
       messagebox.showerror("Permission Error", f"Failed to copy cookies database: {e}")
       return
 
 
   conn = sqlite3.connect(temp_db_path)
   cursor = conn.cursor()
   cursor.execute("DELETE FROM cookies")
   conn.commit()
   conn.close()
 
 
   try:
       shutil.copyfile(temp_db_path, db_path)
   except PermissionError as e:
       messagebox.showerror("Permission Error", f"Failed to update cookies database: {e}")
       return
   messagebox.showinfo("Info", "All cookies have been deleted.")
 
 
def on_extract_click():
   """Handle the extract cookies button click event."""
   cookies_data = retrieve_cookies()
   for i, cookie in enumerate(cookies_data):
       tree.insert("", "end", values=cookie, iid=i)
 
 
def on_delete_click():
   """Handle the delete selected cookies button click event."""
   selected_items = tree.selection()
   selected_cookies = [tree.item(item)['values'][:2] for item in selected_items]
   delete_selected_cookies(selected_cookies)
   for item in selected_items:
       tree.delete(item)
 
 
# Set up the Tkinter GUI
root = tk.Tk()
root.title("Chrome Cookies Manager - The Pycodes")
 
 
frame = tk.Frame(root)
frame.pack(padx=10, pady=10)
 
 
tk.Button(frame, text="Extract Cookies", command=on_extract_click).pack(pady=5)
 
 
columns = ("Domain", "Name", "Value", "Created On", "Accessed On", "Expires On")
tree = ttk.Treeview(frame, columns=columns, show='headings')
 
 
# Adding scrollbar
scrollbar = ttk.Scrollbar(frame, orient="vertical", command=tree.yview)
tree.configure(yscrollcommand=scrollbar.set)
scrollbar.pack(side="right", fill="y")
 
 
tree.pack(pady=5)
 
 
for col in columns:
   tree.heading(col, text=col)
   tree.column(col, width=150)
 
 
tk.Button(frame, text="Delete Selected Cookies", command=on_delete_click).pack(pady=5)
tk.Button(frame, text="Delete All Cookies", command=delete_all_cookies).pack(pady=5)
 
 
root.mainloop()
