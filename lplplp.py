#!/usr/bin/env python3
"""
License Plate Information System - Tkinter GUI with Captcha
Features:
- Admin and Client roles with login/signup
- Captcha (case-insensitive) on login and client signup
- Client signup password rules: at least 1 uppercase, 1 digit, 1 special char (@#$%^&+=!), length 6-20
- Default admin 'pranav' / 'pranav'
- 50 default Indian license records
- Persistent JSON storage
- Admin: view/add/edit/delete, add admin, view logs, undo last change
- Client: signup/login, add vehicle, view & edit own vehicles, search
- Single main window, frames swapped dynamically
"""

import json
import os
import random
import re
import string
from copy import deepcopy
import tkinter as tk
from tkinter import ttk, messagebox, simpledialog

# ---------- File constants ----------
DATA_FILE = "license_data.json"
USERS_FILE = "users.json"
LOG_FILE = "search_log.json"
UNDO_FILE = "undo_stack.json"

# ---------- Utilities ----------
def load_json(path):
    if not os.path.exists(path):
        with open(path, "w") as f:
            json.dump({}, f)
    with open(path, "r") as f:
        try:
            return json.load(f)
        except Exception:
            return {}

def save_json(path, data):
    with open(path, "w") as f:
        json.dump(data, f, indent=4)

def push_undo_state():
    """Save a deep copy of current DATA_FILE into UNDO_FILE for single-step undo."""
    data = load_json(DATA_FILE)
    save_json(UNDO_FILE, {"last_state": deepcopy(data)})

def undo_last_change_confirm(parent):
    """Ask confirmation and restore previous state if present."""
    if not os.path.exists(UNDO_FILE):
        messagebox.showinfo("Undo", "No previous state to undo.", parent=parent)
        return False
    stack = load_json(UNDO_FILE)
    if "last_state" not in stack or not stack["last_state"]:
        messagebox.showinfo("Undo", "Nothing to undo.", parent=parent)
        return False
    if messagebox.askyesno("Confirm Undo", "Are you sure you want to undo the last change?", parent=parent):
        save_json(DATA_FILE, stack["last_state"])
        messagebox.showinfo("Undo", "Undo successful — last change reverted.", parent=parent)
        return True
    else:
        return False

# ---------- Password validation ----------
def is_valid_password(password: str) -> bool:
    """
    Requirements:
    - At least one uppercase letter
    - At least one digit
    - At least one special character from @#$%^&+=!
    - Length between 6 and 20 characters
    """
    pattern = r'^(?=.*[A-Z])(?=.*\d)(?=.*[@#$%^&+=!]).{6,20}$'
    return re.match(pattern, password) is not None

# ---------- Captcha helpers ----------
def generate_captcha(length=5):
    chars = string.ascii_letters + string.digits
    return ''.join(random.choice(chars) for _ in range(length))

def captcha_check(input_text, actual):
    # case-insensitive
    return (input_text or "").strip().lower() == (actual or "").strip().lower()

# ---------- Default data setup ----------
def setup_default_users():
    users = load_json(USERS_FILE)
    if "admin" not in users:
        users["admin"] = {"pranav": "pranav"}
    else:
        users["admin"]["pranav"] = users["admin"].get("pranav", "pranav")
    if "clients" not in users:
        # sample clients with passwords that satisfy rules
        clients = {}
        for i in range(1, 16):
            clients[f"client{i}"] = "Password1!"
        users["clients"] = clients
    save_json(USERS_FILE, users)

def setup_default_data():
    data = load_json(DATA_FILE)
    if data:
        return
    sample_clients = [f"client{i}" for i in range(1, 16)]
    plates = {
        "MH01AB1001": ("Akhil Mehta","Car","Hyundai","i20","Pune, Maharashtra","2018-04-10"),
        "DL1CAQ2002": ("Sunita Rao","Car","Maruti Suzuki","Baleno","New Delhi, Delhi","2019-07-22"),
        "KA03BC3003": ("Rohit Shetty","Bike","Royal Enfield","Classic 350","Bengaluru, Karnataka","2020-01-15"),
        "TN07DE4004": ("Nisha Krishnan","Car","Hyundai","Verna","Chennai, Tamil Nadu","2017-11-30"),
        "UP32EF5005": ("Vikas Singh","Truck","Tata Motors","407 LPT","Lucknow, Uttar Pradesh","2016-05-12"),
        "GJ05GH6006": ("Priyanka Patel","Car","Maruti Suzuki","Swift","Surat, Gujarat","2021-03-03"),
        "WB20IJ7007": ("Arjun Banerjee","Scooter","TVS","Jupiter","Kolkata, West Bengal","2022-08-19"),
        "HR26KL8008": ("Suman Rao","Car","Honda","City","Gurugram, Haryana","2019-12-01"),
        "RJ14MN9009": ("Pawan Sharma","Bike","Bajaj","Pulsar","Jaipur, Rajasthan","2015-06-27"),
        "KL07OP1010": ("Meera Nair","Car","Toyota","Innova Crysta","Thiruvananthapuram, Kerala","2020-10-05"),
        "MH02QR1111": ("Karan Desai","Car","Skoda","Rapid","Mumbai, Maharashtra","2018-02-14"),
        "DL2ST1212": ("Aarti Gupta","Scooter","Honda","Activa","New Delhi, Delhi","2019-09-09"),
        "KA04UV1313": ("Manish Gowda","Car","Tata Motors","Nexon","Mysuru, Karnataka","2021-01-20"),
        "TN10WX1414": ("Deepa Subramanian","Car","Ford","EcoSport","Coimbatore, Tamil Nadu","2017-08-24"),
        "UP16YZ1515": ("Ramesh Yadav","Truck","Ashok Leyland","Ecomet","Noida, Uttar Pradesh","2014-04-04"),
        "GJ01AB1616": ("Bhavna Desai","Car","Hyundai","i10","Ahmedabad, Gujarat","2016-07-31"),
        "WB19CD1717": ("Soham Chatterjee","Bike","TVS","Apache","Howrah, West Bengal","2021-05-18"),
        "HR55EF1818": ("Anita Singh","Car","Mahindra","Thar","Rohtak, Haryana","2023-02-02"),
        "RJ27GH1919": ("Tarun Mehta","Scooter","Suzuki","Access","Udaipur, Rajasthan","2020-12-12"),
        "KL15IJ2020": ("Leena Varghese","Car","Hyundai","Creta","Kochi, Kerala","2018-09-09"),
        "MH43KL2121": ("Siddharth Rao","Car","Honda","Civic","Nashik, Maharashtra","2016-11-11"),
        "DL3MN2222": ("Ritu Verma","Bike","Hero","Splendor","New Delhi, Delhi","2015-03-23"),
        "KA05OP2323": ("Vijay Kumar","Car","Maruti Suzuki","Dzire","Hubli, Karnataka","2019-10-10"),
        "TN11QR2424": ("Lakshmi Narayanan","Car","Toyota","Fortuner","Tiruchirappalli, Tamil Nadu","2022-06-06"),
        "UP78ST2525": ("Naveen Gupta","Truck","Tata Motors","407 LPT","Varanasi, Uttar Pradesh","2013-01-01"),
        "GJ27UV2626": ("Rina Shah","Car","Renault","Kwid","Rajkot, Gujarat","2020-05-05"),
        "WB14WX2727": ("Sanjay Dutta","Car","Mercedes","A-Class","Asansol, West Bengal","2021-07-07"),
        "HR12YZ2828": ("Preeti Kaur","Bike","KTM","Duke","Panchkula, Haryana","2019-03-03"),
        "RJ02AB2929": ("Mohit Arora","Car","Ford","Endeavour","Jodhpur, Rajasthan","2017-02-02"),
        "KL11CD3030": ("Joseph Mathew","Scooter","Yamaha","Fascino","Kozhikode, Kerala","2018-08-08"),
        "MH14EF3131": ("Rakesh Patil","Car","Skoda","Octavia","Thane, Maharashtra","2016-06-16"),
        "DL4GH3232": ("Pooja Malhotra","Car","Volkswagen","Vento","New Delhi, Delhi","2015-05-25"),
        "KA06IJ3333": ("Suresh Nayak","Bike","Royal Enfield","Meteor 350","Belgaum, Karnataka","2021-09-09"),
        "TN12KL3434": ("Anu R","Car","Hyundai","Venue","Madurai, Tamil Nadu","2020-11-11"),
        "UP36MN3535": ("Chandra Prakash","Car","Maruti Suzuki","Ertiga","Kanpur, Uttar Pradesh","2014-10-10"),
        "GJ06OP3636": ("Isha Mehta","Scooter","Hero","Pleasure","Surendranagar, Gujarat","2019-01-18"),
        "WB12QR3737": ("Kunal Roy","Car","Tata Motors","Harrier","Durgapur, West Bengal","2022-02-22"),
        "HR38ST3838": ("Ritika Bansal","Car","MG","Hector","Sonepat, Haryana","2021-12-12"),
        "RJ14UV3939": ("Vimal Joshi","Truck","Eicher","Pro 2050","Bikaner, Rajasthan","2013-09-09"),
        "KL07WX4040": ("Sajith Kumar","Car","Honda","Amaze","Alappuzha, Kerala","2018-01-01"),
        "MH20YZ4141": ("Gauri Deshpande","Bike","Bajaj","Dominar","Aurangabad, Maharashtra","2017-07-07"),
        "DL5AB4242": ("Rohini Chopra","Car","Hyundai","Tucson","New Delhi, Delhi","2020-03-03"),
        "KA07CD4343": ("Nandan Hegde","Scooter","TVS","Ntorq","Davangere, Karnataka","2022-09-09"),
        "TN15EF4444": ("Sathish Kumar","Car","Kia","Seltos","Salem, Tamil Nadu","2019-04-04"),
        "UP53GH4545": ("Hemant Verma","Car","Ford","Figo","Agra, Uttar Pradesh","2016-02-02"),
        "GJ18IJ4646": ("Smita Patel","Car","Nissan","Kicks","Bhavnagar, Gujarat","2021-06-06"),
        "WB09KL4747": ("Amitava Sen","Bike","Honda","CBR","Siliguri, West Bengal","2015-08-08"),
        "HR20MN4848": ("Poonam Luthra","Car","Hyundai","Elantra","Panipat, Haryana","2018-12-12"),
        "RJ33OP4949": ("Devika R","Scooter","Suzuki","Burgman Street","Bharatpur, Rajasthan","2020-02-20"),
        "KL17QR5050": ("Thomas George","Car","Mercedes","C-Class","Thrissur, Kerala","2019-11-11")
    }
    data_out = {}
    for plate, tup in plates.items():
        owner_username = random.choice(sample_clients)
        data_out[plate] = {
            "owner_name": tup[0],
            "vehicle_type": tup[1],
            "vehicle_company": tup[2],
            "vehicle_model": tup[3],
            "owner_address": tup[4],
            "registration_date": tup[5],
            "owner_username": owner_username
        }
    save_json(DATA_FILE, data_out)

def setup_all_defaults():
    setup_default_users()
    setup_default_data()
    # ensure logs and undo files exist
    load_json(LOG_FILE)
    load_json(UNDO_FILE)

# ---------- GUI Application ----------
class LicenseApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("License Plate Information System")
        self.geometry("1000x620")
        self.minsize(900, 550)
        # current logged in user and role
        self.current_user = None
        self.current_role = None  # "admin" or "client"
        # main container frames
        self.create_widgets()

    def create_widgets(self):
        # top frame: title and breadcrumb / logout
        top = ttk.Frame(self)
        top.pack(side=tk.TOP, fill=tk.X)
        title = ttk.Label(top, text="License Plate Information System", font=("Segoe UI", 16, "bold"))
        title.pack(side=tk.LEFT, padx=10, pady=8)
        self.breadcrumb = ttk.Label(top, text="", font=("Segoe UI", 10))
        self.breadcrumb.pack(side=tk.LEFT, padx=20)
        self.logout_btn = ttk.Button(top, text="Logout", command=self.logout)
        self.logout_btn.pack(side=tk.RIGHT, padx=10)
        self.logout_btn["state"] = "disabled"

        # main content area
        self.container = ttk.Frame(self)
        self.container.pack(fill=tk.BOTH, expand=True)

        # initialize frames dict
        self.frames = {}
        for F in (StartFrame, AuthFrame, AdminFrame, ClientFrame):
            frame = F(parent=self.container, controller=self)
            self.frames[F.__name__] = frame
            frame.grid(row=0, column=0, sticky="nsew")

        self.show_frame("StartFrame")

    def show_frame(self, name):
        frame = self.frames[name]
        frame.tkraise()
        crumb = {
            "StartFrame": "Home",
            "AuthFrame": "Login / Signup",
            "AdminFrame": f"Admin: {self.current_user}" if self.current_user else "Admin",
            "ClientFrame": f"Client: {self.current_user}" if self.current_user else "Client"
        }.get(name, "")
        self.breadcrumb.config(text=crumb)

    def login(self, role, username):
        self.current_role = role
        self.current_user = username
        self.logout_btn["state"] = "normal"
        if role == "admin":
            self.frames["AdminFrame"].refresh()
            self.show_frame("AdminFrame")
        else:
            self.frames["ClientFrame"].refresh()
            self.show_frame("ClientFrame")

    def logout(self):
        self.current_user = None
        self.current_role = None
        self.logout_btn["state"] = "disabled"
        messagebox.showinfo("Logged out", "You have been logged out.")
        self.show_frame("StartFrame")

# ---------- Frames ----------
class StartFrame(ttk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent)
        self.controller = controller
        pad = 20
        label = ttk.Label(self, text="Choose role", font=("Segoe UI", 14))
        label.pack(pady=pad)
        btn_admin = ttk.Button(self, text="Admin", command=self.open_admin_auth)
        btn_admin.pack(pady=5, ipadx=10)
        btn_client = ttk.Button(self, text="Client", command=self.open_client_auth)
        btn_client.pack(pady=5, ipadx=10)

    def open_admin_auth(self):
        auth = self.controller.frames["AuthFrame"]
        auth.set_role("admin")
        self.controller.show_frame("AuthFrame")

    def open_client_auth(self):
        auth = self.controller.frames["AuthFrame"]
        auth.set_role("client")
        self.controller.show_frame("AuthFrame")

class AuthFrame(ttk.Frame):
    """
    Handles both Admin and Client login and Client signup.
    Includes a case-insensitive captcha for both login and signup.
    """
    def __init__(self, parent, controller):
        super().__init__(parent, padding=10)
        self.controller = controller
        self.role = None  # "admin" or "client"
        self.current_captcha = generate_captcha()

        self.header = ttk.Label(self, text="", font=("Segoe UI", 13))
        self.header.pack(pady=8)

        frm = ttk.Frame(self)
        frm.pack(pady=4)

        ttk.Label(frm, text="Username:").grid(row=0, column=0, sticky="e", padx=5, pady=5)
        self.username_var = tk.StringVar()
        ttk.Entry(frm, textvariable=self.username_var).grid(row=0, column=1, padx=5, pady=5)

        ttk.Label(frm, text="Password:").grid(row=1, column=0, sticky="e", padx=5, pady=5)
        self.password_var = tk.StringVar()
        ttk.Entry(frm, show="*", textvariable=self.password_var).grid(row=1, column=1, padx=5, pady=5)

        # Captcha display & entry
        captcha_frame = ttk.Frame(self)
        captcha_frame.pack(pady=6)
        self.captcha_label_var = tk.StringVar(value=self.current_captcha)
        captcha_display = ttk.Label(captcha_frame, textvariable=self.captcha_label_var, font=("Courier", 14, "bold"))
        captcha_display.pack(side=tk.LEFT, padx=6)
        ttk.Button(captcha_frame, text="Regenerate", command=self.regenerate_captcha).pack(side=tk.LEFT, padx=6)
        ttk.Label(captcha_frame, text="Enter Captcha:").pack(side=tk.LEFT, padx=6)
        self.captcha_entry_var = tk.StringVar()
        ttk.Entry(captcha_frame, textvariable=self.captcha_entry_var).pack(side=tk.LEFT, padx=6)

        # login / signup buttons
        self.login_btn = ttk.Button(self, text="Login", command=self.attempt_login)
        self.login_btn.pack(pady=6)

        self.signup_btn = ttk.Button(self, text="Signup (Client)", command=self.signup_client)
        self.signup_btn.pack(pady=3)

        self.back_btn = ttk.Button(self, text="Back", command=lambda: controller.show_frame("StartFrame"))
        self.back_btn.pack(pady=6)

    def set_role(self, role):
        self.role = role
        self.header.config(text=f"{role.title()} Login")
        if role == "admin":
            self.signup_btn["state"] = "disabled"
        else:
            self.signup_btn["state"] = "normal"
        self.username_var.set("")
        self.password_var.set("")
        self.captcha_entry_var.set("")
        self.regenerate_captcha()

    def regenerate_captcha(self):
        self.current_captcha = generate_captcha()
        self.captcha_label_var.set(self.current_captcha)
        self.captcha_entry_var.set("")

    def attempt_login(self):
        # check captcha first (case-insensitive)
        captcha_input = self.captcha_entry_var.get()
        if not captcha_check(captcha_input, self.current_captcha):
            messagebox.showerror("Captcha", "Incorrect captcha. Please try again.")
            self.regenerate_captcha()
            return

        users = load_json(USERS_FILE)
        uname = self.username_var.get().strip()
        pwd = self.password_var.get().strip()
        if self.role == "admin":
            if uname in users.get("admin", {}) and users["admin"][uname] == pwd:
                messagebox.showinfo("Login", "Admin login successful.")
                self.controller.login("admin", uname)
                # reset captcha for next time
                self.regenerate_captcha()
            else:
                messagebox.showerror("Login Failed", "Invalid admin credentials.")
                self.regenerate_captcha()
        else:
            if uname in users.get("clients", {}) and users["clients"][uname] == pwd:
                messagebox.showinfo("Login", "Client login successful.")
                self.controller.login("client", uname)
                self.regenerate_captcha()
            else:
                messagebox.showerror("Login Failed", "Invalid client credentials. Or sign up first.")
                self.regenerate_captcha()

    def signup_client(self):
        """
        Client signup flow with captcha, password confirmation and validation.
        """
        # check captcha
        captcha_input = self.captcha_entry_var.get()
        if not captcha_check(captcha_input, self.current_captcha):
            messagebox.showerror("Captcha", "Incorrect captcha. Please try again.")
            self.regenerate_captcha()
            return

        users = load_json(USERS_FILE)
        uname = self.username_var.get().strip()
        pwd = self.password_var.get().strip()
        if not uname or not pwd:
            messagebox.showerror("Signup", "Enter username and password to sign up (password must meet rules).")
            self.regenerate_captcha()
            return
        if uname in users.get("clients", {}):
            messagebox.showerror("Signup", "Username already exists. Please choose another.")
            self.regenerate_captcha()
            return
        # ask for confirm password
        confirm = simpledialog.askstring("Confirm Password", "Re-enter password:", show="*", parent=self)
        if confirm is None:
            # cancelled
            self.regenerate_captcha()
            return
        if pwd != confirm:
            messagebox.showerror("Signup", "Passwords do not match.")
            self.regenerate_captcha()
            return
        # validate password
        if not is_valid_password(pwd):
            messagebox.showerror(
                "Invalid Password",
                "Password must contain:\n"
                "- At least one UPPERCASE letter\n"
                "- At least one number\n"
                "- At least one special character (@#$%^&+=!)\n"
                "- Length between 6 and 20 characters"
            )
            self.regenerate_captcha()
            return
        users.setdefault("clients", {})[uname] = pwd
        save_json(USERS_FILE, users)
        messagebox.showinfo("Signup", "Signup successful. You can now login.")
        # reset fields and captcha
        self.username_var.set("")
        self.password_var.set("")
        self.captcha_entry_var.set("")
        self.regenerate_captcha()

class AdminFrame(ttk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent, padding=8)
        self.controller = controller

        left = ttk.Frame(self)
        left.pack(side=tk.LEFT, fill=tk.Y, padx=6, pady=6)
        right = ttk.Frame(self)
        right.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=6, pady=6)

        ttk.Label(left, text="Admin Controls", font=("Segoe UI", 12, "bold")).pack(pady=4)
        ttk.Button(left, text="Refresh", command=self.refresh).pack(fill=tk.X, pady=4)
        ttk.Button(left, text="Add Record", command=self.add_record).pack(fill=tk.X, pady=4)
        ttk.Button(left, text="Edit Record", command=self.edit_selected_record).pack(fill=tk.X, pady=4)
        ttk.Button(left, text="Delete Record", command=self.delete_selected_record).pack(fill=tk.X, pady=4)
        ttk.Button(left, text="View Logs", command=self.view_logs).pack(fill=tk.X, pady=4)
        ttk.Button(left, text="Add Admin", command=self.add_admin).pack(fill=tk.X, pady=4)
        ttk.Button(left, text="Back Home", command=self.back_home).pack(fill=tk.X, pady=12)

        filterfrm = ttk.Frame(left)
        filterfrm.pack(fill=tk.X, pady=8)
        ttk.Label(filterfrm, text="Filter (plate / owner):").pack(anchor="w")
        self.filter_var = tk.StringVar()
        ent = ttk.Entry(filterfrm, textvariable=self.filter_var)
        ent.pack(fill=tk.X, pady=4)
        ent.bind("<KeyRelease>", lambda e: self.refresh())
        ttk.Button(filterfrm, text="Clear", command=lambda: (self.filter_var.set(""), self.refresh())).pack(fill=tk.X)

        cols = ("plate","owner_name","vehicle_type","vehicle_company","vehicle_model","owner_address","registration_date","owner_username")
        self.tree = ttk.Treeview(right, columns=cols, show="headings")
        headings = {
            "plate":"License Plate",
            "owner_name":"Owner Name",
            "vehicle_type":"Vehicle Type",
            "vehicle_company":"Company",
            "vehicle_model":"Model",
            "owner_address":"Address",
            "registration_date":"Registration Date",
            "owner_username":"Owner Username"
        }
        for c in cols:
            self.tree.heading(c, text=headings[c])
            self.tree.column(c, width=120, anchor="center")
        self.tree.pack(fill=tk.BOTH, expand=True)
        vsb = ttk.Scrollbar(right, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscroll=vsb.set)
        vsb.pack(side=tk.RIGHT, fill=tk.Y)

    def back_home(self):
        self.controller.logout()

    def refresh(self):
        for r in self.tree.get_children():
            self.tree.delete(r)
        data = load_json(DATA_FILE)
        flt = self.filter_var.get().strip().lower()
        for plate, info in sorted(data.items()):
            if flt:
                if flt not in plate.lower() and flt not in info.get("owner_name","").lower():
                    continue
            row = (plate,
                   info.get("owner_name",""),
                   info.get("vehicle_type",""),
                   info.get("vehicle_company",""),
                   info.get("vehicle_model",""),
                   info.get("owner_address",""),
                   info.get("registration_date",""),
                   info.get("owner_username",""))
            self.tree.insert("", tk.END, values=row)

    def get_selected_plate(self):
        sel = self.tree.selection()
        if not sel:
            messagebox.showwarning("Select", "Please select a record in the table.")
            return None
        item = self.tree.item(sel[0])["values"]
        if not item:
            return None
        return item[0]

    def add_record(self):
        AddEditRecordWindow(self, mode="add", role="admin")

    def edit_selected_record(self):
        plate = self.get_selected_plate()
        if not plate:
            return
        AddEditRecordWindow(self, mode="edit", role="admin", plate=plate)

    def delete_selected_record(self):
        plate = self.get_selected_plate()
        if not plate:
            return
        if messagebox.askyesno("Confirm Delete", f"Delete record {plate}?"):
            push_undo_state()
            data = load_json(DATA_FILE)
            if plate in data:
                del data[plate]
                save_json(DATA_FILE, data)
                messagebox.showinfo("Deleted", f"Record {plate} deleted.")
                self.refresh()
            else:
                messagebox.showerror("Error", "Record not found.")

    def view_logs(self):
        logs = load_json(LOG_FILE)
        if not logs:
            messagebox.showinfo("Logs", "No logs yet.")
            return
        dlg = tk.Toplevel(self)
        dlg.title("Client Search Logs")
        dlg.geometry("600x400")
        txt = tk.Text(dlg, wrap="word")
        txt.pack(fill=tk.BOTH, expand=True)
        for user, history in logs.items():
            txt.insert(tk.END, f"{user}:\n")
            txt.insert(tk.END, "  " + ", ".join(history) + "\n\n")
        txt.config(state=tk.DISABLED)
        ttk.Button(dlg, text="Close", command=dlg.destroy).pack(pady=6)

    def add_admin(self):
        users = load_json(USERS_FILE)
        def do_add():
            uname = e_uname.get().strip()
            pwd = e_pwd.get().strip()
            if not uname or not pwd:
                messagebox.showerror("Input", "Provide username and password.")
                return
            if uname in users.get("admin", {}):
                messagebox.showerror("Exists", "Admin already exists.")
                return
            users.setdefault("admin", {})[uname] = pwd
            save_json(USERS_FILE, users)
            messagebox.showinfo("Added", f"Admin '{uname}' added.")
            top.destroy()
        top = tk.Toplevel(self)
        top.title("Add Admin")
        top.geometry("320x160")
        ttk.Label(top, text="New admin username:").pack(pady=4)
        e_uname = ttk.Entry(top); e_uname.pack(pady=4)
        ttk.Label(top, text="Password:").pack(pady=4)
        e_pwd = ttk.Entry(top, show="*"); e_pwd.pack(pady=4)
        ttk.Button(top, text="Add", command=do_add).pack(pady=8)

class ClientFrame(ttk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent, padding=8)
        self.controller = controller
        top = ttk.Frame(self)
        top.pack(fill=tk.X, padx=6, pady=6)

        left = ttk.Frame(top)
        left.pack(side=tk.LEFT, fill=tk.X, expand=True)
        ttk.Label(left, text="Client Actions", font=("Segoe UI", 12, "bold")).pack(anchor="w")
        btn_add = ttk.Button(left, text="Add your vehicle", command=self.add_vehicle)
        btn_add.pack(side=tk.LEFT, padx=4)
        btn_view_mine = ttk.Button(left, text="View My Vehicles", command=self.view_my_vehicles)
        btn_view_mine.pack(side=tk.LEFT, padx=4)
        btn_edit_selected = ttk.Button(left, text="Edit Selected Vehicle", command=self.edit_selected_vehicle)
        btn_edit_selected.pack(side=tk.LEFT, padx=4)

        right = ttk.Frame(top)
        right.pack(side=tk.RIGHT, fill=tk.X)
        ttk.Label(right, text="Search by plate:").pack(side=tk.LEFT, padx=4)
        self.search_var = tk.StringVar()
        ent = ttk.Entry(right, textvariable=self.search_var)
        ent.pack(side=tk.LEFT, padx=4)
        ent.bind("<Return>", lambda e: self.do_search())
        ttk.Button(right, text="Search", command=self.do_search).pack(side=tk.LEFT, padx=4)

        cols = ("plate","owner_name","vehicle_type","vehicle_company","vehicle_model","owner_address","registration_date","owner_username")
        self.tree = ttk.Treeview(self, columns=cols, show="headings", height=15)
        headings = {
            "plate":"License Plate",
            "owner_name":"Owner Name",
            "vehicle_type":"Vehicle Type",
            "vehicle_company":"Company",
            "vehicle_model":"Model",
            "owner_address":"Address",
            "registration_date":"Registration Date",
            "owner_username":"Owner Username"
        }
        for c in cols:
            self.tree.heading(c, text=headings[c])
            self.tree.column(c, width=120, anchor="center")
        self.tree.pack(fill=tk.BOTH, expand=True, padx=6, pady=6)
        vsb = ttk.Scrollbar(self, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscroll=vsb.set)
        vsb.pack(side=tk.RIGHT, fill=tk.Y)

    def refresh(self):
        # clear tree
        for r in self.tree.get_children():
            self.tree.delete(r)

    def add_vehicle(self):
        AddEditRecordWindow(self, mode="add", role="client", owner_username=self.controller.current_user)

    def view_my_vehicles(self):
        self.refresh()
        data = load_json(DATA_FILE)
        username = self.controller.current_user
        owned = [(p, info) for p, info in sorted(data.items()) if info.get("owner_username") == username]
        if not owned:
            messagebox.showinfo("No vehicles", "You have no registered vehicles.")
            return
        for plate, info in owned:
            row = (plate,
                   info.get("owner_name",""),
                   info.get("vehicle_type",""),
                   info.get("vehicle_company",""),
                   info.get("vehicle_model",""),
                   info.get("owner_address",""),
                   info.get("registration_date",""),
                   info.get("owner_username",""))
            self.tree.insert("", tk.END, values=row)

    def edit_selected_vehicle(self):
        sel = self.tree.selection()
        if not sel:
            messagebox.showwarning("Select", "Please select one of your vehicles in the table to edit.")
            return
        item = self.tree.item(sel[0])["values"]
        if not item:
            messagebox.showwarning("Select", "Invalid selection.")
            return
        plate = item[0]
        # check ownership before allowing edit
        data = load_json(DATA_FILE)
        record = data.get(plate)
        if not record:
            messagebox.showerror("Error", "Record not found.")
            return
        if record.get("owner_username") != self.controller.current_user:
            messagebox.showerror("Permission", "You can only edit your own vehicles.")
            return
        # open edit popup (role=client)
        AddEditRecordWindow(self, mode="edit", role="client", plate=plate, owner_username=self.controller.current_user)

    def do_search(self):
        plate = self.search_var.get().strip().upper()
        data = load_json(DATA_FILE)
        for r in self.tree.get_children():
            self.tree.delete(r)
        if not plate:
            messagebox.showwarning("Input", "Enter a license plate to search.")
            return
        if plate in data:
            info = data[plate]
            row = (plate,
                   info.get("owner_name",""),
                   info.get("vehicle_type",""),
                   info.get("vehicle_company",""),
                   info.get("vehicle_model",""),
                   info.get("owner_address",""),
                   info.get("registration_date",""),
                   info.get("owner_username",""))
            self.tree.insert("", tk.END, values=row)
        else:
            messagebox.showinfo("Search", "No record found.")
        logs = load_json(LOG_FILE)
        logs.setdefault(self.controller.current_user or "anonymous", []).append(plate)
        save_json(LOG_FILE, logs)

# ---------- Add/Edit Record Window ----------
class AddEditRecordWindow:
    """
    Popup-style overlay using an in-window Frame that disables parent widgets visually.
    For clients: allow editing of owner_name, vehicle_type, vehicle_company, vehicle_model,
                 owner_address, registration_date (owner_username readonly)
    For admins: can edit all fields (except plate when editing)
    """
    def __init__(self, parent_frame, mode="add", role="admin", plate=None, owner_username=None):
        self.parent_frame = parent_frame
        self.controller = parent_frame.controller
        self.mode = mode
        self.role = role
        self.plate = plate
        self.owner_username = owner_username or (self.controller.current_user if role=="client" else "N/A")

        # overlay frame
        self.overlay = ttk.Frame(self.controller.container, relief="raised", borderwidth=2)
        self.overlay.place(relx=0.08, rely=0.06, relwidth=0.84, relheight=0.88)
        head_text = ("Add New Record" if mode=="add" else f"Edit Record: {plate}")
        ttk.Label(self.overlay, text=head_text, font=("Segoe UI", 13, "bold")).pack(pady=6)
        form = ttk.Frame(self.overlay)
        form.pack(padx=10, pady=6, fill=tk.BOTH, expand=True)

        self.vars = {
            "plate": tk.StringVar(value=self.plate if self.plate else ""),
            "owner_name": tk.StringVar(),
            "vehicle_type": tk.StringVar(),
            "vehicle_company": tk.StringVar(),
            "vehicle_model": tk.StringVar(),
            "owner_address": tk.StringVar(),
            "registration_date": tk.StringVar(),
            "owner_username": tk.StringVar(value=self.owner_username)
        }

        if mode == "edit" and plate:
            data = load_json(DATA_FILE)
            rec = data.get(plate)
            if rec:
                self.vars["owner_name"].set(rec.get("owner_name",""))
                self.vars["vehicle_type"].set(rec.get("vehicle_type",""))
                self.vars["vehicle_company"].set(rec.get("vehicle_company",""))
                self.vars["vehicle_model"].set(rec.get("vehicle_model",""))
                self.vars["owner_address"].set(rec.get("owner_address",""))
                self.vars["registration_date"].set(rec.get("registration_date",""))
                self.vars["owner_username"].set(rec.get("owner_username",""))

        labels = [
            ("License Plate", "plate"),
            ("Owner Name", "owner_name"),
            ("Vehicle Type", "vehicle_type"),
            ("Company", "vehicle_company"),
            ("Model", "vehicle_model"),
            ("Owner Address", "owner_address"),
            ("Registration Date (YYYY-MM-DD)", "registration_date"),
            ("Owner Username", "owner_username")
        ]
        for i, (lab, key) in enumerate(labels):
            ttk.Label(form, text=lab).grid(row=i, column=0, sticky="e", padx=6, pady=4)
            ent_state = "readonly" if (key=="plate" and mode=="edit") else "normal"
            e = ttk.Entry(form, textvariable=self.vars[key], state=ent_state)
            e.grid(row=i, column=1, sticky="we", padx=6, pady=4)
            # client should not edit owner_username
            if key == "owner_username" and role == "client":
                e["state"] = "readonly"
        form.columnconfigure(1, weight=1)

        btnfrm = ttk.Frame(self.overlay)
        btnfrm.pack(pady=8)
        ttk.Button(btnfrm, text="Save", command=self.save).pack(side=tk.LEFT, padx=6)
        if mode == "edit":
            ttk.Button(btnfrm, text="Undo Last Change", command=self.undo_action).pack(side=tk.LEFT, padx=6)
        ttk.Button(btnfrm, text="Cancel", command=self.close).pack(side=tk.LEFT, padx=6)

        self.disable_parent_widgets()

    def disable_parent_widgets(self):
        self.disabled = []
        for child in self.parent_frame.winfo_children():
            try:
                child_state = child.cget("state")
                child.configure(state="disabled")
                self.disabled.append((child, child_state))
            except Exception:
                pass

    def enable_parent_widgets(self):
        for w, st in getattr(self, "disabled", []):
            try:
                w.configure(state=st)
            except Exception:
                pass

    def close(self):
        self.overlay.destroy()
        self.enable_parent_widgets()
        try:
            self.parent_frame.refresh()
        except Exception:
            pass
        try:
            self.controller.frames["AdminFrame"].refresh()
        except Exception:
            pass
        try:
            self.controller.frames["ClientFrame"].refresh()
        except Exception:
            pass

    def undo_action(self):
        undone = undo_last_change_confirm(self.overlay)
        if undone:
            self.close()

    def save(self):
        plate = self.vars["plate"].get().strip().upper()
        if not plate:
            messagebox.showerror("Input", "License plate is required.", parent=self.overlay)
            return
        data = load_json(DATA_FILE)
        if self.mode == "add":
            if plate in data:
                messagebox.showerror("Exists", "A record with that plate already exists.", parent=self.overlay)
                return
            push_undo_state()
            data[plate] = {
                "owner_name": self.vars["owner_name"].get().strip(),
                "vehicle_type": self.vars["vehicle_type"].get().strip(),
                "vehicle_company": self.vars["vehicle_company"].get().strip(),
                "vehicle_model": self.vars["vehicle_model"].get().strip(),
                "owner_address": self.vars["owner_address"].get().strip(),
                "registration_date": self.vars["registration_date"].get().strip(),
                "owner_username": self.vars["owner_username"].get().strip() or (self.controller.current_user if self.role=="client" else "N/A")
            }
            save_json(DATA_FILE, data)
            messagebox.showinfo("Added", f"Record {plate} added.", parent=self.overlay)
            self.close()
        else:
            if plate not in data:
                messagebox.showerror("Not found", "Record not found.", parent=self.overlay)
                return
            if self.role == "client":
                rec = data[plate]
                if rec.get("owner_username") != self.controller.current_user:
                    messagebox.showerror("Permission", "You can only edit your own vehicles.", parent=self.overlay)
                    return
                push_undo_state()
                rec["owner_name"] = self.vars["owner_name"].get().strip()
                rec["vehicle_type"] = self.vars["vehicle_type"].get().strip()
                rec["vehicle_company"] = self.vars["vehicle_company"].get().strip()
                rec["vehicle_model"] = self.vars["vehicle_model"].get().strip()
                rec["owner_address"] = self.vars["owner_address"].get().strip()
                rec["registration_date"] = self.vars["registration_date"].get().strip()
                rec["owner_username"] = self.controller.current_user
                save_json(DATA_FILE, data)
                messagebox.showinfo("Updated", f"Record {plate} updated.", parent=self.overlay)
                self.close()
            else:
                push_undo_state()
                data[plate] = {
                    "owner_name": self.vars["owner_name"].get().strip(),
                    "vehicle_type": self.vars["vehicle_type"].get().strip(),
                    "vehicle_company": self.vars["vehicle_company"].get().strip(),
                    "vehicle_model": self.vars["vehicle_model"].get().strip(),
                    "owner_address": self.vars["owner_address"].get().strip(),
                    "registration_date": self.vars["registration_date"].get().strip(),
                    "owner_username": self.vars["owner_username"].get().strip() or "N/A"
                }
                save_json(DATA_FILE, data)
                messagebox.showinfo("Updated", f"Record {plate} updated.", parent=self.overlay)
                self.close()

# ---------- Main ----------
def main():
    setup_all_defaults()
    app = LicenseApp()
    app.mainloop()

if __name__ == "__main__":
    main()
