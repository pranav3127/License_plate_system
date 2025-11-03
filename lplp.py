import json
import os
import getpass
from tabulate import tabulate
from copy import deepcopy
import random

DATA_FILE = "license_data.json"
LOG_FILE = "search_log.json"
USERS_FILE = "users.json"
UNDO_FILE = "undo_stack.json"

def load_data(file):
    if not os.path.exists(file):
        with open(file, "w") as f:
            json.dump({}, f)
    with open(file, "r") as f:
        return json.load(f)

def save_data(file, data):
    with open(file, "w") as f:
        json.dump(data, f, indent=4)

def push_undo_state(data):
    stack = {"last_state": deepcopy(data)}
    save_data(UNDO_FILE, stack)

def undo_last_change_confirm():
    if not os.path.exists(UNDO_FILE):
        print("No previous state to undo.")
        return False
    stack = load_data(UNDO_FILE)
    if "last_state" not in stack or not stack["last_state"]:
        print("Nothing to undo.")
        return False
    confirm = input("Are you sure you want to undo the last change? (Y/N): ").strip().lower()
    if confirm in ("y", "yes"):
        prev_data = stack["last_state"]
        save_data(DATA_FILE, prev_data)
        print("✅ Undo successful — last change reverted.")
        return True
    else:
        print("Undo cancelled.")
        return False

def setup_default_users():
    users = load_data(USERS_FILE)
    if "admin" not in users:
        users["admin"] = {"pranav": "pranav"}
    else:
        users["admin"]["pranav"] = users["admin"].get("pranav", "pranav")
    if "clients" not in users:
        clients = {}
        for i in range(1, 16):
            clients[f"client{i}"] = "password"
        users["clients"] = clients
    save_data(USERS_FILE, users)

def setup_default_data():
    data = load_data(DATA_FILE)
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
    save_data(DATA_FILE, data_out)

def admin_login():
    users = load_data(USERS_FILE)
    username = input("Admin Username: ")
    password = getpass.getpass("Admin Password: ")
    if username in users.get("admin", {}) and users["admin"][username] == password:
        print("\nLogin successful.\n")
        return username
    else:
        print("\nInvalid credentials.\n")
        return None

def client_signup():
    users = load_data(USERS_FILE)
    username = input("Choose a username: ")
    if username in users["clients"]:
        print("Username already exists. Please login instead.")
        return None
    password = getpass.getpass("Choose a password: ")
    confirm = getpass.getpass("Confirm password: ")
    if password != confirm:
        print("Passwords do not match.")
        return None
    users["clients"][username] = password
    save_data(USERS_FILE, users)
    print("\nSignup successful! You can now log in.\n")
    return username

def client_login():
    users = load_data(USERS_FILE)
    print("\n1. Login")
    print("2. Signup")
    choice = input("Enter choice: ").strip()
    if choice == "2":
        username = client_signup()
        return username
    username = input("Client Username: ")
    password = getpass.getpass("Client Password: ")
    if username in users.get("clients", {}) and users["clients"][username] == password:
        print("\nLogin successful.\n")
        return username
    else:
        print("\nInvalid credentials.\n")
        return None

def add_new_admin():
    users = load_data(USERS_FILE)
    new_admin = input("Enter new admin username: ")
    if new_admin in users.get("admin", {}):
        print("Admin already exists.")
        return
    new_pass = getpass.getpass("Enter new admin password: ")
    users["admin"][new_admin] = new_pass
    save_data(USERS_FILE, users)
    print(f"New admin '{new_admin}' added successfully.")

def display_table(data):
    if not data:
        print("No vehicle data available.")
        return
    table = []
    headers = ["License Plate","Owner Name","Vehicle Type","Company","Model","Address","Registration Date","Owner Username"]
    for plate, info in sorted(data.items()):
        row = [
            plate,
            info.get("owner_name",""),
            info.get("vehicle_type",""),
            info.get("vehicle_company",""),
            info.get("vehicle_model",""),
            info.get("owner_address",""),
            info.get("registration_date",""),
            info.get("owner_username","")
        ]
        table.append(row)
    print("\n" + tabulate(table, headers=headers, tablefmt="fancy_grid"))

def display_single_record_table(plate, info):
    headers = ["License Plate","Owner Name","Vehicle Type","Company","Model","Address","Registration Date","Owner Username"]
    row = [[
        plate,
        info.get("owner_name",""),
        info.get("vehicle_type",""),
        info.get("vehicle_company",""),
        info.get("vehicle_model",""),
        info.get("owner_address",""),
        info.get("registration_date",""),
        info.get("owner_username","")
    ]]
    print("\n" + tabulate(row, headers=headers, tablefmt="fancy_grid"))

def edit_vehicle_info_admin(data, plate):
    info = data[plate]
    while True:
        print(f"\nEditing record for: {plate}")
        print("1. Owner Name")
        print("2. Vehicle Type")
        print("3. Vehicle Company")
        print("4. Vehicle Model")
        print("5. Owner Address")
        print("6. Registration Date")
        print("7. Owner Username")
        print("8. Undo Last Change")
        print("9. Done")
        choice = input("Select field to edit: ").strip()
        if choice in {"1","2","3","4","5","6","7"}:
            push_undo_state(load_data(DATA_FILE))
        if choice == "1":
            info["owner_name"] = input("New Owner Name: ")
        elif choice == "2":
            info["vehicle_type"] = input("New Vehicle Type: ")
        elif choice == "3":
            info["vehicle_company"] = input("New Vehicle Company: ")
        elif choice == "4":
            info["vehicle_model"] = input("New Vehicle Model: ")
        elif choice == "5":
            info["owner_address"] = input("New Owner Address: ")
        elif choice == "6":
            info["registration_date"] = input("New Registration Date (YYYY-MM-DD): ")
        elif choice == "7":
            info["owner_username"] = input("New Owner Username (client's username): ")
        elif choice == "8":
            undone = undo_last_change_confirm()
            if undone:
                current = load_data(DATA_FILE)
                if plate not in current:
                    print("The record you were editing no longer exists after undo.")
                    return
                info = current[plate]
                data.clear()
                data.update(current)
            continue
        elif choice == "9":
            break
        else:
            print("Invalid choice.")
            continue
        save_data(DATA_FILE, data)
        print("Record updated.")

def admin_menu(username):
    while True:
        print(f"\n=== ADMIN MENU (Logged in as {username}) ===")
        print("1. View client search logs")
        print("2. Add license plate info")
        print("3. Edit license plate info")
        print("4. Delete license plate info")
        print("5. View all license plate data (Tabular Form)")
        print("6. Add new admin")
        print("7. Logout")
        choice = input("Enter choice: ").strip()
        data = load_data(DATA_FILE)
        logs = load_data(LOG_FILE)
        if choice == "1":
            if logs:
                print("\n--- Client Search Logs ---")
                for user, history in logs.items():
                    print(f"{user}: {history}")
            else:
                print("No logs yet.")
        elif choice == "2":
            plate = input("License Plate: ").upper()
            if plate in data:
                print("Already exists.")
                continue
            push_undo_state(load_data(DATA_FILE))
            owner_username = input("Owner username (optional, press enter for N/A): ").strip() or "N/A"
            data[plate] = {
                "owner_name": input("Owner Name: "),
                "vehicle_type": input("Vehicle Type: "),
                "vehicle_company": input("Vehicle Company: "),
                "vehicle_model": input("Vehicle Model: "),
                "owner_address": input("Owner Address: "),
                "registration_date": input("Registration Date (YYYY-MM-DD): "),
                "owner_username": owner_username
            }
            save_data(DATA_FILE, data)
            print("Record added.")
        elif choice == "3":
            plate = input("License Plate to edit: ").upper()
            if plate not in data:
                print("Not found.")
                continue
            edit_vehicle_info_admin(data, plate)
        elif choice == "4":
            plate = input("License Plate to delete: ").upper()
            if plate in data:
                push_undo_state(load_data(DATA_FILE))
                del data[plate]
                save_data(DATA_FILE, data)
                print("Record deleted.")
            else:
                print("Not found.")
        elif choice == "5":
            display_table(data)
        elif choice == "6":
            add_new_admin()
        elif choice == "7":
            break
        else:
            print("Invalid choice.")

def edit_vehicle_info_client(data, plate, username):
    info = data[plate]
    while True:
        print(f"\nEditing your vehicle info for: {plate}")
        print("1. Vehicle Type")
        print("2. Vehicle Company")
        print("3. Vehicle Model")
        print("4. Owner Address")
        print("5. Registration Date")
        print("6. Done")
        choice = input("Select field to edit: ").strip()
        if choice in {"1","2","3","4","5"}:
            push_undo_state(load_data(DATA_FILE))
        if choice == "1":
            info["vehicle_type"] = input("New Vehicle Type: ")
        elif choice == "2":
            info["vehicle_company"] = input("New Vehicle Company: ")
        elif choice == "3":
            info["vehicle_model"] = input("New Vehicle Model: ")
        elif choice == "4":
            info["owner_address"] = input("New Owner Address: ")
        elif choice == "5":
            info["registration_date"] = input("New Registration Date (YYYY-MM-DD): ")
        elif choice == "6":
            break
        else:
            print("Invalid choice.")
            continue
        info["owner_username"] = username
        save_data(DATA_FILE, data)
        print("Record updated.")

def client_menu(username):
    while True:
        print(f"\n=== CLIENT MENU (Logged in as {username}) ===")
        print("1. Add your vehicle info")
        print("2. Edit your vehicle info")
        print("3. Search vehicle by license plate")
        print("4. Logout")
        choice = input("Enter choice: ").strip()
        data = load_data(DATA_FILE)
        logs = load_data(LOG_FILE)
        if choice == "1":
            plate = input("Your License Plate: ").upper()
            if plate in data:
                print("A record with that plate already exists.")
                continue
            data[plate] = {
                "owner_name": input("Owner Name: "),
                "vehicle_type": input("Vehicle Type: "),
                "vehicle_company": input("Vehicle Company: "),
                "vehicle_model": input("Vehicle Model: "),
                "owner_address": input("Owner Address: "),
                "registration_date": input("Registration Date (YYYY-MM-DD): "),
                "owner_username": username
            }
            save_data(DATA_FILE, data)
            print("Vehicle added.")
        elif choice == "2":
            owned = [p for p, info in data.items() if info.get("owner_username") == username]
            if not owned:
                print("You have no registered vehicles.")
                continue
            print("Your Vehicles:", ", ".join(owned))
            plate = input("Enter license plate to edit: ").upper()
            if plate not in owned:
                print("You can only edit your own vehicles.")
                continue
            edit_vehicle_info_client(data, plate, username)
        elif choice == "3":
            plate = input("Enter License Plate to search: ").upper()
            if plate in data:
                display_single_record_table(plate, data[plate])
            else:
                print("\nNo record found.")
            logs.setdefault(username, []).append(plate)
            save_data(LOG_FILE, logs)
        elif choice == "4":
            break
        else:
            print("Invalid choice.")

def main():
    setup_default_users()
    setup_default_data()
    while True:
        print("\n=== LICENSE PLATE INFORMATION SYSTEM ===")
        print("1. Admin")
        print("2. Client")
        print("3. Exit")
        choice = input("Enter choice: ").strip()
        if choice == "1":
            username = admin_login()
            if username:
                admin_menu(username)
        elif choice == "2":
            username = client_login()
            if username:
                client_menu(username)
        elif choice == "3":
            print("Goodbye!")
            break
        else:
            print("Invalid choice.")

if __name__ == "__main__":
    main()
