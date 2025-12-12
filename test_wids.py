import os
import json
import pyttsx3
import threading
import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
from scapy.all import Ether, ARP, srp, conf
import sys
import socket

# --- 1. BACKEND LOGIC ---

def get_app_data_dir():
    """
    Gets the appropriate directory for storing app data (logs, settings).
    This ensures data persists when run as a PyInstaller .exe.
    """
    try:
        if getattr(sys, 'frozen', False):
            # --- PRODUCTION MODE (.exe) ---
            app_data_dir = os.getenv('LOCALAPPDATA')
            if not app_data_dir:
                app_data_dir = os.path.expanduser("~")
                app_dir_name = ".NetworkPatrol"
            else:
                app_dir_name = "NetworkPatrol"
            final_path = os.path.join(app_data_dir, app_dir_name, "logs")
        else:
            # --- DEVELOPMENT MODE (.py) ---
            script_dir = os.path.dirname(os.path.abspath(__file__))
            final_path = os.path.join(script_dir, "logs")
        
        os.makedirs(final_path, exist_ok=True)
        return final_path
    except Exception as e:
        print(f"Error creating app data dir: {e}")
        # Fallback to a simple logs folder
        os.makedirs("logs", exist_ok=True)
        return "logs"

# --- Define Permanent File Paths ---
LOGS_DIR = get_app_data_dir()
KNOWN_DEVICES_FILE = os.path.join(LOGS_DIR, "known_devices.json")

def speak_async(text):
    """Run pyttsx3 in a separate thread to avoid blocking the GUI."""
    def speak():
        try:
            engine = pyttsx3.init()
            engine.setProperty('rate', 150)
            engine.setProperty('volume', 1.0)
            engine.say(text)
            engine.runAndWait()
        except Exception as e:
            print(f"Error in text-to-speech: {e}")
    
    # Start the speech in a new thread
    threading.Thread(target=speak, daemon=True).start()

def load_known_devices():
    """Loads the known device list from JSON."""
    if not os.path.exists(KNOWN_DEVICES_FILE):
        return {}  # Return an empty dictionary

    try:
        with open(KNOWN_DEVICES_FILE, "r") as f:
            data = json.load(f)

        # --- Automatic Conversion Logic ---
        # Check if data is an old 'list'
        if isinstance(data, list):
            print("Old 'list' format detected. Converting to new 'dict' format...")
            new_dict = {}
            for item in data:
                if isinstance(item, dict) and 'mac' in item:
                    # Sanitize the MAC address
                    mac = item['mac'].lower().strip()
                    # Use a default name if not present
                    name = item.get('name', f"Known Device ({mac[-5:]})")
                    new_dict[mac] = name
            
            # Save the new format back to the file
            save_known_devices(new_dict)
            return new_dict
        
        # If it's already a dict, sanitize MAC keys
        if isinstance(data, dict):
            return {k.lower().strip(): v for k, v in data.items()}

        return {} # Default to empty dict if format is unknown

    except (json.JSONDecodeError, IOError):
        print("Error reading known_devices.json. Starting fresh.")
        return {}

def save_known_devices(devices_dict):
    """Saves the known device list (dict) to a JSON file."""
    try:
        with open(KNOWN_DEVICES_FILE, "w") as f:
            # Sanitize keys one last time before saving
            sanitized_dict = {k.lower().strip(): v for k, v in devices_dict.items()}
            json.dump(sanitized_dict, f, indent=4)
    except IOError as e:
        print(f"Error saving known_devices.json: {e}")

def get_default_network_range():
    """Helper to guess the local network range (e.g. 192.168.1.0/24)."""
    try:
        # Get local IP address
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # Connect to a public DNS (doesn't actually send data) to get local IP
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        
        # Assume /24 subnet (Standard for home/office)
        # Convert 192.168.1.5 -> 192.168.1.0/24
        ip_parts = local_ip.split('.')
        network_base = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.0/24"
        return network_base
    except Exception:
        return "192.168.0.0/24" # Fallback default

def scan_network_scapy(network_range):
    """
    Performs a Scapy ARP scan on the network provided.
    Auto-detects the correct interface (Wi-Fi or Ethernet).
    """
    devices = []
    error_msg = None
    
    try:
        # Auto-detect the best interface
        interface = conf.iface
        if not interface or interface.name == 'lo':
             # Try to force reload iface list
             conf.iface = conf.route.route("0.0.0.0")[0]
             interface = conf.iface

        print(f"Scanning network {network_range} on interface {interface.name}...")

        arp_request = ARP(pdst=network_range)
        ether_frame = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether_frame / arp_request

        answered_list = srp(packet, timeout=5, verbose=False, iface=interface)[0]
        
        for sent, received in answered_list:
            devices.append({"ip": received.psrc, "mac": received.hwsrc.lower().strip()})
            
        if len(devices) <= 2 and not any(d['ip'] == network_range.split('/')[0] for d in devices):
             # Only show AP isolation warning if we found almost nothing
             # AND we are fairly sure the scan ran
             pass 

    except Exception as e:
        print(f"Scapy scan failed: {e}")
        error_msg = (f"Network Scan Error:\n{e}\n\n"
                     "1. Make sure Npcap is installed.\n"
                     "2. Run this app as an Administrator.\n"
                     "3. Check if the Network Range is correct.")

    return devices, error_msg

# --- 2. GUI (Connecting the backend) ---

class NetworkPatrolApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Network Patrol")
        self.root.geometry("950x600")
        self.root.minsize(800, 500)

        # Load data
        self.known_devices = load_known_devices() # This is a dict: {'mac': 'name'}
        self.current_ip_map = {} # Stores {'mac': 'ip'} from the last scan

        # --- Styles ---
        style = ttk.Style()
        style.configure("Header.TFrame", background="#f0f0f0")
        style.configure("Scan.TButton", font=("Helvetica", 10, "bold"), padding=5)
        style.configure("TLabel", font=("Helvetica", 10))
        style.configure("Header.TLabel", font=("Helvetica", 12, "bold"))
        style.configure("Treeview.Heading", font=("Helvetica", 10, "bold"))
        style.configure("Status.TLabel", font=("Helvetica", 9))
        style.configure("TFrame", background="white")

        # --- Header ---
        header_frame = ttk.Frame(root, style="Header.TFrame", padding=(10, 5))
        header_frame.pack(fill="x", side="top")

        # INPUT: Network Range Label
        ttk.Label(header_frame, text="Network Range:", background="#f0f0f0").pack(side="left", padx=(10, 2))
        
        # INPUT: Network Range Entry Box
        self.network_entry = ttk.Entry(header_frame, width=18)
        self.network_entry.pack(side="left", padx=5)
        # Pre-fill with auto-detected network
        self.network_entry.insert(0, get_default_network_range())

        self.scan_button = ttk.Button(
            header_frame,
            text="Scan Network",
            command=self.start_scan_thread,
            style="Scan.TButton"
        )
        self.scan_button.pack(side="left", padx=10, pady=10)

        self.status_label = ttk.Label(header_frame, text="Ready.", style="Status.TLabel", background="#f0f0f0")
        self.status_label.pack(side="left", padx=10, fill="x", expand=True)

        self.status_indicator = ttk.Progressbar(header_frame, length=100, mode='indeterminate')

        # --- Main Content Panes ---
        main_pane = ttk.PanedWindow(root, orient="horizontal")
        main_pane.pack(fill="both", expand=True, side="top", padx=10, pady=10)

        # --- Left Pane: Unknown Devices ---
        unknown_frame = ttk.Frame(main_pane, padding=10)
        main_pane.add(unknown_frame, weight=1)
        
        ttk.Label(unknown_frame, text="Unknown Devices Found", style="Header.TLabel").pack(pady=5, anchor="w")

        self.unknown_tree = self.create_device_tree(unknown_frame)
        self.unknown_tree.pack(fill="both", expand=True)

        # --- Middle Pane: Control Buttons ---
        button_frame = ttk.Frame(main_pane, padding=(10, 100))
        button_frame.pack(fill="y")
        main_pane.add(button_frame)
        
        ttk.Button(button_frame, text="Trust >>", command=self.trust_selected).pack(pady=10, fill="x")
        ttk.Button(button_frame, text="<< Forget", command=self.forget_selected).pack(pady=10, fill="x")

        # --- Right Pane: Known Devices ---
        known_frame = ttk.Frame(main_pane, padding=10)
        main_pane.add(known_frame, weight=1)

        ttk.Label(known_frame, text="Known (Trusted) Devices", style="Header.TLabel").pack(pady=5, anchor="w")
        
        self.known_tree = self.create_device_tree(known_frame)
        self.known_tree.pack(fill="both", expand=True)
        self.known_tree.bind("<Double-1>", self.on_rename_device)

        # Initial population of known list
        self.populate_known_list()

    def create_device_tree(self, parent):
        """Helper function to create the Treeview widget."""
        cols = ("ip", "mac", "name")
        tree = ttk.Treeview(parent, columns=cols, show="headings")
        tree.heading("ip", text="IP Address")
        tree.column("ip", width=100, anchor="w")
        tree.heading("mac", text="MAC Address")
        tree.column("mac", width=130, anchor="w")
        tree.heading("name", text="Device Name")
        tree.column("name", width=150, anchor="w")
        
        # Add a scrollbar
        scrollbar = ttk.Scrollbar(parent, orient="vertical", command=tree.yview)
        tree.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side="right", fill="y")

        return tree

    def start_scan_thread(self):
        """Starts the network scan in a separate thread."""
        
        # Get the network range from the box
        target_network = self.network_entry.get().strip()
        
        if not target_network:
            messagebox.showerror("Error", "Please enter a network range (e.g. 192.168.0.1/24)")
            return

        self.scan_button.config(state="disabled")
        self.status_label.config(text=f"Scanning {target_network}...")
        self.status_indicator.pack(side="left", padx=5)
        self.status_indicator.start()
        
        # Clear current IPs
        self.current_ip_map.clear()
        
        # Run the scan logic in a daemon thread, passing the target network
        scan_thread = threading.Thread(target=self.run_scan_logic, args=(target_network,), daemon=True)
        scan_thread.start()

    def run_scan_logic(self, network_range):
        """The logic that runs in the background thread."""
        devices, error_msg = scan_network_scapy(network_range)
        
        unknown_devices_found = []
        
        if devices:
            for dev in devices:
                mac = dev['mac'].strip()
                self.current_ip_map[mac] = dev['ip'] # Store current IP
                
                if mac not in self.known_devices:
                    unknown_devices_found.append(dev)

        # Send results back to the main thread
        self.root.after(0, self.update_gui_after_scan, unknown_devices_found, error_msg)

    def update_gui_after_scan(self, unknown_devices_found, error_msg):
        """Updates the GUI from the main thread with scan results."""
        self.scan_button.config(state="normal")
        self.status_indicator.stop()
        self.status_indicator.pack_forget()

        # Clear old results
        for item in self.unknown_tree.get_children():
            self.unknown_tree.delete(item)
            
        # Repopulate both lists
        self.populate_known_list() # Refresh known list to show new IPs/Offline
        self.populate_unknown_list(unknown_devices_found) # Populate new unknown

        # Set status message
        if error_msg:
            self.status_label.config(text="Scan encountered errors.")
            messagebox.showwarning("Scan Warning", error_msg)
        elif unknown_devices_found:
            status_text = f"Scan complete. Found {len(unknown_devices_found)} new device(s)!"
            self.status_label.config(text=status_text)
            speak_async(f"Warning! {len(unknown_devices_found)} unknown devices detected.")
        else:
            self.status_label.config(text="Scan complete. No unknown devices found.")

    def populate_unknown_list(self, devices):
        """Adds devices to the 'Unknown' tree."""
        for dev in devices:
            self.unknown_tree.insert("", "end", values=(dev['ip'], dev['mac'], "N/A (Unknown)"))

    def populate_known_list(self):
        """Refreshes the 'Known' tree with data, showing current IP or 'Offline'."""
        for item in self.known_tree.get_children():
            self.known_tree.delete(item)
            
        for mac, name in self.known_devices.items():
            mac = mac.strip()
            # Get current IP from the last scan, default to 'Offline'
            ip = self.current_ip_map.get(mac, "Offline")
            self.known_tree.insert("", "end", values=(ip, mac, name))

    def trust_selected(self):
        """Moves selected devices from 'Unknown' to 'Known'."""
        selected_items = self.unknown_tree.selection()
        if not selected_items:
            return

        for item_id in selected_items:
            values = self.unknown_tree.item(item_id, "values")
            mac = values[1].strip()
            
            # Ask for a name
            name = simpledialog.askstring(
                "Name Device", 
                f"Enter a name for this device:\nMAC: {mac}",
                parent=self.root
            )
            if not name:
                name = f"Known Device ({mac[-5:]})" # Default name
            
            # Add to known dict and save
            self.known_devices[mac] = name
            self.unknown_tree.delete(item_id) # Remove from unknown tree
        
        save_known_devices(self.known_devices)
        self.populate_known_list() # Refresh known list

    def forget_selected(self):
        """Moves selected devices from 'Known' to 'Unknown' (if still online)."""
        selected_items = self.known_tree.selection()
        if not selected_items:
            return

        if not messagebox.askyesno("Confirm", "Are you sure you want to forget these devices?"):
            return

        for item_id in selected_items:
            values = self.known_tree.item(item_id, "values")
            mac = values[1].strip()
            
            # Remove from known dict and save
            if mac in self.known_devices:
                del self.known_devices[mac]
            
            self.known_tree.delete(item_id) # Remove from known tree
            
            # If device is still online, add back to unknown list
            if mac in self.current_ip_map:
                ip = self.current_ip_map[mac]
                self.unknown_tree.insert("", "end", values=(ip, mac, "N/A (Unknown)"))

        save_known_devices(self.known_devices)

    def on_rename_device(self, event):
        """Handles double-click to rename a known device."""
        try:
            item_id = self.known_tree.identify_row(event.y)
            if not item_id:
                return
                
            self.known_tree.selection_set(item_id) # Highlight the item
            values = self.known_tree.item(item_id, "values")
            mac = values[1].strip()
            old_name = values[2]

            new_name = simpledialog.askstring(
                "Rename Device",
                f"Enter a new name for:\n{mac}",
                initialvalue=old_name,
                parent=self.root
            )

            if new_name and new_name != old_name:
                self.known_devices[mac] = new_name
                save_known_devices(self.known_devices)
                self.populate_known_list() # Refresh list with new name
        except Exception as e:
            print(f"Error renaming: {e}")


# --- 3. Main Execution ---

if __name__ == "__main__":
    # Check for Admin rights on Windows
    if os.name == 'nt':
        try:
            # Try to get admin rights
            os.access("C:\\Windows\\System32\\drivers\\etc\\hosts", os.W_OK)
        except Exception:
             try:
                # Fallback check
                if not (os.environ.get("PROCESSOR_ARCHITECTURE") == "AMD64" and 
                        os.environ.get("PROCESSOR_ARCHITEW6432") == "AMD64"):
                    messagebox.showerror("Admin Rights Required", 
                                         "This application must be run as an Administrator to scan the network.\n\nPlease re-start the app as an Administrator.")
                    sys.exit(1)
             except Exception:
                 print("Warning: Could not check for admin rights. Scanning may fail.")
                 
    # --- Start the GUI ---
    root = tk.Tk()
    app = NetworkPatrolApp(root)
    
    # This call blocks and runs the GUI
    try:
        root.mainloop()
    except Exception as e:
        print(f"GUI Error: {e}")
