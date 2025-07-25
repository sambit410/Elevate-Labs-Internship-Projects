import scapy.all as scapy
from datetime import datetime
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import threading
import logging
import sys
from queue import Queue
import psutil
import socket

# Configure logging with a clean format
logging.basicConfig(
    filename='firewall.log',
    level=logging.INFO,
    format='%(asctime)s | %(levelname)s | %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

# Initial rule set for filtering
RULES = {
    'block_ips': ['192.168.1.100', '10.0.0.50'],  # Blocked IPs
    'block_ports': [23, 445],  # Blocked ports (e.g., Telnet, SMB)
    'allow_protocols': ['TCP', 'UDP']  # Allowed protocols
}

# Common port-to-service mapping
PORT_SERVICES = {
    20: 'FTP-Data', 21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP',
    53: 'DNS', 80: 'HTTP', 110: 'POP3', 143: 'IMAP', 443: 'HTTPS',
    445: 'SMB', 3389: 'RDP'
}

# Queue for GUI log updates
packet_queue = Queue()

# Flag and thread for sniffing control
sniffing_active = False
sniffing_thread = None

# Professional White Theme Colors
COLORS = {
    "primary": "#2c7be5",  # Primary blue
    "primary_dark": "#1a68d1",  # Darker blue
    "primary_light": "#e6f0fd",  # Light blue
    "secondary": "#00d97e",  # Green for actions
    "background": "#f9fbfd",  # Very light gray background
    "surface": "#ffffff",  # White surface/cards
    "error": "#e63757",  # Red for errors/stops
    "warning": "#f6c343",  # Yellow for warnings
    "text_primary": "#12263f",  # Dark text
    "text_secondary": "#6e84a3",  # Gray text
    "border": "#e3ebf6",  # Light border
    "success": "#00ac69",  # Success green
    "highlight": "#f0f5ff"  # Highlight color
}


def get_service_name(port):
    """Return service name for a given port, if known."""
    return PORT_SERVICES.get(port, 'Unknown')


def get_process_name(port, ip, is_source=True):
    """Attempt to get the process name associated with a local port."""
    try:
        local_ips = [addr.address for addr in psutil.net_if_addrs().values() for addr in addr if
                     addr.family == socket.AF_INET]
        for conn in psutil.net_connections(kind='inet'):
            if is_source:
                if conn.laddr.port == port and (conn.laddr.ip in local_ips or conn.laddr.ip == '0.0.0.0'):
                    return psutil.Process(conn.pid).name()
            else:
                if conn.laddr.port == port and (conn.laddr.ip in local_ips or conn.laddr.ip == '0.0.0.0'):
                    return psutil.Process(conn.pid).name()
    except (psutil.NoSuchProcess, psutil.AccessDenied, OSError):
        pass
    return 'Unknown'


def log_packet(packet, action):
    """Log packet details with application and service name."""
    src_ip = packet[scapy.IP].src if scapy.IP in packet else 'N/A'
    dst_ip = packet[scapy.IP].dst if scapy.IP in packet else 'N/A'
    protocol = packet[scapy.IP].proto if scapy.IP in packet else 'N/A'
    src_port = (packet[scapy.TCP].sport if scapy.TCP in packet else
                packet[scapy.UDP].sport if scapy.UDP in packet else 'N/A')
    dst_port = (packet[scapy.TCP].dport if scapy.TCP in packet else
                packet[scapy.UDP].dport if scapy.UDP in packet else 'N/A')

    src_service = get_service_name(src_port) if src_port != 'N/A' else 'N/A'
    dst_service = get_service_name(dst_port) if dst_port != 'N/A' else 'N/A'
    src_app = get_process_name(src_port, src_ip, is_source=True) if src_port != 'N/A' else 'N/A'
    dst_app = get_process_name(dst_port, dst_ip, is_source=False) if dst_port != 'N/A' else 'N/A'

    log_message = (f"Action: {action} | Src: {src_ip}:{src_port} ({src_app}, {src_service}) | "
                   f"Dst: {dst_ip}:{dst_port} ({dst_app}, {dst_service}) | Proto: {protocol}")
    logging.info(log_message)
    packet_queue.put(log_message)


def check_packet(packet):
    """Apply rules to determine if packet should be allowed or blocked."""
    if scapy.IP not in packet:
        log_packet(packet, 'ALLOWED (Non-IP)')
        return True

    src_ip = packet[scapy.IP].src
    dst_ip = packet[scapy.IP].dst
    protocol = packet[scapy.IP].proto
    src_port = (packet[scapy.TCP].sport if scapy.TCP in packet else
                packet[scapy.UDP].sport if scapy.UDP in packet else None)
    dst_port = (packet[scapy.TCP].dport if scapy.TCP in packet else
                packet[scapy.UDP].dport if scapy.UDP in packet else None)

    proto_map = {6: 'TCP', 17: 'UDP'}
    proto_name = proto_map.get(protocol, 'UNKNOWN')

    if src_ip in RULES['block_ips'] or dst_ip in RULES['block_ips']:
        log_packet(packet, 'BLOCKED (IP)')
        return False
    if src_port in RULES['block_ports'] or dst_port in RULES['block_ports']:
        log_packet(packet, 'BLOCKED (Port)')
        return False
    if proto_name not in RULES['allow_protocols'] and proto_name != 'UNKNOWN':
        log_packet(packet, 'BLOCKED (Protocol)')
        return False

    log_packet(packet, 'ALLOWED')
    return True


def sniff_packets():
    """Sniff packets and apply rules while sniffing is active."""
    global sniffing_active
    try:
        while sniffing_active:
            scapy.sniff(filter="ip", prn=check_packet, store=0, timeout=1)
    except PermissionError:
        error_msg = "Error: Run with sudo/admin privileges for packet sniffing."
        logging.error(error_msg)
        packet_queue.put(error_msg)
        sniffing_active = False
        sys.exit(1)


def start_sniffing():
    """Start packet sniffing in a new thread."""
    global sniffing_active, sniffing_thread
    if not sniffing_active:
        sniffing_active = True
        sniffing_thread = threading.Thread(target=sniff_packets, daemon=True)
        sniffing_thread.start()


def stop_sniffing():
    """Stop packet sniffing."""
    global sniffing_active, sniffing_thread
    sniffing_active = False
    sniffing_thread = None


# GUI Implementation
class FirewallGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Personal Firewall Dashboard")
        self.root.geometry("1200x800")
        self.root.configure(bg=COLORS["background"])

        # Configure styles
        self.setup_styles()

        # Build UI
        self.create_layout()

        self.is_running = False
        self.log_count = 0
        self.update_log()

    def setup_styles(self):
        style = ttk.Style()
        style.theme_use('clam')

        # Background styles
        style.configure('.', background=COLORS["background"], foreground=COLORS["text_primary"])

        # Frame styles
        style.configure('TFrame', background=COLORS["background"])
        style.configure('Card.TFrame', background=COLORS["surface"], relief=tk.FLAT, borderwidth=1,
                        bordercolor=COLORS["border"])

        # Label styles
        style.configure('Header.TLabel',
                        font=('Segoe UI', 20, 'bold'),
                        foreground=COLORS["primary"],
                        background=COLORS["background"])
        style.configure('Subheader.TLabel',
                        font=('Segoe UI', 12),
                        foreground=COLORS["text_secondary"],
                        background=COLORS["background"])
        style.configure('Status.TLabel',
                        font=('Segoe UI', 11, 'bold'),
                        foreground=COLORS["text_primary"],
                        background=COLORS["surface"],
                        padding=5)

        # Button styles
        style.configure('TButton',
                        font=('Segoe UI', 10, 'bold'),
                        borderwidth=0,
                        relief=tk.FLAT,
                        padding=8,
                        background=COLORS["primary"],
                        foreground='white')
        style.map('TButton',
                  background=[('active', COLORS["primary_dark"]),
                              ('!active', COLORS["primary"])],
                  foreground=[('active', 'white'),
                              ('!active', 'white')])

        style.configure('Accent.TButton',
                        background=COLORS["secondary"],
                        foreground='white')
        style.map('Accent.TButton',
                  background=[('active', '#00c271'),
                              ('!active', COLORS["secondary"])])

        style.configure('Stop.TButton',
                        background=COLORS["error"],
                        foreground='white')
        style.map('Stop.TButton',
                  background=[('active', '#d42a4a'),
                              ('!active', COLORS["error"])])

        # Entry styles
        style.configure('TEntry',
                        fieldbackground=COLORS["surface"],
                        foreground=COLORS["text_primary"],
                        insertcolor=COLORS["text_primary"],
                        relief=tk.SOLID,
                        borderwidth=1,
                        bordercolor=COLORS["border"],
                        padding=5)

        # Notebook styles
        style.configure('TNotebook', background=COLORS["background"])
        style.configure('TNotebook.Tab',
                        background=COLORS["background"],
                        foreground=COLORS["text_secondary"],
                        padding=[10, 5],
                        font=('Segoe UI', 10, 'bold'),
                        borderwidth=0)
        style.map('TNotebook.Tab',
                  background=[('selected', COLORS["surface"]),
                              ('!selected', COLORS["background"])],
                  foreground=[('selected', COLORS["primary"]),
                              ('!selected', COLORS["text_secondary"])],
                  bordercolor=[('selected', COLORS["border"]),
                               ('!selected', COLORS["background"])])

        # Treeview styles
        style.configure('Treeview',
                        background=COLORS["surface"],
                        foreground=COLORS["text_primary"],
                        fieldbackground=COLORS["surface"],
                        borderwidth=0,
                        rowheight=25)
        style.configure('Treeview.Heading',
                        background=COLORS["primary_light"],
                        foreground=COLORS["primary"],
                        font=('Segoe UI', 10, 'bold'),
                        borderwidth=0,
                        relief=tk.FLAT)
        style.map('Treeview',
                  background=[('selected', COLORS["primary"])],
                  foreground=[('selected', 'white')])

    def create_layout(self):
        # Main container
        self.main_frame = ttk.Frame(self.root)
        self.main_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)

        # Header
        self.header_frame = ttk.Frame(self.main_frame)
        self.header_frame.pack(fill=tk.X, pady=(0, 15))

        ttk.Label(self.header_frame,
                  text="NetShield",
                  style='Header.TLabel').pack(side=tk.LEFT)

        ttk.Label(self.header_frame,
                  text="Personal Firewall Protection",
                  style='Subheader.TLabel').pack(side=tk.LEFT, padx=10)

        # Status indicator
        self.status_frame = ttk.Frame(self.header_frame)
        self.status_frame.pack(side=tk.RIGHT)

        self.status_indicator = tk.Canvas(self.status_frame, width=12, height=12,
                                          bg=COLORS["background"], highlightthickness=0)
        self.status_indicator.pack(side=tk.LEFT, padx=5)
        self.draw_status_circle(COLORS["error"])

        self.status_label = ttk.Label(self.status_frame,
                                      text="Inactive",
                                      style='Status.TLabel')
        self.status_label.pack(side=tk.LEFT)

        # Control buttons
        self.control_frame = ttk.Frame(self.main_frame)
        self.control_frame.pack(fill=tk.X, pady=(0, 20))

        self.start_btn = ttk.Button(self.control_frame,
                                    text="Activate Protection",
                                    command=self.start_firewall,
                                    style='Accent.TButton')
        self.start_btn.pack(side=tk.LEFT, padx=5)

        self.stop_btn = ttk.Button(self.control_frame,
                                   text="Deactivate",
                                   command=self.stop_firewall,
                                   style='Stop.TButton',
                                   state=tk.DISABLED)
        self.stop_btn.pack(side=tk.LEFT, padx=5)

        # Tabbed interface
        self.notebook = ttk.Notebook(self.main_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True)

        # Create tabs
        self.create_monitor_tab()
        self.create_rules_tab()

    def draw_status_circle(self, color):
        self.status_indicator.delete("all")
        self.status_indicator.create_oval(2, 2, 10, 10, fill=color, outline="")

    def create_monitor_tab(self):
        self.monitor_tab = ttk.Frame(self.notebook, style='Card.TFrame')
        self.notebook.add(self.monitor_tab, text="Traffic Monitor")

        # Log display
        log_frame = ttk.LabelFrame(self.monitor_tab,
                                   text="Firewall Activity Log",
                                   style='Card.TFrame')
        log_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        self.log_text = scrolledtext.ScrolledText(log_frame,
                                                  bg=COLORS["surface"],
                                                  fg=COLORS["text_primary"],
                                                  insertbackground=COLORS["text_primary"],
                                                  font=('Consolas', 9),
                                                  wrap=tk.WORD)
        self.log_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Log controls
        log_controls = ttk.Frame(log_frame)
        log_controls.pack(fill=tk.X, pady=(0, 5))

        ttk.Button(log_controls,
                   text="Clear Logs",
                   command=self.clear_logs).pack(side=tk.LEFT, padx=5)

    def create_rules_tab(self):
        self.rules_tab = ttk.Frame(self.notebook, style='Card.TFrame')
        self.notebook.add(self.rules_tab, text="Firewall Rules")

        # Rule management frame
        rule_management = ttk.LabelFrame(self.rules_tab,
                                         text="Configure Rules",
                                         style='Card.TFrame')
        rule_management.pack(fill=tk.X, padx=10, pady=10)

        # Rule input
        rule_input_frame = ttk.Frame(rule_management)
        rule_input_frame.pack(fill=tk.X, pady=5)

        ttk.Label(rule_input_frame,
                  text="IP Address:",
                  font=('Segoe UI', 10)).pack(side=tk.LEFT, padx=5)

        self.ip_entry = ttk.Entry(rule_input_frame, font=('Segoe UI', 10))
        self.ip_entry.pack(side=tk.LEFT, padx=5, expand=True, fill=tk.X)

        # Port input
        port_input_frame = ttk.Frame(rule_management)
        port_input_frame.pack(fill=tk.X, pady=5)

        ttk.Label(port_input_frame,
                  text="Port:",
                  font=('Segoe UI', 10)).pack(side=tk.LEFT, padx=5)

        self.port_entry = ttk.Entry(port_input_frame, font=('Segoe UI', 10))
        self.port_entry.pack(side=tk.LEFT, padx=5, expand=True, fill=tk.X)

        # Action buttons - now both in the same row
        button_frame = ttk.Frame(rule_management)
        button_frame.pack(fill=tk.X, pady=10)

        ttk.Button(button_frame,
                   text="Add Block Rule",
                   command=lambda: self.add_rule("block"),
                   style='Stop.TButton').pack(side=tk.LEFT, padx=5)

        ttk.Button(button_frame,
                   text="Remove Selected Rule",
                   command=self.remove_rule,
                   style='TButton').pack(side=tk.LEFT, padx=5)

        # Current rules display
        rules_display = ttk.LabelFrame(self.rules_tab,
                                       text="Active Rules",
                                       style='Card.TFrame')
        rules_display.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        self.rules_tree = ttk.Treeview(rules_display, columns=("type", "value"), show="headings")
        self.rules_tree.heading("type", text="Rule Type")
        self.rules_tree.heading("value", text="Value")
        self.rules_tree.column("type", width=100)
        self.rules_tree.column("value", width=200)
        self.rules_tree.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Load existing rules
        self.update_rules_listbox()

    def update_rules_listbox(self):
        """Update the rules listbox with current rules."""
        # Clear existing items
        for item in self.rules_tree.get_children():
            self.rules_tree.delete(item)

        # Add IP rules
        for ip in RULES['block_ips']:
            self.rules_tree.insert("", tk.END, values=("Block IP", ip))

        # Add port rules
        for port in RULES['block_ports']:
            self.rules_tree.insert("", tk.END, values=("Block Port", port))

        # Add protocol rules
        for proto in RULES['allow_protocols']:
            self.rules_tree.insert("", tk.END, values=("Allow Protocol", proto))

    def clear_logs(self):
        """Clear the log display."""
        self.log_text.delete(1.0, tk.END)
        log_message = "Logs cleared."
        logging.info(log_message)
        packet_queue.put(log_message)

    def add_rule(self, action):
        ip = self.ip_entry.get().strip()
        port = self.port_entry.get().strip()

        if not ip and not port:
            messagebox.showwarning("Input Error", "Please enter an IP or port to block.")
            return

        if ip:
            if ip not in RULES['block_ips']:
                RULES['block_ips'].append(ip)
                self.ip_entry.delete(0, tk.END)
                log_message = f"Added IP rule: {ip}"
                logging.info(log_message)
                packet_queue.put(log_message)
        if port:
            if not port.isdigit():
                messagebox.showwarning("Input Error", "Port must be a number.")
                return
            port = int(port)
            if port not in RULES['block_ports']:
                RULES['block_ports'].append(port)
                self.port_entry.delete(0, tk.END)
                log_message = f"Added port rule: {port}"
                logging.info(log_message)
                packet_queue.put(log_message)

        self.update_rules_listbox()
        messagebox.showinfo("Success", "Rule added successfully")

    def remove_rule(self):
        selected_item = self.rules_tree.selection()
        if not selected_item:
            messagebox.showwarning("Warning", "Please select a rule to delete")
            return

        item = self.rules_tree.item(selected_item)
        rule_type = item['values'][0]
        value = item['values'][1]

        if rule_type == "Block IP":
            if value in RULES['block_ips']:
                RULES['block_ips'].remove(value)
        elif rule_type == "Block Port":
            if int(value) in RULES['block_ports']:
                RULES['block_ports'].remove(int(value))
        elif rule_type == "Allow Protocol":
            if value in RULES['allow_protocols']:
                RULES['allow_protocols'].remove(value)

        self.update_rules_listbox()
        messagebox.showinfo("Success", "Rule removed successfully")

    def start_firewall(self):
        """Start the firewall and sniffing."""
        if not self.is_running:
            self.is_running = True
            self.start_btn.config(state=tk.DISABLED)
            self.stop_btn.config(state=tk.NORMAL)
            self.status_label.config(text="Active - Monitoring")
            self.draw_status_circle(COLORS["success"])
            start_sniffing()
            log_message = "Firewall protection activated"
            self.log_text.insert(tk.END, log_message + "\n")
            logging.info(log_message)
            packet_queue.put(log_message)
            self.log_text.see(tk.END)

    def stop_firewall(self):
        """Stop the firewall and sniffing."""
        if self.is_running:
            self.is_running = False
            self.start_btn.config(state=tk.NORMAL)
            self.stop_btn.config(state=tk.DISABLED)
            self.status_label.config(text="Inactive")
            self.draw_status_circle(COLORS["error"])
            stop_sniffing()
            log_message = "Firewall protection deactivated"
            self.log_text.insert(tk.END, log_message + "\n")
            logging.info(log_message)
            packet_queue.put(log_message)
            self.log_text.see(tk.END)

    def update_log(self):
        """Update GUI with new log entries."""
        while not packet_queue.empty():
            log_message = packet_queue.get()
            self.log_text.insert(tk.END, log_message + "\n")
            self.log_text.see(tk.END)

        self.root.after(1000, self.update_log)


def main():
    """Main function to run CLI or GUI mode."""
    if len(sys.argv) > 1 and sys.argv[1] == '--cli':
        print("Starting firewall in CLI mode...")
        global sniffing_active
        sniffing_active = True
        sniff_packets()
        try:
            while sniffing_active:
                pass
        except KeyboardInterrupt:
            sniffing_active = False
            print("Firewall stopped.")
    else:
        root = tk.Tk()
        app = FirewallGUI(root)
        root.mainloop()


if __name__ == "__main__":
    main()