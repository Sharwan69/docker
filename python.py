import tkinter as tk
from tkinter import ttk, messagebox
import threading
import time
from datetime import datetime
import os
from collections import defaultdict
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from scapy.all import sniff, get_if_list, TCP, UDP, ICMP, IP # Import specific layers for clarity
import pandas as pd

# CUSTOM HASH TABLE CLASS
class CustomHashTable:
    """
    Custom hash table implementation for IP address tracking
    Uses separate chaining for collision resolution
    """
    def __init__(self, initial_size=1024):
        self.size = initial_size
        self.count = 0
        self.buckets = [[] for _ in range(self.size)]
    
    def _hash(self, key):
        """Simple hash function using built-in hash() with modulo"""
        return hash(key) % self.size
    
    def _resize(self):
        """Resize hash table when load factor exceeds 0.75"""
        old_buckets = self.buckets
        self.size *= 2
        self.count = 0
        self.buckets = [[] for _ in range(self.size)]
        
        # Rehash all existing items
        for bucket in old_buckets:
            for key, value in bucket:
                self.insert(key, value)
    
    def insert(self, key, value=1):
        """Insert or update key-value pair"""
        # Check if resize is needed (load factor > 0.75)
        if self.count >= self.size * 0.75:
            self._resize()
        
        bucket_index = self._hash(key)
        bucket = self.buckets[bucket_index]
        
        # Check if key already exists
        for i, (k, v) in enumerate(bucket):
            if k == key:
                bucket[i] = (key, v + value)  # Update existing
                return
        
        # Add new key-value pair
        bucket.append((key, value))
        self.count += 1
    
    def get(self, key):
        """Get value for a key, return 0 if not found"""
        bucket_index = self._hash(key)
        bucket = self.buckets[bucket_index]
        
        for k, v in bucket:
            if k == key:
                return v
        return 0
    
    def increment(self, key):
        """Increment counter for a key (main method for packet counting)"""
        # Check if resize is needed *before* potentially adding a new key
        if self.count >= self.size * 0.75:
            self._resize()

        bucket_index = self._hash(key)
        bucket = self.buckets[bucket_index]
        
        # Check if key already exists
        for i, (k, v) in enumerate(bucket):
            if k == key:
                bucket[i] = (key, v + 1)  # Increment existing
                return
        
        # Add new key with count 1
        bucket.append((key, 1))
        self.count += 1
    
    def get_all_items(self):
        """Return all key-value pairs as a list of tuples"""
        items = []
        for bucket in self.buckets:
            for key, value in bucket:
                items.append((key, value))
        return items
    
    def get_top_items(self, n=10):
        """Get top N items by value (packet count)"""
        items = self.get_all_items()
        return sorted(items, key=lambda x: x[1], reverse=True)[:n]


# MAIN CLASS WITH MODIFICATIONS
class NetworkTrafficAnalyzer:
    def __init__(self, root):
        self.root = root
        self.root.title("Network Traffic Analyzer")
        self.root.geometry("1200x800")
        
        # Using custom hash tables instead of defaultdict
        self.protocol_counts = CustomHashTable(initial_size=16)
        self.ip_packets = CustomHashTable(initial_size=512)
        
        self.traffic_history = {'incoming': [], 'outgoing': [], 'timestamps': []}
        self.interface = tk.StringVar()
        self.is_sniffing = False
        self.packet_count_since_last_gui_update = 0 # Counter for more controlled updates

        self.setup_gui()
        self.detect_interface()
    
    def setup_gui(self):
        """Set up the graphical user interface"""
        # Control Panel
        control_frame = ttk.Frame(self.root)
        control_frame.pack(fill=tk.X, padx=10, pady=5)
        
        # Interface selection
        ttk.Label(control_frame, text="Interface:").pack(side=tk.LEFT, padx=5)
        interface_combo = ttk.Combobox(control_frame, textvariable=self.interface, width=30) # Increased width
        interface_combo['values'] = self.get_available_interfaces()
        interface_combo.pack(side=tk.LEFT, padx=5)
        
        # Control buttons
        self.start_button = ttk.Button(control_frame, text="Start Sniffing", command=self.start_sniffing)
        self.start_button.pack(side=tk.LEFT, padx=5)
        
        self.stop_button = ttk.Button(control_frame, text="Stop Sniffing", command=self.stop_sniffing, state=tk.DISABLED)
        self.stop_button.pack(side=tk.LEFT, padx=5)
        
        self.export_button = ttk.Button(control_frame, text="Export Data", command=self.export_data)
        self.export_button.pack(side=tk.LEFT, padx=5)
        
        # Charts Frame
        charts_frame = ttk.Frame(self.root)
        charts_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # Create matplotlib figure
        self.fig, (self.ax1, self.ax2) = plt.subplots(1, 2, figsize=(12, 4))
        self.canvas = FigureCanvasTkAgg(self.fig, charts_frame)
        self.canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
        
        # IP Table
        table_frame = ttk.Frame(self.root)
        table_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        ttk.Label(table_frame, text="Top IP Addresses", font=("Arial", 12, "bold")).pack()
        
        self.ip_tree = ttk.Treeview(table_frame, columns=("IP", "Packets", "Type"), show="headings", height=8)
        self.ip_tree.heading("IP", text="IP Address")
        self.ip_tree.heading("Packets", text="Packet Count")
        self.ip_tree.heading("Type", text="Traffic Type")
        self.ip_tree.pack(fill=tk.BOTH, expand=True)
        
        # Status Bar
        self.status_label = ttk.Label(self.root, text="Ready", relief=tk.SUNKEN, anchor=tk.W)
        self.status_label.pack(fill=tk.X, side=tk.BOTTOM)
    
    def detect_interface(self):
        """Detect and set default network interface"""
        interfaces = self.get_available_interfaces()
        if interfaces:
            self.interface.set(interfaces[0])
            print(f"Detected interfaces: {interfaces}") # Debugging
        else:
            print("No interfaces detected. Using fallback options.") # Debugging
            self.interface.set("No interfaces found") # Inform user
    
    def get_available_interfaces(self):
        """Get list of available network interfaces"""
        try:
            # On Windows, Scapy's get_if_list might return names like '\Device\NPF_{GUID}'
            # On Linux/macOS, it's usually 'eth0', 'wlan0', 'en0', etc.
            interfaces = get_if_list()
            if not interfaces:
                messagebox.showwarning("No Interfaces", "No network interfaces found by Scapy. This might be a permission issue or missing packet capture drivers (Npcap/WinPcap). Try running as administrator/sudo.")
                return ["eth0", "wlan0", "lo"] # Fallback
            return interfaces
        except Exception as e:
            # Added more specific error message for common Scapy issues
            messagebox.showerror("Interface Detection Error",
                                 f"Could not detect network interfaces. This often indicates missing packet capture drivers (like Npcap on Windows) or insufficient permissions (e.g., you might need to run the script as administrator/sudo).\n\nError: {e}")
            print(f"Error getting network interfaces: {e}")
            return ["eth0", "wlan0", "lo"]  # fallback options
    
    def is_local_ip(self, ip):
        """Check if IP address is local/private"""
        # This function identifies if an IP is within a private range or localhost.
        private_ranges = [
            '192.168.', '10.', '172.16.', '172.17.', '172.18.', '172.19.',
            '172.20.', '172.21.', '172.22.', '172.23.', '172.24.', '172.25.',
            '172.26.', '172.27.', '172.28.', '172.29.', '172.30.', '172.31.',
            '127.'
        ]
        return any(ip.startswith(prefix) for prefix in private_ranges)
    
    def packet_handler(self, packet):
        """Handle captured packets using custom hash table"""
        try:
            if packet.haslayer(IP): # Changed 'IP' to IP for consistency with imports
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                
                # Use custom hash table increment method
                self.ip_packets.increment(src_ip)
                self.ip_packets.increment(dst_ip)
                
                # Protocol detection using custom hash table
                if packet.haslayer(TCP):
                    self.protocol_counts.increment('TCP')
                elif packet.haslayer(UDP):
                    self.protocol_counts.increment('UDP')
                elif packet.haslayer(ICMP):
                    self.protocol_counts.increment('ICMP')
                else:
                    self.protocol_counts.increment('Other')
                
                # Traffic history
                packet_size = len(packet)
                # timestamp = time.time() # This is not currently used for graphing but kept for export

                # Assuming local IP for src indicates outgoing, and dst indicates incoming for non-local src
                # This logic can be refined for more precise incoming/outgoing calculation
                # For simplicity, we'll just sum packet sizes for overall traffic
                
                # For basic incoming/outgoing, you need to know YOUR IP address.
                # Without knowing the local machine's IP, `is_local_ip` is a heuristic.
                # Let's simplify history collection for now for the charts
                
                # Option 1: Store total bytes over time (simpler for general traffic trends)
                if not self.traffic_history['timestamps']: # Initialize if empty
                    self.traffic_history['timestamps'].append(time.time())
                    self.traffic_history['incoming'].append(0)
                    self.traffic_history['outgoing'].append(0)
                
                # Add to the last recorded entry
                if self.is_local_ip(src_ip):
                    self.traffic_history['outgoing'][-1] += packet_size
                else:
                    self.traffic_history['incoming'][-1] += packet_size
                
                self.packet_count_since_last_gui_update += 1

                # Update GUI every N packets or periodically to avoid freezing
                # Trigger update more frequently for better responsiveness on small traffic
                if self.packet_count_since_last_gui_update >= 5 or (time.time() - self.traffic_history['timestamps'][-1] > 1 and self.packet_count_since_last_gui_update > 0):
                    self.root.after(0, self.update_gui)
                    self.packet_count_since_last_gui_update = 0 # Reset counter
                    # Add a new timestamp point every few seconds, even if no packets arrived
                    self.traffic_history['timestamps'].append(time.time())
                    self.traffic_history['incoming'].append(self.traffic_history['incoming'][-1])
                    self.traffic_history['outgoing'].append(self.traffic_history['outgoing'][-1])


        except Exception as e:
            # Catching specific Scapy errors might be useful here if they cause crashes
            print(f"Error processing packet: {e}")
    
    def start_sniffing(self):
        """Start packet sniffing"""
        selected_interface = self.interface.get()
        if not selected_interface or selected_interface == "No interfaces found":
            messagebox.showwarning("No Interface", "Please select a valid network interface before starting.")
            return
        
        self.is_sniffing = True
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        self.status_label.config(text=f"Sniffing on {selected_interface}...")
        
        # Clear previous data for a fresh start
        self.protocol_counts = CustomHashTable(initial_size=16)
        self.ip_packets = CustomHashTable(initial_size=512)
        self.traffic_history = {'incoming': [], 'outgoing': [], 'timestamps': []}
        self.packet_count_since_last_gui_update = 0
        self.update_gui() # Clear charts immediately
        
        # Start sniffing in separate thread
        # Add an error callback to sniff for better error reporting for non-GUI threads
        sniff_thread = threading.Thread(target=self.sniff_packets, args=(selected_interface,))
        sniff_thread.daemon = True
        sniff_thread.start()
    
    def stop_sniffing(self):
        """Stop packet sniffing"""
        self.is_sniffing = False
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        self.status_label.config(text="Stopped sniffing")
    
    def sniff_packets(self, iface):
        """Sniff packets on specified interface"""
        try:
            # Using store=0 (or store=False) to prevent Scapy from storing packets in memory
            # This is crucial for long-running sniffers and avoids memory buildup.
            sniff(iface=iface, prn=self.packet_handler, stop_filter=lambda x: not self.is_sniffing, store=0) [cite: 315, 413]
        except Exception as e:
            # Use root.after to safely update GUI from a different thread
            self.root.after(0, lambda: messagebox.showerror("Sniffing Error", f"Error during sniffing: {str(e)}\n\nPossible causes:\n1. Insufficient permissions (try running as administrator/sudo).\n2. Interface '{iface}' is not found or not active.\n3. Missing Npcap/WinPcap drivers."))
            self.root.after(0, self.stop_sniffing)
    
    def update_gui(self):
        """Update GUI using custom hash table data"""
        try:
            # Clear previous charts
            self.ax1.clear()
            self.ax2.clear()
            
            # Protocol distribution chart
            protocol_data = self.protocol_counts.get_all_items()
            if protocol_data:
                protocols, counts = zip(*protocol_data)
                self.ax1.bar(protocols, counts, color=['blue', 'green', 'red', 'orange', 'purple'])
                self.ax1.set_title('Protocol Distribution')
                self.ax1.set_xlabel('Protocol')
                self.ax1.set_ylabel('Packet Count')
            else:
                self.ax1.set_title('Protocol Distribution (No data)')
                self.ax1.set_xlabel('Protocol')
                self.ax1.set_ylabel('Packet Count')

            # Top IPs chart
            top_ips = self.ip_packets.get_top_items(5)
            if top_ips:
                ips, counts = zip(*top_ips)
                # Truncate long IPs for display
                display_ips = [ip[:15] + '...' if len(ip) > 15 else ip for ip in ips]
                self.ax2.bar(range(len(display_ips)), counts, color='skyblue')
                self.ax2.set_title('Top 5 IP Addresses')
                self.ax2.set_xlabel('IP Address')
                self.ax2.set_ylabel('Packet Count')
                self.ax2.set_xticks(range(len(display_ips)))
                self.ax2.set_xticklabels(display_ips, rotation=45, ha='right')
            else:
                self.ax2.set_title('Top 5 IP Addresses (No data)')
                self.ax2.set_xlabel('IP Address')
                self.ax2.set_ylabel('Packet Count')
            
            plt.tight_layout()
            self.canvas.draw_idle() # Use draw_idle for efficiency

            # Update IP table
            self.update_ip_table()
            
            # Update status
            total_packets = sum(self.protocol_counts.get_all_items()[i][1] for i in range(len(self.protocol_counts.get_all_items()))) if self.protocol_counts.count > 0 else 0
            self.status_label.config(text=f"Packets captured: {total_packets} | Interface: {self.interface.get()}")
            
        except Exception as e:
            print(f"Error updating GUI: {e}")
    
    def update_ip_table(self):
        """Update IP table using custom hash table"""
        try:
            # Clear existing items
            for item in self.ip_tree.get_children():
                self.ip_tree.delete(item)
            
            # Get top 10 IPs from custom hash table
            top_ips = self.ip_packets.get_top_items(10)
            
            for ip, count in top_ips:
                traffic_type = "Local" if self.is_local_ip(ip) else "External"
                self.ip_tree.insert("", "end", values=(ip, count, traffic_type))
                
        except Exception as e:
            print(f"Error updating IP table: {e}")
    
    def export_data(self):
        """Export data with hash table statistics"""
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            export_dir = f"network_analysis_export_{timestamp}"
            os.makedirs(export_dir, exist_ok=True)
            
            # Export protocol data
            protocol_data = self.protocol_counts.get_all_items()
            if protocol_data:
                protocol_df = pd.DataFrame(protocol_data, columns=['Protocol', 'Count'])
                protocol_df.to_csv(f"{export_dir}/protocol_data.csv", index=False)
            
            # Export IP data
            ip_data = self.ip_packets.get_all_items()
            if ip_data:
                ip_df = pd.DataFrame(ip_data, columns=['IP_Address', 'Packet_Count'])
                ip_df['Traffic_Type'] = ip_df['IP_Address'].apply(
                    lambda ip: "Local" if self.is_local_ip(ip) else "External"
                )
                ip_df.to_csv(f"{export_dir}/ip_data.csv", index=False)
            
            # Export custom hash table statistics
            with open(f"{export_dir}/hashtable_performance.txt", 'w') as f:
                f.write("Custom Hash Table Performance Report\n")
                f.write("=" * 50 + "\n\n")
                
                f.write(f"IP Hash Table:\n")
                f.write(f"  Total unique IPs: {self.ip_packets.count}\n")
                f.write(f"  Table size: {self.ip_packets.size}\n")
                f.write(f"  Load factor: {self.ip_packets.count / self.ip_packets.size:.3f}\n")
                
                f.write(f"\nProtocol Hash Table:\n")
                f.write(f"  Total protocols: {self.protocol_counts.count}\n")
                f.write(f"  Table size: {self.protocol_counts.size}\n")
                f.write(f"  Load factor: {self.protocol_counts.count / self.protocol_counts.size:.3f}\n")
            
            # Save charts
            if hasattr(self, 'fig'):
                self.fig.savefig(f"{export_dir}/network_analysis_charts.png", dpi=300, bbox_inches='tight')
            
            messagebox.showinfo("Export Successful", f"Data exported to: {export_dir}")
            
        except Exception as e:
            messagebox.showerror("Export Error", f"Failed to export data: {str(e)}")


# MAIN EXECUTION
if __name__ == "__main__":
    root = tk.Tk()
    app = NetworkTrafficAnalyzer(root)
    root.mainloop()