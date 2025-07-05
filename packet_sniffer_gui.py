import tkinter as tk
from scapy.all import sniff, IP
from threading import Thread

# List to store packet info
packet_list = []

# Function to process each packet
def process_packet(packet):
    if IP in packet:
        src = packet[IP].src
        dst = packet[IP].dst
        proto = packet[IP].proto
        info = f"Src: {src} | Dst: {dst} | Proto: {proto}"
        packet_list.append(info)
        update_gui(info)

# Function to update the GUI
def update_gui(info):
    packet_display.insert(tk.END, info + "\n")
    packet_display.yview(tk.END)

# Function to start sniffing in a thread
def start_sniffing():
    sniff_thread = Thread(target=lambda: sniff(prn=process_packet, store=0))
    sniff_thread.daemon = True
    sniff_thread.start()
    status_label.config(text="Sniffing started...", fg="green")

# GUI setup
root = tk.Tk()
root.title("Network Packet Analyzer")
root.geometry("600x400")

tk.Label(root, text="Network Packet Analyzer", font=("Arial", 16)).pack(pady=10)

start_button = tk.Button(root, text="Start Sniffing", bg="green", fg="white", font=("Arial", 12), command=start_sniffing)
start_button.pack(pady=5)

status_label = tk.Label(root, text="Idle", fg="gray")
status_label.pack(pady=5)

packet_display = tk.Text(root, height=15, width=70)
packet_display.pack(pady=10)

tk.Label(root, text="Press Start to begin capturing packets").pack()

root.mainloop()
