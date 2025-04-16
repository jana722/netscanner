from scapy.all import ARP, Ether, srp, conf
from mac_vendor_lookup import MacLookup
import os

def banner():
    os.system('clear')  # clears terminal for clean banner display
    print("\033[1;36m")  # Cyan Bold Text
    print("="*80)
    print(r"""
███╗   ██╗███████╗████████╗███████╗ ██████╗ █████╗ ███╗   ██╗
████╗  ██║██╔════╝╚══██╔══╝██╔════╝██╔════╝██╔══██╗████╗  ██║
██╔██╗ ██║█████╗     ██║   █████╗  ██║     ███████║██╔██╗ ██║
██║╚██╗██║██╔══╝     ██║   ██╔══╝  ██║     ██╔══██║██║╚██╗██║
██║ ╚████║███████╗   ██║   ███████╗╚██████╗██║  ██║██║ ╚████║
╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝
    """)
    print("="*80)
    print("📡 NetScan - Simple Network Scanner")
    print("👤 Author      : N. Janarthanan")
    print("🛠️  Description : Scan a given IP range to find live devices and their MAC vendors.")
    print("💡 Usage       : Just run the script and follow the prompts.")
    print("="*80)
    print("\033[0m")  # Reset color

def get_inputs():
    interface = input("Enter your network interface (e.g., eth0, wlan0): ")
    if not interface:
        print("[!] Interface is required.")
        exit()

    ip_range = input("Enter the IP range of your network (e.g., 192.168.1.0/24): ")
    if not ip_range:
        print("[!] IP range is required.")
        exit()

    return interface, ip_range

def scan(ip, iface):
    conf.iface = iface
    arp_request = ARP(pdst=ip)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    clients = []

    for element in answered_list:
        mac = element[1].hwsrc
        try:
            vendor = MacLookup().lookup(mac)
        except:
            vendor = "Unknown"
        client_info = {"IP": element[1].psrc, "MAC": mac, "Vendor": vendor}
        clients.append(client_info)

    return clients

def print_result(clients):
    print("\n" + "-"*90)
    print("IP Address\t\tMAC Address\t\t\tVendor")
    print("-"*90)
    for client in clients:
        print(f"{client['IP']}\t\t{client['MAC']}\t\t{client['Vendor']}")
    print("-"*90 + "\n")

# ------------------ MAIN ---------------------
if __name__ == "__main__":
    banner()
    interface, target_ip = get_inputs()
    result = scan(target_ip, interface)
    print_result(result)
