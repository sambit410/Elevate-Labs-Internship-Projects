# Elevate-Labs-Internship-Projects

# **NetShield Personal Firewall - README**

## **📌 Overview**
**NetShield** is a Python-based personal firewall that monitors and filters network traffic in real-time. It provides both a **GUI dashboard** and **CLI mode** for blocking suspicious IPs, ports, and protocols.

## **⚙️ Installation**

### **📥 Prerequisites**
- **Python 3.7+** ([Download Python](https://www.python.org/downloads/))
- **Administrator/root access** (Required for packet sniffing)

### **🔧 Setup Steps**
1. **Clone the repository** (if applicable):
   ```bash
   git clone https://github.com/your-repo/personal-firewall.git
   cd personal-firewall
   ```

2. **Install dependencies**:
  *( manually install: `pip install scapy psutil tkinter`)*

3. **On Windows**: Install **Npcap** (required for Scapy)  
   📥 Download: [https://npcap.com/#download](https://npcap.com/#download)

## **🚀 Running the Firewall**

### **🖥️ GUI Mode (Recommended)**
```bash
python firewall.py
```
*(Launches an interactive dashboard for monitoring and managing rules.)*  

## **🔒 Admin Privileges Required**
- **Windows**: Right-click → *"Run as Administrator"*
- **Mac/Linux**: Prefix with `sudo`:
  ```bash
  sudo python firewall.py
  ```

## **🛡️ Features**
| Feature               | Description                                                                 |
|-----------------------|-----------------------------------------------------------------------------|
| **IP Blocking**       | Block specific IP addresses (e.g., known attackers).                        |
| **Port Filtering**    | Block risky ports (e.g., Telnet on 23, SMB on 445).                         |
| **Protocol Control**  | Allow only TCP/UDP by default.                                              |
| **Traffic Logs**      | View real-time connections with timestamps and process names.               |
| **Rule Management**   | Add/remove rules via GUI .                                                  |

---

## **⚠️ Troubleshooting**

| Issue                          | Solution                                                                 |
|--------------------------------|-------------------------------------------------------------------------|
| **"No permission to sniff"**   | Run as admin (`sudo`/Administrator). On Windows, ensure Npcap is installed. |
| **Scapy missing dependencies** | Install `libpcap-dev` (Linux) or Npcap (Windows).                       |
| **Firewall not blocking**      | Check rules in `RULES` dictionary or GUI. Restart the application.      |
| **GUI crashes/freezes**        | Ensure `tkinter` is installed (`sudo apt-get install python3-tk` on Linux). |



**🎉 Happy Securing!** Block those pesky intruders! 🔥🛡️  
