import ipaddress, logging, subprocess
log = logging.getLogger("SOC-AI.firewall")

def block_ip(ip: str) -> bool:
    from config import PFSENSE_IP, PFSENSE_USER
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        log.error(f"IP invalide refusée : {ip!r}")
        return False
    log.info(f"🚫 BLOCAGE {ip} sur pfSense")
    try:
        subprocess.run(
            ["ssh", "-o", "StrictHostKeyChecking=no",
             f"{PFSENSE_USER}@{PFSENSE_IP}",
             f"pfctl -t blocklist -T add {ip}"],
            check=True, timeout=10)
        return True
    except subprocess.CalledProcessError as e:
        log.error(f"Échec blocage {ip} : {e}")
    except subprocess.TimeoutExpired:
        log.error(f"Timeout SSH {ip}")
    return False
