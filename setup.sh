#!/usr/bin/env bash
#
# ShellCracker kurulum scripti (Kali / Debian / Ubuntu).
# Tool'un kullandigi tum dis araclari ve Python bagimliliklarini kurar.
# Zaten kurulu olanlar atlanir. Calistir:  sudo ./setup.sh
#
set -u

APT_PKGS=(
  nmap metasploit-framework exploitdb      # cekirdek
  netexec whatweb nuclei gobuster ffuf nikto  # vulnscan
  hydra                                     # bruteforce
  john hashcat wordlists                    # hash kirma + wordlist
)

say()  { printf '\n[*] %s\n' "$1"; }
ok()   { printf '[+] %s\n' "$1"; }
warn() { printf '[!] %s\n' "$1"; }

SUDO=""
if [ "$(id -u)" -ne 0 ]; then SUDO="sudo"; fi

if ! command -v apt-get >/dev/null 2>&1; then
  warn "apt-get yok. Bu script Kali/Debian/Ubuntu icindir."
  warn "Paketleri elle kur: ${APT_PKGS[*]}"
  exit 2
fi

say "Paket listesi guncelleniyor..."
$SUDO apt-get update -y

say "Dis araclar kuruluyor..."
$SUDO apt-get install -y "${APT_PKGS[@]}" || warn "Bazi paketler kurulamadi (asagi bak)."

# netexec eski Kali'de 'crackmapexec' olabilir; ikisi de yoksa pipx ile dene.
if ! command -v nxc >/dev/null 2>&1 && ! command -v netexec >/dev/null 2>&1 \
   && ! command -v crackmapexec >/dev/null 2>&1; then
  warn "netexec apt'ten gelmedi; pipx ile deneniyor..."
  $SUDO apt-get install -y pipx >/dev/null 2>&1
  pipx install git+https://github.com/Pennyw0rth/NetExec 2>/dev/null \
    || warn "netexec kurulamadi; elle kur: pipx install git+https://github.com/Pennyw0rth/NetExec"
fi

# nuclei sablonlari
if command -v nuclei >/dev/null 2>&1; then
  say "nuclei sablonlari guncelleniyor..."
  nuclei -update-templates >/dev/null 2>&1 || true
fi

# rockyou.txt Kali'de gzip'li gelir
if [ -f /usr/share/wordlists/rockyou.txt.gz ] && [ ! -f /usr/share/wordlists/rockyou.txt ]; then
  say "rockyou.txt aciliyor..."
  $SUDO gzip -d -k /usr/share/wordlists/rockyou.txt.gz 2>/dev/null || true
fi

# Python bagimliliklari
if command -v pip3 >/dev/null 2>&1; then
  say "Python paketleri kuruluyor..."
  pip3 install -r requirements.txt 2>/dev/null \
    || pip3 install --break-system-packages -r requirements.txt 2>/dev/null \
    || warn "pip kurulumunda sorun; elle: pip3 install -r requirements.txt"
fi

say "Kurulum bitti. Dogrulama:"
python3 shell.py --check 2>/dev/null || warn "Dogrulama icin: python3 shell.py --check"
ok "Hazir. Ornek: python3 shell.py --target 10.10.10.5"
