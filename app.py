import os
import socket
import hashlib
import json
import threading
import datetime
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
from urllib.parse import urlparse
from pathlib import Path
import webbrowser

try:
    import whois as whois_pkg
except Exception:
    whois_pkg = None

try:
    import requests
except Exception:
    requests = None

try:
    import geoip2.database
except Exception:
    geoip2 = None


VT_API_KEY_CONFIG = ""
try:
    import config
    VT_API_KEY_CONFIG = getattr(config, "VT_API_KEY", "") or ""
except Exception:
    VT_API_KEY_CONFIG = ""

LANG = {
    "de": {
        "title": "URL Reputation Analyzer",
        "enter_url": "URL eingeben",
        "analyze": "Analysieren",
        "clear": "Zurücksetzen",
        "save_report": "Bericht speichern",
        "info": "Info",
        "github": "GitHub",
        "tab_overview": "Übersicht",
        "tab_whois": "WHOIS",
        "tab_dns": "DNS",
        "tab_geoip": "GeoIP",
        "tab_hash": "Hash-Check",
        "tab_vt": "VirusTotal",
        "invalid_url": "Ungültige URL",
        "no_domain": "Keine Domain extrahierbar",
        "whois_not_installed": "WHOIS-Bibliothek nicht installiert.",
        "geoip_not_available": "Keine lokale GeoIP DB gefunden und kein Netzwerk/requests verfügbar.",
        "vt_no_key": "VirusTotal API-Key nicht gesetzt.",
        "vt_no_requests": "Requests-Modul nicht verfügbar; VirusTotal nicht möglich.",
        "load_hashes": "Hashliste laden",
        "hashes_loaded": "Hashliste geladen",
        "no_hashes_loaded": "Keine Hashliste geladen",
        "match_found": "Übereinstimmung gefunden",
        "no_match": "Keine Übereinstimmungen",
        "report_saved": "Bericht gespeichert:",
        "ok": "OK",
        "error": "Fehler",
        "confirm_overwrite": "Datei existiert bereits. Überschreiben?"
    },
    "en": {
        "title": "URL Reputation Analyzer",
        "enter_url": "Enter URL",
        "analyze": "Analyze",
        "clear": "Reset",
        "save_report": "Save report",
        "info": "Info",
        "github": "GitHub",
        "tab_overview": "Overview",
        "tab_whois": "WHOIS",
        "tab_dns": "DNS",
        "tab_geoip": "GeoIP",
        "tab_hash": "Hash Check",
        "tab_vt": "VirusTotal",
        "invalid_url": "Invalid URL",
        "no_domain": "No domain could be extracted",
        "whois_not_installed": "WHOIS library not installed.",
        "geoip_not_available": "No local GeoIP DB and requests/network not available.",
        "vt_no_key": "VirusTotal API key not set.",
        "vt_no_requests": "Requests module not available; VirusTotal not possible.",
        "load_hashes": "Load hash list",
        "hashes_loaded": "Hash list loaded",
        "no_hashes_loaded": "No hash list loaded",
        "match_found": "Match found",
        "no_match": "No matches",
        "report_saved": "Report saved:",
        "ok": "OK",
        "error": "Error",
        "confirm_overwrite": "File exists. Overwrite?"
    }
}

GITHUB_URL = "https://github.com/bylickilabs"


class URLReputationAnalyzer:
    def __init__(self, root):
        self.root = root
        self.lang = "de"
        self.root.title(self._t("title"))
        self.root.geometry("980x720")
        self.root.minsize(880, 600)

        self.current_url = ""
        self.domain = ""
        self.ip_list = []
        self.whois_data = None
        self.dns_data = None
        self.geoip_data = None
        self.hash_list = set()
        self.vt_api_key = VT_API_KEY_CONFIG
        self.report = {}
        self._geoip_reader_path = ""

        self._build_ui()
        self._log(f"App gestartet ({self._t('title')})")

    def _t(self, key):
        return LANG[self.lang].get(key, key)

    def _log(self, text):
        ts = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        self.log_text.config(state="normal")
        self.log_text.insert("end", f"[{ts}] {text}\n")
        self.log_text.see("end")
        self.log_text.config(state="disabled")

    def _build_ui(self):
        header = ttk.Frame(self.root, padding=8)
        header.pack(fill="x")
        self.lbl_title = ttk.Label(header, text=self._t("title"), font=("Segoe UI", 13, "bold"))
        self.lbl_title.pack(side="left")

        header_right = ttk.Frame(header)
        header_right.pack(side="right")

        self.cmb_lang = ttk.Combobox(header_right, values=["Deutsch", "English"], state="readonly", width=10)
        self.cmb_lang.current(0 if self.lang == "de" else 1)
        self.cmb_lang.pack(side="right", padx=(4, 0))
        self.cmb_lang.bind("<<ComboboxSelected>>", self.on_language_change)

        self.btn_github = ttk.Button(header_right, text=self._t("github"), command=lambda: webbrowser.open_new_tab(GITHUB_URL))
        self.btn_github.pack(side="right", padx=(6, 0))
        self.btn_info = ttk.Button(header_right, text=self._t("info"), command=self.show_info)
        self.btn_info.pack(side="right", padx=(6, 8))

        input_row = ttk.Frame(self.root, padding=(8, 6))
        input_row.pack(fill="x")
        self.ent_url = ttk.Entry(input_row)
        self.ent_url.pack(side="left", fill="x", expand=True, padx=(0, 6))
        self.ent_url.insert(0, "https://")
        self.btn_analyze = ttk.Button(input_row, text=self._t("analyze"), command=self.on_analyze)
        self.btn_analyze.pack(side="left", padx=(0, 4))
        self.btn_clear = ttk.Button(input_row, text=self._t("clear"), command=self.on_clear)
        self.btn_clear.pack(side="left", padx=(4, 4))
        self.btn_save = ttk.Button(input_row, text=self._t("save_report"), command=self.save_report)
        self.btn_save.pack(side="left")

        self.tab_control = ttk.Notebook(self.root)
        self.tab_control.pack(fill="both", expand=True, padx=8, pady=8)

        self.tab_overview = ttk.Frame(self.tab_control)
        self.tab_control.add(self.tab_overview, text=self._t("tab_overview"))
        self.ov_tree = ttk.Treeview(self.tab_overview, columns=("key", "value"), show="headings")
        self.ov_tree.heading("key", text="Field")
        self.ov_tree.heading("value", text="Value")
        self.ov_tree.column("key", width=260, anchor="w")
        self.ov_tree.column("value", width=640, anchor="w")
        self.ov_tree.pack(fill="both", expand=True, padx=6, pady=6)

        self.tab_whois = ttk.Frame(self.tab_control)
        self.tab_control.add(self.tab_whois, text=self._t("tab_whois"))
        self.txt_whois = scrolledtext.ScrolledText(self.tab_whois, wrap="word")
        self.txt_whois.pack(fill="both", expand=True, padx=6, pady=6)

        self.tab_dns = ttk.Frame(self.tab_control)
        self.tab_control.add(self.tab_dns, text=self._t("tab_dns"))
        self.txt_dns = scrolledtext.ScrolledText(self.tab_dns, wrap="word")
        self.txt_dns.pack(fill="both", expand=True, padx=6, pady=6)

        self.tab_geoip = ttk.Frame(self.tab_control)
        self.tab_control.add(self.tab_geoip, text=self._t("tab_geoip"))
        self.txt_geoip = scrolledtext.ScrolledText(self.tab_geoip, wrap="word")
        self.txt_geoip.pack(fill="both", expand=True, padx=6, pady=6)
        geo_row = ttk.Frame(self.tab_geoip)
        geo_row.pack(fill="x", padx=6, pady=(0, 6))
        ttk.Button(geo_row, text="Load GeoIP DB...", command=self.load_geoip_db).pack(side="left")
        self.lbl_geo_db = ttk.Label(geo_row, text="(no DB loaded)")
        self.lbl_geo_db.pack(side="left", padx=(6, 0))

        self.tab_hash = ttk.Frame(self.tab_control)
        self.tab_control.add(self.tab_hash, text=self._t("tab_hash"))
        hash_row = ttk.Frame(self.tab_hash)
        hash_row.pack(fill="x", padx=6, pady=(6, 0))
        ttk.Button(hash_row, text=self._t("load_hashes"), command=self.load_hash_list).pack(side="left")
        self.lbl_hash_count = ttk.Label(hash_row, text=self._t("no_hashes_loaded"))
        self.lbl_hash_count.pack(side="left", padx=(8, 0))
        self.txt_hash = scrolledtext.ScrolledText(self.tab_hash, wrap="word", height=20)
        self.txt_hash.pack(fill="both", expand=True, padx=6, pady=6)

        self.tab_vt = ttk.Frame(self.tab_control)
        self.tab_control.add(self.tab_vt, text=self._t("tab_vt"))
        vt_row = ttk.Frame(self.tab_vt)
        vt_row.pack(fill="x", padx=6, pady=(6, 0))
        ttk.Label(vt_row, text="API Key:").pack(side="left")
        self.ent_vt_key = ttk.Entry(vt_row, width=60, show="*")
        self.ent_vt_key.pack(side="left", padx=(6, 6))
        if VT_API_KEY_CONFIG:
            self.ent_vt_key.insert(0, VT_API_KEY_CONFIG)
        ttk.Button(vt_row, text="Set Key (Temp)", command=self.set_vt_key_temp).pack(side="left", padx=(4, 4))
        ttk.Button(vt_row, text="Save Key to config.py", command=self.save_vt_key_to_config).pack(side="left")
        self.txt_vt_res = scrolledtext.ScrolledText(self.tab_vt, wrap="word")
        self.txt_vt_res.pack(fill="both", expand=True, padx=6, pady=6)

        bottom = ttk.Frame(self.root, padding=6)
        bottom.pack(fill="x")
        ttk.Label(bottom, text="Log:").pack(anchor="w")
        self.log_text = scrolledtext.ScrolledText(bottom, height=8, state="disabled")
        self.log_text.pack(fill="x", pady=(4, 0))

        self.status = ttk.Label(self.root, text="")
        self.status.pack(side="bottom", fill="x")

        self.update_language_ui()

    def update_language_ui(self):
        self.lbl_title.config(text=self._t("title"))
        self.btn_analyze.config(text=self._t("analyze"))
        self.btn_clear.config(text=self._t("clear"))
        self.btn_save.config(text=self._t("save_report"))
        self.tab_control.tab(self.tab_overview, text=self._t("tab_overview"))
        self.tab_control.tab(self.tab_whois, text=self._t("tab_whois"))
        self.tab_control.tab(self.tab_dns, text=self._t("tab_dns"))
        self.tab_control.tab(self.tab_geoip, text=self._t("tab_geoip"))
        self.tab_control.tab(self.tab_hash, text=self._t("tab_hash"))
        self.tab_control.tab(self.tab_vt, text=self._t("tab_vt"))
        self.btn_info.config(text=self._t("info"))
        self.btn_github.config(text=self._t("github"))
        self._log(f"Sprache gesetzt: {self.lang.upper()}")

    def on_language_change(self, event=None):
        sel = self.cmb_lang.get()
        self.lang = "de" if sel.lower().startswith("d") else "en"
        self.update_language_ui()

    def show_info(self):
        if self.lang == "de":
            text = (
                "URL Reputation Analyzer\n\n"
                "Offline-fokussiertes Werkzeug zur schnellen Einschätzung von URLs. \n\nBietet Domain-Extraktion, WHOIS, DNS, GeoIP (lokal oder Netzwerk)"
                " und Hash-basierte Prüfungen. \n\nOptional: VirusTotal-Integration.\n\n"
                "Features: Mehrsprachig (DE/EN), lokale Hash-Listen, optionale GeoIP-DB und VirusTotal.\n\n"
                "Entwickelt für Sicherheits- und Forensik-Anwender.\n\n\n"
                "©BYLICKILABS | ©Thorsten Bylicki"                
            )
        else:
            text = (
                "URL Reputation Analyzer\n\n"
                "Offline-first tool to quickly assess URLs. \n\nProvides domain extraction, WHOIS, DNS, GeoIP (local or network),"
                " and hash-based checks. \n\nOptional VirusTotal integration.\n\n"
                "Features: multi-language (DE/EN), local hash lists, optional GeoIP DB and VirusTotal.\n\n"
                "Developed for security practitioners and analysts.\n\n\n"
                "©BYLICKILABS | ©Thorsten Bylicki"                
            )
        messagebox.showinfo(self._t("info"), text)

    def on_analyze(self):
        url = self.ent_url.get().strip()
        if not url:
            messagebox.showwarning(self._t("invalid_url"), self._t("invalid_url"))
            return
        thread = threading.Thread(target=self.analyze_url, args=(url,), daemon=True)
        thread.start()

    def on_clear(self):
        self.ent_url.delete(0, "end")
        self.ov_tree.delete(*self.ov_tree.get_children())
        self.txt_whois.delete("1.0", "end")
        self.txt_dns.delete("1.0", "end")
        self.txt_geoip.delete("1.0", "end")
        self.txt_hash.delete("1.0", "end")
        self.txt_vt_res.delete("1.0", "end")
        self._log("Panels zurückgesetzt.")
        self.report = {}

    def analyze_url(self, url):
        self._log(f"Analysiere URL: {url}")
        self.current_url = url
        self.report = {"url": url, "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat()}
        parsed = urlparse(url if "://" in url else "http://" + url)
        domain = parsed.netloc.split(":")[0].lower()
        if not domain:
            self._log(self._t("no_domain"))
            messagebox.showerror(self._t("invalid_url"), self._t("no_domain"))
            return
        self.domain = domain
        self.report["domain"] = domain
        self._log(f"Domain extrahiert: {domain}")

        self._update_overview({
            "URL": url,
            "Domain": domain,
            "Scheme": parsed.scheme,
            "Path": parsed.path or "/",
            "Timestamp (UTC)": self.report["timestamp"]
        })

        try:
            if whois_pkg:
                self._log("WHOIS wird ausgeführt...")
                whois_res = whois_pkg.whois(domain)
                self.whois_data = whois_res
                self.txt_whois.delete("1.0", "end")
                try:
                    for k, v in dict(whois_res).items():
                        self.txt_whois.insert("end", f"{k}: {v}\n")
                except Exception:
                    self.txt_whois.insert("end", str(whois_res))
                self.report["whois"] = str(whois_res)
            else:
                self.txt_whois.delete("1.0", "end")
                self.txt_whois.insert("end", self._t("whois_not_installed"))
                self._log(self._t("whois_not_installed"))
        except Exception as e:
            self._log(f"WHOIS error: {e}")
            self.txt_whois.delete("1.0", "end")
            self.txt_whois.insert("end", f"WHOIS error: {e}")

        try:
            self._log("DNS-Auflösung...")
            dns_info = {}
            try:
                addrinfo = socket.getaddrinfo(domain, None)
                ips = sorted({ai[4][0] for ai in addrinfo})
                dns_info["resolved_ips"] = ips
            except Exception as e:
                dns_info["resolved_ips"] = []
                self._log(f"DNS resolve error: {e}")

            reverse_map = {}
            for ip in dns_info["resolved_ips"]:
                try:
                    rev = socket.gethostbyaddr(ip)
                    reverse_map[ip] = rev[0]
                except Exception:
                    reverse_map[ip] = None
            dns_info["reverse"] = reverse_map
            self.dns_data = dns_info

            self.txt_dns.delete("1.0", "end")
            self.txt_dns.insert("end", f"Resolved IPs: {', '.join(dns_info['resolved_ips']) or '(none)'}\n\n")
            for ip, rev in dns_info["reverse"].items():
                self.txt_dns.insert("end", f"{ip} -> {rev}\n")
            self.report["dns"] = dns_info
            self.ip_list = dns_info["resolved_ips"]
        except Exception as e:
            self._log(f"DNS error: {e}")
            self.txt_dns.delete("1.0", "end")
            self.txt_dns.insert("end", f"DNS error: {e}")

        geo = {}
        if geoip2 and getattr(self, "_geoip_reader_path", ""):
            try:
                reader = geoip2.database.Reader(self._geoip_reader_path)
                if self.ip_list:
                    for ip in self.ip_list:
                        try:
                            rec = reader.city(ip)
                            geo[ip] = {
                                "country": rec.country.name,
                                "city": rec.city.name,
                                "latitude": rec.location.latitude,
                                "longitude": rec.location.longitude,
                                "subdivision": rec.subdivisions.most_specific.name,
                            }
                        except Exception as e:
                            geo[ip] = {"error": str(e)}
                reader.close()
            except Exception as e:
                self._log(f"GeoIP DB error: {e}")

        if not geo and requests and self.ip_list:
            self._log("Versuche GeoIP via ipinfo.io (Netzwerk)...")
            for ip in self.ip_list:
                try:
                    r = requests.get(f"https://ipinfo.io/{ip}/json", timeout=6)
                    if r.status_code == 200:
                        data = r.json()
                        loc = data.get("loc", "")
                        lat, lon = (loc.split(",") if loc else (None, None))
                        geo[ip] = {
                            "ip": ip,
                            "city": data.get("city"),
                            "region": data.get("region"),
                            "country": data.get("country"),
                            "org": data.get("org"),
                            "latitude": lat,
                            "longitude": lon
                        }
                except Exception as e:
                    geo[ip] = {"error": str(e)}

        if not geo:
            self.txt_geoip.delete("1.0", "end")
            self.txt_geoip.insert("end", self._t("geoip_not_available"))
            self._log(self._t("geoip_not_available"))
            self.report["geoip"] = None
        else:
            self.txt_geoip.delete("1.0", "end")
            for ip, info in geo.items():
                self.txt_geoip.insert("end", f"{ip}: {json.dumps(info, ensure_ascii=False, indent=2)}\n\n")
            self.report["geoip"] = geo

        domain_hash = hashlib.sha256(domain.encode("utf-8")).hexdigest().lower()
        self.txt_hash.delete("1.0", "end")
        self.txt_hash.insert("end", f"Domain SHA256: {domain_hash}\n")
        if self.hash_list:
            if domain_hash in self.hash_list:
                self.txt_hash.insert("end", f"\n{self._t('match_found')}\n")
                self.report["hash_check"] = {"domain_hash": domain_hash, "match": True}
            else:
                self.txt_hash.insert("end", f"\n{self._t('no_match')}\n")
                self.report["hash_check"] = {"domain_hash": domain_hash, "match": False}
            self._log(self._t("hashes_loaded"))
            self.lbl_hash_count.config(text=f"{len(self.hash_list)} hashes")
        else:
            self._log(self._t("no_hashes_loaded"))
            self.lbl_hash_count.config(text=self._t("no_hashes_loaded"))

        self.txt_vt_res.delete("1.0", "end")
        vtkey = self.ent_vt_key.get().strip() or self.vt_api_key
        if vtkey:
            if not requests:
                self.txt_vt_res.insert("end", self._t("vt_no_requests"))
                self._log(self._t("vt_no_requests"))
            else:
                self._log("VirusTotal (API) wird abgefragt...")
                try:
                    headers = {"x-apikey": vtkey}
                    r = requests.post("https://www.virustotal.com/api/v3/urls", data={"url": self.current_url}, headers=headers, timeout=15)
                    if r.status_code in (200, 201):
                        res = r.json()
                        analysis_id = res.get("data", {}).get("id")
                        if analysis_id:
                            rr = requests.get(f"https://www.virustotal.com/api/v3/analyses/{analysis_id}", headers=headers, timeout=15)
                            if rr.status_code == 200:
                                self.txt_vt_res.insert("end", json.dumps(rr.json(), indent=2))
                                self.report["virustotal"] = rr.json()
                            else:
                                self.txt_vt_res.insert("end", f"VT analysis fetch failed: {rr.status_code}")
                                self.report["virustotal_error"] = rr.text
                        else:
                            self.txt_vt_res.insert("end", json.dumps(res, indent=2))
                            self.report["virustotal"] = res
                    else:
                        self.txt_vt_res.insert("end", f"VT request failed: {r.status_code} {r.text}")
                        self.report["virustotal_error"] = r.text
                except Exception as e:
                    self._log(f"VirusTotal error: {e}")
                    self.txt_vt_res.insert("end", f"VirusTotal error: {e}")
        else:
            self.txt_vt_res.insert("end", self._t("vt_no_key"))

        self._log("Analyse abgeschlossen.")
        self.report["completed_at"] = datetime.datetime.now(datetime.timezone.utc).isoformat()

    def _update_overview(self, kv):
        self.ov_tree.delete(*self.ov_tree.get_children())
        for k, v in kv.items():
            self.ov_tree.insert("", "end", values=(k, v))

    def load_geoip_db(self):
        path = filedialog.askopenfilename(title="Select GeoIP2/GeoLite2 DB", filetypes=[("MMDB", "*.mmdb"), ("All files", "*.*")])
        if path:
            self._geoip_reader_path = path
            self.lbl_geo_db.config(text=f"DB: {Path(path).name}")
            self._log(f"GeoIP DB geladen: {path}")

    def load_hash_list(self):
        path = filedialog.askopenfilename(title=self._t("load_hashes"), filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
        if not path:
            return
        try:
            with open(path, "r", encoding="utf-8") as f:
                lines = [ln.strip().lower() for ln in f if ln.strip()]
            cleaned = {ln for ln in lines if len(ln) >= 32}
            self.hash_list = cleaned
            self.lbl_hash_count.config(text=f"{len(self.hash_list)} hashes")
            self._log(self._t("hashes_loaded") + f" ({len(self.hash_list)})")
        except Exception as e:
            messagebox.showerror(self._t("error"), f"Load hashes failed: {e}")
            self._log(f"Load hashes error: {e}")

    def set_vt_key_temp(self):
        key = self.ent_vt_key.get().strip()
        if not key:
            messagebox.showinfo(self._t("info"), self._t("vt_no_key"))
            return
        self.vt_api_key = key
        self._log("VT API key temporary set (in-memory).")

    def save_vt_key_to_config(self):
        key = self.ent_vt_key.get().strip()
        if not key:
            messagebox.showinfo(self._t("info"), self._t("vt_no_key"))
            return
        cfg_path = Path("config.py")
        content = f'# Auto-generated by URL Reputation Analyzer\nVT_API_KEY = "{key}"\n'
        try:
            if cfg_path.exists():
                if not messagebox.askyesno(self._t("save_report"), self._t("confirm_overwrite")):
                    return
            with open(cfg_path, "w", encoding="utf-8") as f:
                f.write(content)
            self._log(f"VT API key saved to config.py ({cfg_path.resolve()}).")
            messagebox.showinfo(self._t("save_report"), f"VT API key saved to {cfg_path}")
        except Exception as e:
            messagebox.showerror(self._t("error"), f"Unable to write config.py: {e}")
            self._log(f"Save config error: {e}")

    def save_report(self):
        if not self.report:
            messagebox.showinfo(self._t("info"), "No report to save.")
            return
        path = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON", "*.json")])
        if not path:
            return
        if os.path.exists(path):
            if not messagebox.askyesno(self._t("save_report"), self._t("confirm_overwrite")):
                return
        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(self.report, f, ensure_ascii=False, indent=2)
            messagebox.showinfo(self._t("save_report"), f"{self._t('report_saved')} {path}")
            self._log(f"Report saved: {path}")
        except Exception as e:
            messagebox.showerror(self._t("error"), f"Save failed: {e}")
            self._log(f"Save report error: {e}")

def main():
    root = tk.Tk()
    app = URLReputationAnalyzer(root)
    root.mainloop()

if __name__ == "__main__":
    main()
