#!/usr/bin/env python3
"""
PhishLens CLI v1.2
Offline Phishing Indicator Analyzer
Python 3.9+ | No database | No external libraries
"""

import argparse
import ipaddress
import json
import re
import sys
from datetime import datetime
from pathlib import Path
from urllib.parse import unquote, urlparse

VERSION = "1.2.0"

# ANSI terminal colors
RESET = "\033[0m"
BOLD = "\033[1m"
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
BLUE = "\033[94m"
GRAY = "\033[90m"


# ============================================================
# BANNER DAN TAMPILAN
# ============================================================

def banner():
    print(CYAN + BOLD + r"""
 ____  _     _     _     _                 
|  _ \| |__ (_)___| |__ | |    ___ _ __  ___
| |_) | '_ \| / __| '_ \| |   / _ \ '_ \/ __|
|  __/| | | | \__ \ | | | |__|  __/ | | \__ \
|_|   |_| |_|_|___/_| |_|_____\___|_| |_|___/
""" + RESET)

    print(BOLD + "       PHISHLENS SECURITY ANALYZER" + RESET)
    print(GRAY + "       Offline phishing indicator detection" + RESET)
    print(GRAY + f"       Version {VERSION} | Python {sys.version.split()[0]}" + RESET)
    print(CYAN + "=" * 58 + RESET)


def line():
    print(CYAN + "-" * 58 + RESET)


def pause():
    input("\nTekan ENTER untuk kembali ke menu...")


def clear_screen():
    # Menggunakan ANSI clear screen tanpa menjalankan perintah OS.
    print("\033[2J\033[H", end="")


def print_status(score):
    if score >= 70:
        color = RED
        label = "TINGGI"
    elif score >= 40:
        color = YELLOW
        label = "SEDANG"
    elif score >= 15:
        color = BLUE
        label = "RENDAH"
    else:
        color = GREEN
        label = "MINIMAL"

    print(color + BOLD + f"{label} ({score}/100)" + RESET)


# ============================================================
# ATURAN DETEKSI PESAN
# ============================================================

TEXT_RULES = [
    (
        "urgent",
        15,
        re.compile(
            r"\b(urgent|immediately|right now|today only|segera|"
            r"sekarang juga|hari ini|secepatnya)\b",
            re.I
        ),
        "Bahasa mendesak atau tekanan waktu"
    ),
    (
        "threat",
        20,
        re.compile(
            r"\b(suspended|suspend|blocked|deactivated|termination|"
            r"diblokir|dinonaktifkan|ditangguhkan|akun ditutup)\b",
            re.I
        ),
        "Ancaman pemblokiran atau penutupan akun"
    ),
    (
        "credentials",
        25,
        re.compile(
            r"\b(password|passcode|kata sandi|login credentials|"
            r"one[- ]time password|otp|pin anda|masukkan pin)\b",
            re.I
        ),
        "Menyebut kata sandi, OTP, PIN, atau kredensial"
    ),
    (
        "prize",
        15,
        re.compile(
            r"\b(free gift|you won|winner|claim your prize|"
            r"hadiah gratis|pemenang|anda memenangkan|klaim hadiah)\b",
            re.I
        ),
        "Iming-iming hadiah atau kemenangan"
    ),
    (
        "payment",
        20,
        re.compile(
            r"\b(transfer now|send money|pay immediately|"
            r"biaya admin|transfer sekarang|segera bayar|tebus hadiah)\b",
            re.I
        ),
        "Permintaan pembayaran dengan tekanan"
    ),
    (
        "identity",
        20,
        re.compile(
            r"\b(verify your identity|verify your account|data pribadi|"
            r"verifikasi akun|verifikasi identitas|unggah ktp)\b",
            re.I
        ),
        "Permintaan verifikasi identitas atau data pribadi"
    ),
]


# ============================================================
# ANALISIS URL
# ============================================================

SUSPICIOUS_TLDS = {
    "zip", "mov", "top", "xyz", "click", "work",
    "gq", "tk", "ml", "cf"
}


def extract_urls(text):
    """Mengambil URL dari teks tanpa mengunjungi URL tersebut."""
    pattern = (
        r"""(?i)\b(?:https?://|www\.)[^\s<>"']+|"""
        r"""(?<![@\w])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"""
        r"""[a-z]{2,}(?:/[^\s<>"']*)?"""
    )

    found = re.findall(pattern, text)
    urls = []

    for url in found:
        url = url.rstrip(".,;:!?)]}")
        if url and url not in urls:
            urls.append(url)

    return urls


def normalize_url(url):
    url = url.strip()

    if url.lower().startswith(("http://", "https://")):
        return url

    return "http://" + url


def is_ip_address(host):
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        return False


def analyze_url(raw_url):
    """Memeriksa struktur URL secara lokal."""
    normalized = normalize_url(raw_url)
    indicators = []
    score = 0

    def add(description, points):
        nonlocal score
        score += points
        indicators.append({
            "description": description,
            "points": points
        })

    try:
        parsed = urlparse(normalized)
        host = (parsed.hostname or "").lower().rstrip(".")

        if not host:
            raise ValueError("Host tidak ditemukan")

        # Batasi karakter yang diterima sebagai nama host.
        if any(char.isspace() for char in host):
            raise ValueError("Host mengandung spasi")

        if parsed.scheme != "https":
            add("Menggunakan HTTP, bukan HTTPS", 10)

        if parsed.username or parsed.password or "@" in parsed.netloc:
            add("Ada informasi sebelum tanda @ pada bagian host", 25)

        if is_ip_address(host):
            add("Host menggunakan alamat IP langsung", 25)

        if "xn--" in host:
            add("Domain menggunakan Punycode", 20)

        if len(host) > 45:
            add("Nama host sangat panjang", 10)

        if host.count("-") >= 3:
            add("Nama host memiliki banyak tanda hubung", 10)

        if len(host.split(".")) >= 5:
            add("Memiliki banyak tingkat subdomain", 10)

        tld = host.rsplit(".", 1)[-1] if "." in host else ""

        if tld in SUSPICIOUS_TLDS:
            add(f"Ekstensi .{tld} perlu diperiksa lebih lanjut", 10)

        decoded = unquote(normalized).lower()

        if any(term in decoded for term in (
            "login", "verify", "verification", "secure",
            "account", "password", "signin", "update"
        )):
            add("URL memuat istilah login atau verifikasi", 5)

        if len(normalized) > 120:
            add("URL sangat panjang", 10)

        if not indicators:
            indicators.append({
                "description": "Tidak ditemukan indikator dari aturan dasar",
                "points": 0
            })

        final_score = min(100, score)

        return {
            "url": raw_url,
            "normalized_url": normalized,
            "host": host,
            "score": final_score,
            "risk": risk_level(final_score),
            "indicators": indicators,
            "note": "URL tidak dikunjungi oleh program."
        }

    except (ValueError, UnicodeError) as exc:
        return {
            "url": raw_url,
            "score": 0,
            "risk": "TIDAK DAPAT DINILAI",
            "indicators": [
                {"description": f"URL tidak valid: {exc}", "points": 0}
            ]
        }


# ============================================================
# MESIN ANALISIS
# ============================================================

def risk_level(score):
    if score >= 70:
        return "TINGGI"
    if score >= 40:
        return "SEDANG"
    if score >= 15:
        return "RENDAH"
    return "MINIMAL"


def analyze_text(text):
    indicators = []
    score = 0

    for rule_id, points, pattern, description in TEXT_RULES:
        matches = pattern.findall(text)

        if matches:
            score += points
            indicators.append({
                "id": rule_id,
                "description": description,
                "points": points,
                "matches_count": len(matches)
            })

    urls = extract_urls(text)
    url_results = [analyze_url(url) for url in urls]

    # Hanya URL dengan skor tertinggi yang berkontribusi,
    # sehingga URL berulang tidak terus menambah skor.
    if url_results:
        highest_url_score = max(item["score"] for item in url_results)
        contribution = round(highest_url_score * 0.6)

        if contribution > 0:
            score += contribution
            indicators.append({
                "id": "url_risk",
                "description": "Kontribusi risiko URL tertinggi",
                "points": contribution
            })

    score = min(100, score)

    if not indicators:
        indicators.append({
            "id": "no_match",
            "description": "Tidak ditemukan pola yang cocok",
            "points": 0,
            "matches_count": 0
        })

    recommendations = []

    ids = {
        item["id"]
        for item in indicators
        if "id" in item
    }

    if "credentials" in ids or "identity" in ids:
        recommendations.append(
            "Jangan berikan kata sandi, OTP, PIN, atau data identitas."
        )

    if urls:
        recommendations.append(
            "Periksa domain melalui kanal resmi sebelum membuka tautan."
        )

    if score >= 40:
        recommendations.append(
            "Verifikasi pesan melalui aplikasi atau situs resmi."
        )

    if not recommendations:
        recommendations.append(
            "Periksa konteks dan identitas pengirim. "
            "Skor rendah bukan jaminan keamanan."
        )

    return {
        "tool": "PhishLens",
        "version": VERSION,
        "timestamp": datetime.now().astimezone().isoformat(
            timespec="seconds"
        ),
        "mode": "offline",
        "score": score,
        "risk": risk_level(score),
        "indicators": indicators,
        "urls": url_results,
        "recommendations": recommendations,
        "disclaimer": (
            "Skor adalah estimasi berbasis aturan, bukan probabilitas "
            "atau bukti pasti. Pesan aman bisa memicu indikator, "
            "sedangkan phishing bisa lolos dari deteksi."
        )
    }


# ============================================================
# INPUT DAN OUTPUT FILE
# ============================================================

def read_text_file(filename):
    path = Path(filename)

    if not path.exists():
        raise FileNotFoundError(f"File tidak ditemukan: {path}")

    if not path.is_file():
        raise ValueError(f"Path bukan file: {path}")

    if path.stat().st_size > 5_000_000:
        raise ValueError("Ukuran file melebihi batas 5 MB.")

    try:
        return path.read_text(encoding="utf-8-sig")
    except UnicodeDecodeError:
        return path.read_text(encoding="latin-1")


def save_json(data, filename):
    path = Path(filename)
    path.parent.mkdir(parents=True, exist_ok=True)

    path.write_text(
        json.dumps(data, ensure_ascii=False, indent=2),
        encoding="utf-8"
    )

    print(GREEN + f"\n[OK] Laporan disimpan: {path}" + RESET)


# ============================================================
# TAMPILAN LAPORAN
# ============================================================

def print_report(report):
    print()
    line()
    print(BOLD + "                 HASIL ANALISIS" + RESET)
    line()

    print(f"Mode        : {report.get('mode', 'offline').upper()}")
    print("Skor risiko : ", end="")
    print_status(report["score"])

    print()
    print(BOLD + "INDIKATOR YANG DITEMUKAN" + RESET)

    for item in report["indicators"]:
        print(
            YELLOW + "[!]" + RESET,
            item["description"],
            f"(+{item.get('points', 0)})"
        )

        if item.get("matches_count"):
            print(f"    Jumlah kecocokan: {item['matches_count']}")

    if report.get("urls"):
        print()
        print(BOLD + "PEMERIKSAAN URL" + RESET)

        for result in report["urls"]:
            print(f"\nURL    : {result['url']}")
            print(f"Host   : {result.get('host', '-')}")
            print(
                f"Risiko : {result['risk']} "
                f"({result['score']}/100)"
            )

            for item in result["indicators"]:
                print(f"  - {item['description']}")

    print()
    print(BOLD + "REKOMENDASI" + RESET)

    for recommendation in report.get("recommendations", []):
        print(GREEN + "[+]" + RESET, recommendation)

    print()
    line()
    print(GRAY + report.get("disclaimer", "") + RESET)
    line()


# ============================================================
# FITUR CLI
# ============================================================

def command_scan(args):
    if args.text is not None:
        text = args.text
        source = "input langsung"
    else:
        text = read_text_file(args.file)
        source = str(args.file)

    report = analyze_text(text)
    report["source"] = source

    print_report(report)

    if args.output:
        save_json(report, args.output)

    if args.strict and report["score"] >= args.threshold:
        return 2

    return 0


def command_url(args):
    result = analyze_url(args.url)

    report = {
        "tool": "PhishLens",
        "version": VERSION,
        "timestamp": datetime.now().astimezone().isoformat(
            timespec="seconds"
        ),
        "mode": "offline",
        "score": result["score"],
        "risk": result["risk"],
        "indicators": result["indicators"],
        "urls": [result],
        "recommendations": [
            "Jangan masukkan kredensial sebelum memastikan domain benar.",
            "Gunakan alamat situs resmi yang sudah diketahui."
        ],
        "disclaimer": result.get("note", "")
    }

    print_report(report)

    if args.output:
        save_json(report, args.output)

    return 0


def command_batch(args):
    folder = Path(args.folder)

    if not folder.exists() or not folder.is_dir():
        raise ValueError(f"Folder tidak ditemukan: {folder}")

    files = sorted(folder.glob("*.txt"))

    if not files:
        print(YELLOW + "Tidak ada file TXT dalam folder." + RESET)
        return 0

    results = []

    print(f"\nMemindai {len(files)} file TXT...\n")

    for path in files:
        try:
            report = analyze_text(read_text_file(path))
            report["source"] = str(path)
            results.append(report)

            print(
                f"{path.name:30} "
                f"{report['score']:3}/100  {report['risk']}"
            )

        except (OSError, ValueError) as exc:
            print(RED + f"{path.name}: {exc}" + RESET)

    summary = {
        "tool": "PhishLens",
        "version": VERSION,
        "timestamp": datetime.now().astimezone().isoformat(
            timespec="seconds"
        ),
        "files_scanned": len(results),
        "results": results
    }

    if args.output:
        save_json(summary, args.output)

    return 0


def command_demo(_args):
    samples = [
        (
            "CONTOH 1: PESAN MENCURIGAKAN",
            "PERINGATAN! Akun Anda akan diblokir hari ini. "
            "Verifikasi akun dan masukkan kata sandi "
            "untuk klaim hadiah gratis."
        ),
        (
            "CONTOH 2: PESAN INFORMASI BIASA",
            "Rapat kelompok dimulai pukul 13.00 di ruang kelas. "
            "Bawa catatan dan tugas yang sudah selesai."
        )
    ]

    for title, sample in samples:
        print()
        print(BOLD + title + RESET)
        print("Pesan:", sample)
        print_report(analyze_text(sample))

    return 0


# ============================================================
# MENU INTERAKTIF
# ============================================================

def interactive_menu():
    while True:
        clear_screen()
        banner()

        print(BOLD + "\nMENU UTAMA" + RESET)
        print(" [1] Analisis pesan teks")
        print(" [2] Analisis file TXT")
        print(" [3] Pemeriksaan URL")
        print(" [4] Pemindaian folder TXT")
        print(" [5] Demo analisis")
        print(" [6] Bantuan perintah CLI")
        print(" [0] Keluar")

        line()
        choice = input(CYAN + "PhishLens > " + RESET).strip()

        try:
            if choice == "1":
                message = input("\nMasukkan pesan: ").strip()

                if not message:
                    print(YELLOW + "Pesan tidak boleh kosong." + RESET)
                else:
                    report = analyze_text(message)
                    print_report(report)

                    if input("\nSimpan laporan JSON? (y/n): ").strip().lower() == "y":
                        filename = input("Nama file [laporan.json]: ").strip()
                        save_json(report, filename or "laporan.json")

                pause()

            elif choice == "2":
                filename = input("\nPath file TXT: ").strip().strip('"')
                report = analyze_text(read_text_file(filename))
                report["source"] = filename
                print_report(report)

                if input("\nSimpan laporan JSON? (y/n): ").strip().lower() == "y":
                    output = input("Nama file [laporan.json]: ").strip()
                    save_json(report, output or "laporan.json")

                pause()

            elif choice == "3":
                url = input("\nMasukkan URL: ").strip()

                if not url:
                    print(YELLOW + "URL tidak boleh kosong." + RESET)
                else:
                    result = analyze_url(url)
                    report = {
                        "mode": "offline",
                        "score": result["score"],
                        "risk": result["risk"],
                        "indicators": result["indicators"],
                        "urls": [result],
                        "recommendations": [
                            "Verifikasi domain melalui sumber resmi."
                        ],
                        "disclaimer": result.get("note", "")
                    }

                    print_report(report)

                    if input("\nSimpan laporan JSON? (y/n): ").strip().lower() == "y":
                        output = input("Nama file [laporan_url.json]: ").strip()
                        save_json(report, output or "laporan_url.json")

                pause()

            elif choice == "4":
                folder = input("\nPath folder: ").strip().strip('"')
                output = input("Nama laporan [laporan_batch.json]: ").strip()

                args = argparse.Namespace(
                    folder=folder,
                    output=output or "laporan_batch.json"
                )

                command_batch(args)
                pause()

            elif choice == "5":
                command_demo(None)
                pause()

            elif choice == "6":
                print("\nContoh penggunaan:")
                print("  python main.py demo")
                print('  python main.py scan --text "Pesan mencurigakan"')
                print("  python main.py scan --file pesan.txt")
                print('  python main.py url "https://contoh.com/login"')
                print("  python main.py batch data/ -o hasil.json")
                print("  python main.py --help")
                pause()

            elif choice == "0":
                print("\nPhishLens ditutup. Tetap waspada saat online.")
                return 0

            else:
                print(RED + "Pilihan tidak valid." + RESET)
                pause()

        except (OSError, ValueError) as exc:
            print(RED + f"\nERROR: {exc}" + RESET)
            pause()

        except KeyboardInterrupt:
            print("\nOperasi dibatalkan.")
            pause()


# ============================================================
# ARGPARSE DAN PROGRAM UTAMA
# ============================================================

def build_parser():
    parser = argparse.ArgumentParser(
        prog="phishlens",
        description="PhishLens: offline phishing indicator analyzer"
    )

    parser.add_argument(
        "--version",
        action="version",
        version=f"PhishLens {VERSION}"
    )

    subparsers = parser.add_subparsers(dest="command")

    scan = subparsers.add_parser(
        "scan",
        help="Analisis pesan atau file TXT"
    )

    source = scan.add_mutually_exclusive_group(required=True)
    source.add_argument("--text", help="Pesan yang dianalisis")
    source.add_argument("--file", help="Path file TXT")

    scan.add_argument("-o", "--output", help="Simpan laporan JSON")
    scan.add_argument(
        "--strict",
        action="store_true",
        help="Gunakan exit code 2 jika ambang risiko tercapai"
    )
    scan.add_argument(
        "--threshold",
        type=int,
        default=40,
        help="Ambang risiko 0-100 (default: 40)"
    )
    scan.set_defaults(func=command_scan)

    url = subparsers.add_parser(
        "url",
        help="Analisis struktur URL"
    )
    url.add_argument("url", help="URL yang diperiksa")
    url.add_argument("-o", "--output", help="Simpan laporan JSON")
    url.set_defaults(func=command_url)

    batch = subparsers.add_parser(
        "batch",
        help="Pindai file TXT dalam folder"
    )
    batch.add_argument("folder", help="Folder berisi file TXT")
    batch.add_argument("-o", "--output", help="Simpan laporan JSON")
    batch.set_defaults(func=command_batch)

    demo = subparsers.add_parser(
        "demo",
        help="Jalankan contoh analisis"
    )
    demo.set_defaults(func=command_demo)

    return parser


def main():
    # Tanpa argumen, buka menu. Tidak ada lagi SystemExit
    # hanya karena pengguna menekan Run Python File.
    if len(sys.argv) == 1:
        return interactive_menu()

    parser = build_parser()
    args = parser.parse_args()

    if args.command is None:
        parser.print_help()
        return 0

    if hasattr(args, "threshold") and not 0 <= args.threshold <= 100:
        parser.error("--threshold harus antara 0 dan 100")

    try:
        return args.func(args)
    except (OSError, ValueError) as exc:
        print(RED + f"ERROR: {exc}" + RESET, file=sys.stderr)
        return 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\nProgram dihentikan pengguna.")
        sys.exit(130)
