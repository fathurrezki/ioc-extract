"""Uji unit untuk ioc-extract. Jalankan: python -m unittest discover -s tests"""

import contextlib
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from ioc_extract import (  # noqa: E402
    Allowlist,
    decode,
    default_allowlist,
    defang,
    extract,
    ip_problem,
    ip_scope,
    main,
    refang,
    render_csv,
    render_json,
    valid_domain,
)

SAMPLES = ROOT / "samples"


def found(text, ioc_type, allowlist=None):
    return extract(text, allowlist).values(ioc_type)


def dropped(text, allowlist=None):
    return {(d.type, d.value): d.reason for d in extract(text, allowlist).dropped}


# --------------------------------------------------------------------------
# tahap 1: refang / defang
# --------------------------------------------------------------------------

class TestRefang(unittest.TestCase):
    def test_skema(self):
        self.assertEqual(refang("hxxp://a.test"), "http://a.test")
        self.assertEqual(refang("HXXPS[:]//a.test"), "https://a.test")
        self.assertEqual(refang("fxp://a.test"), "ftp://a.test")
        self.assertEqual(refang("hxxps[://]a.test"), "https://a.test")

    def test_titik(self):
        for teks in ("evil[.]test", "evil(.)test", "evil{.}test", "evil[ . ]test",
                     "evil[dot]test", "evil (dot) test", "evil [DOT] test"):
            self.assertEqual(refang(teks), "evil.test", teks)

    def test_ip_sebagian_dijinakkan(self):
        self.assertEqual(refang("203.0.113[.]45"), "203.0.113.45")

    def test_at(self):
        for teks in ("user[at]evil.test", "user [at] evil.test", "user(@)evil.test", "user[@]evil.test"):
            self.assertEqual(refang(teks), "user@evil.test", teks)

    def test_karakter_tak_terlihat(self):
        self.assertEqual(refang("evil​.test"), "evil.test")

    def test_teks_biasa_tidak_berubah(self):
        teks = "Meet at 10, the dot matrix printer (see page 3) [draft]"
        self.assertEqual(refang(teks), teks)
        self.assertEqual(refang("hxxpress"), "hxxpress")


class TestDefang(unittest.TestCase):
    def test_url(self):
        self.assertEqual(defang("https://evil.test/a.php"), "hxxps://evil[.]test/a[.]php")

    def test_ip(self):
        self.assertEqual(defang("203.0.113.45"), "203[.]0[.]113[.]45")

    def test_hash_tidak_berubah(self):
        h = "832ca94a2240429b6bcd6be9413b2fa1ac3d12c9dc79c9bc219f96a82b054497"
        self.assertEqual(defang(h), h)

    def test_bolak_balik(self):
        for v in ("https://evil.test/x", "203.0.113.45", "user@evil.test"):
            self.assertEqual(refang(defang(v)), v)


# --------------------------------------------------------------------------
# tahap 2-4 per jenis IOC
# --------------------------------------------------------------------------

class TestIPv4(unittest.TestCase):
    def test_dasar(self):
        self.assertEqual(found("C2 di 203.0.113.45, cadangan 198.51.100.7.", "ipv4"),
                         ["198.51.100.7", "203.0.113.45"])

    def test_oktet_tidak_sah(self):
        for teks in ("256.1.1.1", "1.2.3.999", "01.2.3.4", "1.2.3"):
            self.assertEqual(found(teks, "ipv4"), [], teks)

    def test_tidak_memotong_versi_atau_oid(self):
        for teks in ("v1.2.3.4", "1.2.3.4.5", "OID 1.3.6.1.4.1.311", "a1.2.3.4"):
            self.assertEqual(found(teks, "ipv4"), [], teks)

    def test_port_cidr_rentang(self):
        self.assertEqual(found("203.0.113.5:443 203.0.113.0/24 198.51.100.1-198.51.100.9", "ipv4"),
                         ["198.51.100.1", "198.51.100.9", "203.0.113.0", "203.0.113.5"])

    def test_nomor_versi_dibuang(self):
        for teks in ("Chrome 120.0.0.1", "versi 7.2.0.15", "build: 1.0.0.9", "Firefox/115.0.0.2",
                     "Bagian 2.1.3.4"):
            self.assertEqual(found(teks, "ipv4"), [], teks)
        # kata kunci harus TEPAT di depan; "server" bukan penanda versi
        self.assertEqual(found("server 203.0.113.9", "ipv4"), ["203.0.113.9"])

    def test_alamat_khusus(self):
        self.assertEqual(ip_problem("127.0.0.1"), "loopback")
        self.assertEqual(ip_problem("255.255.255.0"), "netmask")
        self.assertEqual(ip_problem("255.255.255.255"), "netmask")
        self.assertEqual(ip_problem("224.0.0.251"), "multicast")
        self.assertEqual(ip_problem("0.0.0.0"), "alamat 'this network'")
        self.assertEqual(ip_problem("255.1.2.3"), "alamat cadangan / broadcast")  # bukan netmask
        self.assertIsNone(ip_problem("8.8.8.8"))

    def test_scope(self):
        self.assertEqual(ip_scope("10.1.2.3"), "internal")
        self.assertEqual(ip_scope("172.20.0.1"), "internal")
        self.assertEqual(ip_scope("100.64.0.1"), "internal")
        self.assertEqual(ip_scope("203.0.113.1"), "documentation")
        self.assertEqual(ip_scope("8.8.8.8"), "public")

    def test_ip_internal_tetap_keluar(self):
        result = extract("host korban 10.20.30.40")
        self.assertEqual([(i.value, i.scope) for i in result.indicators], [("10.20.30.40", "internal")])

    def test_diurutkan_numerik(self):
        self.assertEqual(found("203.0.113.100 203.0.113.9 203.0.113.20", "ipv4"),
                         ["203.0.113.9", "203.0.113.20", "203.0.113.100"])


class TestDomain(unittest.TestCase):
    def test_dasar_dan_huruf_kecil(self):
        self.assertEqual(found("C2: Cdn-Update.test dan mail.evil.example", "domain"),
                         ["mail.evil.example", "cdn-update.test"])

    def test_tld_harus_terdaftar(self):
        self.assertTrue(valid_domain("evil.com"))
        self.assertTrue(valid_domain("evil.co.id"))
        self.assertFalse(valid_domain("setup.exe"))
        self.assertFalse(valid_domain("kernel32.dll"))
        self.assertEqual(found("setup.exe kernel32.dll laporan.pdf config.json", "domain"), [])

    def test_bagian_depan_email_bukan_domain(self):
        self.assertEqual(found("john.smith@evil.test", "domain"), ["evil.test"])

    def test_label_tidak_sah(self):
        self.assertEqual(found("-evil.test evil-.test", "domain"), [])

    def test_mirip_nama_file(self):
        self.assertEqual(found("README.md setup.py deploy.sh", "domain"), [])
        self.assertEqual(dropped("README.md")[("domain", "readme.md")], "mirip nama file")

    def test_tld_ambigu_lolos_kalau_ada_konteks_tegas(self):
        # ditulis dijinakkan = penulis sengaja menandainya sebagai IOC
        self.assertEqual(found("payload di evil[.]zip", "domain"), ["evil.zip"])
        # jadi host URL
        self.assertEqual(found("unduh https://evil.zip/a", "domain"), ["evil.zip"])
        # jadi domain email
        self.assertEqual(found("dari admin@evil.zip", "domain"), ["evil.zip"])
        # tiga label: jelas bukan nama file
        self.assertEqual(found("cdn.evil.zip", "domain"), ["cdn.evil.zip"])

    def test_potongan_kode(self):
        teks = "self.name = x; window.open(u); using System.IO; print(user.info())"
        self.assertEqual(found(teks, "domain"), [])
        alasan = dropped(teks)
        self.assertIn("kode", alasan[("domain", "self.name")])
        self.assertIn("namespace", alasan[("domain", "system.io")])
        self.assertIn("fungsi", alasan[("domain", "user.info")])

    def test_huruf_besar_semua_tetap_domain(self):
        self.assertEqual(found("EVIL.TEST", "domain"), ["evil.test"])

    def test_subdomain_berkumpul(self):
        self.assertEqual(found("b.test a.evil.test evil.test", "domain"),
                         ["b.test", "evil.test", "a.evil.test"])


class TestUrl(unittest.TestCase):
    def test_dasar_dan_normalisasi(self):
        self.assertEqual(found("buka HTTPS://Evil.TEST/Path?A=1", "url"), ["https://evil.test/Path?A=1"])

    def test_tanda_baca_di_ujung(self):
        self.assertEqual(found("lihat https://evil.test/a.", "url"), ["https://evil.test/a"])
        self.assertEqual(found("(https://evil.test/a)", "url"), ["https://evil.test/a"])
        self.assertEqual(found("https://evil.test/wiki/A_(b).", "url"), ["https://evil.test/wiki/A_(b)"])
        self.assertEqual(found('href="https://evil.test/x"', "url"), ["https://evil.test/x"])

    def test_dijinakkan(self):
        self.assertEqual(found("hxxp://203.0.113[.]45:8080/gate.php", "url"),
                         ["http://203.0.113.45:8080/gate.php"])

    def test_host_tidak_sah(self):
        self.assertEqual(found("http://intranet/login http://localhost:8080/", "url"), [])
        self.assertEqual(found("http://127.0.0.1:8080/", "url"), [])

    def test_host_url_ikut_jadi_domain(self):
        self.assertEqual(found("https://evil.test/x", "domain"), ["evil.test"])


class TestEmail(unittest.TestCase):
    def test_dasar(self):
        self.assertEqual(found("dari Billing@Secure-Login.example", "email"),
                         ["billing@secure-login.example"])

    def test_dijinakkan(self):
        self.assertEqual(found("billing[at]evil[.]test", "email"), ["billing@evil.test"])

    def test_tld_tidak_sah(self):
        self.assertEqual(found("user@host.local", "email"), [])


class TestHash(unittest.TestCase):
    SHA256 = "832ca94a2240429b6bcd6be9413b2fa1ac3d12c9dc79c9bc219f96a82b054497"
    SHA1 = "9adf2ce75e3d6d3fa0d64edf123789fcda7cdaf5"
    MD5 = "abdc2a6a13ad73bcf3b40f32df469e02"

    def test_tiga_jenis(self):
        result = extract(f"{self.MD5} {self.SHA1} {self.SHA256}")
        self.assertEqual(result.values("md5"), [self.MD5])
        self.assertEqual(result.values("sha1"), [self.SHA1])
        self.assertEqual(result.values("sha256"), [self.SHA256])

    def test_huruf_besar_dan_hitungan(self):
        result = extract(f"{self.SHA256} lalu {self.SHA256.upper()}")
        self.assertEqual([(i.value, i.count) for i in result.indicators], [(self.SHA256, 2)])

    def test_panjang_lain_ditolak(self):
        self.assertEqual(extract(self.SHA256[:48]).indicators, [])
        self.assertEqual(extract("0x" + self.MD5).indicators, [])

    def test_bukan_hash(self):
        self.assertEqual(extract("1" * 16 + "2" * 16).indicators, [])  # angka semua
        self.assertEqual(extract("ab" * 16).indicators, [])            # pola berulang

    def test_id_sesi_dan_commit(self):
        for teks in (f"session_id={self.SHA256}", f"X-Request-ID: {self.SHA256}",
                     f'"sessionToken": "{self.SHA256}"', f"PHPSESSID={self.MD5}",
                     f"commit {self.SHA1}"):
            self.assertEqual(extract(teks).indicators, [], teks)
        # kata "sid" di tengah kata lain tidak boleh memicu
        self.assertEqual(found(f"outside: {self.MD5}", "md5"), [self.MD5])

    def test_cukup_satu_kemunculan_yang_lolos(self):
        teks = f"session={self.SHA256}\nSHA256 berkas: {self.SHA256}"
        self.assertEqual(found(teks, "sha256"), [self.SHA256])


class TestCve(unittest.TestCase):
    def test_dasar_dan_urutan(self):
        self.assertEqual(found("cve-2024-3400, CVE-2021-44228 dan CVE-2024-21412", "cve"),
                         ["CVE-2021-44228", "CVE-2024-3400", "CVE-2024-21412"])

    def test_en_dash_dari_pdf(self):
        self.assertEqual(found("CVE–2023–4966", "cve"), ["CVE-2023-4966"])

    def test_tahun_mustahil(self):
        self.assertEqual(found("CVE-1899-0001 CVE-2999-1234", "cve"), [])


class TestAllowlist(unittest.TestCase):
    def test_domain_beserta_subdomain(self):
        allow = Allowlist(["perusahaan.test"])
        teks = "mail.perusahaan.test perusahaan.test https://sso.perusahaan.test/x staf@perusahaan.test"
        self.assertEqual(extract(teks, allow).indicators, [])

    def test_cidr_dan_nilai_persis(self):
        allow = Allowlist(["10.20.0.0/16", "CVE-2021-44228", "abdc2a6a13ad73bcf3b40f32df469e02"])
        teks = "10.20.1.1 10.21.1.1 CVE-2021-44228 ABDC2A6A13AD73BCF3B40F32DF469E02"
        self.assertEqual([i.value for i in extract(teks, allow).indicators], ["10.21.1.1"])

    def test_komentar_dan_baris_kosong(self):
        allow = Allowlist(["# komentar", "", "evil.test   # alasan"])
        self.assertEqual(extract("evil.test", allow).indicators, [])

    def test_bawaan_tidak_memuat_domain_populer(self):
        # hosting sah sering dipakai phishing; tidak boleh dibisukan secara bawaan
        teks = "https://sites.google.com/view/x https://evil.sharepoint.com/y"
        self.assertEqual(len(extract(teks, default_allowlist()).values("url")), 2)

    def test_bawaan_membuang_placeholder_dan_hash_kosong(self):
        teks = "https://example.com/x e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        self.assertEqual(extract(teks, default_allowlist()).indicators, [])


# --------------------------------------------------------------------------
# sampel: rem terhadap aturan yang terlalu galak / terlalu longgar
# --------------------------------------------------------------------------

class TestSampel(unittest.TestCase):
    def test_noise_wajib_kosong(self):
        teks = (SAMPLES / "noise.txt").read_text(encoding="utf-8")
        result = extract(teks, default_allowlist())
        self.assertEqual(result.indicators, [], [i.value for i in result.indicators])
        self.assertGreater(len(result.dropped), 20)  # jebakannya memang tertangkap, bukan terlewat

    def test_advisory_persis(self):
        teks = (SAMPLES / "advisory.txt").read_text(encoding="utf-8")
        result = extract(teks, default_allowlist())
        self.assertEqual({t: result.values(t) for t in ("ipv4", "domain", "url", "email", "md5",
                                                         "sha1", "sha256", "cve")}, {
            "ipv4": ["10.20.30.40", "198.51.100.23", "203.0.113.45"],
            "domain": ["secure-login.example", "cdn-update.test"],
            "url": ["http://203.0.113.45:8080/gate.php", "https://secure-login.example/verify?id=7&ref=mail"],
            "email": ["billing@secure-login.example"],
            "md5": ["abdc2a6a13ad73bcf3b40f32df469e02"],
            "sha1": ["9adf2ce75e3d6d3fa0d64edf123789fcda7cdaf5"],
            "sha256": ["832ca94a2240429b6bcd6be9413b2fa1ac3d12c9dc79c9bc219f96a82b054497"],
            "cve": ["CVE-2023-4966", "CVE-2024-3400"],
        })


# --------------------------------------------------------------------------
# tahap 5: keluaran + CLI
# --------------------------------------------------------------------------

class TestKeluaran(unittest.TestCase):
    TEKS = "C2 hxxps://evil[.]test/a dari 203.0.113.45"

    def test_json_defang_dan_raw(self):
        doc = json.loads(render_json(extract(self.TEKS)))
        self.assertTrue(doc["defanged"])
        self.assertIn("hxxps://evil[.]test/a", [i["value"] for i in doc["indicators"]])
        self.assertEqual(doc["summary"], {"ipv4": 1, "domain": 1, "url": 1})
        raw = json.loads(render_json(extract(self.TEKS), raw=True))
        self.assertIn("https://evil.test/a", [i["value"] for i in raw["indicators"]])
        self.assertEqual(raw["indicators"][0]["scope"], "documentation")

    def test_csv(self):
        lines = render_csv(extract(self.TEKS)).splitlines()
        self.assertEqual(lines[0], "type,value,count,scope")
        self.assertIn("ipv4,203[.]0[.]113[.]45,1,documentation", lines)


def run_main(*argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = main(list(argv))
    return code, out.getvalue(), err.getvalue()


class TestCli(unittest.TestCase):
    def test_kode_keluar(self):
        self.assertEqual(run_main(str(SAMPLES / "advisory.txt"))[0], 0)
        self.assertEqual(run_main(str(SAMPLES / "noise.txt"))[0], 1)
        code, _, err = run_main("tidak-ada.txt")
        self.assertEqual(code, 2)
        self.assertIn("tidak-ada.txt", err)

    def test_filter_jenis_dan_values_only(self):
        _, out, _ = run_main(str(SAMPLES / "advisory.txt"), "-t", "ipv4", "--values-only", "--raw")
        self.assertEqual(out.split(), ["10.20.30.40", "198.51.100.23", "203.0.113.45"])

    def test_jenis_tidak_dikenal(self):
        with self.assertRaises(SystemExit) as ctx, contextlib.redirect_stderr(io.StringIO()):
            main(["-t", "ipv6", str(SAMPLES / "advisory.txt")])
        self.assertEqual(ctx.exception.code, 2)

    def test_show_dropped_ke_stderr(self):
        _, out, err = run_main(str(SAMPLES / "noise.txt"), "--show-dropped")
        self.assertEqual(out, "")
        self.assertIn("mirip nama file", err)

    def test_allowlist_tambahan(self):
        with tempfile.TemporaryDirectory() as tmp:
            allow = Path(tmp) / "milik-sendiri.txt"
            allow.write_text("secure-login.example\n10.0.0.0/8\n", encoding="utf-8")
            _, out, _ = run_main(str(SAMPLES / "advisory.txt"), "--allowlist", str(allow), "--raw")
        self.assertNotIn("secure-login.example", out)
        self.assertNotIn("10.20.30.40", out)
        self.assertIn("cdn-update.test", out)

    def test_stdin_utf16_dari_powershell(self):
        data = "C2 evil[.]test".encode("utf-16")  # ber-BOM, seperti hasil `>` di PowerShell 5.1
        completed = subprocess.run([sys.executable, str(ROOT / "ioc_extract.py"), "--raw"],
                                   input=data, capture_output=True, timeout=30)
        self.assertEqual(completed.returncode, 0)
        self.assertEqual(completed.stdout.decode().split(), ["domain", "evil.test"])

    def test_decode(self):
        self.assertEqual(decode("évil".encode("utf-8")), "évil")
        self.assertEqual(decode("évil".encode("cp1252")), "évil")
        self.assertEqual(decode(b"\xef\xbb\xbfabc"), "abc")


if __name__ == "__main__":
    unittest.main()
