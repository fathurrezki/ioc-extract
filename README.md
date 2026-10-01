# ioc-extract

Memungut indikator serangan (IOC) dari teks bebas apa pun (tiket, advisory vendor, chat,
badan email, log yang gagal di-parse SIEM) lalu mengeluarkan daftar yang **sudah divalidasi,
disaring dari sampah, dan bebas duplikat**, siap dicari di SIEM atau dimasukkan ke blocklist.

Hanya pustaka standar Python 3.9+. Tanpa instalasi paket. **Tanpa koneksi keluar**: tidak ada
data yang meninggalkan mesin.

## Masalah yang dipecahkan

Analis SOC setiap hari menerima teks yang berisi indikator, dalam bentuk yang berantakan:
advisory 20 halaman dengan IP dan hash tersebar di paragraf, tiket berisi tempelan log mentah,
chat yang menulis `hxxp://evil[.]com`. Menyalin satu per satu lambat, rawan salah ketik, dan
sering terlewat. Salinan mentah `evil[.]com` bahkan tidak akan pernah cocok di SIEM.

Parser SIEM (grok) hanya bisa membaca format yang sudah dikenalnya. ioc-extract tidak perlu tahu
formatnya: ia mencari **bentuk** indikator, sehingga bekerja justru di tempat yang tidak terjangkau
parser (`_grokparsefailure`, field teks bebas seperti `message` atau `process.command_line`,
dokumen yang tidak pernah masuk SIEM).

## Untuk siapa, kapan dipakai

| Pengguna | Skenario |
|---|---|
| Analis SOC L1/L2 | Advisory vendor masuk, lalu semua IOC-nya dicari di SIEM/EDR |
| Analis SOC L1/L2 | Tiket berisi log mentah yang gagal di-parse |
| Penangan phishing | Bersama [eml-triage](../eml-triage): eml-triage menilai email, ioc-extract memungut indikatornya |
| Threat intel / IR | Merangkum advisory, menyusun lampiran IOC laporan insiden |
| Admin IT | Menyiapkan daftar blokir dari IOC kiriman vendor |

**Bukan** untuk memberi vonis "berbahaya/aman". Alat ini *mengumpulkan*, analis yang *menilai*.

## Cara pakai

```bash
python ioc_extract.py advisory.txt                  # dari berkas
python ioc_extract.py --clip                        # dari clipboard
Get-Content tiket.txt | python ioc_extract.py       # dari pipa (PowerShell / bash)
python ioc_extract.py --json advisory.txt > ioc.json
python ioc_extract.py -t ipv4 --values-only --raw advisory.txt   # daftar IP polos untuk blocklist
python ioc_extract.py --show-dropped advisory.txt   # tunjukkan juga apa yang dibuang dan alasannya
```

| Opsi | Arti |
|---|---|
| `--json` / `--csv` | format keluaran (bawaan: satu IOC per baris) |
| `--raw` | jangan defang (untuk diolah mesin). Tanpa opsi ini SEMUA format didefang |
| `-t ipv4,domain` | hanya jenis tertentu: `ipv4 domain url email md5 sha1 sha256 cve` |
| `--values-only` | nilainya saja, tanpa kolom jenis |
| `--allowlist FILE` | allowlist tambahan (boleh diulang), misalnya domain milik organisasi sendiri |
| `--no-default-allowlist` | matikan `data/allowlist.txt` |
| `--show-dropped` | daftar yang dibuang + alasannya (ke stderr; di JSON menjadi kunci `dropped`) |

Kode keluar: `0` ada IOC, `1` tidak ada IOC, `2` galat. Bisa dipakai di skrip:
`python ioc_extract.py tiket.txt > /dev/null && echo "ada indikator"`.

## Contoh

Dari [`samples/advisory.txt`](samples/advisory.txt):

```
$ python ioc_extract.py samples/advisory.txt
ipv4    10[.]20[.]30[.]40  [internal]
ipv4    198[.]51[.]100[.]23  [dokumentasi]
ipv4    203[.]0[.]113[.]45  [dokumentasi]
domain  secure-login[.]example
domain  cdn-update[.]test
url     hxxp://203[.]0[.]113[.]45:8080/gate[.]php
url     hxxps://secure-login[.]example/verify?id=7&ref=mail
email   billing@secure-login[.]example
md5     abdc2a6a13ad73bcf3b40f32df469e02
sha1    9adf2ce75e3d6d3fa0d64edf123789fcda7cdaf5
sha256  832ca94a2240429b6bcd6be9413b2fa1ac3d12c9dc79c9bc219f96a82b054497
cve     CVE-2023-4966
cve     CVE-2024-3400
```

Berkas yang sama juga berisi `Chrome 120.0.0.1`, `255.255.255.0`, `README.md`,
`session_id=<hex 64>`, dan `https://example.com/lapor`. Semuanya **tidak** keluar sebagai IOC.
`--show-dropped` menunjukkan alasannya:

```
# dibuang  ipv4    120[.]0[.]0[.]1  <- nomor versi atau penomoran
# dibuang  ipv4    255[.]255[.]255[.]0  <- netmask
# dibuang  domain  readme[.]md  <- mirip nama file
# dibuang  sha256  a4473db1...a0a9  <- ID sesi / token / commit
# dibuang  url     hxxps://example[.]com/lapor  <- allowlist (example.com)
```

## Cara kerjanya

```
teks ──► 1. refang ──► 2. ekstraksi ──► 3. validasi ──► 4. penyaringan ──► 5. keluaran
         hxxp→http     regex per         oktet 0-255,      versi, nama file,   dedupe, urut,
         [.]→.         jenis IOC         TLD IANA,         kode, ID sesi,      defang,
         [at]→@                          tahun CVE         alamat khusus,      baris/JSON/CSV
                                                           allowlist
```

**Penyaringan adalah bagian terpenting.** Menemukan bentuk IOC itu mudah; yang sulit adalah
tidak membanjiri analis dengan sampah. Aturannya:

| Jenis | Dibuang kalau... | Contoh |
|---|---|---|
| IPv4 | didahului kata versi/produk/penomoran | `Chrome 120.0.0.1`, `versi 7.2.0.15`, `Bagian 2.1.3.4` |
| IPv4 | netmask, loopback, 0.x, multicast, cadangan | `255.255.255.0`, `127.0.0.1`, `224.0.0.251` |
| Domain | TLD tidak terdaftar di IANA | `setup.exe`, `kernel32.dll`, `config.json` |
| Domain | TLD ambigu + dua label (`.zip .py .md .sh .app ...`) | `README.md`, `setup.py`, `Terminal.app` |
| Domain | gaya potongan kode | `self.name`, `window.open(...)`, `System.IO` |
| Hash | didahului kata sesi/token/commit | `session_id=...`, `X-Request-ID: ...`, `commit ...` |
| Hash | angka semua / pola berulang | nomor resi 32 digit |
| CVE | tahun di luar 1999 sampai tahun depan | `CVE-1899-0001` |
| Semua | ada di allowlist | `example.com`, namespace XML, hash berkas kosong |

Dua prinsip yang menjaga agar penyaringan tidak kebablasan:

1. **Konteks tegas mengalahkan heuristik.** `evil.zip` sendirian dianggap nama file, tetapi kalau
   ia muncul sebagai host URL, domain email, atau ditulis dijinakkan (`evil[.]zip`), ia tetap
   dilaporkan, karena penulisnya jelas bermaksud menandainya sebagai indikator.
2. **Satu kemunculan yang lolos sudah cukup.** Hash yang muncul sekali sebagai `session=` dan
   sekali sebagai `SHA256 berkas:` tetap dilaporkan.

IP internal (`10.x`, `172.16-31.x`, `192.168.x`, `100.64.x`, `169.254.x`) **tetap dikeluarkan**
dengan label `[internal]`, karena "host korban 10.20.30.40" adalah informasi penting. Hanya saja
alamat itu bukan untuk diblokir di firewall perimeter.

## Batasan (disampaikan terus terang)

- **Tidak ada lookup reputasi** (VirusTotal dan sejenisnya), dan ini disengaja: nol data keluar.
- **Tidak memberi vonis.** Masuk daftar tidak berarti jahat.
- **Heuristik bisa keliru.** Karena itu setiap pembuangan bisa diperiksa dengan `--show-dropped`.
- **v1 hanya teks.** PDF/DOCX direncanakan di v1.2; IPv6 dan indikator lain (path registri,
  mutex, JA3) belum didukung.
- **Allowlist bawaan sengaja minim.** `google.com`, `microsoft.com`, dan sejenisnya TIDAK
  dimasukkan, karena layanan sah (Google Sites, SharePoint) sering dipakai menampung phishing.
  Domain milik organisasi sendiri ditambahkan lewat `--allowlist`.

## Keamanan & privasi

- Semua proses lokal; tidak ada soket jaringan yang dibuka.
- Keluaran bawaan didefang agar tidak ada yang tak sengaja mengklik tautan dari tiket.
- Daftar TLD (`data/tlds.txt`) disalin sekali dari IANA dan dibaca offline.
  Perbarui sesekali dari `https://data.iana.org/TLD/tlds-alpha-by-domain.txt`.
- Sampel memakai nama cadangan RFC 2606 (`.example`, `.test`) dan IP dokumentasi RFC 5737;
  tidak ada data klien.

## Struktur

```
ioc_extract.py          seluruh logika (refang, regex, validasi, saring, keluaran, CLI)
data/tlds.txt           daftar TLD resmi IANA
data/allowlist.txt      allowlist bawaan (minimal, beralasan)
samples/advisory.txt    advisory sintetis: keluaran harus persis 13 IOC
samples/noise.txt       berisi jebakan saja: keluaran WAJIB kosong
tests/                  uji unit
```

## Uji

```bash
python -m unittest discover -s tests
```

`samples/noise.txt` adalah rem: setiap aturan baru yang membuat berkas itu menghasilkan temuan
berarti terlalu galak dan harus diperbaiki sebelum dipakai.

## Rencana

- **v1.1**: keluaran ECS `threat.indicator.*` agar bisa langsung di-ingest ke indeks threat intel
  Elastic dan dipakai Indicator Match rule.
- **v1.2**: membaca PDF/DOCX.
