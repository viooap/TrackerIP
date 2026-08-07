<img width="687" height="135" alt="Screenshot_20260807_111502" src="https://github.com/user-attachments/assets/8dab3970-6a75-4e7e-93bc-5ad1a51fd46f" />



# TrackerIP
TrackerIp.py adalah lokasi toolkit satu file untuk CTF (Capture The Flag) — alat OSINT untuk mencari posisi geografis dari berbagai jejak digital

# CTF
CTF (Capture The Flag) adalah kompetisi keamanan siber di mana peserta menyelesaikan berbagai tantangan untuk mendapatkan "flag" (kode rahasia berisi poin) dalam kategori seperti OSINT, Forensics, Crypto, Web, Reversing, dan Pwn. Tools TrackerIp.py sangat berguna di kategori OSINT/lokasi karena dalam sekejap mengubah jejak digital—IP, BSSID WiFi, koordinat seluler (BTS), atau metadata GPS di foto—menjadi lokasi geografis yang bisa jadi petunjuk penentu flag. Semua providernya gratis tanpa API key, hanya pakai stdlib Python sehingga langsung jalan, dan hasilnya tersimpan rapi di folder out/ per target—efisien untuk tantangan yang menuntut kecepatan. Autotopia: tinggal lempar target (IP, foto, BSSID, atau teks apapun) ke mode auto-detect, tool menggak sendiri jenisnya. Intinya, ini alat andalan untuk tantangan CTF yang bertanya "di mana flag/lokasi ini berada?".

# Install 
```
git clone https://github.com/viooap/TrackerIP.git
```
# Menu
| No | Menu | Fungsi | Output / Folder out/ |
|----|------|--------|-----------------------|
| 1 | IP geolocation | Cari lokasi (negara/kota/ISP/koordinat) dari alamat IP | out/1_ip/<ip>/ip.txt |
| 2 | GPS dari EXIF foto | Ekstrak koordinat lat/lon & alamat dari metadata foto | out/2_exif/<nama>/exif.txt |
| 3 | WiFi BSSID lookup | Cari posisi access point WiFi dari MAC BSSID | out/3_wifi/<bssid>/wifi.txt |
| 4 | Cell tower (BTS) | Cari lokasi menara seluler dari MCC/MNC/LAC/CellID | out/4_cell/<mcc-mnc-lac-cid>/cell.txt |
| 5 | Auto-detect input | Tebak otomatis tipe target (IP/BSSID/cell/foto) lalu proses sesuai ketentuan | out/5_auto/<target>/... |
| 0 | Keluar | Tutup program | — |



# ⚠️ Peringatan Penting

TrackerIp adalah alat geolokasi (OSINT) yang dibuat untuk kebutuhan CTF
(Capture The Flag) dan riset keamanan profesional. Penggunaannya hanya
diperbolehkan pada target lab / challenge yang menjadi bagian dari arena CTF,
atau pada aset yang Anda miliki dan sudah Anda izinkan secara resmi. Jangan
pernah:

- Melacak / memantau target di luar lingkup challenge CTF atau tanpa izin.
- Menggunakan hasil geolokasi (IP, GPS foto, BSSID, data BTS) untuk memantau,
  mengintai, atau mengumpulkan data pribadi orang lain.

#  📢 Disclaimer

Alat ini disediakan "sebagaimana adanya" (as-is), tanpa jaminan apa pun —
baik tersurat maupun tersirat, termasuk garansi kelayakan dagang atau
kesesuaian untuk tujuan tertentu. Data yang ditampilkan bergantung pada
layanan pihak ketiga gratis sehingga tidak dijamin akurat, lengkap, atau
selalu terkini. Dengan menggunakan TrackerIp, Anda menyetujui bahwa:

- Anda sepenuhnya bertanggung jawab atas segala risiko dan konsekuensi penggunaan.
- Pengembang tidak bertanggung jawab atas kerusakan, kehilangan data, kerugian,
  atau masalah hukum yang timbul dari penggunaan alat ini.
- Anda hanya akan menggunakannya untuk tujuan keamanan, pendidikan, dan
  challenge CTF yang sah.

💡 Ingat: keamanan yang baik dibangun di atas etika. Gunakan ilmu ini untuk
melindungi, bukan merusak.
