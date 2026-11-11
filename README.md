# Khas-Gang-Azalea
Untuk Khas Gang

MONITORING KHAS GANG AZALEA (PHP + SQLite)

FITUR
- Sistem Login & Manajemen Role (akun 'admin' untuk akses penuh CRUD, akun 'user' untuk hak akses view-only).
- Dashboard statistik lengkap: Saldo keseluruhan, Saldo bulan berjalan, Total pemasukan, dan Total pengeluaran.
- Manajemen Transaksi: Tambah, Edit, dan Hapus data transaksi.
- Riwayat transaksi dengan filter per bulan dan input nominal dengan format titik ribuan otomatis.
- Database SQLite terkelola otomatis di folder data/[cite: 5].

CARA MENJALANKAN (PHP lokal)
1. Ekstrak folder proyek[cite: 5].
2. Pastikan PHP terpasang dan ekstensi PDO_SQLite aktif[cite: 5].
3. Buka terminal/Command Prompt, masuk ke folder proyek[cite: 5].
4. Jalankan perintah:
      php -S localhost:8000[cite: 5]
5. Buka browser dan akses:
      http://localhost:8000[cite: 5]

Jika menggunakan XAMPP:
- Letakkan folder proyek di dalam htdocs[cite: 5].
- Pastikan ekstensi PDO_SQLite aktif di php.ini[cite: 5].
- Buka http://localhost/nama_folder_proyek/[cite: 5]

AKUN DEFAULT (LOGIN)
- Admin (Full Access): username: admin | password: admin123
- User (View Only): username: user | password: user123

CATATAN
- Data tersimpan secara lokal di data/kas_gang.sqlite[cite: 5].
- Salin file database tersebut secara berkala untuk keperluan backup[cite: 5].
