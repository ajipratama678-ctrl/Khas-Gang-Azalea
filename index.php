<?php
declare(strict_types=1);
session_start();

/*
 * Monitoring Khas Gang Azalea - PHP + SQLite + Login & Role Management
 * Jalankan dari folder proyek: php -S localhost:8000
 */
$dbFile = __DIR__ . '/data/kas_gang.sqlite';
if (!is_dir(__DIR__ . '/data')) {
    mkdir(__DIR__ . '/data', 0775, true);
}
$pdo = new PDO('sqlite:' . $dbFile);
$pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

// Buat tabel transaksi
$pdo->exec("
    CREATE TABLE IF NOT EXISTS transaksi (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        tanggal TEXT NOT NULL,
        jenis TEXT NOT NULL CHECK(jenis IN ('masuk','keluar')),
        keterangan TEXT NOT NULL,
        jumlah INTEGER NOT NULL CHECK(jumlah > 0),
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )
");

// Buat tabel users untuk sistem login
$pdo->exec("
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        role TEXT NOT NULL CHECK(role IN ('admin','user'))
    )
");

// Seed akun default jika tabel users masih kosong (Admin & User)
$userCount = $pdo->query("SELECT COUNT(*) FROM users")->fetchColumn();
if ($userCount == 0) {
    $adminPass = password_hash('admin123', PASSWORD_DEFAULT);
    $userPass = password_hash('user123', PASSWORD_DEFAULT);
    
    $stmt = $pdo->prepare("INSERT INTO users (username, password, role) VALUES (?, ?, ?)");
    $stmt->execute(['admin', $adminPass, 'admin']);
    $stmt->execute(['user', $userPass, 'user']);
}

if (empty($_SESSION['csrf'])) {
    $_SESSION['csrf'] = bin2hex(random_bytes(32));
}

function e(string $value): string {
    return htmlspecialchars($value, ENT_QUOTES, 'UTF-8');
}
function rupiah(int $value): string {
    return 'Rp ' . number_format($value, 0, ',', '.');
}

$pesan = '';
$error = '';

// Proses Handler POST (Login, Logout, Tambah, Edit, Hapus)
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $aksi = $_POST['aksi'] ?? '';

    // Aksi Login
    if ($aksi === 'login') {
        $username = trim($_POST['username'] ?? '');
        $password = $_POST['password'] ?? '';

        $stmt = $pdo->prepare("SELECT * FROM users WHERE username = ?");
        $stmt->execute([$username]);
        $user = $stmt->fetch(PDO::FETCH_ASSOC);

        if ($user && password_verify($password, $user['password'])) {
            $_SESSION['user_id'] = $user['id'];
            $_SESSION['username'] = $user['username'];
            $_SESSION['role'] = $user['role'];
            header('Location: index.php');
            exit;
        } else {
            $error = 'Username atau password salah.';
        }
    } 
    // Aksi Logout
    elseif ($aksi === 'logout') {
        session_destroy();
        header('Location: index.php');
        exit;
    } 
    // Aksi di bawah ini memerlukan login & proteksi CSRF
    else {
        if (!hash_equals($_SESSION['csrf'], $_POST['csrf'] ?? '')) {
            $error = 'Permintaan tidak valid. Muat ulang halaman.';
        } elseif (!isset($_SESSION['user_id'])) {
            $error = 'Silakan login terlebih dahulu.';
        } else {
            // Cek hak akses: jika role 'user', cegah aksi tambah/edit/hapus
            if ($_SESSION['role'] === 'user' && in_array($aksi, ['tambah', 'edit', 'hapus'])) {
                $error = 'Akses ditolak. Akun Anda memiliki hak akses View Only (hanya lihat).';
            } else {
                if ($aksi === 'tambah') {
                    $tanggal = $_POST['tanggal'] ?? date('Y-m-d');
                    $jenis = $_POST['jenis'] ?? '';
                    $keterangan = trim($_POST['keterangan'] ?? '');
                    
                    $jumlahRaw = str_replace('.', '', $_POST['jumlah'] ?? '');
                    $jumlah = filter_var($jumlahRaw, FILTER_VALIDATE_INT);
                    
                    if (!preg_match('/^\d{4}-\d{2}-\d{2}$/', $tanggal) ||
                        !in_array($jenis, ['masuk', 'keluar'], true) ||
                        $keterangan === '' || !$jumlah || $jumlah < 1) {
                        $error = 'Lengkapi data dengan benar. Nominal minimal Rp 1.';
                    } else {
                        $stmt = $pdo->prepare('INSERT INTO transaksi (tanggal, jenis, keterangan, jumlah) VALUES (?, ?, ?, ?)');
                        $stmt->execute([$tanggal, $jenis, $keterangan, $jumlah]);
                        header('Location: index.php?status=ditambahkan'); exit;
                    }
                } elseif ($aksi === 'edit') {
                    $id = filter_var($_POST['id'] ?? null, FILTER_VALIDATE_INT);
                    $tanggal = $_POST['tanggal'] ?? date('Y-m-d');
                    $jenis = $_POST['jenis'] ?? '';
                    $keterangan = trim($_POST['keterangan'] ?? '');
                    
                    $jumlahRaw = str_replace('.', '', $_POST['jumlah'] ?? '');
                    $jumlah = filter_var($jumlahRaw, FILTER_VALIDATE_INT);
                    
                    if (!$id || !preg_match('/^\d{4}-\d{2}-\d{2}$/', $tanggal) ||
                        !in_array($jenis, ['masuk', 'keluar'], true) ||
                        $keterangan === '' || !$jumlah || $jumlah < 1) {
                        $error = 'Gagal memperbarui. Lengkapi data dengan benar.';
                    } else {
                        $stmt = $pdo->prepare('UPDATE transaksi SET tanggal = ?, jenis = ?, keterangan = ?, jumlah = ? WHERE id = ?');
                        $stmt->execute([$tanggal, $jenis, $keterangan, $jumlah, $id]);
                        header('Location: index.php?status=diperbarui'); exit;
                    }
                } elseif ($aksi === 'hapus') {
                    $id = filter_var($_POST['id'] ?? null, FILTER_VALIDATE_INT);
                    if ($id) {
                        $stmt = $pdo->prepare('DELETE FROM transaksi WHERE id = ?');
                        $stmt->execute([$id]);
                        header('Location: index.php?status=dihapus'); exit;
                    }
                }
            }
        }
    }
}

if (($_GET['status'] ?? '') === 'ditambahkan') $pesan = 'Transaksi berhasil ditambahkan.';
if (($_GET['status'] ?? '') === 'diperbarui') $pesan = 'Transaksi berhasil diperbarui.';
if (($_GET['status'] ?? '') === 'dihapus') $pesan = 'Transaksi berhasil dihapus.';

$filterBulan = $_GET['bulan'] ?? date('Y-m');
if (!preg_match('/^\d{4}-\d{2}$/', $filterBulan)) $filterBulan = date('Y-m');

$summary = $pdo->prepare("
    SELECT
      COALESCE(SUM(CASE WHEN jenis='masuk' THEN jumlah ELSE 0 END),0) AS masuk,
      COALESCE(SUM(CASE WHEN jenis='keluar' THEN jumlah ELSE 0 END),0) AS keluar
    FROM transaksi WHERE substr(tanggal,1,7)=?
");
$summary->execute([$filterBulan]);
$totals = $summary->fetch(PDO::FETCH_ASSOC);
$saldo = (int)$totals['masuk'] - (int)$totals['keluar'];

$stmt = $pdo->prepare('SELECT * FROM transaksi WHERE substr(tanggal,1,7)=? ORDER BY tanggal DESC, id DESC');
$stmt->execute([$filterBulan]);
$transaksi = $stmt->fetchAll(PDO::FETCH_ASSOC);

$all = $pdo->query("
    SELECT
      COALESCE(SUM(CASE WHEN jenis='masuk' THEN jumlah ELSE -jumlah END),0)
      FROM transaksi
")->fetchColumn();

$editData = null;
if (isset($_GET['edit_id']) && isset($_SESSION['user_id']) && $_SESSION['role'] === 'admin') {
    $editId = filter_var($_GET['edit_id'], FILTER_VALIDATE_INT);
    if ($editId) {
        $editStmt = $pdo->prepare('SELECT * FROM transaksi WHERE id = ?');
        $editStmt->execute([$editId]);
        $editData = $editStmt->fetch(PDO::FETCH_ASSOC);
    }
}
?>
<!doctype html>
<html lang="id">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Monitoring Khas Gang Azalea</title>
<link rel="stylesheet" href="style.css">
<style>
  .btn-edit {
    background: transparent;
    color: #3159a5;
    padding: 6px 7px;
    font-size: 11px;
    font-weight: 600;
    cursor: pointer;
    text-decoration: none;
    display: inline-block;
  }
  .btn-edit:hover {
    text-decoration: underline;
  }
  .action-group {
    display: flex;
    gap: 4px;
    align-items: center;
    white-space: nowrap;
  }
  .btn-cancel-edit {
    background: #e4e7ec;
    color: #475467;
    margin-top: 6px;
    text-align: center;
    display: block;
    width: 100%;
    padding: 10px;
    border-radius: 9px;
    text-decoration: none;
    font-weight: 700;
    font-size: 13px;
  }
  .btn-cancel-edit:hover {
    background: #d0d5dd;
  }
  .login-wrapper {
    max-width: 400px;
    margin: 80px auto;
  }
  .user-badge {
    background: #edf2fb;
    color: #3159a5;
    padding: 6px 12px;
    border-radius: 20px;
    font-size: 12px;
    font-weight: 700;
    display: inline-block;
    margin-bottom: 8px;
  }
</style>
</head>
<body>

<?php if (!isset($_SESSION['user_id'])): ?>
<!-- TAMPILAN HALAMAN LOGIN -->
<div class="app login-wrapper">
  <div class="panel">
    <div class="panel-heading" style="text-align: center; margin-bottom: 25px;">
      <div class="eyebrow">ADMINISTRASI WARGA</div>
      <h1>Login</h1>
      <p>Monitoring Khas Gang Azalea</p>
    </div>

    <?php if ($error): ?><div class="notice error"><?= e($error) ?></div><?php endif; ?>

    <form method="post" class="transaction-form">
      <input type="hidden" name="aksi" value="login">
      <label>Username
        <input type="text" name="username" placeholder="Masukkan username" required autofocus>
      </label>
      <label>Password
        <input type="password" name="password" placeholder="Masukkan password" required>
      </label>
      <button type="submit" style="width: 100%; margin-top: 10px;">Masuk</button>
    </form>

    <div style="margin-top: 20px; font-size: 12px; color: #667085; text-align: center; line-height: 1.5;">
      <strong>Akun Demo:</strong><br>
      Admin (Full Access): <code>admin</code> / <code>admin123</code><br>
      User (View Only): <code>user</code> / <code>user123</code>
    </div>
  </div>
</div>

<?php else: ?>
<!-- TAMPILAN UTAMA APLIKASI SETELAH LOGIN -->
<div class="app">
  <header class="topbar">
    <div>
      <div class="eyebrow">ADMINISTRASI WARGA</div>
      <h1>Monitoring Khas Gang Azalea</h1>
      <p>Catat pemasukan dan pengeluaran kas lingkungan.</p>
    </div>
    <div style="display: flex; align-items: center; gap: 12px;">
      <div>
        <span class="user-badge">Role: <?= strtoupper(e($_SESSION['role'])) ?> (<?= e($_SESSION['username']) ?>)</span>
      </div>
      <form method="post" style="margin: 0;">
        <input type="hidden" name="aksi" value="logout">
        <button type="submit" class="secondary" style="padding: 8px 14px; font-size: 12px;">Keluar</button>
      </form>
      <div class="date-pill"><?= e(date('d/m/Y')) ?></div>
    </div>
  </header>

  <?php if ($pesan): ?><div class="notice success"><?= e($pesan) ?></div><?php endif; ?>
  <?php if ($error): ?><div class="notice error"><?= e($error) ?></div><?php endif; ?>

  <!-- 4 Kolom Kartu Statistik -->
  <section class="cards">
    <article class="stat balance">
      <span>Saldo keseluruhan</span>
      <strong><?= rupiah((int)$all) ?></strong>
      <small>Akumulasi total kas</small>
    </article>
    <article class="stat">
      <span>Saldo bulan ini</span>
      <strong class="blue"><?= rupiah($saldo) ?></strong>
      <small><?= e(date('F Y', strtotime($filterBulan . '-01'))) ?></small>
    </article>
    <article class="stat">
      <span>Total pemasukan</span>
      <strong class="green"><?= rupiah((int)$totals['masuk']) ?></strong>
      <small>Bulan terpilih</small>
    </article>
    <article class="stat">
      <span>Total pengeluaran</span>
      <strong class="red"><?= rupiah((int)$totals['keluar']) ?></strong>
      <small>Bulan terpilih</small>
    </article>
  </section>

  <main class="layout">
    <!-- PANEL FORM (Tambah / Edit) -->
    <section class="panel">
      <div class="panel-heading">
        <div>
          <h2><?= $editData ? 'Edit transaksi' : 'Tambah transaksi' ?></h2>
          <p>
            <?php if ($_SESSION['role'] === 'user'): ?>
              <span style="color: #d04444; font-weight: 600;">Mode View Only (Input dinonaktifkan)</span>
            <?php else: ?>
              <?= $editData ? 'Perbarui data transaksi.' : 'Masukkan data kas terbaru.' ?>
            <?php endif; ?>
          </p>
        </div>
      </div>
      <form method="post" class="transaction-form">
        <input type="hidden" name="csrf" value="<?= e($_SESSION['csrf']) ?>">
        <input type="hidden" name="aksi" value="<?= $editData ? 'edit' : 'tambah' ?>">
        <?php if ($editData): ?>
          <input type="hidden" name="id" value="<?= (int)$editData['id'] ?>">
        <?php endif; ?>

        <label>Tanggal
          <input type="date" name="tanggal" value="<?= e($editData ? $editData['tanggal'] : date('Y-m-d')) ?>" <?= $_SESSION['role'] === 'user' ? 'disabled' : 'required' ?>>
        </label>
        <label>Jenis transaksi
          <select name="jenis" <?= $_SESSION['role'] === 'user' ? 'disabled' : 'required' ?>>
            <option value="masuk" <?= ($editData && $editData['jenis'] === 'masuk') ? 'selected' : '' ?>>Pemasukan</option>
            <option value="keluar" <?= ($editData && $editData['jenis'] === 'keluar') ? 'selected' : '' ?>>Pengeluaran</option>
          </select>
        </label>
        <label>Keterangan
          <input type="text" name="keterangan" maxlength="150" placeholder="Contoh: Iuran warga bulan ini" value="<?= e($editData ? $editData['keterangan'] : '') ?>" <?= $_SESSION['role'] === 'user' ? 'disabled' : 'required' ?>>
        </label>
        <label>Nominal (Rp)
          <input type="text" id="jumlah" name="jumlah" placeholder="Contoh: 50.000" value="<?= e($editData ? number_format((int)$editData['jumlah'], 0, ',', '.') : '') ?>" <?= $_SESSION['role'] === 'user' ? 'disabled' : 'required' ?> autocomplete="off">
        </label>
        
        <?php if ($_SESSION['role'] === 'admin'): ?>
          <button type="submit"><?= $editData ? 'Simpan Perubahan' : '+ Simpan transaksi' ?></button>
          <?php if ($editData): ?>
            <a href="index.php?bulan=<?= e($filterBulan) ?>" class="btn-cancel-edit">Batal</a>
          <?php endif; ?>
        <?php else: ?>
          <button type="button" disabled style="background: #98a2b3; cursor: not-allowed;">Akses Terbatas (View Only)</button>
        <?php endif; ?>
      </form>
    </section>

    <!-- PANEL RIWAYAT TRANSAKSI -->
    <section class="panel history">
      <div class="panel-heading history-head">
        <div><h2>Riwayat transaksi</h2><p>Daftar transaksi berdasarkan bulan.</p></div>
        <form method="get" class="filter">
          <input type="month" name="bulan" value="<?= e($filterBulan) ?>">
          <button type="submit" class="secondary">Tampilkan</button>
        </form>
      </div>
      <div class="table-wrap">
      <table>
        <thead><tr><th>Tanggal</th><th>Keterangan</th><th>Jenis</th><th>Nominal</th><th></th></tr></thead>
        <tbody>
        <?php if (!$transaksi): ?>
          <tr><td colspan="5" class="empty">Belum ada transaksi pada bulan ini.</td></tr>
        <?php else: foreach ($transaksi as $row): ?>
          <tr>
            <td><?= e(date('d/m/Y', strtotime($row['tanggal']))) ?></td>
            <td class="description"><?= e($row['keterangan']) ?></td>
            <td><span class="tag <?= $row['jenis'] ?>"><?= $row['jenis'] === 'masuk' ? 'Masuk' : 'Keluar' ?></span></td>
            <td class="amount <?= $row['jenis'] === 'masuk' ? 'green' : 'red' ?>"><?= rupiah((int)$row['jumlah']) ?></td>
            <td>
              <?php if ($_SESSION['role'] === 'admin'): ?>
                <div class="action-group">
                  <a href="index.php?edit_id=<?= (int)$row['id'] ?>&bulan=<?= e($filterBulan) ?>" class="btn-edit">Edit</a>
                  <form method="post" onsubmit="return confirm('Hapus transaksi ini?')" style="display:inline;">
                    <input type="hidden" name="csrf" value="<?= e($_SESSION['csrf']) ?>">
                    <input type="hidden" name="aksi" value="hapus">
                    <input type="hidden" name="id" value="<?= (int)$row['id'] ?>">
                    <button class="delete" type="submit" aria-label="Hapus transaksi">Hapus</button>
                  </form>
                </div>
              <?php else: ?>
                <span style="color: #98a2b3; font-size: 11px;">(View Only)</span>
              <?php endif; ?>
            </td>
          </tr>
        <?php endforeach; endif; ?>
        </tbody>
      </table>
      </div>
    </section>
  </main>
  <footer>Monitoring Khas Gang Azalea · Data tersimpan di komputer lokal Anda.</footer>
</div>
<?php endif; ?>

<!-- Format titik otomatis saat mengetik nominal -->
<script>
    const inputJumlah = document.getElementById('jumlah');
    if (inputJumlah) {
        inputJumlah.addEventListener('input', function(e) {
            let value = this.value.replace(/[^,\d]/g, '').toString();
            let split = value.split(',');
            let sisa = split[0].length % 3;
            let rupiah = split[0].substr(0, sisa);
            let ribuan = split[0].substr(sisa).match(/\d{3}/gi);

            if (ribuan) {
                let separator = sisa ? '.' : '';
                rupiah += separator + ribuan.join('.');
            }

            rupiah = split[1] !== undefined ? rupiah + ',' + split[1] : rupiah;
            this.value = rupiah;
        });
    }
</script>
</body>
</html>
