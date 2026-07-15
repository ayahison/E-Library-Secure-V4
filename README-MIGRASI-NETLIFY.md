# E-Library Secure V4 — Netlify Public Frontend + Apps Script Backend

Arsitektur:

```
Pengunjung → custom domain / Netlify → Netlify Function → Google Apps Script
                                                   ├→ Google Sheets
                                                   └→ Google Drive
Admin      → Google Apps Script HTML Service
```

Frontend publik tidak lagi memakai `google.script.run`. Panel admin, upload buku, backup, restore, dan pengaturan tetap berjalan di Apps Script.

## Struktur paket

- `public/index.html` — frontend publik yang di-host Netlify.
- `netlify/functions/elibrary.mjs` — gateway server-side bertanda tangan HMAC.
- `netlify.toml` — konfigurasi publish, function, redirect, dan header keamanan.
- `apps-script/code.gs` — backend Secure V3.1 + API Netlify.
- `apps-script/Admin.html` — panel admin GAS; tombol kembali menuju custom domain.
- `apps-script/Index.html` — fallback lama jika custom domain belum dikonfigurasi.
- `.env.example` — contoh Environment Variables Netlify.

---

## A. Persiapan Google Apps Script

### 1. Cadangkan versi aktif

Cadangkan project Apps Script, Spreadsheet, folder cover, dan folder PDF terlebih dahulu.

### 2. Ganti file Apps Script

Ganti isi project dengan:

- `apps-script/code.gs`
- `apps-script/Admin.html`
- `apps-script/Index.html`

ID berikut di awal `code.gs` harus tetap sesuai instalasi perpustakaan:

```javascript
const SPREADSHEET_ID = "...";
const FOLDER_COVER_ID = "...";
const FOLDER_PDF_ID = "...";
```

### 3. Buat shared secret

Di komputer yang memiliki Node.js, jalankan dari folder project:

```bash
npm run secret
```

Atau:

```bash
node scripts/generate-secret.mjs
```

Hasilnya adalah 64 karakter hex. Simpan di password manager karena nilai yang sama dipakai pada Apps Script dan Netlify.

### 4. Tambahkan Script Properties

Buka **Project Settings → Script Properties**, lalu tambahkan:

| Property              | Nilai                                                         |
| --------------------- | ------------------------------------------------------------- |
| `API_SHARED_SECRET`   | secret 64 karakter dari langkah sebelumnya                    |
| `PUBLIC_FRONTEND_URL` | boleh dikosongkan sementara; isi setelah URL Netlify tersedia |

Properti keamanan lama seperti `MASTER_USERNAME`, `MASTER_PASSWORD_HASH`, dan `MASTER_PASSWORD_SALT` jangan dihapus.

`INIT_MASTER_USER` dan `INIT_MASTER_PASSWORD` tidak perlu dimasukkan kembali apabila setup keamanan sebelumnya sudah berhasil.

### 5. Simpan dan cek konfigurasi

Pada tahap awal `publicFrontendUrlValid` boleh masih `false` bila site Netlify belum dibuat. Jalankan fungsi berikut dari dropdown Apps Script:

```javascript
cekKonfigurasiNetlify;
```

Hasil yang benar:

```json
{
  "publicFrontendUrlValid": true,
  "apiSharedSecretValid": true,
  "webAppUrl": "https://script.google.com/macros/s/.../exec"
}
```

Fungsi `setupKeamananAwal` tanpa underscore juga tersedia bila instalasi benar-benar baru.

### 6. Deploy ulang

Pilih:

- **Deploy → Manage deployments → Edit**
- **Execute as:** Me
- **Who has access:** Anyone
- **New version → Deploy**

Salin URL yang berakhiran `/exec`. URL ini digunakan sebagai `GAS_WEB_APP_URL` di Netlify.

Jangan gunakan URL `/dev`.

---

## B. Deploy frontend ke GitHub dan Netlify

### 1. Upload project ke GitHub

Upload seluruh isi folder paket ini ke repository privat atau publik. Hanya folder `public` yang dipublikasikan oleh Netlify; folder `apps-script` tidak ikut menjadi file website.

Jangan membuat file `.env` dan jangan memasukkan shared secret ke GitHub.

### 2. Hubungkan repository ke Netlify

Di Netlify:

1. **Add new project → Import an existing project**.
2. Pilih repository GitHub.
3. Konfigurasi akan dibaca otomatis dari `netlify.toml`.
4. Build command boleh dikosongkan.
5. Publish directory otomatis: `public`.
6. Functions directory otomatis: `netlify/functions`.

### 3. Tambahkan Environment Variables

Buka **Project configuration → Environment variables**, lalu tambahkan:

| Variable            | Nilai                                              |
| ------------------- | -------------------------------------------------- |
| `GAS_WEB_APP_URL`   | URL deployment Apps Script yang berakhiran `/exec` |
| `API_SHARED_SECRET` | harus sama persis dengan Script Property GAS       |
| `ALLOWED_ORIGINS`   | URL Netlify dan custom domain, dipisahkan koma     |

Contoh:

```text
GAS_WEB_APP_URL=https://script.google.com/macros/s/DEPLOYMENT_ID/exec
API_SHARED_SECRET=64_karakter_secret_yang_sama
ALLOWED_ORIGINS=https://nama-situs.netlify.app,https://perpus.example.go.id
```

Setelah Environment Variables disimpan, lakukan **Trigger deploy → Deploy site**.

### 4. Uji endpoint

Buka halaman Netlify. Periksa:

- katalog tampil;
- kategori tampil;
- tombol Mulai Membaca bekerja;
- PDF dapat dibuka;
- kritik dan saran berhasil dikirim;
- tombol Admin desktop membuka panel GAS.

Jika halaman menampilkan “Layanan perpustakaan sedang tidak dapat dihubungi”, periksa **Netlify → Functions → elibrary → Logs** dan **Apps Script → Executions**.

---

## C. Memasang custom domain

1. Di Netlify buka **Domain management → Add a domain**.
2. Tambahkan domain atau subdomain, misalnya:

```text
perpusdigital.example.go.id
```

3. Atur DNS sesuai instruksi Netlify.
4. Tunggu SSL aktif.
5. Ubah Script Property (perubahan Script Properties berlaku langsung dan tidak memerlukan deployment GAS baru):

```text
PUBLIC_FRONTEND_URL=https://perpusdigital.example.go.id
```

6. Ubah Environment Variable Netlify:

```text
ALLOWED_ORIGINS=https://nama-situs.netlify.app,https://perpusdigital.example.go.id
```

7. Deploy ulang Netlify setelah Environment Variable diubah. Apps Script hanya perlu **New version** jika file kodenya ikut berubah.

Setelah itu, membuka URL Apps Script tanpa `?page=Admin` akan diarahkan ke custom domain.

---

## D. Keamanan yang diterapkan

- Secret API hanya berada pada Script Properties GAS dan Environment Variables Netlify.
- Secret tidak pernah dikirim ke browser.
- Netlify Function menandatangani setiap request memakai HMAC-SHA256.
- Apps Script memeriksa signature, timestamp maksimal lima menit, nonce sekali pakai, dan rate limit.
- Browser memanggil endpoint same-origin `/api/elibrary`, bukan URL Apps Script langsung.
- IP mentah tidak dikirim ke GAS; Netlify hanya mengirim fingerprint HMAC.
- Kritik dan saran memiliki honeypot anti-bot.
- Fungsi publik hanya mengizinkan action: `bootstrap`, `recordVisit`, `recordRead`, `submitFeedback`, dan `health`.
- Fungsi admin tetap memakai token sesi server-side Secure V3.

### Jangan lakukan

- Jangan menulis `API_SHARED_SECRET` di `public/index.html`.
- Jangan memasukkan secret ke repository GitHub.
- Jangan menggunakan URL Apps Script `/dev` pada Netlify.
- Jangan menghapus autentikasi token pada fungsi admin.
- Jangan membagikan Spreadsheet, folder backup, atau folder koleksi sebagai Editor publik.

---

## E. Operasional backup

Backup database dan koleksi Secure V3 tetap bekerja melalui panel admin GAS. Catat juga konfigurasi berikut secara aman di password manager/dokumen pemulihan internal:

- URL deployment Apps Script;
- `PUBLIC_FRONTEND_URL`;
- `API_SHARED_SECRET`;
- nama project Netlify;
- nama repository GitHub;
- domain dan pengaturan DNS.

Shared secret tidak dimasukkan ke manifest backup agar tidak bocor apabila file backup tersalin ke pihak lain.

---

## F. Migrasi banyak perpustakaan

Gunakan satu salinan backend dan database untuk setiap perpustakaan. Untuk tahap awal, buat satu site Netlify per perpustakaan agar konfigurasi dan statistik tidak tercampur:

```text
Perpustakaan A → Netlify A → GAS A → Spreadsheet/Drive A
Perpustakaan B → Netlify B → GAS B → Spreadsheet/Drive B
```

Frontend yang sama dapat digunakan ulang; yang berbeda hanya tiga Environment Variables dan tiga ID instalasi GAS.
