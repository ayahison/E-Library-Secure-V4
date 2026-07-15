/**
 * ====================================================================
 * APLIKASI E-LIBRARY - SECURE EDITION V3
 * Google Apps Script + Google Sheets + Google Drive
 * ====================================================================
 *
 * KEAMANAN:
 * - Semua operasi admin memakai token sesi server-side.
 * - Password disimpan sebagai salted iterative SHA-256, bukan teks asli.
 * - Kredensial master disimpan di Script Properties.
 * - Semua input teks divalidasi dan disanitasi di server.
 * - Setiap perubahan penting dicatat pada sheet Log_Aktivitas.
 * - Backup database cepat dan backup koleksi penuh dengan manifest V3.
 * - Restore massal, simulasi restore, pemeriksaan integritas, dan log pemulihan.
 * - File cover/PDF dibagikan otomatis sebagai Anyone with the link - Viewer.
 */

// --------------------------------------------------------------------
// 1. KONFIGURASI INSTALASI
// ID bukan password. Untuk setiap perpustakaan, sesuaikan tiga ID berikut.
// --------------------------------------------------------------------
const SPREADSHEET_ID = "1_tyVEBd1UHD1H6ugeAdxpxrXhKGROlQYYvVqBEPovFA";
const FOLDER_COVER_ID = "1xtOoZJuy9fRBKypl3BtSDnziwsJZbfRZ";
const FOLDER_PDF_ID = "1Mt6u3pwhDg0d34eRkssGmEL-j6SDedjd";

const APP_TIMEZONE = "Asia/Jakarta";
const SESSION_DURATION_SECONDS = 2 * 60 * 60;
const SESSION_PREFIX = "ADMIN_SESSION_";
const PASSWORD_HASH_ROUNDS = 2000;
const LOGIN_MAX_ATTEMPTS = 5;
const LOGIN_BLOCK_SECONDS = 15 * 60;
const BACKUP_KEEP_SETS = 12;
const FULL_BACKUP_KEEP_SETS = 4;
const MAINTENANCE_JOB_PROPERTY = "ELIBRARY_MAINTENANCE_JOB_V3";
const MAINTENANCE_TRIGGER_HANDLER = "jalankanPekerjaanPemeliharaan_";
const MAINTENANCE_MAX_RUNTIME_MS = 4 * 60 * 1000;
const MAINTENANCE_BATCH_MAX_ROWS = 60;

// Script Properties yang digunakan:
// MASTER_USERNAME, MASTER_PASSWORD_HASH, MASTER_PASSWORD_SALT
// BACKUP_FOLDER_ID
// Untuk inisialisasi master, isi sementara:
// INIT_MASTER_USER, INIT_MASTER_PASSWORD
// Lalu jalankan setupKeamananAwal_() satu kali dari editor Apps Script.

// --------------------------------------------------------------------
// 2. WEB APP
// --------------------------------------------------------------------
function doGet(e) {
  var requestedPage = String((e && e.parameter && e.parameter.page) || "Index");

  if (requestedPage === "Admin") {
    return HtmlService.createTemplateFromFile("Admin")
      .evaluate()
      .setTitle("Panel Admin E-Library")
      .addMetaTag(
        "viewport",
        "width=device-width, initial-scale=1, maximum-scale=1",
      );
  }

  // Halaman publik utama berada di Netlify/custom domain.
  var publicUrl = getPublicFrontendUrl_();
  if (publicUrl) {
    var escapedUrl = publicUrl
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#39;");

    return HtmlService.createHtmlOutput(
      '<!doctype html><html lang="id"><head><meta charset="utf-8">' +
        '<meta name="viewport" content="width=device-width,initial-scale=1">' +
        '<meta http-equiv="refresh" content="0;url=' +
        escapedUrl +
        '">' +
        "<title>Membuka Perpustakaan Digital</title></head>" +
        '<body style="font-family:Arial,sans-serif;text-align:center;padding:48px">' +
        "<p>Mengarahkan ke halaman perpustakaan digital...</p>" +
        '<p><a href="' +
        escapedUrl +
        '">Klik di sini jika tidak berpindah otomatis</a></p>' +
        "</body></html>",
    ).setTitle("Membuka Perpustakaan Digital");
  }

  // Fallback jika PUBLIC_FRONTEND_URL belum diisi.
  return HtmlService.createTemplateFromFile("Index")
    .evaluate()
    .setTitle("E-Library")
    .addMetaTag(
      "viewport",
      "width=device-width, initial-scale=1, maximum-scale=1",
    );
}

function include_(filename) {
  var safeName = sanitizeIdentifier_(filename, 60);
  return HtmlService.createHtmlOutputFromFile(safeName).getContent();
}

function getScriptUrl() {
  return ScriptApp.getService().getUrl();
}

// --------------------------------------------------------------------
// 2A. INTEGRASI FRONTEND NETLIFY / CUSTOM DOMAIN
// --------------------------------------------------------------------
function getPublicFrontendUrl_() {
  var value = String(
    PropertiesService.getScriptProperties().getProperty(
      "PUBLIC_FRONTEND_URL",
    ) || "",
  ).trim();

  if (!/^https:\/\/[A-Za-z0-9.-]+(?::\d+)?(?:\/[^\s]*)?$/.test(value)) {
    return "";
  }
  return value.replace(/\/+$/, "");
}

function getPublicFrontendUrl() {
  return getPublicFrontendUrl_() || ScriptApp.getService().getUrl();
}

function getAdminWebAppUrl_() {
  return ScriptApp.getService().getUrl() + "?page=Admin";
}

function getPublicApiSecret_() {
  return String(
    PropertiesService.getScriptProperties().getProperty("API_SHARED_SECRET") ||
      "",
  );
}

function canonicalPublicApiRequest_(
  action,
  timestamp,
  nonce,
  clientKey,
  payloadText,
) {
  return [
    String(action || ""),
    String(timestamp || ""),
    String(nonce || ""),
    String(clientKey || ""),
    String(payloadText || "{}"),
  ].join("\n");
}

function hmacSha256Hex_(value, secret) {
  return bytesToHex_(
    Utilities.computeHmacSha256Signature(
      String(value || ""),
      String(secret || ""),
      Utilities.Charset.UTF_8,
    ),
  );
}

function verifyPublicApiRequest_(body) {
  var secret = getPublicApiSecret_();
  if (secret.length < 32) {
    return { ok: false, message: "API backend belum dikonfigurasi." };
  }

  var action = sanitizeIdentifier_(body && body.action, 50);
  var timestamp = Number(body && body.timestamp);
  var nonce = sanitizeIdentifier_(body && body.nonce, 120);
  var clientKey = sanitizeIdentifier_(body && body.clientKey, 100);
  var payloadText = String((body && body.payload) || "{}");
  var signature = String((body && body.signature) || "").toLowerCase();

  if (!action || !timestamp || nonce.length < 20 || clientKey.length < 20) {
    return { ok: false, message: "Permintaan API tidak lengkap." };
  }
  if (payloadText.length > 20000) {
    return { ok: false, message: "Payload API terlalu besar." };
  }

  var nowSeconds = Math.floor(new Date().getTime() / 1000);
  if (Math.abs(nowSeconds - timestamp) > 300) {
    return { ok: false, message: "Permintaan API sudah kedaluwarsa." };
  }

  var expected = hmacSha256Hex_(
    canonicalPublicApiRequest_(
      action,
      timestamp,
      nonce,
      clientKey,
      payloadText,
    ),
    secret,
  );
  if (!constantTimeEquals_(expected, signature)) {
    return { ok: false, message: "Tanda tangan API tidak valid." };
  }

  var cache = CacheService.getScriptCache();
  var nonceKey = "PUBLIC_API_NONCE_" + sha256Hex_(nonce).substring(0, 40);
  if (cache.get(nonceKey)) {
    return { ok: false, message: "Permintaan API telah digunakan." };
  }
  cache.put(nonceKey, "1", 600);

  var payload;
  try {
    payload = JSON.parse(payloadText || "{}");
  } catch (error) {
    return { ok: false, message: "Payload API tidak valid." };
  }

  return {
    ok: true,
    action: action,
    clientKey: clientKey,
    payload: payload || {},
  };
}

function publicApiRateLimit_(clientKey, action) {
  var rules = {
    bootstrap: { limit: 180, windowSeconds: 600 },
    recordVisit: { limit: 120, windowSeconds: 600 },
    recordRead: { limit: 300, windowSeconds: 600 },
    submitFeedback: { limit: 6, windowSeconds: 600 },
    health: { limit: 120, windowSeconds: 600 },
  };
  var rule = rules[action];
  if (!rule) return false;

  var bucket = Math.floor(new Date().getTime() / 1000 / rule.windowSeconds);
  var key =
    "PUBLIC_API_RATE_" +
    sha256Hex_(clientKey + "|" + action + "|" + bucket).substring(0, 40);
  var cache = CacheService.getScriptCache();
  var count = Number(cache.get(key) || 0) + 1;
  cache.put(key, String(count), rule.windowSeconds + 30);
  return count <= rule.limit;
}

function jsonOutput_(value) {
  return ContentService.createTextOutput(JSON.stringify(value)).setMimeType(
    ContentService.MimeType.JSON,
  );
}

function doPost(e) {
  try {
    var raw = String((e && e.postData && e.postData.contents) || "");
    if (!raw || raw.length > 30000) {
      return jsonOutput_(
        errorResponse_("Permintaan API kosong atau terlalu besar."),
      );
    }

    var body = JSON.parse(raw);
    var verified = verifyPublicApiRequest_(body);
    if (!verified.ok) {
      return jsonOutput_(errorResponse_(verified.message));
    }
    if (!publicApiRateLimit_(verified.clientKey, verified.action)) {
      return jsonOutput_(
        errorResponse_(
          "Terlalu banyak permintaan. Silakan coba kembali beberapa saat lagi.",
        ),
      );
    }

    var payload = verified.payload || {};
    var response;

    switch (verified.action) {
      case "bootstrap":
        response = successResponse_(
          {
            settings: getPengaturanData(),
            categories: getKategoriData(),
            books: getKatalogPublik(),
            adminUrl: getAdminWebAppUrl_(),
            generatedAt: new Date().toISOString(),
          },
          "Data perpustakaan berhasil dimuat.",
        );
        break;

      case "recordVisit":
        response = catatSesiKunjungan(payload.token);
        break;

      case "recordRead":
        response = catatBukuDibaca(payload.bookId)
          ? successResponse_(null, "Statistik baca tercatat.")
          : errorResponse_("Statistik baca tidak dapat dicatat.");
        break;

      case "submitFeedback":
        if (sanitizeText_(payload.website, 200, false)) {
          // Honeypot terisi: balas sukses tanpa menyimpan spam.
          response = successResponse_(
            null,
            "Pesan Anda sudah diterima. Terima kasih.",
          );
        } else {
          response = kirimPesanSilima(payload.name, payload.message);
        }
        break;

      case "health":
        response = successResponse_(
          { service: "elibrary-api", time: new Date().toISOString() },
          "API aktif.",
        );
        break;

      default:
        response = errorResponse_("Aksi API tidak dikenali.");
    }

    return jsonOutput_(response);
  } catch (error) {
    console.error("Public API error: " + error);
    return jsonOutput_(
      errorResponse_("Backend tidak dapat memproses permintaan."),
    );
  }
}

function cekKonfigurasiNetlify() {
  var props = PropertiesService.getScriptProperties();
  var frontend = getPublicFrontendUrl_();
  var secret = getPublicApiSecret_();
  var result = {
    publicFrontendUrlValid: Boolean(frontend),
    apiSharedSecretValid: secret.length >= 32,
    webAppUrl: ScriptApp.getService().getUrl(),
  };
  console.log(JSON.stringify(result, null, 2));
  return result;
}

// Folder koleksi tetap dapat dibuat PRIVATE/Restricted.
// Hanya file cover dan PDF yang dibagikan satu per satu sebagai viewer.
function setCollectionFilePublic_(file) {
  if (!file) throw new Error("Objek file Google Drive tidak valid.");

  try {
    file.setSharing(DriveApp.Access.ANYONE_WITH_LINK, DriveApp.Permission.VIEW);
    return file;
  } catch (error) {
    throw new Error(
      "File koleksi tidak dapat dibagikan untuk akses tanpa login. " +
        "Pastikan kebijakan akun/Google Workspace mengizinkan 'Anyone with the link'. " +
        "Detail: " +
        error.toString(),
    );
  }
}

function getDriveResourceKeyQuery_(file, prefix) {
  try {
    var resourceKey = String(file.getResourceKey() || "");
    if (!resourceKey) return "";
    return (
      String(prefix || "?") + "resourcekey=" + encodeURIComponent(resourceKey)
    );
  } catch (error) {
    return "";
  }
}

function buildPublicCoverUrl_(file) {
  return (
    "https://drive.google.com/thumbnail?id=" +
    encodeURIComponent(file.getId()) +
    "&sz=w600" +
    getDriveResourceKeyQuery_(file, "&")
  );
}

function buildPublicPdfPreviewUrl_(file) {
  return (
    "https://drive.google.com/file/d/" +
    encodeURIComponent(file.getId()) +
    "/preview" +
    getDriveResourceKeyQuery_(file, "?")
  );
}

function extractDriveFileId_(url) {
  var value = String(url || "");
  var patterns = [
    /[?&]id=([a-zA-Z0-9_-]+)/,
    /\/d\/([a-zA-Z0-9_-]+)/,
    /^([a-zA-Z0-9_-]{20,})$/,
  ];

  for (var i = 0; i < patterns.length; i++) {
    var match = value.match(patterns[i]);
    if (match && match[1]) return match[1];
  }
  return "";
}

// Jalankan satu kali dari editor bila ada koleksi lama.
// Fungsi privat ini tidak dapat dipanggil dari browser melalui google.script.run.
function sinkronkanAksesPublikKoleksi_() {
  var sheet = getSpreadsheet_().getSheetByName("Katalog");
  if (!sheet || sheet.getLastRow() < 2) {
    return "Tidak ada data koleksi yang perlu disinkronkan.";
  }

  var data = sheet.getRange(2, 1, sheet.getLastRow() - 1, 8).getValues();
  var berhasilCover = 0;
  var berhasilPdf = 0;
  var gagal = [];

  for (var i = 0; i < data.length; i++) {
    var rowNumber = i + 2;
    var idBuku = String(data[i][0] || "Baris " + rowNumber);

    try {
      var coverId = extractDriveFileId_(data[i][4]);
      if (coverId) {
        var coverFile = DriveApp.getFileById(coverId);
        setCollectionFilePublic_(coverFile);
        sheet.getRange(rowNumber, 5).setValue(buildPublicCoverUrl_(coverFile));
        berhasilCover++;
      }
    } catch (coverError) {
      gagal.push(idBuku + " cover: " + coverError.toString());
    }

    try {
      var pdfId = extractDriveFileId_(data[i][5]);
      if (pdfId) {
        var pdfFile = DriveApp.getFileById(pdfId);
        setCollectionFilePublic_(pdfFile);
        sheet
          .getRange(rowNumber, 6)
          .setValue(buildPublicPdfPreviewUrl_(pdfFile));
        berhasilPdf++;
      }
    } catch (pdfError) {
      gagal.push(idBuku + " PDF: " + pdfError.toString());
    }
  }

  var ringkasan =
    "Sinkronisasi selesai. Cover: " +
    berhasilCover +
    ", PDF: " +
    berhasilPdf +
    ", gagal: " +
    gagal.length +
    ".";

  if (gagal.length) {
    console.warn(ringkasan + "\n" + gagal.join("\n"));
  } else {
    console.log(ringkasan);
  }
  return ringkasan;
}

// --------------------------------------------------------------------
// 3. UTILITAS UMUM: SANITASI, HASH, RESPONS
// --------------------------------------------------------------------
function sanitizeText_(value, maxLength, preserveNewlines) {
  var text = String(value == null ? "" : value);

  // Hilangkan tag HTML, karakter kontrol, dan null byte.
  text = text.replace(/<[^>]*>/g, "");
  text = text.replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/g, "");

  if (preserveNewlines) {
    text = text.replace(/\r\n?/g, "\n");
    text = text
      .split("\n")
      .map(function (line) {
        return line.replace(/[\t ]+/g, " ").trim();
      })
      .join("\n")
      .replace(/\n{3,}/g, "\n\n")
      .trim();
  } else {
    text = text.replace(/\s+/g, " ").trim();
  }

  var limit = Number(maxLength) || 255;
  return text.substring(0, limit);
}

function sanitizeIdentifier_(value, maxLength) {
  return String(value == null ? "" : value)
    .replace(/[^A-Za-z0-9_.-]/g, "")
    .substring(0, Number(maxLength) || 100);
}

function sanitizeUsername_(value) {
  return String(value == null ? "" : value)
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9_.@-]/g, "")
    .substring(0, 80);
}

function sanitizeTheme_(value) {
  var theme = String(value || "default");
  return ["default", "light", "dark"].indexOf(theme) >= 0 ? theme : "default";
}

function sanitizeStatus_(value) {
  return String(value || "") === "Sudah Dibaca"
    ? "Sudah Dibaca"
    : "Belum Dibaca";
}

function safeGoogleUrl_(value, type) {
  var url = String(value || "").trim();
  if (!url) return "";

  var allowed = false;
  if (type === "cover") {
    allowed =
      /^https:\/\/(drive\.google\.com|lh3\.googleusercontent\.com|lh4\.googleusercontent\.com|lh5\.googleusercontent\.com|lh6\.googleusercontent\.com)\//i.test(
        url,
      );
  } else if (type === "pdf") {
    allowed = /^https:\/\/drive\.google\.com\//i.test(url);
  }

  return allowed ? url.substring(0, 1000) : "";
}

function validatePasswordStrength_(password) {
  var value = String(password || "");
  if (value.length < 10 || value.length > 128) {
    return "Password minimal 10 karakter dan maksimal 128 karakter.";
  }
  if (!/[a-z]/.test(value) || !/[A-Z]/.test(value) || !/[0-9]/.test(value)) {
    return "Password harus mengandung huruf kecil, huruf besar, dan angka.";
  }
  return "";
}

function bytesToHex_(bytes) {
  return bytes
    .map(function (byte) {
      var value = byte < 0 ? byte + 256 : byte;
      return ("0" + value.toString(16)).slice(-2);
    })
    .join("");
}

function sha256Hex_(value) {
  return bytesToHex_(
    Utilities.computeDigest(
      Utilities.DigestAlgorithm.SHA_256,
      String(value),
      Utilities.Charset.UTF_8,
    ),
  );
}

function createSalt_() {
  return (
    Utilities.getUuid().replace(/-/g, "") +
    Utilities.getUuid().replace(/-/g, "")
  );
}

function hashPassword_(password, salt) {
  var current = String(salt) + "|" + String(password);
  for (var i = 0; i < PASSWORD_HASH_ROUNDS; i++) {
    current = sha256Hex_(String(salt) + "|" + current + "|" + i);
  }
  return current;
}

function constantTimeEquals_(left, right) {
  var a = String(left || "");
  var b = String(right || "");
  if (a.length !== b.length) return false;

  var difference = 0;
  for (var i = 0; i < a.length; i++) {
    difference |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return difference === 0;
}

function createToken_() {
  return (
    Utilities.getUuid().replace(/-/g, "") +
    Utilities.getUuid().replace(/-/g, "") +
    new Date().getTime().toString(36)
  );
}

function successResponse_(data, message) {
  return {
    status: "success",
    pesan: sanitizeText_(message || "Berhasil.", 300, false),
    data: data == null ? null : data,
  };
}

function errorResponse_(message) {
  return {
    status: "error",
    pesan: sanitizeText_(message || "Terjadi kesalahan.", 500, false),
  };
}

function unauthorizedResponse_() {
  return {
    status: "unauthorized",
    pesan: "Sesi admin tidak valid atau sudah berakhir. Silakan login kembali.",
  };
}

function getSpreadsheet_() {
  return SpreadsheetApp.openById(SPREADSHEET_ID);
}

function formatDateTime_(date) {
  if (!(date instanceof Date)) return sanitizeText_(date, 50, false);
  return Utilities.formatDate(date, APP_TIMEZONE, "dd/MM/yyyy HH:mm:ss");
}

function formatDateKey_(date) {
  return Utilities.formatDate(date || new Date(), APP_TIMEZONE, "yyyy-MM-dd");
}

// --------------------------------------------------------------------
// 4. SETUP DATABASE DAN MIGRASI PASSWORD LAMA
// --------------------------------------------------------------------
function createSheetIfNotExists_(ss, sheetName, headers) {
  var sheet = ss.getSheetByName(sheetName);
  if (!sheet) {
    sheet = ss.insertSheet(sheetName);
  }

  if (sheet.getLastRow() === 0) {
    sheet.getRange(1, 1, 1, headers.length).setValues([headers]);
  } else {
    sheet.getRange(1, 1, 1, headers.length).setValues([headers]);
  }

  sheet
    .getRange(1, 1, 1, headers.length)
    .setFontWeight("bold")
    .setBackground("#e0e0e0");
  sheet.setFrozenRows(1);
  return sheet;
}

function ensureAdminSheetSecurity_() {
  var ss = getSpreadsheet_();
  var sheet = ss.getSheetByName("Admin");

  if (!sheet) {
    sheet = ss.insertSheet("Admin");
    sheet
      .getRange(1, 1, 1, 6)
      .setValues([
        ["Username", "Password_Hash", "Salt", "Role", "Status", "Updated_At"],
      ]);
    sheet.setFrozenRows(1);
    return sheet;
  }

  var lastRow = sheet.getLastRow();
  var lastColumn = Math.max(sheet.getLastColumn(), 2);
  var legacyData =
    lastRow > 1
      ? sheet.getRange(2, 1, lastRow - 1, lastColumn).getValues()
      : [];

  var migrated = [];
  legacyData.forEach(function (row) {
    var username = sanitizeUsername_(row[0]);
    if (!username) return;

    var storedValue = String(row[1] || "");
    var salt = String(row[2] || "");
    var role = sanitizeIdentifier_(row[3] || "admin", 20) || "admin";
    var status =
      String(row[4] || "aktif").toLowerCase() === "nonaktif"
        ? "nonaktif"
        : "aktif";

    var looksHashed = /^[a-f0-9]{64}$/i.test(storedValue) && salt.length >= 16;
    var passwordHash = storedValue;

    if (!looksHashed && storedValue) {
      salt = createSalt_();
      passwordHash = hashPassword_(storedValue, salt);
    }

    if (passwordHash && salt) {
      migrated.push([
        username,
        passwordHash,
        salt,
        role === "master" ? "master" : "admin",
        status,
        new Date(),
      ]);
    }
  });

  sheet.clearContents();
  sheet
    .getRange(1, 1, 1, 6)
    .setValues([
      ["Username", "Password_Hash", "Salt", "Role", "Status", "Updated_At"],
    ]);
  sheet.getRange(1, 1, 1, 6).setFontWeight("bold").setBackground("#e0e0e0");
  sheet.setFrozenRows(1);

  if (migrated.length > 0) {
    sheet.getRange(2, 1, migrated.length, 6).setValues(migrated);
    sheet
      .getRange(2, 6, migrated.length, 1)
      .setNumberFormat("dd/MM/yyyy HH:mm");
  }

  return sheet;
}

function setupAwal_() {
  try {
    var ss = getSpreadsheet_();

    createSheetIfNotExists_(ss, "Katalog", [
      "ID_Buku",
      "Judul",
      "Pengarang",
      "Kategori",
      "Link_Cover",
      "Link_PDF",
      "Tgl_Upload",
      "Jumlah_Dibaca",
      "Cover_File_ID",
      "PDF_File_ID",
      "Cover_File_Name",
      "PDF_File_Name",
    ]);

    createSheetIfNotExists_(ss, "Kategori", ["ID_Kategori", "Nama_Kategori"]);

    createSheetIfNotExists_(ss, "Kritik_Saran", [
      "Timestamp",
      "Nama_Pengirim",
      "Isi_Pesan",
      "Status",
    ]);

    var settingsSheet = createSheetIfNotExists_(ss, "Pengaturan", [
      "Parameter",
      "Nilai",
    ]);
    if (settingsSheet.getLastRow() <= 1) {
      settingsSheet.getRange(2, 1, 5, 2).setValues([
        ["Nama_Perpus", "Perpustakaan Digital"],
        ["Alamat", "Kabupaten Banyumas"],
        ["Teks_Sambutan", "Selamat datang di E-Library kami. Mari membaca!"],
        ["Link_Logo", ""],
        ["Tema_Warna", "default"],
      ]);
    }

    ensureAdminSheetSecurity_();

    var visitSheet = createSheetIfNotExists_(ss, "Kunjungan", [
      "Token_Sesi_Hash",
      "Tanggal",
      "Waktu_Mulai",
      "Jenis",
    ]);
    visitSheet.getRange("B:B").setNumberFormat("@");

    createSheetIfNotExists_(ss, "Log_Aktivitas", [
      "Timestamp",
      "Username",
      "Role",
      "Aksi",
      "Target",
      "Detail",
      "Status",
    ]);

    createSheetIfNotExists_(ss, "Backup_Log", [
      "Timestamp",
      "Username",
      "Spreadsheet_Backup_ID",
      "Manifest_ID",
      "Status",
      "Keterangan",
      "Backup_Set_Folder_ID",
      "Jenis_Backup",
    ]);

    createSheetIfNotExists_(ss, "Restore_Log", [
      "Timestamp",
      "Username",
      "Jenis",
      "Sumber_Backup",
      "Diproses",
      "Berhasil",
      "Gagal",
      "Status",
      "Keterangan",
    ]);

    return "Setup database, keamanan, dan Backup & Restore Center berhasil. 9 sheet siap digunakan.";
  } catch (error) {
    return "Setup gagal: " + sanitizeText_(error.toString(), 500, false);
  }
}

function setupKeamananAwal_() {
  var result = setupAwal_();
  var props = PropertiesService.getScriptProperties();
  var initUser = sanitizeUsername_(props.getProperty("INIT_MASTER_USER"));
  var initPassword = props.getProperty("INIT_MASTER_PASSWORD") || "";

  if (!initUser || !initPassword) {
    return (
      result +
      " Master belum dikonfigurasi. Isi INIT_MASTER_USER dan INIT_MASTER_PASSWORD di Script Properties, lalu jalankan setupKeamananAwal_() kembali."
    );
  }

  var passwordError = validatePasswordStrength_(initPassword);
  if (passwordError) {
    return "Master gagal dibuat: " + passwordError;
  }

  var salt = createSalt_();
  props.setProperties(
    {
      MASTER_USERNAME: initUser,
      MASTER_PASSWORD_SALT: salt,
      MASTER_PASSWORD_HASH: hashPassword_(initPassword, salt),
    },
    false,
  );
  props.deleteProperty("INIT_MASTER_USER");
  props.deleteProperty("INIT_MASTER_PASSWORD");

  ensureBackupFolder_();
  catatLog_(
    { username: initUser, role: "master" },
    "SETUP_KEAMANAN",
    "Sistem",
    "Kredensial master dipindahkan ke Script Properties dan di-hash.",
    "BERHASIL",
  );

  return result + " Keamanan master berhasil dikonfigurasi.";
}

// --------------------------------------------------------------------
// 5. AUTENTIKASI SERVER-SIDE
// --------------------------------------------------------------------
function getLoginAttemptKey_(username) {
  return (
    "LOGIN_ATTEMPT_" + sha256Hex_(sanitizeUsername_(username)).substring(0, 24)
  );
}

function cleanupExpiredSessions_() {
  var props = PropertiesService.getScriptProperties();
  var all = props.getProperties();
  var now = new Date().getTime();

  Object.keys(all).forEach(function (key) {
    if (key.indexOf(SESSION_PREFIX) !== 0) return;
    try {
      var session = JSON.parse(all[key]);
      if (!session.expiresAt || Number(session.expiresAt) <= now) {
        props.deleteProperty(key);
      }
    } catch (e) {
      props.deleteProperty(key);
    }
  });
}

function saveSession_(token, session) {
  var key = SESSION_PREFIX + sha256Hex_(token);
  var json = JSON.stringify(session);
  CacheService.getScriptCache().put(key, json, SESSION_DURATION_SECONDS);
  PropertiesService.getScriptProperties().setProperty(key, json);
}

function loadSession_(token, refreshExpiry) {
  var rawToken = String(token || "");
  if (!/^[A-Za-z0-9]{40,200}$/.test(rawToken)) return null;

  var key = SESSION_PREFIX + sha256Hex_(rawToken);
  var cache = CacheService.getScriptCache();
  var json = cache.get(key);

  if (!json) {
    json = PropertiesService.getScriptProperties().getProperty(key);
  }
  if (!json) return null;

  try {
    var session = JSON.parse(json);
    var now = new Date().getTime();
    if (!session.expiresAt || Number(session.expiresAt) <= now) {
      cache.remove(key);
      PropertiesService.getScriptProperties().deleteProperty(key);
      return null;
    }

    if (refreshExpiry !== false) {
      session.expiresAt = now + SESSION_DURATION_SECONDS * 1000;
      saveSession_(rawToken, session);
    }
    return session;
  } catch (e) {
    cache.remove(key);
    PropertiesService.getScriptProperties().deleteProperty(key);
    return null;
  }
}

function deleteSession_(token) {
  var rawToken = String(token || "");
  if (!rawToken) return;
  var key = SESSION_PREFIX + sha256Hex_(rawToken);
  CacheService.getScriptCache().remove(key);
  PropertiesService.getScriptProperties().deleteProperty(key);
}

function deleteSessionsForUser_(username) {
  var props = PropertiesService.getScriptProperties();
  var all = props.getProperties();
  var normalized = sanitizeUsername_(username);

  Object.keys(all).forEach(function (key) {
    if (key.indexOf(SESSION_PREFIX) !== 0) return;
    try {
      var session = JSON.parse(all[key]);
      if (sanitizeUsername_(session.username) === normalized) {
        props.deleteProperty(key);
        CacheService.getScriptCache().remove(key);
      }
    } catch (e) {
      props.deleteProperty(key);
    }
  });
}

function requireAdminSession_(token) {
  var session = loadSession_(token, true);
  if (!session) return null;
  if (["admin", "master"].indexOf(session.role) < 0) return null;
  return session;
}

function verifyMasterPassword_(username, password) {
  var props = PropertiesService.getScriptProperties();
  var masterUser = sanitizeUsername_(props.getProperty("MASTER_USERNAME"));
  var salt = props.getProperty("MASTER_PASSWORD_SALT") || "";
  var expectedHash = props.getProperty("MASTER_PASSWORD_HASH") || "";

  if (!masterUser || !salt || !expectedHash || username !== masterUser) {
    return false;
  }

  return constantTimeEquals_(hashPassword_(password, salt), expectedHash);
}

function findAdminCredential_(username) {
  var sheet = ensureAdminSheetSecurity_();
  var lastRow = sheet.getLastRow();
  if (lastRow <= 1) return null;

  var data = sheet.getRange(2, 1, lastRow - 1, 6).getValues();
  for (var i = 0; i < data.length; i++) {
    if (sanitizeUsername_(data[i][0]) === username) {
      return {
        row: i + 2,
        username: username,
        passwordHash: String(data[i][1] || ""),
        salt: String(data[i][2] || ""),
        role: String(data[i][3] || "admin") === "master" ? "master" : "admin",
        status: String(data[i][4] || "aktif").toLowerCase(),
      };
    }
  }
  return null;
}

function prosesLogin(username, password) {
  cleanupExpiredSessions_();

  var normalizedUsername = sanitizeUsername_(username);
  var rawPassword = String(password || "");
  var cache = CacheService.getScriptCache();
  var attemptKey = getLoginAttemptKey_(normalizedUsername);
  var attempts = Number(cache.get(attemptKey) || 0);

  if (attempts >= LOGIN_MAX_ATTEMPTS) {
    catatLog_(
      { username: normalizedUsername || "-", role: "-" },
      "LOGIN_DIBLOKIR",
      "Admin",
      "Percobaan login melebihi batas.",
      "DITOLAK",
    );
    return errorResponse_(
      "Terlalu banyak percobaan login. Coba kembali sekitar 15 menit lagi.",
    );
  }

  if (!normalizedUsername || !rawPassword) {
    return errorResponse_("Username dan password wajib diisi.");
  }

  var role = "";
  var valid = false;

  if (verifyMasterPassword_(normalizedUsername, rawPassword)) {
    role = "master";
    valid = true;
  } else {
    var credential = findAdminCredential_(normalizedUsername);
    if (credential && credential.status === "aktif") {
      valid = constantTimeEquals_(
        hashPassword_(rawPassword, credential.salt),
        credential.passwordHash,
      );
      role = credential.role;
    }
  }

  if (!valid) {
    attempts++;
    cache.put(attemptKey, String(attempts), LOGIN_BLOCK_SECONDS);
    catatLog_(
      { username: normalizedUsername, role: "-" },
      "LOGIN_GAGAL",
      "Admin",
      "Username atau password tidak valid.",
      "DITOLAK",
    );
    return errorResponse_("Username atau password salah.");
  }

  cache.remove(attemptKey);
  var token = createToken_();
  var now = new Date().getTime();
  var session = {
    username: normalizedUsername,
    role: role,
    createdAt: now,
    expiresAt: now + SESSION_DURATION_SECONDS * 1000,
  };
  saveSession_(token, session);

  catatLog_(
    session,
    "LOGIN",
    "Admin",
    "Login server-side berhasil.",
    "BERHASIL",
  );

  return {
    status: "success",
    pesan: "Login berhasil.",
    token: token,
    session: {
      username: session.username,
      role: session.role,
      expiresAt: session.expiresAt,
    },
  };
}

function verifikasiSesiAdmin(token) {
  var session = requireAdminSession_(token);
  if (!session) return unauthorizedResponse_();

  return successResponse_(
    {
      username: session.username,
      role: session.role,
      expiresAt: session.expiresAt,
    },
    "Sesi aktif.",
  );
}

function logoutAdmin(token) {
  var session = loadSession_(token, false);
  if (session) {
    catatLog_(session, "LOGOUT", "Admin", "Sesi admin diakhiri.", "BERHASIL");
  }
  deleteSession_(token);
  return successResponse_(null, "Logout berhasil.");
}

function ubahPasswordAdmin(token, passwordLama, passwordBaru) {
  var session = requireAdminSession_(token);
  if (!session) return unauthorizedResponse_();

  var strengthError = validatePasswordStrength_(passwordBaru);
  if (strengthError) return errorResponse_(strengthError);

  var validOld = false;
  if (session.role === "master") {
    validOld = verifyMasterPassword_(
      session.username,
      String(passwordLama || ""),
    );
    if (validOld) {
      var props = PropertiesService.getScriptProperties();
      var newSalt = createSalt_();
      props.setProperties(
        {
          MASTER_PASSWORD_SALT: newSalt,
          MASTER_PASSWORD_HASH: hashPassword_(passwordBaru, newSalt),
        },
        false,
      );
    }
  } else {
    var credential = findAdminCredential_(session.username);
    if (credential) {
      validOld = constantTimeEquals_(
        hashPassword_(String(passwordLama || ""), credential.salt),
        credential.passwordHash,
      );
      if (validOld) {
        var sheet = ensureAdminSheetSecurity_();
        var salt = createSalt_();
        sheet
          .getRange(credential.row, 2, 1, 5)
          .setValues([
            [
              hashPassword_(passwordBaru, salt),
              salt,
              credential.role,
              "aktif",
              new Date(),
            ],
          ]);
      }
    }
  }

  if (!validOld) {
    catatLog_(
      session,
      "UBAH_PASSWORD",
      "Admin",
      "Password lama salah.",
      "DITOLAK",
    );
    return errorResponse_("Password lama tidak sesuai.");
  }

  catatLog_(
    session,
    "UBAH_PASSWORD",
    "Admin",
    "Password berhasil diperbarui.",
    "BERHASIL",
  );
  deleteSessionsForUser_(session.username);
  return {
    status: "success",
    pesan: "Password berhasil diubah. Silakan login kembali.",
    harusLoginUlang: true,
  };
}

// --------------------------------------------------------------------
// 6. LOG AKTIVITAS
// --------------------------------------------------------------------
function catatLog_(session, action, target, detail, status) {
  try {
    var ss = getSpreadsheet_();
    var sheet = ss.getSheetByName("Log_Aktivitas");
    if (!sheet) {
      sheet = createSheetIfNotExists_(ss, "Log_Aktivitas", [
        "Timestamp",
        "Username",
        "Role",
        "Aksi",
        "Target",
        "Detail",
        "Status",
      ]);
    }

    sheet.appendRow([
      new Date(),
      sanitizeUsername_((session && session.username) || "system") || "system",
      sanitizeIdentifier_((session && session.role) || "system", 30),
      sanitizeIdentifier_(action, 60),
      sanitizeText_(target, 150, false),
      sanitizeText_(detail, 1000, true),
      sanitizeIdentifier_(status || "INFO", 30),
    ]);
    sheet
      .getRange(sheet.getLastRow(), 1)
      .setNumberFormat("dd/MM/yyyy HH:mm:ss");
  } catch (e) {
    console.error("Gagal menulis log: " + e);
  }
}

function getAktivitasTerbaru(token, limit) {
  var session = requireAdminSession_(token);
  if (!session) return unauthorizedResponse_();

  try {
    var sheet = getSpreadsheet_().getSheetByName("Log_Aktivitas");
    if (!sheet || sheet.getLastRow() <= 1) {
      return successResponse_([], "Belum ada aktivitas.");
    }

    var requestedLimit = Math.min(Math.max(Number(limit) || 20, 1), 100);
    var totalRows = sheet.getLastRow() - 1;
    var rowCount = Math.min(totalRows, requestedLimit);
    var startRow = sheet.getLastRow() - rowCount + 1;
    var data = sheet.getRange(startRow, 1, rowCount, 7).getValues().reverse();

    var result = data.map(function (row) {
      return {
        timestamp: formatDateTime_(row[0]),
        username: sanitizeUsername_(row[1]) || "system",
        role: sanitizeIdentifier_(row[2], 30),
        aksi: sanitizeIdentifier_(row[3], 60),
        target: sanitizeText_(row[4], 150, false),
        detail: sanitizeText_(row[5], 500, true),
        status: sanitizeIdentifier_(row[6], 30),
      };
    });

    return successResponse_(result, "Aktivitas berhasil dimuat.");
  } catch (error) {
    return errorResponse_("Aktivitas gagal dimuat: " + error.toString());
  }
}

// --------------------------------------------------------------------
// 7. PENGATURAN PUBLIK DAN ADMIN
// --------------------------------------------------------------------
function getPengaturanData() {
  try {
    var sheet = getSpreadsheet_().getSheetByName("Pengaturan");
    if (!sheet) return null;
    var data = sheet.getDataRange().getValues();
    var settings = {};

    for (var i = 1; i < data.length; i++) {
      var key = sanitizeIdentifier_(data[i][0], 60);
      if (!key) continue;
      settings[key] = sanitizeText_(
        data[i][1],
        key === "Teks_Sambutan" ? 500 : 200,
        true,
      );
    }

    settings.Nama_Perpus = sanitizeText_(
      settings.Nama_Perpus || "Perpustakaan Digital",
      120,
      false,
    );
    settings.Alamat = sanitizeText_(settings.Alamat || "", 200, false);
    settings.Teks_Sambutan = sanitizeText_(
      settings.Teks_Sambutan || "Selamat datang.",
      500,
      true,
    );
    settings.Tema_Warna = sanitizeTheme_(settings.Tema_Warna);
    settings.Link_Logo = safeGoogleUrl_(settings.Link_Logo, "cover");
    return settings;
  } catch (e) {
    console.error("Pengaturan publik gagal: " + e);
    return null;
  }
}

function simpanPengaturan(token, dataInput) {
  var session = requireAdminSession_(token);
  if (!session) return unauthorizedResponse_();

  try {
    var input = dataInput || {};
    var values = {
      Nama_Perpus: sanitizeText_(input.nama, 120, false),
      Alamat: sanitizeText_(input.alamat, 200, false),
      Teks_Sambutan: sanitizeText_(input.sambutan, 500, true),
      Tema_Warna: sanitizeTheme_(input.tema),
    };

    if (!values.Nama_Perpus || !values.Teks_Sambutan) {
      return errorResponse_(
        "Nama perpustakaan dan pesan sambutan wajib diisi.",
      );
    }

    var sheet = getSpreadsheet_().getSheetByName("Pengaturan");
    if (!sheet) throw new Error('Sheet "Pengaturan" tidak ditemukan.');
    var data = sheet.getDataRange().getValues();
    var updated = {};

    for (var i = 1; i < data.length; i++) {
      var key = String(data[i][0] || "");
      if (Object.prototype.hasOwnProperty.call(values, key)) {
        sheet.getRange(i + 1, 2).setValue(values[key]);
        updated[key] = true;
      }
    }

    Object.keys(values).forEach(function (key) {
      if (!updated[key]) sheet.appendRow([key, values[key]]);
    });

    catatLog_(
      session,
      "UBAH_PENGATURAN",
      "Pengaturan",
      "Identitas dan tema diperbarui.",
      "BERHASIL",
    );
    return successResponse_(null, "Pengaturan berhasil diperbarui.");
  } catch (error) {
    catatLog_(
      session,
      "UBAH_PENGATURAN",
      "Pengaturan",
      error.toString(),
      "GAGAL",
    );
    return errorResponse_("Gagal menyimpan pengaturan: " + error.toString());
  }
}

// --------------------------------------------------------------------
// 8. KATEGORI
// --------------------------------------------------------------------
function getKategoriData() {
  try {
    var sheet = getSpreadsheet_().getSheetByName("Kategori");
    if (!sheet) return [];
    var data = sheet.getDataRange().getValues();
    var result = [];

    for (var i = 1; i < data.length; i++) {
      var id = sanitizeIdentifier_(data[i][0], 100);
      var name = sanitizeText_(data[i][1], 100, false);
      if (id && name) result.push({ id: id, nama: name });
    }
    return result;
  } catch (e) {
    console.error("Kategori gagal dimuat: " + e);
    return [];
  }
}

function tambahKategori(token, namaKategori) {
  var session = requireAdminSession_(token);
  if (!session) return unauthorizedResponse_();

  try {
    var name = sanitizeText_(namaKategori, 100, false);
    if (!name) return errorResponse_("Nama kategori tidak boleh kosong.");

    var sheet = getSpreadsheet_().getSheetByName("Kategori");
    var data = sheet.getDataRange().getValues();
    var normalized = name.toLowerCase();
    for (var i = 1; i < data.length; i++) {
      if (sanitizeText_(data[i][1], 100, false).toLowerCase() === normalized) {
        return errorResponse_("Kategori tersebut sudah tersedia.");
      }
    }

    var id = "KAT" + new Date().getTime();
    sheet.appendRow([id, name]);
    catatLog_(session, "TAMBAH_KATEGORI", id, name, "BERHASIL");
    return successResponse_(
      { id: id, nama: name },
      "Kategori berhasil ditambahkan.",
    );
  } catch (error) {
    catatLog_(
      session,
      "TAMBAH_KATEGORI",
      "Kategori",
      error.toString(),
      "GAGAL",
    );
    return errorResponse_("Kategori gagal ditambahkan: " + error.toString());
  }
}

function editKategori(token, idKategori, namaBaru) {
  var session = requireAdminSession_(token);
  if (!session) return unauthorizedResponse_();

  var id = sanitizeIdentifier_(idKategori, 100);
  var name = sanitizeText_(namaBaru, 100, false);
  if (!id || !name) return errorResponse_("Data kategori tidak valid.");

  try {
    var ss = getSpreadsheet_();
    var categorySheet = ss.getSheetByName("Kategori");
    var categoryData = categorySheet.getDataRange().getValues();
    var oldName = "";
    var rowNumber = 0;

    for (var i = 1; i < categoryData.length; i++) {
      if (String(categoryData[i][0]) === id) {
        rowNumber = i + 1;
        oldName = sanitizeText_(categoryData[i][1], 100, false);
        break;
      }
    }
    if (!rowNumber) return errorResponse_("Kategori tidak ditemukan.");

    categorySheet.getRange(rowNumber, 2).setValue(name);

    // Sinkronkan nama kategori pada katalog agar filter tidak terputus.
    var catalogSheet = ss.getSheetByName("Katalog");
    if (catalogSheet && catalogSheet.getLastRow() > 1 && oldName) {
      var catalogValues = catalogSheet
        .getRange(2, 4, catalogSheet.getLastRow() - 1, 1)
        .getValues();
      for (var j = 0; j < catalogValues.length; j++) {
        if (sanitizeText_(catalogValues[j][0], 100, false) === oldName) {
          catalogValues[j][0] = name;
        }
      }
      catalogSheet
        .getRange(2, 4, catalogValues.length, 1)
        .setValues(catalogValues);
    }

    catatLog_(
      session,
      "EDIT_KATEGORI",
      id,
      oldName + " -> " + name,
      "BERHASIL",
    );
    return successResponse_(null, "Kategori berhasil diperbarui.");
  } catch (error) {
    catatLog_(session, "EDIT_KATEGORI", id, error.toString(), "GAGAL");
    return errorResponse_("Kategori gagal diperbarui: " + error.toString());
  }
}

function hapusKategori(token, idKategori) {
  var session = requireAdminSession_(token);
  if (!session) return unauthorizedResponse_();
  var id = sanitizeIdentifier_(idKategori, 100);

  try {
    var ss = getSpreadsheet_();
    var categorySheet = ss.getSheetByName("Kategori");
    var data = categorySheet.getDataRange().getValues();
    var categoryName = "";
    var rowNumber = 0;

    for (var i = 1; i < data.length; i++) {
      if (String(data[i][0]) === id) {
        rowNumber = i + 1;
        categoryName = sanitizeText_(data[i][1], 100, false);
        break;
      }
    }
    if (!rowNumber) return errorResponse_("Kategori tidak ditemukan.");

    // Cegah penghapusan kategori yang masih dipakai buku.
    var catalogSheet = ss.getSheetByName("Katalog");
    if (catalogSheet && catalogSheet.getLastRow() > 1) {
      var categories = catalogSheet
        .getRange(2, 4, catalogSheet.getLastRow() - 1, 1)
        .getValues();
      var used = categories.some(function (row) {
        return sanitizeText_(row[0], 100, false) === categoryName;
      });
      if (used) {
        return errorResponse_(
          "Kategori masih digunakan oleh koleksi. Ubah kategori bukunya terlebih dahulu.",
        );
      }
    }

    categorySheet.deleteRow(rowNumber);
    catatLog_(session, "HAPUS_KATEGORI", id, categoryName, "BERHASIL");
    return successResponse_(null, "Kategori berhasil dihapus.");
  } catch (error) {
    catatLog_(session, "HAPUS_KATEGORI", id, error.toString(), "GAGAL");
    return errorResponse_("Kategori gagal dihapus: " + error.toString());
  }
}

// --------------------------------------------------------------------
// 9. BUKU: PUBLIK DAN ADMIN
// --------------------------------------------------------------------
function validateBookPayload_(data) {
  var input = data || {};
  var result = {
    judul: sanitizeText_(input.judul, 250, false),
    pengarang: sanitizeText_(input.pengarang, 180, false),
    kategori: sanitizeText_(input.kategori, 100, false),
    coverName: sanitizeText_(input.coverName, 180, false),
    coverMime: String(input.coverMime || ""),
    coverBase64: String(input.coverBase64 || ""),
    pdfName: sanitizeText_(input.pdfName, 180, false),
    pdfMime: String(input.pdfMime || ""),
    pdfBase64: String(input.pdfBase64 || ""),
  };

  if (!result.judul || !result.pengarang || !result.kategori) {
    throw new Error("Judul, pengarang, dan kategori wajib diisi.");
  }
  if (!result.pdfBase64 || result.pdfMime !== "application/pdf") {
    throw new Error("File PDF wajib diunggah dengan format application/pdf.");
  }
  if (
    result.coverBase64 &&
    ["image/jpeg", "image/png"].indexOf(result.coverMime) < 0
  ) {
    throw new Error("Cover hanya boleh berupa JPG atau PNG.");
  }

  // Base64 berukuran sekitar 4/3 dari file asli.
  if (result.pdfBase64.length > 21 * 1024 * 1024) {
    throw new Error("Ukuran PDF melebihi batas 15 MB.");
  }
  if (result.coverBase64.length > 3 * 1024 * 1024) {
    throw new Error("Ukuran cover melebihi batas 2 MB.");
  }
  return result;
}

function extensionForFile_(mimeType, originalName, fallback) {
  var mime = String(mimeType || "").toLowerCase();
  if (mime === "image/jpeg") return "jpg";
  if (mime === "image/png") return "png";
  if (mime === "application/pdf") return "pdf";
  var name = String(originalName || "");
  var match = name.match(/\.([A-Za-z0-9]{1,8})$/);
  return match ? match[1].toLowerCase() : fallback;
}

function buildCollectionFileName_(bookId, type, extension) {
  var id = sanitizeIdentifier_(bookId, 100);
  var suffix = type === "cover" ? "cover" : "ebook";
  var ext =
    sanitizeIdentifier_(extension, 8).toLowerCase() ||
    (type === "cover" ? "jpg" : "pdf");
  return id + "__" + suffix + "." + ext;
}

function simpanBuku(token, data) {
  var session = requireAdminSession_(token);
  if (!session) return unauthorizedResponse_();

  var coverFile = null;
  var pdfFile = null;

  try {
    var book = validateBookPayload_(data);
    var id =
      "BKU" +
      new Date().getTime() +
      String(Math.floor(Math.random() * 1000)).padStart(3, "0");
    var coverUrl = "";
    var pdfUrl = "";
    var coverName = "";
    var pdfName = buildCollectionFileName_(id, "pdf", "pdf");

    if (book.coverBase64) {
      coverName = buildCollectionFileName_(
        id,
        "cover",
        extensionForFile_(book.coverMime, book.coverName, "jpg"),
      );
      var coverBlob = Utilities.newBlob(
        Utilities.base64Decode(book.coverBase64),
        book.coverMime,
        coverName,
      );
      coverFile = DriveApp.getFolderById(FOLDER_COVER_ID).createFile(coverBlob);
      coverFile.setDescription("E-Library " + id + " | Cover | " + book.judul);
      setCollectionFilePublic_(coverFile);
      coverUrl = buildPublicCoverUrl_(coverFile);
    }

    var pdfBlob = Utilities.newBlob(
      Utilities.base64Decode(book.pdfBase64),
      book.pdfMime,
      pdfName,
    );
    pdfFile = DriveApp.getFolderById(FOLDER_PDF_ID).createFile(pdfBlob);
    pdfFile.setDescription("E-Library " + id + " | PDF | " + book.judul);
    setCollectionFilePublic_(pdfFile);
    pdfUrl = buildPublicPdfPreviewUrl_(pdfFile);

    var sheet = getSpreadsheet_().getSheetByName("Katalog");
    sheet.appendRow([
      id,
      book.judul,
      book.pengarang,
      book.kategori,
      coverUrl,
      pdfUrl,
      new Date(),
      0,
      coverFile ? coverFile.getId() : "",
      pdfFile.getId(),
      coverName,
      pdfName,
    ]);
    sheet.getRange(sheet.getLastRow(), 7).setNumberFormat("dd/MM/yyyy HH:mm");

    catatLog_(session, "TAMBAH_BUKU", id, book.judul, "BERHASIL");
    return successResponse_(
      { id: id },
      'Buku "' + book.judul + '" berhasil ditambahkan.',
    );
  } catch (error) {
    try {
      if (coverFile) coverFile.setTrashed(true);
      if (pdfFile) pdfFile.setTrashed(true);
    } catch (rollbackError) {
      console.error("Rollback file gagal: " + rollbackError);
    }
    catatLog_(session, "TAMBAH_BUKU", "Katalog", error.toString(), "GAGAL");
    return errorResponse_("Gagal menyimpan buku: " + error.toString());
  }
}

function getBukuData(token) {
  var session = requireAdminSession_(token);
  if (!session) return unauthorizedResponse_();

  try {
    var sheet = getSpreadsheet_().getSheetByName("Katalog");
    var data = sheet.getDataRange().getValues();
    var result = [];

    for (var i = 1; i < data.length; i++) {
      var id = sanitizeIdentifier_(data[i][0], 100);
      if (!id) continue;
      result.push({
        id: id,
        judul: sanitizeText_(data[i][1], 250, false),
        pengarang: sanitizeText_(data[i][2], 180, false),
        kategori: sanitizeText_(data[i][3], 100, false),
        dibaca: Number(data[i][7]) || 0,
      });
    }
    return successResponse_(result.reverse(), "Data buku berhasil dimuat.");
  } catch (error) {
    return errorResponse_("Data buku gagal dimuat: " + error.toString());
  }
}

function getKatalogPublik() {
  try {
    var sheet = getSpreadsheet_().getSheetByName("Katalog");
    if (!sheet) return [];
    var data = sheet.getDataRange().getValues();
    var result = [];

    for (var i = 1; i < data.length; i++) {
      var id = sanitizeIdentifier_(data[i][0], 100);
      if (!id) continue;
      result.push({
        id: id,
        judul: sanitizeText_(data[i][1], 250, false),
        pengarang: sanitizeText_(data[i][2], 180, false),
        kategori: sanitizeText_(data[i][3], 100, false),
        cover: safeGoogleUrl_(data[i][4], "cover"),
        pdf: safeGoogleUrl_(data[i][5], "pdf"),
      });
    }
    return result.reverse();
  } catch (e) {
    console.error("Katalog publik gagal: " + e);
    return [];
  }
}

function editBuku(token, idBuku, judulBaru, pengarangBaru, kategoriBaru) {
  var session = requireAdminSession_(token);
  if (!session) return unauthorizedResponse_();

  var id = sanitizeIdentifier_(idBuku, 100);
  var title = sanitizeText_(judulBaru, 250, false);
  var author = sanitizeText_(pengarangBaru, 180, false);
  var category = sanitizeText_(kategoriBaru, 100, false);
  if (!id || !title || !author || !category) {
    return errorResponse_("Data buku tidak lengkap atau tidak valid.");
  }

  try {
    var sheet = getSpreadsheet_().getSheetByName("Katalog");
    var data = sheet.getDataRange().getValues();
    for (var i = 1; i < data.length; i++) {
      if (String(data[i][0]) === id) {
        var oldTitle = sanitizeText_(data[i][1], 250, false);
        sheet.getRange(i + 1, 2, 1, 3).setValues([[title, author, category]]);
        catatLog_(
          session,
          "EDIT_BUKU",
          id,
          oldTitle + " -> " + title,
          "BERHASIL",
        );
        return successResponse_(null, "Data buku berhasil diperbarui.");
      }
    }
    return errorResponse_("Buku tidak ditemukan.");
  } catch (error) {
    catatLog_(session, "EDIT_BUKU", id, error.toString(), "GAGAL");
    return errorResponse_("Gagal mengedit buku: " + error.toString());
  }
}

function hapusBuku(token, idBuku) {
  var session = requireAdminSession_(token);
  if (!session) return unauthorizedResponse_();
  var id = sanitizeIdentifier_(idBuku, 100);

  try {
    var sheet = getSpreadsheet_().getSheetByName("Katalog");
    var data = sheet.getDataRange().getValues();

    for (var i = 1; i < data.length; i++) {
      if (String(data[i][0]) === id) {
        var title = sanitizeText_(data[i][1], 250, false);
        [data[i][4], data[i][5]].forEach(function (url) {
          var fileId = extractDriveFileId_(url);
          if (!fileId) return;
          try {
            DriveApp.getFileById(fileId).setTrashed(true);
          } catch (fileError) {
            console.warn("File tidak dapat dipindahkan ke Trash: " + fileError);
          }
        });

        sheet.deleteRow(i + 1);
        catatLog_(session, "HAPUS_BUKU", id, title, "BERHASIL");
        return successResponse_(
          null,
          "Buku dan file terkait dipindahkan ke Trash.",
        );
      }
    }
    return errorResponse_("Buku tidak ditemukan.");
  } catch (error) {
    catatLog_(session, "HAPUS_BUKU", id, error.toString(), "GAGAL");
    return errorResponse_("Gagal menghapus buku: " + error.toString());
  }
}

function catatBukuDibaca(idBuku) {
  var id = sanitizeIdentifier_(idBuku, 100);
  if (!id) return false;
  var lock = LockService.getScriptLock();

  try {
    lock.waitLock(5000);
    var sheet = getSpreadsheet_().getSheetByName("Katalog");
    var data = sheet.getDataRange().getValues();
    for (var i = 1; i < data.length; i++) {
      if (String(data[i][0]) === id) {
        var current = Number(data[i][7]) || 0;
        sheet.getRange(i + 1, 8).setValue(current + 1);
        return true;
      }
    }
    return false;
  } catch (e) {
    console.error("Statistik baca gagal: " + e);
    return false;
  } finally {
    try {
      lock.releaseLock();
    } catch (ignore) {}
  }
}

// --------------------------------------------------------------------
// 10. SESI KUNJUNGAN PUBLIK
// --------------------------------------------------------------------
function getVisitSheet_() {
  var ss = getSpreadsheet_();
  var sheet = ss.getSheetByName("Kunjungan");
  if (!sheet) {
    sheet = createSheetIfNotExists_(ss, "Kunjungan", [
      "Token_Sesi_Hash",
      "Tanggal",
      "Waktu_Mulai",
      "Jenis",
    ]);
    sheet.getRange("B:B").setNumberFormat("@");
  }
  return sheet;
}

function catatSesiKunjungan(tokenSesi) {
  var token = sanitizeIdentifier_(tokenSesi, 180);
  if (token.length < 20) return errorResponse_("Token sesi tidak valid.");

  var tokenHash = sha256Hex_(token);
  var lock = LockService.getScriptLock();
  try {
    lock.waitLock(5000);
    var sheet = getVisitSheet_();
    var lastRow = sheet.getLastRow();

    if (lastRow > 1) {
      var found = sheet
        .getRange(2, 1, lastRow - 1, 1)
        .createTextFinder(tokenHash)
        .matchEntireCell(true)
        .findNext();
      if (found)
        return successResponse_({ tercatat: false }, "Sesi sudah tercatat.");
    }

    var now = new Date();
    sheet.appendRow([tokenHash, formatDateKey_(now), now, "Sesi Pemustaka"]);
    sheet.getRange(sheet.getLastRow(), 2).setNumberFormat("@");
    sheet
      .getRange(sheet.getLastRow(), 3)
      .setNumberFormat("dd/MM/yyyy HH:mm:ss");
    return successResponse_({ tercatat: true }, "Kunjungan tercatat.");
  } catch (error) {
    return errorResponse_("Kunjungan tidak dapat dicatat.");
  } finally {
    try {
      lock.releaseLock();
    } catch (ignore) {}
  }
}

// --------------------------------------------------------------------
// 11. STATISTIK ADMIN
// --------------------------------------------------------------------
function getStatistikData(token) {
  var session = requireAdminSession_(token);
  if (!session) return unauthorizedResponse_();

  try {
    var ss = getSpreadsheet_();
    var categorySheet = ss.getSheetByName("Kategori");
    var totalCategories = categorySheet
      ? Math.max(categorySheet.getLastRow() - 1, 0)
      : 0;

    var catalogSheet = ss.getSheetByName("Katalog");
    var catalog = catalogSheet ? catalogSheet.getDataRange().getValues() : [];
    var totalBooks = 0;
    var totalReads = 0;
    var highestReads = 0;
    var mostPopular = "Belum ada data";

    for (var i = 1; i < catalog.length; i++) {
      if (!sanitizeIdentifier_(catalog[i][0], 100)) continue;
      totalBooks++;
      var reads = Number(catalog[i][7]) || 0;
      totalReads += reads;
      if (reads > highestReads) {
        highestReads = reads;
        mostPopular =
          sanitizeText_(catalog[i][1], 250, false) + " (" + reads + "x)";
      }
    }

    var today = formatDateKey_(new Date());
    var currentMonth = today.substring(0, 7);
    var todayVisits = 0;
    var monthVisits = 0;
    var totalVisits = 0;
    var visitSheet = ss.getSheetByName("Kunjungan");

    if (visitSheet && visitSheet.getLastRow() > 1) {
      var dates = visitSheet
        .getRange(2, 2, visitSheet.getLastRow() - 1, 1)
        .getDisplayValues();
      dates.forEach(function (row) {
        var date = sanitizeText_(row[0], 20, false);
        if (!date) return;
        totalVisits++;
        if (date === today) todayVisits++;
        if (date.indexOf(currentMonth) === 0) monthVisits++;
      });
    }

    return successResponse_(
      {
        totalBuku: totalBooks,
        totalKategori: totalCategories,
        totalDibaca: totalReads,
        bukuTerpopuler: mostPopular,
        kunjunganHariIni: todayVisits,
        kunjunganBulanIni: monthVisits,
        totalKunjungan: totalVisits,
      },
      "Statistik berhasil dimuat.",
    );
  } catch (error) {
    return errorResponse_("Statistik gagal dimuat: " + error.toString());
  }
}

// --------------------------------------------------------------------
// 12. KRITIK DAN SARAN
// --------------------------------------------------------------------
function kirimPesanSilima(nama, pesan) {
  try {
    var sender = sanitizeText_(nama, 100, false) || "Anonim";
    var message = sanitizeText_(pesan, 1500, true);
    if (!message) return errorResponse_("Pesan tidak boleh kosong.");

    var sheet = getSpreadsheet_().getSheetByName("Kritik_Saran");
    if (!sheet) throw new Error('Sheet "Kritik_Saran" tidak ditemukan.');

    sheet.appendRow([new Date(), sender, message, "Belum Dibaca"]);
    sheet.getRange(sheet.getLastRow(), 1).setNumberFormat("dd/MM/yyyy HH:mm");
    return successResponse_(null, "Pesan Anda sudah diterima. Terima kasih.");
  } catch (error) {
    return errorResponse_("Pesan gagal dikirim: " + error.toString());
  }
}

function getPesanData(token) {
  var session = requireAdminSession_(token);
  if (!session) return unauthorizedResponse_();

  try {
    var sheet = getSpreadsheet_().getSheetByName("Kritik_Saran");
    if (!sheet) throw new Error('Sheet "Kritik_Saran" tidak ditemukan.');
    var data = sheet.getDataRange().getValues();
    var messages = [];
    var unreadCount = 0;

    for (var i = 1; i < data.length; i++) {
      if (data[i][0] === "") continue;
      var status = sanitizeStatus_(data[i][3]);
      if (status === "Belum Dibaca") unreadCount++;
      messages.push({
        baris: i + 1,
        tanggal: formatDateTime_(data[i][0]),
        nama: sanitizeText_(data[i][1], 100, false) || "Anonim",
        pesan: sanitizeText_(data[i][2], 1500, true),
        status: status,
      });
    }

    return successResponse_(
      { messages: messages.reverse(), unreadCount: unreadCount },
      "Kritik dan saran berhasil dimuat.",
    );
  } catch (error) {
    return errorResponse_("Kritik dan saran gagal dimuat: " + error.toString());
  }
}

function tandaiPesanDibaca(token, rowNumber) {
  var session = requireAdminSession_(token);
  if (!session) return unauthorizedResponse_();

  var row = Number(rowNumber);
  if (!Number.isInteger(row) || row < 2)
    return errorResponse_("Nomor baris tidak valid.");

  try {
    var sheet = getSpreadsheet_().getSheetByName("Kritik_Saran");
    if (!sheet || row > sheet.getLastRow())
      return errorResponse_("Pesan tidak ditemukan.");
    sheet.getRange(row, 4).setValue("Sudah Dibaca");
    catatLog_(
      session,
      "BACA_PESAN",
      "Kritik_Saran baris " + row,
      "Pesan ditandai sudah dibaca.",
      "BERHASIL",
    );
    return successResponse_(null, "Status pesan diperbarui.");
  } catch (error) {
    return errorResponse_("Status pesan gagal diperbarui: " + error.toString());
  }
}

// --------------------------------------------------------------------
// 13. BACKUP DATABASE, KOLEKSI, DAN RESTORE CENTER V3
// --------------------------------------------------------------------
function ensureBackupFolder_() {
  var props = PropertiesService.getScriptProperties();
  var folderId = props.getProperty("BACKUP_FOLDER_ID");
  if (folderId) {
    try {
      return DriveApp.getFolderById(folderId);
    } catch (e) {
      props.deleteProperty("BACKUP_FOLDER_ID");
    }
  }

  var spreadsheetFile = DriveApp.getFileById(SPREADSHEET_ID);
  var parents = spreadsheetFile.getParents();
  var parent = parents.hasNext() ? parents.next() : DriveApp.getRootFolder();
  var folder = parent.createFolder(
    "Backup E-Library - " +
      sanitizeText_(spreadsheetFile.getName(), 100, false),
  );
  props.setProperty("BACKUP_FOLDER_ID", folder.getId());
  return folder;
}

function ensureKatalogMetadataColumns_() {
  var sheet = getSpreadsheet_().getSheetByName("Katalog");
  if (!sheet) throw new Error("Sheet Katalog tidak ditemukan.");
  var headers = [
    "ID_Buku",
    "Judul",
    "Pengarang",
    "Kategori",
    "Link_Cover",
    "Link_PDF",
    "Tgl_Upload",
    "Jumlah_Dibaca",
    "Cover_File_ID",
    "PDF_File_ID",
    "Cover_File_Name",
    "PDF_File_Name",
  ];
  sheet.getRange(1, 1, 1, headers.length).setValues([headers]);
  sheet
    .getRange(1, 1, 1, headers.length)
    .setFontWeight("bold")
    .setBackground("#e0e0e0");
  return sheet;
}

function buildBackupManifest_() {
  var ss = getSpreadsheet_();
  var sheetNames = [
    "Katalog",
    "Kategori",
    "Pengaturan",
    "Admin",
    "Kunjungan",
    "Kritik_Saran",
    "Log_Aktivitas",
    "Backup_Log",
    "Restore_Log",
  ];
  var data = {
    version: 3,
    generatedAt: new Date().toISOString(),
    spreadsheetId: SPREADSHEET_ID,
    coverFolderId: FOLDER_COVER_ID,
    pdfFolderId: FOLDER_PDF_ID,
    sheets: {},
  };

  sheetNames.forEach(function (name) {
    var sheet = ss.getSheetByName(name);
    if (!sheet) return;
    var values = sheet.getDataRange().getDisplayValues();
    if (name === "Admin") {
      values = values.map(function (row, index) {
        if (index === 0) return row;
        return [row[0], "[REDACTED]", "[REDACTED]", row[3], row[4], row[5]];
      });
    }
    data.sheets[name] = values;
  });
  return data;
}

function cleanupOldBackups_(folder) {
  var files = folder.getFiles();
  var candidates = [];
  while (files.hasNext()) {
    var file = files.next();
    if (/^E-Library_(Database|Manifest)_/i.test(file.getName()))
      candidates.push(file);
  }
  candidates.sort(function (a, b) {
    return b.getDateCreated().getTime() - a.getDateCreated().getTime();
  });
  var keepFiles = BACKUP_KEEP_SETS * 2;
  for (var i = keepFiles; i < candidates.length; i++) {
    try {
      candidates[i].setTrashed(true);
    } catch (e) {
      console.warn("Backup lama gagal dibersihkan: " + e);
    }
  }
}

function cleanupOldFullBackupSets_(rootFolder) {
  var folders = rootFolder.getFolders();
  var sets = [];
  while (folders.hasNext()) {
    var folder = folders.next();
    if (/^E-Library_Full_/i.test(folder.getName())) sets.push(folder);
  }
  sets.sort(function (a, b) {
    return b.getDateCreated().getTime() - a.getDateCreated().getTime();
  });
  for (var i = FULL_BACKUP_KEEP_SETS; i < sets.length; i++) {
    try {
      sets[i].setTrashed(true);
    } catch (e) {
      console.warn("Backup penuh lama gagal dibersihkan: " + e);
    }
  }
}

function createBackupInternal_(session) {
  var lock = LockService.getScriptLock();
  lock.waitLock(20000);
  try {
    var folder = ensureBackupFolder_();
    var stamp = Utilities.formatDate(
      new Date(),
      APP_TIMEZONE,
      "yyyyMMdd-HHmmss",
    );
    var spreadsheetFile = DriveApp.getFileById(SPREADSHEET_ID);
    var backupCopy = spreadsheetFile.makeCopy(
      "E-Library_Database_" + stamp,
      folder,
    );
    var manifestBlob = Utilities.newBlob(
      JSON.stringify(buildBackupManifest_(), null, 2),
      "application/json",
      "E-Library_Manifest_" + stamp + ".json",
    );
    var manifestFile = folder.createFile(manifestBlob);

    var logSheet = createSheetIfNotExists_(getSpreadsheet_(), "Backup_Log", [
      "Timestamp",
      "Username",
      "Spreadsheet_Backup_ID",
      "Manifest_ID",
      "Status",
      "Keterangan",
      "Backup_Set_Folder_ID",
      "Jenis_Backup",
    ]);
    logSheet.appendRow([
      new Date(),
      sanitizeUsername_(session.username) || "system",
      backupCopy.getId(),
      manifestFile.getId(),
      "BERHASIL",
      "Salinan Spreadsheet dan manifest JSON dibuat.",
      folder.getId(),
      "DATABASE_CEPAT",
    ]);
    logSheet
      .getRange(logSheet.getLastRow(), 1)
      .setNumberFormat("dd/MM/yyyy HH:mm:ss");
    cleanupOldBackups_(folder);
    catatLog_(
      session,
      "BACKUP",
      "Database",
      "Backup database dan manifest berhasil dibuat.",
      "BERHASIL",
    );
    return {
      timestamp: formatDateTime_(new Date()),
      folderId: folder.getId(),
      spreadsheetBackupId: backupCopy.getId(),
      manifestId: manifestFile.getId(),
    };
  } finally {
    try {
      lock.releaseLock();
    } catch (ignore) {}
  }
}

function buatBackupSekarang(token) {
  var session = requireAdminSession_(token);
  if (!session) return unauthorizedResponse_();
  try {
    return successResponse_(
      createBackupInternal_(session),
      "Backup database cepat berhasil dibuat.",
    );
  } catch (error) {
    catatLog_(session, "BACKUP", "Database", error.toString(), "GAGAL");
    return errorResponse_("Backup gagal: " + error.toString());
  }
}

function parseDriveId_(value) {
  var text = String(value || "").trim();
  if (/^[A-Za-z0-9_-]{20,}$/.test(text)) return text;
  var match =
    text.match(/\/folders\/([A-Za-z0-9_-]+)/) ||
    text.match(/\/d\/([A-Za-z0-9_-]+)/) ||
    text.match(/[?&]id=([A-Za-z0-9_-]+)/);
  return match ? match[1] : "";
}

function getMaintenanceJob_() {
  var raw = PropertiesService.getScriptProperties().getProperty(
    MAINTENANCE_JOB_PROPERTY,
  );
  if (!raw) return null;
  try {
    return JSON.parse(raw);
  } catch (e) {
    return null;
  }
}

function saveMaintenanceJob_(job) {
  job.updatedAt = new Date().toISOString();
  PropertiesService.getScriptProperties().setProperty(
    MAINTENANCE_JOB_PROPERTY,
    JSON.stringify(job),
  );
}

function maintenanceJobIsRunning_() {
  var job = getMaintenanceJob_();
  return job && job.status === "RUNNING";
}

function ensureMaintenanceTrigger_() {
  var exists = ScriptApp.getProjectTriggers().some(function (trigger) {
    return trigger.getHandlerFunction() === MAINTENANCE_TRIGGER_HANDLER;
  });
  if (!exists)
    ScriptApp.newTrigger(MAINTENANCE_TRIGGER_HANDLER)
      .timeBased()
      .everyMinutes(1)
      .create();
}

function removeMaintenanceTriggers_() {
  ScriptApp.getProjectTriggers().forEach(function (trigger) {
    if (trigger.getHandlerFunction() === MAINTENANCE_TRIGGER_HANDLER)
      ScriptApp.deleteTrigger(trigger);
  });
}

function getFolderByName_(parent, name) {
  var iterator = parent.getFoldersByName(name);
  return iterator.hasNext() ? iterator.next() : null;
}

function getFileByName_(folder, name) {
  if (!folder || !name) return null;
  var iterator = folder.getFilesByName(name);
  return iterator.hasNext() ? iterator.next() : null;
}

function getFileSafely_(fileId) {
  if (!fileId) return null;
  try {
    var file = DriveApp.getFileById(fileId);
    if (typeof file.isTrashed === "function" && file.isTrashed()) return null;
    return file;
  } catch (e) {
    return null;
  }
}

function assetFileInfo_(url, storedId, storedName) {
  var id = sanitizeIdentifier_(storedId, 200) || extractDriveFileId_(url);
  var file = getFileSafely_(id);
  return {
    id: file ? file.getId() : id,
    name: file ? file.getName() : sanitizeText_(storedName, 250, false),
    file: file,
  };
}

function copyAssetToBackup_(sourceInfo, targetFolder, targetName, optional) {
  if (!sourceInfo.file) {
    return {
      id: "",
      name: targetName || sourceInfo.name || "",
      status: optional ? "TIDAK_ADA" : "SUMBER_HILANG",
    };
  }
  var existing = getFileByName_(targetFolder, targetName);
  var copy = existing || sourceInfo.file.makeCopy(targetName, targetFolder);
  return {
    id: copy.getId(),
    name: copy.getName(),
    status: existing ? "SUDAH_ADA" : "TERSALIN",
  };
}

function backupManifestHeaders_() {
  return [
    "ID_Buku",
    "Judul",
    "Pengarang",
    "Kategori",
    "Tgl_Upload",
    "Jumlah_Dibaca",
    "Cover_Source_ID",
    "PDF_Source_ID",
    "Cover_Source_Name",
    "PDF_Source_Name",
    "Cover_Backup_ID",
    "PDF_Backup_ID",
    "Cover_Backup_Name",
    "PDF_Backup_Name",
    "Cover_Status",
    "PDF_Status",
    "Link_Cover_Asli",
    "Link_PDF_Asli",
  ];
}

function mulaiBackupKoleksiLengkap(token) {
  var session = requireAdminSession_(token);
  if (!session) return unauthorizedResponse_();
  if (maintenanceJobIsRunning_())
    return errorResponse_("Masih ada pekerjaan backup/restore yang berjalan.");

  try {
    ensureKatalogMetadataColumns_();
    var root = ensureBackupFolder_();
    var stamp = Utilities.formatDate(
      new Date(),
      APP_TIMEZONE,
      "yyyyMMdd-HHmmss",
    );
    var setFolder = root.createFolder("E-Library_Full_" + stamp);
    var coverFolder = setFolder.createFolder("Covers");
    var pdfFolder = setFolder.createFolder("PDFs");
    var backupCopy = DriveApp.getFileById(SPREADSHEET_ID).makeCopy(
      "E-Library_Database_" + stamp,
      setFolder,
    );
    var backupSS = SpreadsheetApp.openById(backupCopy.getId());
    var manifest =
      backupSS.getSheetByName("Backup_Manifest_V3") ||
      backupSS.insertSheet("Backup_Manifest_V3");
    manifest.clearContents();
    manifest
      .getRange(1, 1, 1, backupManifestHeaders_().length)
      .setValues([backupManifestHeaders_()]);
    manifest
      .getRange(1, 1, 1, backupManifestHeaders_().length)
      .setFontWeight("bold")
      .setBackground("#e0e0e0");
    manifest.setFrozenRows(1);

    var totalRows = Math.max(
      ensureKatalogMetadataColumns_().getLastRow() - 1,
      0,
    );
    var job = {
      id: "JOB" + new Date().getTime(),
      type: "BACKUP_FULL",
      status: "RUNNING",
      createdAt: new Date().toISOString(),
      username: session.username,
      role: session.role,
      nextRow: 2,
      totalRows: totalRows,
      processed: 0,
      success: 0,
      failed: 0,
      backupSetFolderId: setFolder.getId(),
      backupSpreadsheetId: backupCopy.getId(),
      coverBackupFolderId: coverFolder.getId(),
      pdfBackupFolderId: pdfFolder.getId(),
      stamp: stamp,
      message: "Backup koleksi penuh disiapkan.",
    };
    setFolder.createFile(
      Utilities.newBlob(
        JSON.stringify(
          {
            version: 3,
            stamp: stamp,
            backupSpreadsheetId: backupCopy.getId(),
            coverFolderId: coverFolder.getId(),
            pdfFolderId: pdfFolder.getId(),
          },
          null,
          2,
        ),
        "application/json",
        "V3_Backup_Metadata.json",
      ),
    );
    saveMaintenanceJob_(job);
    ensureMaintenanceTrigger_();
    catatLog_(
      session,
      "MULAI_BACKUP_PENUH",
      setFolder.getId(),
      "Backup koleksi penuh dimulai.",
      "BERHASIL",
    );
    return successResponse_(
      job,
      "Backup koleksi penuh dimulai dan akan diproses bertahap.",
    );
  } catch (error) {
    catatLog_(
      session,
      "MULAI_BACKUP_PENUH",
      "Koleksi",
      error.toString(),
      "GAGAL",
    );
    return errorResponse_("Backup koleksi gagal dimulai: " + error.toString());
  }
}

function processFullBackupJob_(job) {
  var started = Date.now();
  var catalog = ensureKatalogMetadataColumns_();
  var backupSS = SpreadsheetApp.openById(job.backupSpreadsheetId);
  var manifest = backupSS.getSheetByName("Backup_Manifest_V3");
  var coverFolder = DriveApp.getFolderById(job.coverBackupFolderId);
  var pdfFolder = DriveApp.getFolderById(job.pdfBackupFolderId);
  var totalLastRow = catalog.getLastRow();
  var output = [];
  var rowsProcessed = 0;

  while (
    job.nextRow <= totalLastRow &&
    rowsProcessed < MAINTENANCE_BATCH_MAX_ROWS &&
    Date.now() - started < MAINTENANCE_MAX_RUNTIME_MS
  ) {
    var rowNumber = job.nextRow;
    var row = catalog.getRange(rowNumber, 1, 1, 12).getValues()[0];
    var id = sanitizeIdentifier_(row[0], 100);
    job.nextRow++;
    if (!id) continue;

    try {
      var coverInfo = assetFileInfo_(row[4], row[8], row[10]);
      var pdfInfo = assetFileInfo_(row[5], row[9], row[11]);
      var coverExt = extensionForFile_(
        coverInfo.file ? coverInfo.file.getMimeType() : "",
        coverInfo.name,
        "jpg",
      );
      var coverBackupName = buildCollectionFileName_(id, "cover", coverExt);
      var pdfBackupName = buildCollectionFileName_(id, "pdf", "pdf");
      var coverResult = copyAssetToBackup_(
        coverInfo,
        coverFolder,
        coverBackupName,
        true,
      );
      var pdfResult = copyAssetToBackup_(
        pdfInfo,
        pdfFolder,
        pdfBackupName,
        false,
      );

      catalog
        .getRange(rowNumber, 9, 1, 4)
        .setValues([
          [
            coverInfo.file ? coverInfo.file.getId() : row[8] || "",
            pdfInfo.file ? pdfInfo.file.getId() : row[9] || "",
            coverInfo.file ? coverInfo.file.getName() : row[10] || "",
            pdfInfo.file ? pdfInfo.file.getName() : row[11] || "",
          ],
        ]);

      output.push([
        id,
        sanitizeText_(row[1], 250, false),
        sanitizeText_(row[2], 180, false),
        sanitizeText_(row[3], 100, false),
        formatDateTime_(row[6]),
        Number(row[7]) || 0,
        coverInfo.id || "",
        pdfInfo.id || "",
        coverInfo.name || "",
        pdfInfo.name || "",
        coverResult.id,
        pdfResult.id,
        coverResult.name,
        pdfResult.name,
        coverResult.status,
        pdfResult.status,
        String(row[4] || ""),
        String(row[5] || ""),
      ]);
      if (pdfResult.status === "SUMBER_HILANG") job.failed++;
      else job.success++;
    } catch (error) {
      output.push([
        id,
        sanitizeText_(row[1], 250, false),
        "",
        "",
        "",
        0,
        "",
        "",
        "",
        "",
        "",
        "",
        "",
        "",
        "GAGAL",
        "GAGAL",
        "",
        sanitizeText_(error.toString(), 500, false),
      ]);
      job.failed++;
    }
    job.processed++;
    rowsProcessed++;
  }

  if (output.length)
    manifest
      .getRange(
        manifest.getLastRow() + 1,
        1,
        output.length,
        backupManifestHeaders_().length,
      )
      .setValues(output);
  job.message =
    "Backup koleksi: " +
    job.processed +
    " dari " +
    job.totalRows +
    " buku diproses.";

  if (job.nextRow > totalLastRow) {
    var setFolder = DriveApp.getFolderById(job.backupSetFolderId);
    var manifestValues = manifest.getDataRange().getDisplayValues();
    var manifestJson = setFolder.createFile(
      Utilities.newBlob(
        JSON.stringify(
          {
            version: 3,
            generatedAt: new Date().toISOString(),
            backupSetFolderId: job.backupSetFolderId,
            backupSpreadsheetId: job.backupSpreadsheetId,
            rows: manifestValues,
          },
          null,
          2,
        ),
        "application/json",
        "E-Library_Manifest_V3_" + job.stamp + ".json",
      ),
    );
    var logSheet = createSheetIfNotExists_(getSpreadsheet_(), "Backup_Log", [
      "Timestamp",
      "Username",
      "Spreadsheet_Backup_ID",
      "Manifest_ID",
      "Status",
      "Keterangan",
      "Backup_Set_Folder_ID",
      "Jenis_Backup",
    ]);
    logSheet.appendRow([
      new Date(),
      job.username || "system",
      job.backupSpreadsheetId,
      manifestJson.getId(),
      job.failed ? "SELESAI_DENGAN_CATATAN" : "BERHASIL",
      job.message,
      job.backupSetFolderId,
      "KOLEKSI_PENUH",
    ]);
    logSheet
      .getRange(logSheet.getLastRow(), 1)
      .setNumberFormat("dd/MM/yyyy HH:mm:ss");
    job.status = "COMPLETED";
    job.finishedAt = new Date().toISOString();
    job.message =
      "Backup koleksi penuh selesai. Berhasil: " +
      job.success +
      ", bermasalah: " +
      job.failed +
      ".";
    cleanupOldFullBackupSets_(ensureBackupFolder_());
    catatLog_(
      { username: job.username, role: job.role },
      "BACKUP_PENUH",
      job.backupSetFolderId,
      job.message,
      job.failed ? "PERINGATAN" : "BERHASIL",
    );
    removeMaintenanceTriggers_();
  }
  saveMaintenanceJob_(job);
}

function findBackupSetComponents_(folderId) {
  var setFolder = DriveApp.getFolderById(folderId);
  var coverFolder = getFolderByName_(setFolder, "Covers");
  var pdfFolder = getFolderByName_(setFolder, "PDFs");
  var spreadsheet = null;
  var sheets = setFolder.getFilesByType(MimeType.GOOGLE_SHEETS);
  while (sheets.hasNext()) {
    var candidate = sheets.next();
    if (/^E-Library_Database_/i.test(candidate.getName())) {
      spreadsheet = candidate;
      break;
    }
    if (!spreadsheet) spreadsheet = candidate;
  }
  if (!spreadsheet || !coverFolder || !pdfFolder)
    throw new Error("Struktur backup V3 tidak lengkap.");
  var backupSS = SpreadsheetApp.openById(spreadsheet.getId());
  var manifest = backupSS.getSheetByName("Backup_Manifest_V3");
  if (!manifest) throw new Error("Sheet Backup_Manifest_V3 tidak ditemukan.");
  return {
    setFolder: setFolder,
    coverFolder: coverFolder,
    pdfFolder: pdfFolder,
    spreadsheet: spreadsheet,
    manifest: manifest,
  };
}

function createRestoreReportSheet_(prefix) {
  var stamp = Utilities.formatDate(new Date(), APP_TIMEZONE, "yyyyMMdd_HHmmss");
  var name = (prefix + "_" + stamp).substring(0, 95);
  var sheet = getSpreadsheet_().insertSheet(name);
  sheet
    .getRange(1, 1, 1, 6)
    .setValues([["Waktu", "ID_Buku", "Judul", "Status", "Jenis", "Detail"]]);
  sheet.getRange(1, 1, 1, 6).setFontWeight("bold").setBackground("#e0e0e0");
  sheet.setFrozenRows(1);
  return sheet;
}

function startRestoreJob_(session, source, mode, simulate, legacy) {
  if (maintenanceJobIsRunning_())
    return errorResponse_("Masih ada pekerjaan backup/restore yang berjalan.");
  var report = createRestoreReportSheet_(
    simulate ? "Simulasi_Restore" : "Restore_Report",
  );
  var job = {
    id: "JOB" + new Date().getTime(),
    type: legacy ? "RESTORE_LEGACY" : "RESTORE_V3",
    status: "RUNNING",
    createdAt: new Date().toISOString(),
    username: session.username,
    role: session.role,
    nextRow: 2,
    totalRows: source.totalRows,
    processed: 0,
    success: 0,
    failed: 0,
    skipped: 0,
    mode: mode === "full" ? "full" : "files_only",
    simulate: Boolean(simulate),
    sourceSpreadsheetId: source.spreadsheetId,
    sourceCoverFolderId: source.coverFolderId,
    sourcePdfFolderId: source.pdfFolderId,
    sourceBackupSetId: source.backupSetId || "",
    reportSheetName: report.getName(),
    message: simulate
      ? "Simulasi pemulihan disiapkan."
      : "Pemulihan disiapkan.",
  };
  saveMaintenanceJob_(job);
  ensureMaintenanceTrigger_();
  catatLog_(
    session,
    simulate ? "SIMULASI_RESTORE" : "MULAI_RESTORE",
    source.backupSetId || source.spreadsheetId,
    "Mode " + job.mode,
    "BERHASIL",
  );
  return successResponse_(
    job,
    (simulate ? "Simulasi" : "Pemulihan") + " dimulai dan diproses bertahap.",
  );
}

function mulaiSimulasiPemulihan(token, backupFolderInput, mode) {
  var session = requireAdminSession_(token);
  if (!session) return unauthorizedResponse_();
  try {
    var folderId = parseDriveId_(backupFolderInput);
    if (!folderId)
      return errorResponse_("ID atau URL folder backup tidak valid.");
    var parts = findBackupSetComponents_(folderId);
    return startRestoreJob_(
      session,
      {
        backupSetId: folderId,
        spreadsheetId: parts.spreadsheet.getId(),
        coverFolderId: parts.coverFolder.getId(),
        pdfFolderId: parts.pdfFolder.getId(),
        totalRows: Math.max(parts.manifest.getLastRow() - 1, 0),
      },
      mode,
      true,
      false,
    );
  } catch (error) {
    return errorResponse_("Simulasi gagal dimulai: " + error.toString());
  }
}

function mulaiPemulihanKoleksi(token, backupFolderInput, mode) {
  var session = requireAdminSession_(token);
  if (!session) return unauthorizedResponse_();
  try {
    var folderId = parseDriveId_(backupFolderInput);
    if (!folderId)
      return errorResponse_("ID atau URL folder backup tidak valid.");
    var parts = findBackupSetComponents_(folderId);
    return startRestoreJob_(
      session,
      {
        backupSetId: folderId,
        spreadsheetId: parts.spreadsheet.getId(),
        coverFolderId: parts.coverFolder.getId(),
        pdfFolderId: parts.pdfFolder.getId(),
        totalRows: Math.max(parts.manifest.getLastRow() - 1, 0),
      },
      mode,
      false,
      false,
    );
  } catch (error) {
    return errorResponse_("Pemulihan gagal dimulai: " + error.toString());
  }
}

function mulaiPemulihanLegacy(
  token,
  spreadsheetInput,
  coverFolderInput,
  pdfFolderInput,
  mode,
  simulate,
) {
  var session = requireAdminSession_(token);
  if (!session) return unauthorizedResponse_();
  try {
    var spreadsheetId = parseDriveId_(spreadsheetInput);
    var coverFolderId = parseDriveId_(coverFolderInput);
    var pdfFolderId = parseDriveId_(pdfFolderInput);
    if (!spreadsheetId || !coverFolderId || !pdfFolderId)
      return errorResponse_(
        "ID Spreadsheet/folder backup legacy belum lengkap.",
      );
    var sourceSS = SpreadsheetApp.openById(spreadsheetId);
    var sourceCatalog = sourceSS.getSheetByName("Katalog");
    if (!sourceCatalog)
      return errorResponse_(
        "Sheet Katalog tidak ditemukan pada Spreadsheet backup.",
      );
    DriveApp.getFolderById(coverFolderId);
    DriveApp.getFolderById(pdfFolderId);
    return startRestoreJob_(
      session,
      {
        spreadsheetId: spreadsheetId,
        coverFolderId: coverFolderId,
        pdfFolderId: pdfFolderId,
        totalRows: Math.max(sourceCatalog.getLastRow() - 1, 0),
      },
      mode,
      Boolean(simulate),
      true,
    );
  } catch (error) {
    return errorResponse_("Restore legacy gagal dimulai: " + error.toString());
  }
}

function getLegacyAsset_(folder, id, title, type, storedName) {
  var candidates = [];
  if (storedName) candidates.push(storedName);
  candidates.push(
    buildCollectionFileName_(id, type, type === "cover" ? "jpg" : "pdf"),
  );
  if (type === "cover")
    candidates.push(buildCollectionFileName_(id, type, "png"));
  var cleanTitle = sanitizeText_(title, 180, false);
  if (cleanTitle) {
    if (type === "pdf") candidates.push(cleanTitle + ".pdf");
    else
      candidates.push(
        cleanTitle + ".jpg",
        cleanTitle + ".jpeg",
        cleanTitle + ".png",
      );
  }
  for (var i = 0; i < candidates.length; i++) {
    var file = getFileByName_(folder, candidates[i]);
    if (file) return file;
  }
  return null;
}

function catalogRowMap_() {
  var sheet = ensureKatalogMetadataColumns_();
  var values = sheet.getDataRange().getValues();
  var map = {};
  for (var i = 1; i < values.length; i++) {
    var id = sanitizeIdentifier_(values[i][0], 100);
    if (id) map[id] = { rowNumber: i + 1, values: values[i] };
  }
  return { sheet: sheet, map: map };
}

function restoreAsset_(
  backupFile,
  activeFileId,
  activeFolderId,
  targetName,
  type,
  simulate,
) {
  var active = getFileSafely_(activeFileId);
  if (active) {
    setCollectionFilePublic_(active);
    return {
      status: "SUDAH_ADA",
      file: active,
      url:
        type === "cover"
          ? buildPublicCoverUrl_(active)
          : buildPublicPdfPreviewUrl_(active),
    };
  }
  if (!backupFile) return { status: "SUMBER_HILANG", file: null, url: "" };
  if (simulate) return { status: "AKAN_DIPULIHKAN", file: null, url: "" };
  var targetFolder = DriveApp.getFolderById(activeFolderId);
  var existing = getFileByName_(targetFolder, targetName);
  var restored = existing || backupFile.makeCopy(targetName, targetFolder);
  restored.setDescription("Dipulihkan oleh E-Library Restore Center");
  setCollectionFilePublic_(restored);
  return {
    status: existing ? "DITEMUKAN_DI_FOLDER_AKTIF" : "DIPULIHKAN",
    file: restored,
    url:
      type === "cover"
        ? buildPublicCoverUrl_(restored)
        : buildPublicPdfPreviewUrl_(restored),
  };
}

function processRestoreJob_(job) {
  var started = Date.now();
  var sourceSS = SpreadsheetApp.openById(job.sourceSpreadsheetId);
  var sourceSheet =
    job.type === "RESTORE_V3"
      ? sourceSS.getSheetByName("Backup_Manifest_V3")
      : sourceSS.getSheetByName("Katalog");
  var sourceCoverFolder = DriveApp.getFolderById(job.sourceCoverFolderId);
  var sourcePdfFolder = DriveApp.getFolderById(job.sourcePdfFolderId);
  var report = getSpreadsheet_().getSheetByName(job.reportSheetName);
  var target = catalogRowMap_();
  var totalLastRow = sourceSheet.getLastRow();
  var reportRows = [];
  var rowsProcessed = 0;

  while (
    job.nextRow <= totalLastRow &&
    rowsProcessed < MAINTENANCE_BATCH_MAX_ROWS &&
    Date.now() - started < MAINTENANCE_MAX_RUNTIME_MS
  ) {
    var sourceRow = sourceSheet
      .getRange(
        job.nextRow,
        1,
        1,
        job.type === "RESTORE_V3"
          ? 18
          : Math.max(sourceSheet.getLastColumn(), 12),
      )
      .getValues()[0];
    job.nextRow++;
    rowsProcessed++;

    var id,
      title,
      author,
      category,
      uploadDate,
      readCount,
      coverBackupId,
      pdfBackupId,
      coverBackupName,
      pdfBackupName;
    if (job.type === "RESTORE_V3") {
      id = sanitizeIdentifier_(sourceRow[0], 100);
      title = sanitizeText_(sourceRow[1], 250, false);
      author = sanitizeText_(sourceRow[2], 180, false);
      category = sanitizeText_(sourceRow[3], 100, false);
      uploadDate = sourceRow[4];
      readCount = Number(sourceRow[5]) || 0;
      coverBackupId = sanitizeIdentifier_(sourceRow[10], 200);
      pdfBackupId = sanitizeIdentifier_(sourceRow[11], 200);
      coverBackupName = sanitizeText_(sourceRow[12], 250, false);
      pdfBackupName = sanitizeText_(sourceRow[13], 250, false);
    } else {
      id = sanitizeIdentifier_(sourceRow[0], 100);
      title = sanitizeText_(sourceRow[1], 250, false);
      author = sanitizeText_(sourceRow[2], 180, false);
      category = sanitizeText_(sourceRow[3], 100, false);
      uploadDate = sourceRow[6];
      readCount = Number(sourceRow[7]) || 0;
      coverBackupName = sanitizeText_(sourceRow[10], 250, false);
      pdfBackupName = sanitizeText_(sourceRow[11], 250, false);
    }
    if (!id) continue;

    try {
      var existingRow = target.map[id] || null;
      var current = existingRow ? existingRow.values : [];
      var coverBackup =
        getFileSafely_(coverBackupId) ||
        getFileByName_(sourceCoverFolder, coverBackupName) ||
        (job.type === "RESTORE_LEGACY"
          ? getLegacyAsset_(
              sourceCoverFolder,
              id,
              title,
              "cover",
              coverBackupName,
            )
          : null);
      var pdfBackup =
        getFileSafely_(pdfBackupId) ||
        getFileByName_(sourcePdfFolder, pdfBackupName) ||
        (job.type === "RESTORE_LEGACY"
          ? getLegacyAsset_(sourcePdfFolder, id, title, "pdf", pdfBackupName)
          : null);
      var coverTargetName =
        coverBackupName ||
        buildCollectionFileName_(
          id,
          "cover",
          coverBackup
            ? extensionForFile_(
                coverBackup.getMimeType(),
                coverBackup.getName(),
                "jpg",
              )
            : "jpg",
        );
      var pdfTargetName =
        pdfBackupName || buildCollectionFileName_(id, "pdf", "pdf");
      var coverActiveId = current[8] || extractDriveFileId_(current[4]);
      var pdfActiveId = current[9] || extractDriveFileId_(current[5]);
      var coverResult = restoreAsset_(
        coverBackup,
        coverActiveId,
        FOLDER_COVER_ID,
        coverTargetName,
        "cover",
        job.simulate,
      );
      var pdfResult = restoreAsset_(
        pdfBackup,
        pdfActiveId,
        FOLDER_PDF_ID,
        pdfTargetName,
        "pdf",
        job.simulate,
      );

      var overall =
        pdfResult.status === "SUMBER_HILANG" && !getFileSafely_(pdfActiveId)
          ? "GAGAL_PDF_TIDAK_ADA"
          : "SIAP";
      var detail =
        "Cover: " + coverResult.status + "; PDF: " + pdfResult.status;

      if (!job.simulate && overall === "SIAP") {
        var finalCoverId = coverResult.file
          ? coverResult.file.getId()
          : coverActiveId || "";
        var finalPdfId = pdfResult.file
          ? pdfResult.file.getId()
          : pdfActiveId || "";
        var finalCoverUrl = coverResult.url || String(current[4] || "");
        var finalPdfUrl = pdfResult.url || String(current[5] || "");
        var rowValues = [
          id,
          title,
          author,
          category,
          finalCoverUrl,
          finalPdfUrl,
          uploadDate || new Date(),
          readCount,
          finalCoverId,
          finalPdfId,
          coverTargetName,
          pdfTargetName,
        ];
        if (existingRow) {
          if (job.mode === "files_only") {
            rowValues[1] = current[1];
            rowValues[2] = current[2];
            rowValues[3] = current[3];
            rowValues[6] = current[6];
            rowValues[7] = current[7];
          }
          target.sheet
            .getRange(existingRow.rowNumber, 1, 1, 12)
            .setValues([rowValues]);
          target.map[id] = {
            rowNumber: existingRow.rowNumber,
            values: rowValues,
          };
        } else if (job.mode === "full") {
          target.sheet.appendRow(rowValues);
          target.map[id] = {
            rowNumber: target.sheet.getLastRow(),
            values: rowValues,
          };
        } else {
          overall = "DILEWATI_BARIS_TIDAK_ADA";
        }
      }

      if (overall.indexOf("GAGAL") === 0) job.failed++;
      else if (overall.indexOf("DILEWATI") === 0) job.skipped++;
      else job.success++;
      job.processed++;
      reportRows.push([
        new Date(),
        id,
        title,
        overall,
        job.simulate ? "SIMULASI" : "RESTORE",
        detail,
      ]);
    } catch (error) {
      job.failed++;
      job.processed++;
      reportRows.push([
        new Date(),
        id,
        title,
        "GAGAL",
        job.simulate ? "SIMULASI" : "RESTORE",
        sanitizeText_(error.toString(), 500, false),
      ]);
    }
  }

  if (reportRows.length) {
    report
      .getRange(report.getLastRow() + 1, 1, reportRows.length, 6)
      .setValues(reportRows);
    report
      .getRange(2, 1, Math.max(report.getLastRow() - 1, 1), 1)
      .setNumberFormat("dd/MM/yyyy HH:mm:ss");
  }
  job.message =
    (job.simulate ? "Simulasi" : "Restore") +
    ": " +
    job.processed +
    " dari " +
    job.totalRows +
    " buku diperiksa.";

  if (job.nextRow > totalLastRow) {
    job.status = "COMPLETED";
    job.finishedAt = new Date().toISOString();
    job.message =
      (job.simulate ? "Simulasi" : "Pemulihan") +
      " selesai. Berhasil/siap: " +
      job.success +
      ", gagal: " +
      job.failed +
      ", dilewati: " +
      job.skipped +
      ". Lihat sheet " +
      job.reportSheetName +
      ".";
    var restoreLog = createSheetIfNotExists_(getSpreadsheet_(), "Restore_Log", [
      "Timestamp",
      "Username",
      "Jenis",
      "Sumber_Backup",
      "Diproses",
      "Berhasil",
      "Gagal",
      "Status",
      "Keterangan",
    ]);
    restoreLog.appendRow([
      new Date(),
      job.username,
      job.simulate ? "SIMULASI" : job.mode,
      job.sourceBackupSetId || job.sourceSpreadsheetId,
      job.processed,
      job.success,
      job.failed,
      job.failed ? "SELESAI_DENGAN_CATATAN" : "BERHASIL",
      job.message,
    ]);
    restoreLog
      .getRange(restoreLog.getLastRow(), 1)
      .setNumberFormat("dd/MM/yyyy HH:mm:ss");
    catatLog_(
      { username: job.username, role: job.role },
      job.simulate ? "SELESAI_SIMULASI_RESTORE" : "SELESAI_RESTORE",
      job.sourceBackupSetId || job.sourceSpreadsheetId,
      job.message,
      job.failed ? "PERINGATAN" : "BERHASIL",
    );
    removeMaintenanceTriggers_();
  }
  saveMaintenanceJob_(job);
}

function mulaiPemeriksaanIntegritas(token) {
  var session = requireAdminSession_(token);
  if (!session) return unauthorizedResponse_();
  if (maintenanceJobIsRunning_())
    return errorResponse_("Masih ada pekerjaan backup/restore yang berjalan.");
  try {
    var report = createRestoreReportSheet_("Cek_Integritas");
    var catalog = ensureKatalogMetadataColumns_();
    var job = {
      id: "JOB" + new Date().getTime(),
      type: "INTEGRITY",
      status: "RUNNING",
      createdAt: new Date().toISOString(),
      username: session.username,
      role: session.role,
      nextRow: 2,
      totalRows: Math.max(catalog.getLastRow() - 1, 0),
      processed: 0,
      success: 0,
      failed: 0,
      skipped: 0,
      reportSheetName: report.getName(),
      message: "Pemeriksaan integritas dimulai.",
    };
    saveMaintenanceJob_(job);
    ensureMaintenanceTrigger_();
    return successResponse_(job, "Pemeriksaan file aktif dimulai.");
  } catch (error) {
    return errorResponse_("Pemeriksaan gagal dimulai: " + error.toString());
  }
}

function processIntegrityJob_(job) {
  var started = Date.now();
  var catalog = ensureKatalogMetadataColumns_();
  var report = getSpreadsheet_().getSheetByName(job.reportSheetName);
  var totalLastRow = catalog.getLastRow();
  var rows = [];
  var count = 0;
  while (
    job.nextRow <= totalLastRow &&
    count < MAINTENANCE_BATCH_MAX_ROWS &&
    Date.now() - started < MAINTENANCE_MAX_RUNTIME_MS
  ) {
    var row = catalog.getRange(job.nextRow, 1, 1, 12).getValues()[0];
    job.nextRow++;
    count++;
    var id = sanitizeIdentifier_(row[0], 100);
    if (!id) continue;
    var cover = getFileSafely_(row[8] || extractDriveFileId_(row[4]));
    var pdf = getFileSafely_(row[9] || extractDriveFileId_(row[5]));
    var status = pdf ? "OK" : "PDF_HILANG";
    var detail =
      "Cover: " +
      (cover ? "OK" : row[4] ? "HILANG" : "TIDAK_ADA") +
      "; PDF: " +
      (pdf ? "OK" : "HILANG");
    if (status === "OK") job.success++;
    else job.failed++;
    job.processed++;
    rows.push([
      new Date(),
      id,
      sanitizeText_(row[1], 250, false),
      status,
      "INTEGRITAS",
      detail,
    ]);
  }
  if (rows.length)
    report.getRange(report.getLastRow() + 1, 1, rows.length, 6).setValues(rows);
  job.message =
    "Pemeriksaan: " + job.processed + " dari " + job.totalRows + " buku.";
  if (job.nextRow > totalLastRow) {
    job.status = "COMPLETED";
    job.finishedAt = new Date().toISOString();
    job.message =
      "Pemeriksaan selesai. Aman: " +
      job.success +
      ", bermasalah: " +
      job.failed +
      ". Lihat sheet " +
      job.reportSheetName +
      ".";
    catatLog_(
      { username: job.username, role: job.role },
      "CEK_INTEGRITAS",
      "Koleksi",
      job.message,
      job.failed ? "PERINGATAN" : "BERHASIL",
    );
    removeMaintenanceTriggers_();
  }
  saveMaintenanceJob_(job);
}

function jalankanPekerjaanPemeliharaan_() {
  var lock = LockService.getScriptLock();
  if (!lock.tryLock(1000)) return;
  try {
    var job = getMaintenanceJob_();
    if (!job || job.status !== "RUNNING") {
      removeMaintenanceTriggers_();
      return;
    }
    if (job.type === "BACKUP_FULL") processFullBackupJob_(job);
    else if (job.type === "RESTORE_V3" || job.type === "RESTORE_LEGACY")
      processRestoreJob_(job);
    else if (job.type === "INTEGRITY") processIntegrityJob_(job);
    else {
      job.status = "FAILED";
      job.message = "Jenis pekerjaan tidak dikenal.";
      saveMaintenanceJob_(job);
      removeMaintenanceTriggers_();
    }
  } catch (error) {
    var failedJob = getMaintenanceJob_() || {};
    failedJob.status = "FAILED";
    failedJob.finishedAt = new Date().toISOString();
    failedJob.message =
      "Pekerjaan gagal: " + sanitizeText_(error.toString(), 500, false);
    saveMaintenanceJob_(failedJob);
    removeMaintenanceTriggers_();
    catatLog_(
      {
        username: failedJob.username || "system",
        role: failedJob.role || "system",
      },
      "PEKERJAAN_PEMELIHARAAN",
      failedJob.type || "unknown",
      failedJob.message,
      "GAGAL",
    );
  } finally {
    try {
      lock.releaseLock();
    } catch (ignore) {}
  }
}

function getStatusPekerjaanPemeliharaan(token) {
  var session = requireAdminSession_(token);
  if (!session) return unauthorizedResponse_();
  var job = getMaintenanceJob_();
  if (!job) return successResponse_(null, "Tidak ada pekerjaan pemeliharaan.");
  return successResponse_(
    {
      id: sanitizeIdentifier_(job.id, 100),
      type: sanitizeIdentifier_(job.type, 50),
      status: sanitizeIdentifier_(job.status, 30),
      createdAt: sanitizeText_(job.createdAt, 50, false),
      updatedAt: sanitizeText_(job.updatedAt, 50, false),
      finishedAt: sanitizeText_(job.finishedAt, 50, false),
      processed: Number(job.processed) || 0,
      totalRows: Number(job.totalRows) || 0,
      success: Number(job.success) || 0,
      failed: Number(job.failed) || 0,
      skipped: Number(job.skipped) || 0,
      message: sanitizeText_(job.message, 500, true),
      reportSheetName: sanitizeText_(job.reportSheetName, 100, false),
      backupSetFolderId: sanitizeIdentifier_(job.backupSetFolderId, 200),
    },
    "Status pekerjaan berhasil dimuat.",
  );
}

function batalkanPekerjaanPemeliharaan(token) {
  var session = requireAdminSession_(token);
  if (!session) return unauthorizedResponse_();
  var job = getMaintenanceJob_();
  if (!job || job.status !== "RUNNING")
    return errorResponse_("Tidak ada pekerjaan aktif.");
  job.status = "CANCELLED";
  job.finishedAt = new Date().toISOString();
  job.message = "Pekerjaan dibatalkan oleh " + session.username + ".";
  saveMaintenanceJob_(job);
  removeMaintenanceTriggers_();
  catatLog_(session, "BATALKAN_PEKERJAAN", job.type, job.message, "BERHASIL");
  return successResponse_(job, "Pekerjaan berhasil dibatalkan.");
}

function getDaftarBackupKoleksi(token) {
  var session = requireAdminSession_(token);
  if (!session) return unauthorizedResponse_();
  try {
    var root = ensureBackupFolder_();
    var folders = root.getFolders();
    var result = [];
    while (folders.hasNext()) {
      var folder = folders.next();
      if (!/^E-Library_Full_/i.test(folder.getName())) continue;
      result.push({
        id: folder.getId(),
        name: sanitizeText_(folder.getName(), 150, false),
        createdAt: formatDateTime_(folder.getDateCreated()),
      });
    }
    result.sort(function (a, b) {
      return a.name < b.name ? 1 : -1;
    });
    return successResponse_(
      result.slice(0, 30),
      "Daftar backup koleksi berhasil dimuat.",
    );
  } catch (error) {
    return errorResponse_("Daftar backup gagal dimuat: " + error.toString());
  }
}

function pasangBackupMingguan(token) {
  var session = requireAdminSession_(token);
  if (!session) return unauthorizedResponse_();
  try {
    ScriptApp.getProjectTriggers().forEach(function (trigger) {
      if (trigger.getHandlerFunction() === "jalankanBackupTerjadwal_")
        ScriptApp.deleteTrigger(trigger);
    });
    ScriptApp.newTrigger("jalankanBackupTerjadwal_")
      .timeBased()
      .everyWeeks(1)
      .onWeekDay(ScriptApp.WeekDay.MONDAY)
      .atHour(2)
      .inTimezone(APP_TIMEZONE)
      .create();
    catatLog_(
      session,
      "PASANG_BACKUP_OTOMATIS",
      "Trigger",
      "Backup database mingguan setiap Senin sekitar pukul 02.00.",
      "BERHASIL",
    );
    return successResponse_(
      null,
      "Backup database mingguan berhasil diaktifkan.",
    );
  } catch (error) {
    return errorResponse_("Trigger backup gagal dipasang: " + error.toString());
  }
}

function jalankanBackupTerjadwal_() {
  try {
    createBackupInternal_({ username: "system", role: "system" });
  } catch (error) {
    catatLog_(
      { username: "system", role: "system" },
      "BACKUP_OTOMATIS",
      "Database",
      error.toString(),
      "GAGAL",
    );
  }
}

function getStatusPemeliharaan(token) {
  var session = requireAdminSession_(token);
  if (!session) return unauthorizedResponse_();

  try {
    var ss = getSpreadsheet_();
    var backupLog = ss.getSheetByName("Backup_Log");
    var lastBackup = null;
    if (backupLog && backupLog.getLastRow() > 1) {
      var row = backupLog
        .getRange(backupLog.getLastRow(), 1, 1, 6)
        .getValues()[0];
      lastBackup = {
        timestamp: formatDateTime_(row[0]),
        username: sanitizeUsername_(row[1]) || "system",
        status: sanitizeIdentifier_(row[4], 30),
        keterangan: sanitizeText_(row[5], 300, true),
      };
    }

    var triggerActive = ScriptApp.getProjectTriggers().some(function (trigger) {
      return trigger.getHandlerFunction() === "jalankanBackupTerjadwal_";
    });

    var props = PropertiesService.getScriptProperties();
    var masterConfigured = Boolean(
      props.getProperty("MASTER_USERNAME") &&
      props.getProperty("MASTER_PASSWORD_HASH") &&
      props.getProperty("MASTER_PASSWORD_SALT"),
    );

    return successResponse_(
      {
        lastBackup: lastBackup,
        weeklyBackupActive: triggerActive,
        masterConfigured: masterConfigured,
        maintenanceJob: getMaintenanceJob_(),
      },
      "Status pemeliharaan berhasil dimuat.",
    );
  } catch (error) {
    return errorResponse_(
      "Status pemeliharaan gagal dimuat: " + error.toString(),
    );
  }
}

/** Entry point publik agar muncul di pilihan fungsi editor Apps Script. */
function setupKeamananAwal() {
  var hasil = setupKeamananAwal_();
  console.log(hasil);
  return hasil;
}
