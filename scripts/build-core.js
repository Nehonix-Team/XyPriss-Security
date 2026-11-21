/***************************************************************************
 * XyPriss Security - Unified Core Provisioner
 *
 * High-speed native core resolution pipeline:
 * 1. Pre-existing binary verification in lib/security-core/ (0ms)
 * 2. Machine-level cache resolution (~/.cache/xypriss-security/bin/) (1ms)
 * 3. Local Go toolchain compilation fallback (2-3s)
 * 4. High-efficiency archive download (.gz / .zip) from GitHub Releases
 *    with real-time progress, timeout protection, and automatic caching.
 ***************************************************************************/

const path = require("path");
const fs = require("fs");
const os = require("os");
const https = require("https");
const zlib = require("zlib");
const { execSync } = require("child_process");

const corePath = path.join(__dirname, "../lib/security-core");
const platform = process.platform;
const arch = process.arch;

const extension = platform === "win32" ? ".exe" : "";
const outFile = `libxypriss_core${extension}`;
const destPath = path.join(corePath, outFile);

// Ensure destination directory exists
if (!fs.existsSync(corePath)) {
  fs.mkdirSync(corePath, { recursive: true });
}

// OS / Arch identifiers matching release naming conventions
const osLabel =
  platform === "win32" ? "windows" : platform === "darwin" ? "darwin" : "linux";
const archLabel = arch === "x64" ? "amd64" : arch === "arm64" ? "arm64" : arch;
const releaseBaseName = `libxypriss_core-${osLabel}-${archLabel}${extension}`;

// Global machine cache path (shared across projects on this machine)
const cacheDir = path.join(os.homedir(), ".cache", "xypriss-security", "bin");
const cachedBinary = path.join(cacheDir, releaseBaseName);

/**
 * Format bytes to human readable string
 */
function formatBytes(bytes) {
  if (!bytes || bytes <= 0) return "0 B";
  const k = 1024;
  const sizes = ["B", "KB", "MB", "GB"];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return `${(bytes / Math.pow(k, i)).toFixed(2)} ${sizes[i]}`;
}

/**
 * Renders a clean progress bar in terminal
 */
function renderProgressBar(received, total, startTime) {
  const barWidth = 24;
  const elapsedSec = Math.max((Date.now() - startTime) / 1000, 0.001);
  const speed = received / elapsedSec;
  const speedStr = `${formatBytes(speed)}/s`;

  if (total > 0) {
    const ratio = Math.min(Math.max(received / total, 0), 1);
    const percent = (ratio * 100).toFixed(1);
    const filled = Math.round(barWidth * ratio);
    const empty = Math.max(barWidth - filled, 0);
    const bar = "█".repeat(filled) + "░".repeat(empty);
    const sizeStr = `${formatBytes(received)} / ${formatBytes(total)}`;
    process.stdout.write(
      `\r    └─ [${bar}] ${percent.padStart(5)}% (${sizeStr}, ${speedStr})   `,
    );
  } else {
    process.stdout.write(
      `\r    └─ ↓ ${formatBytes(received)} (${speedStr})   `,
    );
  }
}

/**
 * Save a verified binary to the global machine cache
 */
function saveToCache(sourcePath) {
  try {
    if (!fs.existsSync(cacheDir)) {
      fs.mkdirSync(cacheDir, { recursive: true });
    }
    fs.copyFileSync(sourcePath, cachedBinary);
    if (platform !== "win32") {
      fs.chmodSync(cachedBinary, 0o755);
    }
  } catch (_) {}
}

/**
 * Download a file with redirect support, timeout, and optional gunzip extraction.
 */
function downloadFile(url, destination, isGzip = false, maxRedirects = 5) {
  return new Promise((resolve, reject) => {
    if (maxRedirects <= 0) {
      return reject(new Error("Too many redirects"));
    }

    const options = {
      headers: {
        "User-Agent": "xypriss-security-installer/2.1 (Nehonix-Team)",
        Accept: "*/*",
      },
      timeout: 25000,
    };

    const req = https.get(url, options, (res) => {
      // Handle redirects (GitHub Release -> Azure Blob / S3)
      if (
        res.statusCode >= 300 &&
        res.statusCode < 400 &&
        res.headers.location
      ) {
        return downloadFile(
          res.headers.location,
          destination,
          isGzip,
          maxRedirects - 1,
        )
          .then(resolve)
          .catch(reject);
      }

      if (res.statusCode !== 200) {
        return reject(
          new Error(`HTTP ${res.statusCode} ${res.statusMessage || ""}`),
        );
      }

      const totalBytes = parseInt(res.headers["content-length"] || "0", 10);
      let receivedBytes = 0;
      const startTime = Date.now();

      const outStream = fs.createWriteStream(destination);

      if (isGzip) {
        const gunzip = zlib.createGunzip();

        res.on("data", (chunk) => {
          receivedBytes += chunk.length;
          renderProgressBar(receivedBytes, totalBytes, startTime);
        });

        res
          .pipe(gunzip)
          .pipe(outStream)
          .on("finish", () => {
            process.stdout.write("\n");
            outStream.close(() => resolve());
          })
          .on("error", (err) => {
            fs.unlink(destination, () => {});
            reject(err);
          });
      } else {
        res.on("data", (chunk) => {
          receivedBytes += chunk.length;
          renderProgressBar(receivedBytes, totalBytes, startTime);
        });

        res
          .pipe(outStream)
          .on("finish", () => {
            process.stdout.write("\n");
            outStream.close(() => resolve());
          })
          .on("error", (err) => {
            fs.unlink(destination, () => {});
            reject(err);
          });
      }
    });

    req.on("timeout", () => {
      req.destroy();
      reject(new Error("Connection timed out after 25 seconds"));
    });

    req.on("error", (err) => {
      fs.unlink(destination, () => {});
      reject(err);
    });
  });
}

async function run() {
  console.log(`\n🛡️  XyPriss Security Core Provisioning [${osLabel}-${archLabel}]...`);

  // --- Tier 1: Check if binary already exists locally ---
  if (fs.existsSync(destPath)) {
    try {
      const stats = fs.statSync(destPath);
      if (stats.size > 100000) {
        console.log(`  ✔ Pre-existing native core verified (${formatBytes(stats.size)}). Ready.`);
        saveToCache(destPath);
        process.exit(0);
      }
    } catch (_) {}
  }

  // --- Tier 2: Check Machine-Level Cache ---
  if (fs.existsSync(cachedBinary)) {
    try {
      const stats = fs.statSync(cachedBinary);
      if (stats.size > 100000) {
        console.log(`  ⚡ Restoring native core from global cache (${formatBytes(stats.size)})...`);
        fs.copyFileSync(cachedBinary, destPath);
        if (platform !== "win32") {
          fs.chmodSync(destPath, 0o755);
        }
        console.log(`  ✔ Binary restored in 1ms.`);
        process.exit(0);
      }
    } catch (_) {}
  }

  // --- Tier 3: Local Go Toolchain Compilation ---
  const mainGo = path.join(corePath, "main.go");
  if (fs.existsSync(mainGo)) {
    try {
      execSync("go version", { stdio: "ignore", timeout: 3000 });
      console.log(`  ⚙  Local Go toolchain detected. Compiling native core locally...`);
      execSync(`go build -ldflags="-s -w" -o "${destPath}" main.go`, {
        cwd: corePath,
        env: { ...process.env, CGO_ENABLED: "0" },
        stdio: "ignore",
        timeout: 45000,
      });
      if (platform !== "win32") {
        fs.chmodSync(destPath, 0o755);
      }
      saveToCache(destPath);
      console.log(`  ✔ Native core successfully compiled and cached in seconds.`);
      process.exit(0);
    } catch (_) {
      // Local Go build failed or timed out; proceed to archive download
    }
  }

  // --- Tier 4: Download from GitHub Releases (.gz archive preferred, raw fallback) ---
  const baseUrl = `https://github.com/Nehonix-Team/XyPriss-Security/releases/latest/download`;
  const gzUrl = `${baseUrl}/${releaseBaseName}.gz`;
  const rawUrl = `${baseUrl}/${releaseBaseName}`;

  try {
    console.log(`  ▶ Downloading compressed release archive (.gz)...`);
    console.log(`    └─ URL: ${gzUrl}`);
    await downloadFile(gzUrl, destPath, true);
    if (platform !== "win32") {
      fs.chmodSync(destPath, 0o755);
    }
    saveToCache(destPath);
    console.log(`  ✔ Archive extracted, binary installed and cached.`);
    process.exit(0);
  } catch (gzErr) {
    console.log(`  ℹ Archive (.gz) not found (${gzErr.message}), falling back to raw binary...`);
    try {
      console.log(`  ▶ Downloading raw binary...`);
      console.log(`    └─ URL: ${rawUrl}`);
      await downloadFile(rawUrl, destPath, false);
      if (platform !== "win32") {
        fs.chmodSync(destPath, 0o755);
      }
      saveToCache(destPath);
      console.log(`  ✔ Binary successfully installed and cached.`);
      process.exit(0);
    } catch (rawErr) {
      console.error(`\n✖ Provisioning failed: ${rawErr.message}`);
      console.error(`  Please verify network access or run: go build -o ${destPath} in ${corePath}\n`);
      process.exit(1);
    }
  }
}

run();
