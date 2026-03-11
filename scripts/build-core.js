/***************************************************************************
 * XyPriss Security - Unified Core Provisioner (Download Only)
 * Optimized for production deployments (no Go required).
 ****************************************************************************/

const path = require("path");
const fs = require("fs");
const https = require("https");

const corePath = path.join(__dirname, "../lib/security-core");
const platform = process.platform;
const arch = process.arch;

let extension = "";
if (platform === "win32") extension = ".exe";

const outFile = `libxypriss_core${extension}`;
const destPath = path.join(corePath, outFile);

// Ensure directory exists
if (!fs.existsSync(corePath)) {
  fs.mkdirSync(corePath, { recursive: true });
}

// Professional OS/Arch labels for release assets
const osLabel =
  platform === "win32" ? "windows" : platform === "darwin" ? "darwin" : "linux";
const archLabel = arch === "x64" ? "amd64" : arch === "arm64" ? "arm64" : arch;

const releaseFileName = `libxypriss_core-${osLabel}-${archLabel}${extension}`;
// Always target the latest release download
const releaseUrl = `https://github.com/Nehonix-Team/XyPriss-Security/releases/latest/download/${releaseFileName}`;

console.log(`\n🛡️  XyPriss Core Provisioning [${osLabel}-${archLabel}]...`);

/**
 * Downloads the pre-built binary from GitHub Releases
 */
function downloadBinary(url = releaseUrl) {
  console.log(`📡 Attempting to download: ${path.basename(url)}`);

  return new Promise((resolve, reject) => {
    const request = https.get(url, (response) => {
      // Handle redirects (GitHub often redirects to objects.githubusercontent.com)
      if (
        response.statusCode >= 300 &&
        response.statusCode < 400 &&
        response.headers.location
      ) {
        return downloadBinary(response.headers.location)
          .then(resolve)
          .catch(reject);
      }

      if (response.statusCode !== 200) {
        reject(
          new Error(`Failed to download binary: HTTP ${response.statusCode}`),
        );
        return;
      }

      const file = fs.createWriteStream(destPath);
      response.pipe(file);
      file.on("finish", () => {
        file.close();
        if (platform !== "win32") fs.chmodSync(destPath, 0o755);
        console.log(`✅ Binary successfully installed to ${outFile}`);
        resolve();
      });
    });

    request.on("error", reject);
  });
}

async function run() {
  try {
    await downloadBinary();
    console.log(`\n✅ Ready for high-performance operations.\n`);
    process.exit(0);
  } catch (error) {
    console.error(`\n❌ Provisioning failed: ${error.message}`);
    console.error(
      `ℹ️  Please check your internet connection or manually install the core at ${outFile}.\n`,
    );
    process.exit(1);
  }
}

run();
