/***************************************************************************
 * XyPriss Security - Unified Core Provisioner (Build or Download)
 ****************************************************************************/

const { spawnSync } = require("child_process");
const path = require("path");
const fs = require("fs");
const https = require("https");

const corePath = path.join(__dirname, "../lib/security-core");
const platform = process.platform;
const arch = process.arch;

let extension = ".so";
if (platform === "win32") extension = ".dll";
if (platform === "darwin") extension = ".dylib";

const outFile = `libxypriss_core${extension}`;
const destPath = path.join(corePath, outFile);

// Professional OS/Arch labels for release assets
const osLabel =
  platform === "win32" ? "windows" : platform === "darwin" ? "macos" : "linux";
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

/**
 * Builds the core from source using Go
 */
function buildFromSource() {
  console.log(`\n🚀 Attempting to build from source...`);

  // Check if Go is installed
  const goCheck = spawnSync("go", ["version"]);
  if (goCheck.status !== 0) {
    console.log("⚠️  Go (golang) not found in PATH.");
    return false;
  }

  const buildArgs = ["build", "-o", outFile, "-buildmode=c-shared", "main.go"];

  console.log(`🔨 Executing: go ${buildArgs.join(" ")}`);

  const build = spawnSync("go", buildArgs, {
    cwd: corePath,
    stdio: "inherit",
  });

  return build.status === 0;
}

async function run() {
  // 1. Try to build from source (Preferred for optimization)
  if (buildFromSource()) {
    console.log(`\n✅ Core built successfully from source.\n`);
    return;
  }

  // 2. Build failed or Go missing, try downloading
  try {
    await downloadBinary();
    console.log(`\n✅ Ready for high-performance operations.\n`);
  } catch (error) {
    console.error(`\n❌ Provisioning failed: ${error.message}`);
    console.error(
      `ℹ️  Please ensure you have Go installed or check your internet connection.\n`,
    );
    process.exit(1);
  }
}

run();
