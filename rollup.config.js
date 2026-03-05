import typescript from "@rollup/plugin-typescript";
import resolve from "@rollup/plugin-node-resolve";
import commonjs from "@rollup/plugin-commonjs";
import json from "@rollup/plugin-json";
import dts from "rollup-plugin-dts";
import { readFileSync, writeFileSync, mkdirSync } from "fs";
import { dirname } from "path";

const pkg = JSON.parse(
  readFileSync(new URL("./package.json", import.meta.url), "utf8"),
);

function copyPackageJson(type, dir) {
  return {
    name: "copy-package-json",
    generateBundle() {
      const packageJsonContent = JSON.stringify({ type }, null, 2);
      const outputPath = `${dir}/package.json`;
      try {
        mkdirSync(dirname(outputPath), { recursive: true });
        writeFileSync(outputPath, packageJsonContent);
        console.log(`✅ Created ${outputPath} with type: ${type}`);
      } catch (error) {
        console.warn(`⚠️ Failed to create ${outputPath}:`, error.message);
      }
    },
  };
}

const nodeBuiltins = [
  "crypto",
  "fs",
  "path",
  "os",
  "http",
  "https",
  "events",
  "stream",
  "buffer",
  "util",
  "url",
  "querystring",
  "zlib",
  "child_process",
  "cluster",
  "dgram",
  "dns",
  "net",
  "tls",
  "readline",
  "repl",
  "vm",
  "worker_threads",
  "perf_hooks",
];

function makeExternal(id) {
  if (id.startsWith("node:")) return true;
  if (nodeBuiltins.includes(id)) return true;
  if (id.includes("node_modules")) return true;
  const allDeps = [
    ...Object.keys(pkg.dependencies || {}),
    ...Object.keys(pkg.peerDependencies || {}),
  ];
  if (allDeps.some((dep) => id === dep || id.startsWith(dep + "/")))
    return true;
  return false;
}

function tsPlugin() {
  return typescript({
    tsconfig: "./tsconfig.json",
    declaration: false,
    declarationMap: false,
    outDir: undefined,
    exclude: [
      "/private/**",
      "**/private/*",
      "src/integrations/react/**/*",
      "**/private/**/*",
      "**/node_modules/**/*",
      "**/*.test.ts",
      "**/*.spec.ts",
    ],
  });
}

// resolveOnly prevents @rollup/plugin-node-resolve from trying to resolve
// the package itself via its own "main"/"module" fields in package.json,
// which would attempt to open dist/esm/index.js before it exists.
function resolvePlugin() {
  return resolve({
    preferBuiltins: true,
    browser: false,
    exportConditions: ["node"],
    resolveOnly: (module) => !module.includes(pkg.name),
  });
}

// ignoreDynamicRequires + ignore(self) stops commonjs-resolver from
// walking into the root package.json and chasing the "main" field.
function commonjsPlugin() {
  return commonjs({
    transformMixedEsModules: true,
    ignoreDynamicRequires: true,
    ignore: (id) => id.includes(pkg.name),
  });
}

export default [
  // ESM build
  {
    input: "./src/index.ts",
    output: {
      dir: "./dist/esm",
      format: "es",
      sourcemap: true,
      exports: "named",
      preserveModules: true,
      preserveModulesRoot: "src",
    },
    external: makeExternal,
    plugins: [
      resolvePlugin(),
      commonjsPlugin(),
      json(),
      tsPlugin(),
      copyPackageJson("module", "./dist/esm"),
    ],
  },

  // CJS build
  {
    input: "./src/index.ts",
    output: {
      dir: "./dist/cjs",
      format: "cjs",
      sourcemap: true,
      exports: "auto",
      esModule: false,
      preserveModules: true,
      preserveModulesRoot: "src",
    },
    external: makeExternal,
    plugins: [
      resolvePlugin(),
      commonjsPlugin(),
      json(),
      tsPlugin(),
      copyPackageJson("commonjs", "./dist/cjs"),
    ],
  },

  // TypeScript declarations
  {
    input: "./src/index.ts",
    output: {
      file: "./dist/index.d.ts",
      format: "es",
    },
    plugins: [dts()],
    external: ["nehonix-uri-processor"],
  },
];
