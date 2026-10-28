// Builds the request path (proxy/, Go: Coraza with the OWASP Core Rule Set, ADR 0069) into vendor/waf-proxy. The Go
// toolchain is a pinned release, fetched into vendor/ and checked against the checksum kept here (ADR 0027); Coraza and
// the rule set are pinned by proxy/go.sum, which the Go checksum database vouches for. Tests run against the binary it
// builds, and the image is built with the same script, so they use the same proxy.
//
//   node scripts/proxy.ts                  # this machine, into vendor/waf-proxy
//   node scripts/proxy.ts linux arm64 out  # another platform, into out/waf-proxy
import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { existsSync, mkdirSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";

export const GO_VERSION = "go1.27.3";
/** sha256 of each toolchain archive, from https://go.dev/dl/?mode=json. Change with GO_VERSION. */
const SHA256: Record<string, string> = {
  "darwin-amd64": "b6f8e931e4ab497fcde6da8ae4499a58f9d258e55c8a80824a516eae5950a750",
  "darwin-arm64": "dd3908cf20959d798c1e06ebe5b72213f0505ce01373b40ce3110975a6cd99c2",
  "linux-amd64": "65efbc80fdc1fa2cd2631cad5b481777a68e8725f34e89f50fc6ac714e379b40",
  "linux-arm64": "a06e99309dbcbdca1a8ccd2282c3ee146e55930886e26b4f1193269587165f49",
};

const ARCH: Record<string, string> = { x64: "amd64", arm64: "arm64" };
const host = `${process.platform}-${ARCH[process.arch] ?? process.arch}`;
const vendor = new URL("../vendor", import.meta.url).pathname;
const source = new URL("../proxy", import.meta.url).pathname;
const [os = process.platform, arch = ARCH[process.arch] ?? process.arch, outDir = vendor] = process.argv.slice(2);
const target = `${os}-${arch}`;
const binary = join(outDir, "waf-proxy");
const stamp = join(outDir, "waf-proxy.version");

// The binary is built again when its sources, the toolchain or the platform change.
const hash = createHash("sha256").update(`${GO_VERSION} ${target}\n`);
for (const f of readdirSync(source).sort()) if (/\.(go|mod|sum)$/.test(f) && !f.endsWith("_test.go")) hash.update(f).update(readFileSync(join(source, f)));
const want = hash.digest("hex");
if (existsSync(binary) && existsSync(stamp) && readFileSync(stamp, "utf8").trim() === want) process.exit(0);

const goRoot = join(vendor, `${GO_VERSION}.${host}`);
const go = join(goRoot, "go", "bin", "go");
if (!existsSync(go)) {
  const sum = SHA256[host];
  if (!sum) {
    console.error(`No pinned checksum for Go ${GO_VERSION} on ${host}. Add it to scripts/proxy.ts.`);
    process.exit(1);
  }
  const name = `${GO_VERSION}.${host}.tar.gz`;
  const res = await fetch(`https://go.dev/dl/${name}`);
  if (!res.ok) throw new Error(`${name}: ${res.status}`);
  const archive = Buffer.from(await res.arrayBuffer());
  const got = createHash("sha256").update(archive).digest("hex");
  if (got !== sum) throw new Error(`${name}: sha256 is ${got}, expected ${sum}`);
  rmSync(goRoot, { recursive: true, force: true });
  mkdirSync(goRoot, { recursive: true });
  writeFileSync(join(goRoot, name), archive);
  execFileSync("tar", ["-xzf", join(goRoot, name), "-C", goRoot]);
  rmSync(join(goRoot, name));
}

mkdirSync(outDir, { recursive: true });
const env = {
  ...process.env,
  // Only the pinned toolchain, modules exactly as go.sum has them, and nothing of the machine's Go setup.
  GOTOOLCHAIN: "local",
  GOFLAGS: "-mod=readonly -trimpath",
  GOPATH: join(vendor, "gopath"),
  GOCACHE: join(vendor, "gocache"),
  GOOS: os,
  GOARCH: arch,
  CGO_ENABLED: "0",
};
execFileSync(go, ["vet", "./..."], { cwd: source, env: { ...env, GOOS: process.platform, GOARCH: ARCH[process.arch] ?? process.arch }, stdio: "inherit" });
execFileSync(go, ["build", "-ldflags=-s -w", "-o", binary, "."], { cwd: source, env, stdio: "inherit" });
writeFileSync(stamp, `${want}\n`);
console.log(`waf-proxy for ${target} in ${binary}`);
