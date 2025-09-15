#!/usr/bin/env node

/**
 * Node.js script to read a package-lock.json file and extract:
 * Alphabetically sorted table of all packages (from both first-level and second-level dependencies)
 * with all encountered version numbers aggregated with counts.
 * Additionally performs vulnerability checking against known vulnerable packages.
 *
 * Usage:
 *   node extract-lock.js <path-to-package-lock.json>
 */

"use strict";

const fs = require("fs");
const path = require("path");

const vulnerablePackages = {
  "ansi-styles": "6.2.2",
  "debug": "4.4.2",
  "chalk": "5.6.1",
  "supports-color": "10.2.1",
  "strip-ansi": "7.1.1",
  "ansi-regex": "6.2.1",
  "wrap-ansi": "9.0.1",
  "color-convert": "3.1.1",
  "color-name": "2.0.1",
  "is-arrayish": "0.3.3",
  "slice-ansi": "7.1.1",
  "color": "5.0.1",
  "color-string": "2.1.1",
  "simple-swizzle": "0.2.3",
  "supports-hyperlinks": "4.1.1",
  "has-ansi": "6.0.1",
  "chalk-template": "1.1.1",
  "backslash": "0.2.1",
  "error-ex": "1.3.3",
  "proto-tinker-wc": "1.8.7",
};

function usage() {
  console.error("Usage: node extract-lock.js <path-to-package-lock.json>");
  process.exit(1);
}

const file = process.argv[2];
if (!file) usage();

// Read file
let content;
try {
  content = fs.readFileSync(file, "utf8");
} catch (err) {
  console.error(`Error reading file "${file}": ${err.message}`);
  process.exit(1);
}

// Parse JSON
let data;
try {
  data = JSON.parse(content);
} catch (err) {
  console.error(`Error parsing JSON: ${err.message}`);
  process.exit(1);
}

// Validate structure
if (
  !data ||
  typeof data !== "object" ||
  !data.packages ||
  typeof data.packages !== "object"
) {
  console.error(
    'Invalid package-lock.json format: "packages" object not found at top level.'
  );
  process.exit(1);
}

const packages = data.packages;

// Helper function to extract package name from path
function extractPackageName(pkgPath) {
  if (!pkgPath || pkgPath === "") return pkgPath;
  // Split by forward slashes and get the last part
  const parts = pkgPath.split('/');
  return parts[parts.length - 1];
}

// Helper function to remove the 'node_modules/' prefix if present
function stripNodeModulesPrefix(pkgPath) {
  if (pkgPath.startsWith("node_modules/")) {
    return pkgPath.slice("node_modules/".length);
  } 
  return pkgPath;
}

// Aggregate all packages and their versions
const allPackagesMap = new Map(); // packageName -> array of version strings encountered

// Collect first-level packages (omit the root package with empty name "")
for (const [pkgName, pkgInfo] of Object.entries(packages)) {
  if (pkgName === "") continue; // omit project itself
  if (!pkgInfo || typeof pkgInfo !== "object") continue;
  const version =
    pkgInfo.version !== undefined && pkgInfo.version !== null
      ? String(pkgInfo.version)
      : "";
  const simpleName = extractPackageName(pkgName);
  if (!allPackagesMap.has(simpleName)) allPackagesMap.set(simpleName, [{name: pkgName, version: version}]);
  allPackagesMap.get(simpleName).push({name: pkgName, version: version});
}

// Prepare aggregated package rows
const packageNames = Array.from(allPackagesMap.keys()).sort((a, b) =>
  a.localeCompare(b, undefined, { sensitivity: "base" })
);

function formatVersions(versionsArray) {
  // versionsArray is an array of objects: { name, version }
  const counts = new Map();
  for (const obj of versionsArray) {
    if (!obj || typeof obj !== "object") continue;
    const shortName = stripNodeModulesPrefix(obj.name || "");
    const version = obj.version || "";
    const key = `${shortName}@${version}`;
    counts.set(key, (counts.get(key) || 0) + 1);
  }
  const entries = Array.from(counts.entries()).sort((a, b) =>
    a[0].localeCompare(b[0], undefined, { sensitivity: "base" })
  );
  return entries
    .map(([pkgVer, count]) => (count > 1 ? `${pkgVer} x${count}` : pkgVer))
    .join(", ");
}

const aggregatedRows = packageNames.map((name) => ({
  name,
  versions: formatVersions(allPackagesMap.get(name)),
}));

// Output
console.log("Aggregated packages:");
if (aggregatedRows.length === 0) {
  console.log("(none)");
} else {
  // Custom print to label columns Package / Versions
  const col1Width = Math.max(
    "Package".length,
    ...aggregatedRows.map((r) => r.name.length)
  );
  const col2Width = Math.max(
    "Versions".length,
    ...aggregatedRows.map((r) => r.versions.length)
  );
  console.log(
    `${"Package".padEnd(col1Width)}  ${"Versions".padEnd(col2Width)}`
  );
  console.log(`${"-".repeat(col1Width)}  ${"-".repeat(col2Width)}`);
  for (const r of aggregatedRows) {
    console.log(`${r.name.padEnd(col1Width)}  ${r.versions.padEnd(col2Width)}`);
  }
}

console.log("");
console.log("=".repeat(80));
console.log("VULNERABILITY ANALYSIS");
console.log("=".repeat(80));

// Vulnerability checking
function getUniqueVersions(versionsArray) {
  // versionsArray is an array of objects: { name, version }
  const unique = new Set();
  for (const obj of versionsArray) {
    if (!obj || typeof obj !== "object") continue;
    const shortName = stripNodeModulesPrefix(obj.name || "");
    const version = obj.version || "";
    if (shortName && version) {
      unique.add(version);
    }
  }
  return Array.from(unique).sort((a, b) =>
    a.localeCompare(b, undefined, { sensitivity: "base" })
  );
}

function isVulnerableVersion(packageVersion, vulnerableVersion) {
  // Simple exact match for now - could be extended for version range checking
  return packageVersion === vulnerableVersion;
}

const vulnerabilityReports = [];
const vulnerablePackagesFound = [];

// Check each package against the vulnerable packages list
for (const [packageName, versionsArray] of allPackagesMap.entries()) {
  if (vulnerablePackages.hasOwnProperty(packageName)) {
    const uniqueVersions = getUniqueVersions(versionsArray);
    const vulnerableVersion = vulnerablePackages[packageName];
    const isVulnerable = uniqueVersions.some(v => isVulnerableVersion(v, vulnerableVersion));

    const report = {
      packageName,
      projectVersions: uniqueVersions,
      vulnerableVersion,
      isVulnerable,
      vulnerableVersionsUsed: uniqueVersions.filter(v => isVulnerableVersion(v, vulnerableVersion))
    };

    vulnerabilityReports.push(report);

    if (isVulnerable) {
      vulnerablePackagesFound.push(packageName);
    }
  }
}

// Sort vulnerability reports by package name
vulnerabilityReports.sort((a, b) =>
  a.packageName.localeCompare(b.packageName, undefined, { sensitivity: "base" })
);

// Output vulnerability reports
if (vulnerabilityReports.length === 0) {
  console.log("No packages found that are in the vulnerable packages list.");
} else {
  console.log(`Found ${vulnerabilityReports.length} package(s) that are in the vulnerable packages list:\n`);

  for (const report of vulnerabilityReports) {
    console.log(`Package: ${report.packageName}`);
    console.log(`  Project versions: ${report.projectVersions.join(", ")}`);
    console.log(`  Vulnerable version: ${report.vulnerableVersion}`);
    console.log(`  Is vulnerable version used: ${report.isVulnerable ? "YES" : "NO"}`);
    if (report.isVulnerable) {
      console.log(`  Vulnerable versions found: ${report.vulnerableVersionsUsed.join(", ")}`);
    }
    console.log("");
  }
}

// Summary
console.log("-".repeat(80));
console.log("VULNERABILITY SUMMARY");
console.log("-".repeat(80));

if (vulnerablePackagesFound.length === 0) {
  console.log("✅ No vulnerable packages detected in this project.");
} else {
  console.log(`❌ Found ${vulnerablePackagesFound.length} vulnerable package(s):`);
  for (const pkgName of vulnerablePackagesFound.sort()) {
    const report = vulnerabilityReports.find(r => r.packageName === pkgName);
    console.log(`   - ${pkgName} (using vulnerable version: ${report.vulnerableVersionsUsed.join(", ")})`);
  }
  console.log("");
  console.log("🔧 Recommendation: Update the vulnerable packages to secure versions.");
}
