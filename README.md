# scan-package-vulnerabilities


Scan Node.js project dependencies for known vulnerabilities, aggregating all occurrences of each package (by simplified name) and their version information.

## Overview

`scan-package-vulnerabilities` is a Node.js tool that analyzes a project's `package-lock.json` file to identify and report vulnerabilities in its dependencies. It collects all occurrences of each package (regardless of path), aggregates them under the simplified package name (without any path information), and lists all found versions and their full package paths. The vulnerability scan then checks for affected version numbers in the aggregated lists for each package name and generates a detailed report.

## Features

- Reads and parses `package-lock.json` from a Node.js project
- Aggregates all occurrences of each package (by simplified name) and their version information, including full package paths
- Checks all found versions for each package name against a list of known vulnerabilities
- Generates a report for each vulnerable package and a summary vulnerability report

## Usage

1. **Clone or download this repository.**
2. Place the `analyse-packages.js` script in your Node.js project directory (or ensure it can access your `package-lock.json`).
3. Run the script using Node.js, providing the path to your `package-lock.json` file as a required command-line argument:

	```sh
	node analyse-packages.js <path-to-package-lock.json>
	```

	For example, if your `package-lock.json` is in the current directory:

	```sh
	node analyse-packages.js package-lock.json
	```

	The script requires this parameter to locate and analyze your project's dependencies.

4. The script will output a list of all packages (grouped by simplified name) with their found versions and full package paths, followed by a vulnerability report based on the provided vulnerabilities list.

## Example Output

```
Aggregated packages:
Package           Versions
-------           --------
ansi-regex        node_modules/ansi-regex@6.2.1
ansi-styles       node_modules/ansi-styles@6.2.2
chalk             node_modules/chalk@5.6.1
color             node_modules/color@5.0.1
color-convert     node_modules/color-convert@3.1.1
color-name        node_modules/color-name@2.0.1
debug             node_modules/debug@4.4.2
error-ex          node_modules/error-ex@1.3.3
has-ansi          node_modules/has-ansi@6.0.1
is-arrayish       node_modules/is-arrayish@0.3.3
simple-swizzle    node_modules/simple-swizzle@0.2.3
slice-ansi        node_modules/slice-ansi@7.1.1
strip-ansi        node_modules/strip-ansi@7.1.1
supports-color    node_modules/supports-color@10.2.1
supports-hyperlinks node_modules/supports-hyperlinks@4.1.1
wrap-ansi         node_modules/wrap-ansi@9.0.1
chalk-template    node_modules/chalk-template@1.1.1
backslash         node_modules/backslash@0.2.1
proto-tinker-wc   node_modules/proto-tinker-wc@1.8.7
color-string      node_modules/color-string@2.1.1

================================================================================
VULNERABILITY ANALYSIS
================================================================================
Found 17 package(s) that are in the vulnerable packages list:

Package: ansi-regex
	Project versions: 6.2.1
	Vulnerable version: 6.2.1
	Is vulnerable version used: YES
	Vulnerable versions found: 6.2.1

Package: ansi-styles
	Project versions: 6.2.2
	Vulnerable version: 6.2.2
	Is vulnerable version used: YES
	Vulnerable versions found: 6.2.2

... (other packages omitted for brevity) ...

--------------------------------------------------------------------------------
VULNERABILITY SUMMARY
--------------------------------------------------------------------------------
❌ Found 17 vulnerable package(s):
	 - ansi-regex (using vulnerable version: 6.2.1)
	 - ansi-styles (using vulnerable version: 6.2.2)
	 - chalk (using vulnerable version: 5.6.1)
	 ... (other packages omitted for brevity) ...

🔧 Recommendation: Update the vulnerable packages to secure versions.
```

## Customizing the Vulnerabilities List

Edit the vulnerabilities list in the script or provide your own list as needed. The script will check all dependencies against this list.

## License

See [LICENSE](LICENSE) for details.
