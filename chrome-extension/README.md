# BreakSmith Chrome Extension

Zero-dependency Manifest V3 extension with two scan modes:

- **Live page scan:** checks the active URL, response security headers, forms, mixed content, and third-party scripts. Runs locally and requires no database.
- **Repository scan:** appears automatically on public GitHub repository pages and calls the existing BreakSmith `POST /api/scan` endpoint.

## Install

1. Open `chrome://extensions`.
2. Enable **Developer mode**.
3. Click **Load unpacked**.
4. Select this `chrome-extension` directory.
5. Pin BreakSmith to the toolbar.

For GitHub repository scans, run BreakSmith with `npm run dev`. The default API URL is `http://localhost:3000`; change it in the extension after deployment.

## Live scan limitations

The live scan only sees browser-visible information. It cannot inspect server source code, database permissions, internal authorization logic, or vulnerabilities that require authenticated penetration testing. Results are held in memory unless the user exports JSON.
