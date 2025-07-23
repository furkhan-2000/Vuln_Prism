console.log("🚀 CyberScythe Frontend JavaScript Loaded");

document.getElementById("scan-button").addEventListener("click", startScan);
console.log("✅ Event listener attached to scan button");

function displayResults(data) {
    const output = document.getElementById("output");

    if (data.detail) {
        output.innerHTML = `<div class="error">Error: ${data.detail}</div>`;
        return;
    }

    if (data.error_count > 0) {
        output.innerHTML = `<div class="error">Scan completed with ${data.error_count} errors. Please check the service logs for details.</div>`;
        return;
    }

    if (data.vuln_count === 0) {
        output.innerHTML = `<div class="success">Scan complete. No vulnerabilities found for ${data.url}. Scanned ${data.scanned_urls} URLs.</div>`;
        return;
    }

    let html = `
        <div class="success">
            Found ${data.vuln_count} vulnerabilities at ${data.url}. Scanned ${data.scanned_urls} URLs.
        </div>
        <div class="mt-4 overflow-x-auto rounded-lg border border-gray-700">
            <table class="min-w-full bg-gray-900/50 text-white">
                <thead class="bg-gray-800/80">
                    <tr>
                        <th class="py-3 px-4 text-left text-sm font-semibold uppercase tracking-wider">Type</th>
                        <th class="py-3 px-4 text-left text-sm font-semibold uppercase tracking-wider">URL</th>
                        <th class="py-3 px-4 text-left text-sm font-semibold uppercase tracking-wider">Parameter/Location</th>
                        <th class="py-3 px-4 text-left text-sm font-semibold uppercase tracking-wider">Severity</th>
                        <th class="py-3 px-4 text-left text-sm font-semibold uppercase tracking-wider">Description</th>
                    </tr>
                </thead>
                <tbody class="divide-y divide-gray-700">
                    ${data.vulnerabilities.map(vuln => `
                        <tr class="hover:bg-gray-800/50 transition-colors duration-200">
                            <td class="py-3 px-4 font-mono text-sm text-red-400">${vuln.type}</td>
                            <td class="py-3 px-4 text-sm break-all">${vuln.url}</td>
                            <td class="py-3 px-4 text-sm">${vuln.param}</td>
                            <td class="py-3 px-4 text-sm text-yellow-400">${vuln.severity || 'N/A'}</td>
                            <td class="py-3 px-4 text-sm">${vuln.description || 'No description available.'}</td>
                        </tr>
                    `).join('')}
                </tbody>
            </table>
        </div>
    `;
    output.innerHTML = html;
}


async function startScan() {
    console.log("🔍 startScan() function called");

    const urlInput = document.getElementById("url");
    const url = urlInput.value;
    const output = document.getElementById("output");

    console.log("📊 Input values:");
    console.log("  - URL:", url);

    if (!url || !url.startsWith('http')) {
        console.log("❌ Invalid URL provided");
        output.innerHTML = `<div class="error">Please enter a valid URL (e.g., http://example.com) to scan.</div>`;
        return;
    }

    console.log("✅ URL validation passed");
    output.innerHTML = `<div class="scanning">Scan in progress for ${url}... <div class="spinner"></div></div>`;

    try {
        console.log("📤 Sending POST request to /scan");
        const requestBody = JSON.stringify({ url });
        console.log("  - Body:", requestBody);

        const res = await fetch(`./scan`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: requestBody
        });

        console.log("📥 Response received:");
        console.log("  - Status:", res.status);
        console.log("  - Status Text:", res.statusText);

        if (!res.ok) {
            const errorData = await res.json();
            throw new Error(errorData.detail || `Scan failed with status: ${res.status}`);
        }

        // Check if response is PDF or JSON
        const contentType = res.headers.get('content-type');
        console.log("  - Content Type:", contentType);

        if (contentType && contentType.includes('application/pdf')) {
            // Handle PDF download
            console.log("✅ Response is PDF - processing download");
            output.innerHTML = `<div class="success">Scan complete! Downloading report...</div>`;

            const blob = await res.blob();
            console.log("📄 PDF blob received, size:", blob.size, "bytes");

            const downloadUrl = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = downloadUrl;
            a.download = 'VulnPrism_CyberScythe_Report.pdf';
            document.body.appendChild(a);
            a.click();
            window.URL.revokeObjectURL(downloadUrl);
            document.body.removeChild(a);

            output.innerHTML = `<div class="success">✅ Scan completed successfully! PDF report downloaded.<br><br>Check your downloads folder for the detailed vulnerability report.</div>`;
        } else {
            // Handle JSON fallback
            console.log("📋 Response is JSON - processing data");
            const data = await res.json();
            console.log("  - Response Data:", data);
            displayResults(data);
        }

    } catch (err) {
        console.error("💥 Error in startScan():", err);
        output.innerHTML = `<div class="error">Failed to execute scan: ${err.message}</div>`;
    }
}