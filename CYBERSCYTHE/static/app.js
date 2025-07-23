console.log("🚀 CyberScythe Frontend JavaScript Loaded");

document.getElementById("scan-button").addEventListener("click", startScan);
console.log("✅ Event listener attached to scan button");

async function startScan() {
    console.log("🔍 startScan() function called");

    const url = document.getElementById("url").value;
    const output = document.getElementById("output");

    console.log("📊 Input values:");
    console.log("  - URL:", url);
    console.log("  - Output element:", output);

    if (!url) {
        console.log("❌ No URL provided");
        output.innerHTML = `<div class="error">Please enter a URL to scan.</div>`;
        return;
    }

    console.log("✅ URL validation passed");
    output.innerHTML = `<div class="scanning">Queuing scan... <div class="spinner"></div></div>`;

    try {
        console.log("📤 Sending POST request to /scan");
        console.log("  - URL:", url);
        console.log("  - Method: POST");
        console.log("  - Headers: Content-Type: application/json");

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
        console.log("  - Headers:", Object.fromEntries(res.headers.entries()));

        const data = await res.json();
        console.log("  - Response Data:", data);

        if (data.scan_id) {
            const scan_id = data.scan_id;
            console.log("✅ Scan initiated successfully with ID:", scan_id);
            output.innerHTML = `<div class="scanning">Scan in progress (ID: ${scan_id})... <div class="spinner"></div></div>`;
            pollStatus(scan_id);
        } else {
            console.log("❌ No scan_id in response");
            output.innerHTML = `<div class="error">Error starting scan: ${data.error || 'Unknown error'}</div>`;
        }
    } catch (err) {
        console.error("💥 Error in startScan():", err);
        output.innerHTML = `<div class="error">Failed to start scan: ${err.message}</div>`;
    }
}

async function pollStatus(scan_id) {
    console.log("📊 Starting status polling for scan ID:", scan_id);
    const output = document.getElementById("output");
    let pollCount = 0;

    const interval = setInterval(async () => {
        pollCount++;
        console.log(`📡 Status poll #${pollCount} for scan ID: ${scan_id}`);

        try {
            const res = await fetch(`./status/${scan_id}`);
            console.log("📥 Status response:");
            console.log("  - Status:", res.status);
            console.log("  - Status Text:", res.statusText);

            if (!res.ok) {
                console.error("❌ Status request failed");
                clearInterval(interval);
                output.innerHTML = `<div class="error">Error fetching status for scan ${scan_id}.</div>`;
                return;
            }

            const data = await res.json();
            console.log("  - Status Data:", data);

            // Update UI with the latest status message
            if (data.message) {
                console.log("📝 Updating UI with message:", data.message);
                output.innerHTML = `<div class="scanning">${data.message} <div class="spinner"></div></div>`;
            }

            if (data.status === 'complete') {
                console.log("🎉 Scan completed successfully!");
                clearInterval(interval);
                output.innerHTML = `
                    <div class="success">
                        <p>Scan complete!</p>
                        <a href="${data.report_path}" target="_blank" class="report-link">
                            Download Report
                        </a>
                    </div>
                `;
            } else if (data.status === 'error') {
                console.error("❌ Scan failed with error:", data.message);
                clearInterval(interval);
                output.innerHTML = `<div class="error">Scan failed: ${data.message || 'An unknown error occurred.'}</div>`;
            } else {
                console.log("⏳ Scan still in progress, status:", data.status);
            }
        } catch (err) {
            console.error("💥 Error in pollStatus():", err);
            clearInterval(interval);
            output.innerHTML = `<div class="error">Error polling for status: ${err.message}</div>`;
        }
    }, 3000); // Poll every 3 seconds

    console.log("✅ Status polling interval started (every 3 seconds)");
}
