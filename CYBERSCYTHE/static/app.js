async function startScan() {
    const url = document.getElementById("url").value;
    const output = document.getElementById("output");

    if (!url) {
        output.innerHTML = `<div class="error">Please enter a URL to scan.</div>`;
        return;
    }

    output.innerHTML = `<div class="scanning">Queuing scan... <div class="spinner"></div></div>`;

    try {
        // Use POST for the scan endpoint now
        const res = await fetch(`/scan?url=${encodeURIComponent(url)}`, { method: 'POST' });
        const data = await res.json();

        if (data.scan_id) {
            const scan_id = data.scan_id;
            output.innerHTML = `<div class="scanning">Scan in progress (ID: ${scan_id})... <div class="spinner"></div></div>`;
            pollStatus(scan_id);
        } else {
            output.innerHTML = `<div class="error">Error starting scan: ${data.error || 'Unknown error'}</div>`;
        }
    } catch (err) {
        output.innerHTML = `<div class="error">Failed to start scan: ${err.message}</div>`;
    }
}

async function pollStatus(scan_id) {
    const output = document.getElementById("output");
    const interval = setInterval(async () => {
        try {
            const res = await fetch(`/status/${scan_id}`);
            if (!res.ok) {
                clearInterval(interval);
                output.innerHTML = `<div class="error">Error fetching status for scan ${scan_id}.</div>`;
                return;
            }
            const data = await res.json();

            // Update UI with the latest status message
            if (data.message) {
                output.innerHTML = `<div class="scanning">${data.message} <div class="spinner"></div></div>`;
            }

            if (data.status === 'complete') {
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
                clearInterval(interval);
                output.innerHTML = `<div class="error">Scan failed: ${data.message || 'An unknown error occurred.'}</div>`;
            }
        } catch (err) {
            clearInterval(interval);
            output.innerHTML = `<div class="error">Error polling for status: ${err.message}</div>`;
        }
    }, 3000); // Poll every 3 seconds
}
