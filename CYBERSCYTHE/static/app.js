async function startScan() {
    const url = document.getElementById("url").value;
    const output = document.getElementById("output");
    output.innerHTML = "<div class='scanning'>Scanning... <div class='spinner'></div></div>";
    
    try {
        const res = await fetch(`/scan?url=${encodeURIComponent(url)}`);
        const data = await res.json();
        if (data.report) {
            output.innerHTML = `
                <div class="success">
                    <p>Scan complete!</p>
                    <a href="${data.report}" target="_blank" class="report-link">
                        Download Report
                    </a>
                </div>
            `;
        } else {
            output.innerHTML = `<div class="error">Error: ${data.error || 'Unknown error'}</div>`;
        }
    } catch (err) {
        output.innerHTML = `<div class="error">Scan failed: ${err.message}</div>`;
    }
}
