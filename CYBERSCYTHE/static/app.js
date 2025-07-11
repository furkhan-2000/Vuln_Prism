async function startScan() {
    const url = document.getElementById("url").value;
    document.getElementById("output").innerHTML = "Scanning...";
    try {
        const res = await fetch(`/scan?url=${encodeURIComponent(url)}`);
        const data = await res.json();
        if (data.report) {
            document.getElementById("output").innerHTML = `<p>Scan complete. <a href="${data.report}" target="_blank">Download Report</a></p>`;
        } else {
            document.getElementById("output").innerHTML = `<p>Error: ${data.error}</p>`;
        }
    } catch (err) {
        document.getElementById("output").innerHTML = `<p>Scan failed: ${err.message}</p>`;
    }
}
