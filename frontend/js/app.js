const API_URL = 'http://localhost:8000/api';


async function fetchMetricsTimeline() {
    try {
        const statsRes = await fetch(`${API_URL}/dashboard-stats`);
        const stats = await statsRes.json();
        document.getElementById('attacks-count').innerText = stats.total_attacks;
        document.getElementById('blocked-count').innerText = stats.total_blocked;

        const logsRes = await fetch(`${API_URL}/logs`);
        const logs = await logsRes.json();
        const tbody = document.getElementById('logs-table-body');
        tbody.innerHTML = "";

        logs.forEach(record => {
            const row = document.createElement('tr');
            row.innerHTML = `
                <td>${record.detected_at}</td>
                <td><b>${record.ip_address}</b></td>
                <td><span style="color:#f59e0b; font-weight:bold;">${record.attack_type}</span></td>
                <td><code>${escapeHTML(record.payload || 'N/A')}</code></td>
                <td><button class="btn-unblock" onclick="triggerUnblock('${record.ip_address}')">Lift Block</button></td>
            `;
            tbody.appendChild(row);
        });
    } catch (error) {
        console.error("Dashboard engine asynchronous fetch loop failure:", error);
    }
}

async function triggerUnblock(ip) {
    if(confirm(`Remove target rule mitigations completely from IP address: ${ip}?`)) {
        await fetch(`${API_URL}/unblock/${ip}`, { method: 'POST' });
        fetchMetricsTimeline();
    }
}

function escapeHTML(str) {
    return str.replace(/[&<>'"]/g,
        tag => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', "'": '&#39;', '"': '&quot;' }[tag] || tag)
    );
}

// Initial fire & background refresh loop settings
fetchMetricsTimeline();
setInterval(fetchMetricsTimeline, 3000);
