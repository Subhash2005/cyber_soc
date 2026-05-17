const ws = new WebSocket('ws://localhost:8001/ws');

const logsBody = document.getElementById('logs-body');
const alertsContainer = document.getElementById('alerts-container');
const eventsCountEl = document.getElementById('events-count');
const threatsCountEl = document.getElementById('threats-count');

let eventsCount = 0;
let threatsCount = 0;

ws.onopen = () => {
    console.log("Connected to AI SOC Backend");
};

ws.onmessage = (event) => {
    const data = JSON.parse(event.data);
    
    if (data.type === 'log') {
        handleNewLog(data.event);
    } else if (data.type === 'alert') {
        handleNewAlert(data);
    }
};

function handleNewLog(log) {
    eventsCount++;
    eventsCountEl.textContent = eventsCount;
    
    const row = document.createElement('tr');
    
    // Format time
    const time = new Date(log.timestamp).toLocaleTimeString();
    
    row.innerHTML = `
        <td>${time}</td>
        <td><strong>${log.user}</strong></td>
        <td>${log.ip_address}</td>
        <td>${log.location}</td>
        <td><span class="badge success">Allowed</span></td>
    `;
    
    // Add to top of table
    logsBody.insertBefore(row, logsBody.firstChild);
    
    // Keep only last 20 logs in UI
    if (logsBody.children.length > 20) {
        logsBody.removeChild(logsBody.lastChild);
    }
}

function handleNewAlert(alert) {
    eventsCount++;
    eventsCountEl.textContent = eventsCount;
    
    threatsCount++;
    threatsCountEl.textContent = threatsCount;
    
    // Also add to the normal logs table but marked as Blocked
    const row = document.createElement('tr');
    const time = new Date(alert.event.timestamp).toLocaleTimeString();
    row.innerHTML = `
        <td>${time}</td>
        <td><strong>${alert.event.user}</strong></td>
        <td>${alert.event.ip_address}</td>
        <td>${alert.event.location}</td>
        <td><span class="badge danger">Blocked</span></td>
    `;
    row.style.backgroundColor = 'rgba(239, 68, 68, 0.1)';
    logsBody.insertBefore(row, logsBody.firstChild);

    // Remove empty state if present
    const emptyState = alertsContainer.querySelector('.empty-state');
    if (emptyState) {
        emptyState.remove();
    }
    
    // Create Alert Card
    const card = document.createElement('div');
    card.className = 'alert-card';
    
    const analysis = alert.analysis;
    
    card.innerHTML = `
        <div class="alert-header">
            <h3>🚨 AI Threat Detection</h3>
            <span class="alert-time">${time}</span>
        </div>
        <div class="alert-body">
            <p><strong>Target User:</strong> ${alert.event.user}</p>
            <p><strong>Trigger Location:</strong> ${alert.event.location} (${alert.event.ip_address})</p>
            <p><strong>AI Reasoning:</strong> ${analysis.reasoning}</p>
            <div class="action-taken">${alert.action_taken}</div>
        </div>
    `;
    
    alertsContainer.insertBefore(card, alertsContainer.firstChild);
}

ws.onerror = (error) => {
    console.error("WebSocket Error:", error);
};

ws.onclose = () => {
    console.log("WebSocket connection closed. Reconnecting in 5s...");
    // Simple reconnect logic could go here
};
