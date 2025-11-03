class LiveGuardDashboard {
    constructor() {
        this.socket = io();
        this.packetChart = null;
        this.packetData = {
            labels: [],
            datasets: [{
                label: 'Packets per Second',
                data: [],
                borderColor: 'rgb(59, 130, 246)',
                backgroundColor: 'rgba(59, 130, 246, 0.1)',
                tension: 0.4,
                fill: true
            }]
        };

        this.init();
    }

    init() {
        this.initializeChart();
        this.setupSocketListeners();
        this.setupEventHandlers();
        this.loadInitialData();
    }


    initializeChart() {
        const ctx = document.getElementById('packetChart').getContext('2d');

        this.packetData = {
            labels: [],
            datasets: [{
                label: 'Packets per Second',
                data: [],
                borderColor: 'rgb(59, 130, 246)',
                backgroundColor: 'rgba(59, 130, 246, 0.1)',
                tension: 0.4,
                fill: true,
                borderWidth: 2
            }]
        };

        this.packetChart = new Chart(ctx, {
            type: 'line',
            data: this.packetData,
            options: {
                responsive: true,
                maintainAspectRatio: false,
                animation: false,
                scales: {
                    y: {
                        beginAtZero: true,
                        min: 0,
                        max: 10, // FIXED Y-AXIS RANGE
                        title: {
                            display: true,
                            text: 'Packets/Sec'
                        },
                        ticks: {
                            stepSize: 2 // Fixed intervals: 0, 2, 4, 6, 8, 10
                        }
                    },
                    x: {
                        title: {
                            display: true,
                            text: 'Time'
                        },
                        ticks: {
                            maxTicksLimit: 8 // Limited number of labels
                        }
                    }
                },
                plugins: {
                    legend: {
                        display: false
                    }
                },
                elements: {
                    point: {
                        radius: 0
                    }
                }
            }
        });
    }
    setupSocketListeners() {
        // Handle connection acknowledgement
        this.socket.on('connection_ack', (data) => {
            console.log('Connected to LiveGuard:', data.message);
            this.updateCaptureStatus(data.is_capturing);
        });

        // Handle new packets
        this.socket.on('new_packet', (packet) => {
            this.addPacketToTable(packet);
        });

        // Handle new threats
        this.socket.on('new_threat', (threat) => {
            this.displayThreat(threat);
        });

        // Handle new alerts
        this.socket.on('new_alert', (alertData) => {
            this.displayAlert(alertData);
        });

        // Handle stats updates
        this.socket.on('stats_update', (stats) => {
            this.updateStats(stats);
            this.updateChart(stats.packets_per_second);
        });
    }

    setupEventHandlers() {
        document.getElementById('toggleCapture').addEventListener('click', () => {
            this.toggleCapture();
        });
    }

    async loadInitialData() {
        try {
            // Load initial alerts
            const alertsResponse = await fetch('/api/alerts');
            const alerts = await alertsResponse.json();
            alerts.forEach(alert => this.displayAlert({ alert }));

            // Load initial threats
            const threatsResponse = await fetch('/api/threats');
            const threats = await threatsResponse.json();
            threats.forEach(threat => this.displayThreat(threat));

            // Load initial stats
            const statsResponse = await fetch('/api/stats');
            const stats = await statsResponse.json();
            this.updateStats(stats);

        } catch (error) {
            console.error('Error loading initial data:', error);
        }
    }

    updateStats(stats) {
        // Update capture stats
        if (stats.capture) {
            document.getElementById('totalPackets').textContent =
                stats.capture.total_packets?.toLocaleString() || '0';
            document.getElementById('packetsPerSecond').textContent =
                stats.capture.packets_per_second?.toFixed(2) || '0';
            document.getElementById('uptime').textContent =
                `${Math.round(stats.capture.uptime || 0)}s`;

            this.updateCaptureStatus(stats.capture.is_capturing);
        }

        // Update alert stats
        if (stats.alert_stats) {
            document.getElementById('activeThreats').textContent =
                stats.alert_stats.active_alerts || '0';
        }
    }


    // updateChart(packetsPerSecond) {
    //     const now = new Date().toLocaleTimeString();

    //     this.packetData.labels.push(now);
    //     this.packetData.datasets[0].data.push(packetsPerSecond);

    //     // Keep only last 15 data points
    //     if (this.packetData.labels.length > 15) {
    //         this.packetData.labels.shift();
    //         this.packetData.datasets[0].data.shift();
    //     }

    //     this.packetChart.update('none');
    // }

    displayAlert(alertData) {
        const alertsList = document.getElementById('alertsList');
        const alert = alertData.alert;
        const threat = alertData.threat;

        const alertElement = document.createElement('div');
        alertElement.className = `p-4 rounded-lg border-l-4 ${alert.is_resolved ? 'border-green-500 bg-green-50' : 'border-red-500 bg-red-50'
            }`;

        alertElement.innerHTML = `
            <div class="flex justify-between items-start">
                <div>
                    <h4 class="font-semibold text-gray-800">${threat?.threat_type || 'Unknown Threat'}</h4>
                    <p class="text-sm text-gray-600 mt-1">${alert.message}</p>
                    <p class="text-sm text-blue-600 mt-2">${alert.recommendation}</p>
                </div>
                <span class="text-xs text-gray-500">${new Date(alert.timestamp).toLocaleTimeString()}</span>
            </div>
            ${!alert.is_resolved ? `
            <div class="mt-3 flex space-x-2">
                <button onclick="dashboard.resolveAlert(${alert.id}, 'monitored')" 
                        class="px-3 py-1 text-xs bg-green-500 text-white rounded hover:bg-green-600">
                    Mark Monitored
                </button>
                <button onclick="dashboard.resolveAlert(${alert.id}, 'blocked')" 
                        class="px-3 py-1 text-xs bg-red-500 text-white rounded hover:bg-red-600">
                    Block IP
                </button>
            </div>
            ` : ''}
        `;

        alertsList.insertBefore(alertElement, alertsList.firstChild);

        // Keep only last 10 alerts visible
        while (alertsList.children.length > 10) {
            alertsList.removeChild(alertsList.lastChild);
        }

        // Also add to recommendations
        this.displayRecommendation(alert);
    }


    // ADD this helper function to format threat types
    formatThreatType(threatType) {
        const typeMap = {
            'PORT_SCAN': 'Port Scan Attack',
            'SYN_FLOOD': 'SYN Flood Attack',
            'SUSPICIOUS_IP': 'Suspicious IP',
            'MALICIOUS_PAYLOAD': 'Malicious Payload'
        };
        return typeMap[threatType] || threatType.replace(/_/g, ' ');
    }
    displayThreat(threat) {
        const threatsList = document.getElementById('threatsList');

        const threatElement = document.createElement('div');
        threatElement.className = `p-3 rounded-lg border ${threat.threat_level === 'CRITICAL' ? 'border-red-300 bg-red-50' :
            threat.threat_level === 'HIGH' ? 'border-orange-300 bg-orange-50' :
                threat.threat_level === 'MEDIUM' ? 'border-yellow-300 bg-yellow-50' :
                    'border-blue-300 bg-blue-50'
            }`;

        threatElement.innerHTML = `
            <div class="flex justify-between items-start">
                <div>
                    <div class="flex items-center space-x-2">
                        <span class="font-semibold text-gray-800">${threat.source_ip}</span>
                        <span class="px-2 py-1 text-xs rounded-full ${threat.threat_level === 'CRITICAL' ? 'bg-red-500 text-white' :
                threat.threat_level === 'HIGH' ? 'bg-orange-500 text-white' :
                    threat.threat_level === 'MEDIUM' ? 'bg-yellow-500 text-black' :
                        'bg-blue-500 text-white'
            }">${threat.threat_level}</span>
                    </div>
                    <p class="text-sm text-gray-600 mt-1">${threat.description}</p>
                </div>
                <span class="text-xs text-gray-500">${new Date(threat.timestamp).toLocaleTimeString()}</span>
            </div>
        `;

        threatsList.insertBefore(threatElement, threatsList.firstChild);

        // Keep only last 10 threats visible
        while (threatsList.children.length > 10) {
            threatsList.removeChild(threatsList.lastChild);
        }
    }

    displayRecommendation(alert) {
        const recommendationsList = document.getElementById('recommendationsList');

        const recElement = document.createElement('div');
        recElement.className = 'p-3 rounded-lg bg-blue-50 border border-blue-200';
        recElement.innerHTML = `
            <div class="flex justify-between items-start">
                <div>
                    <h4 class="font-semibold text-blue-800">Recommended Action</h4>
                    <p class="text-sm text-blue-600 mt-1">${alert.recommendation}</p>
                    <p class="text-xs text-gray-500 mt-2">Source: ${alert.threat?.source_ip || 'Unknown'}</p>
                </div>
                <span class="text-xs text-gray-500">${new Date(alert.timestamp).toLocaleTimeString()}</span>
            </div>
        `;

        recommendationsList.insertBefore(recElement, recommendationsList.firstChild);

        // Keep only last 5 recommendations visible
        while (recommendationsList.children.length > 5) {
            recommendationsList.removeChild(recommendationsList.lastChild);
        }
    }

    async toggleCapture() {
        const button = document.getElementById('toggleCapture');
        const endpoint = button.textContent.includes('Start') ? '/api/start_capture' : '/api/stop_capture';

        try {
            const response = await fetch(endpoint);
            const data = await response.json();

            if (data.status === 'started' || data.status === 'stopped') {
                this.updateCaptureStatus(data.status === 'started');
            }
        } catch (error) {
            console.error('Error toggling capture:', error);
        }
    }

    updateCaptureStatus(isCapturing) {
        const indicator = document.getElementById('statusIndicator');
        const button = document.getElementById('toggleCapture');

        if (isCapturing) {
            indicator.innerHTML = '<div class="w-3 h-3 bg-green-500 rounded-full mr-2 animate-pulse"></div><span class="text-sm text-gray-600">Capture Running</span>';
            button.textContent = 'Stop Capture';
            button.className = 'bg-red-500 hover:bg-red-700 text-white font-bold py-2 px-4 rounded';
        } else {
            indicator.innerHTML = '<div class="w-3 h-3 bg-red-500 rounded-full mr-2"></div><span class="text-sm text-gray-600">Capture Stopped</span>';
            button.textContent = 'Start Capture';
            button.className = 'bg-blue-500 hover:bg-blue-700 text-white font-bold py-2 px-4 rounded';
        }
    }

    async resolveAlert(alertId, action) {
        try {
            // In a real application, you would send this to the backend
            console.log(`Resolving alert ${alertId} with action: ${action}`);

            // For now, just update the UI
            const alertElement = document.querySelector(`[onclick*="dashboard.resolveAlert(${alertId}"]`).closest('.border-red-500');
            if (alertElement) {
                alertElement.className = alertElement.className.replace('border-red-500 bg-red-50', 'border-green-500 bg-green-50');
                const buttons = alertElement.querySelectorAll('button');
                buttons.forEach(btn => btn.remove());
            }
        } catch (error) {
            console.error('Error resolving alert:', error);
        }
    }

    addPacketToTable(packet) {
        // This would update a packet table if we had one
        // For now, we're just using the chart
        console.log('New packet:', packet);
    }
}

// Initialize dashboard when page loads
const dashboard = new LiveGuardDashboard();