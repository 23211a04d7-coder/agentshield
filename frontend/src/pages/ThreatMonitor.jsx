import { useState, useEffect, useCallback } from 'react'
import { AlertTriangle, RefreshCw, Search, Filter, Zap, ChevronDown, ChevronUp } from 'lucide-react'
import { fetchAlerts, ingestLogs } from '../services/api'

const SEVERITY_CONFIG = {
    CRITICAL: {
        badge: 'badge-high',
        dot: 'bg-cyber-red',
        color: '#ff0055',
        bg: 'rgba(255,0,85,0.08)',
        border: 'rgba(255,0,85,0.25)',
    },
    HIGH: {
        badge: 'badge-high',
        dot: 'bg-cyber-red',
        color: '#ff3366',
        bg: 'rgba(255,51,102,0.05)',
        border: 'rgba(255,51,102,0.2)',
    },
    MEDIUM: {
        badge: 'badge-medium',
        dot: 'bg-cyber-yellow',
        color: '#ffcc00',
        bg: 'rgba(255,204,0,0.05)',
        border: 'rgba(255,204,0,0.2)',
    },
    LOW: {
        badge: 'badge-low',
        dot: 'bg-cyber-blue',
        color: '#3b82f6',
        bg: 'rgba(59,130,246,0.05)',
        border: 'rgba(59,130,246,0.2)',
    },
}

const THREAT_ICONS = {
    PORT_SCAN: '🔍',
    BRUTE_FORCE: '🔐',
    DATA_EXFILTRATION: '📤',
    C2_BEACON: '🛰️',
    DNS_TUNNELING: '🌐',
    LATERAL_MOVEMENT: '🔀',
    RANSOMWARE_SPREAD: '💀',
}

function AlertRow({ alert, expanded, onToggle }) {
    const cfg = SEVERITY_CONFIG[alert.severity] || SEVERITY_CONFIG.LOW
    const ts = new Date(alert.timestamp)

    return (
        <>
            <tr
                className="threat-row cursor-pointer"
                style={{ background: expanded ? cfg.bg : undefined }}
                onClick={onToggle}
            >
                <td className="px-4 py-3">
                    <div className="flex items-center gap-2">
                        <span className="w-2 h-2 rounded-full flex-shrink-0" style={{ background: cfg.color, boxShadow: `0 0 6px ${cfg.color}` }} />
                        <span className="font-mono text-xs text-cyber-muted">{alert.alert_id?.slice(0, 8)}...</span>
                    </div>
                </td>
                <td className="px-4 py-3">
                    <div className="flex items-center gap-2">
                        <span>{THREAT_ICONS[alert.threat_type] || '⚠️'}</span>
                        <span className="text-sm font-medium text-cyber-text">
                            {alert.threat_type?.replace('_', ' ')}
                        </span>
                    </div>
                </td>
                <td className="px-4 py-3">
                    <span className={cfg.badge}>{alert.severity}</span>
                </td>
                <td className="px-4 py-3">
                    <span className="font-mono text-sm text-cyber-accent">{alert.source_ip}</span>
                </td>
                <td className="px-4 py-3">
                    <div className="flex items-center gap-2">
                        <div className="flex-1 bg-cyber-border rounded-full h-1.5 w-20">
                            <div
                                className="h-full rounded-full"
                                style={{ width: `${alert.risk_score}%`, background: cfg.color }}
                            />
                        </div>
                        <span className="text-xs font-bold" style={{ color: cfg.color }}>{alert.risk_score}</span>
                    </div>
                </td>
                <td className="px-4 py-3 text-xs text-cyber-muted font-mono">
                    {ts.toLocaleTimeString()} {ts.toLocaleDateString()}
                </td>
                <td className="px-4 py-3">
                    {expanded ? (
                        <ChevronUp className="w-4 h-4 text-cyber-muted" />
                    ) : (
                        <ChevronDown className="w-4 h-4 text-cyber-muted" />
                    )}
                </td>
            </tr>
            {expanded && (
                <tr style={{ background: cfg.bg }}>
                    <td colSpan={7} className="px-6 py-3">
                        <div className="text-sm text-cyber-text/80 border-l-2 pl-3" style={{ borderColor: cfg.color }}>
                            {alert.description}
                        </div>
                    </td>
                </tr>
            )}
        </>
    )
}

export default function ThreatMonitor() {
    const [alerts, setAlerts] = useState([])
    const [loading, setLoading] = useState(true)
    const [search, setSearch] = useState('')
    const [severityFilter, setSeverityFilter] = useState('ALL')
    const [expandedId, setExpandedId] = useState(null)
    const [lastRefresh, setLastRefresh] = useState(new Date())
    const [generating, setGenerating] = useState(false)

    const loadAlerts = useCallback(async () => {
        try {
            const data = await fetchAlerts({ limit: 200 })
            setAlerts(data.alerts || [])
            setLastRefresh(new Date())
        } catch (e) {
            console.error('Failed to load alerts:', e)
        } finally {
            setLoading(false)
        }
    }, [])

    useEffect(() => {
        loadAlerts()
        const interval = setInterval(loadAlerts, 5000)
        return () => clearInterval(interval)
    }, [loadAlerts])

    const handleGenerate = async () => {
        setGenerating(true)
        try {
            await ingestLogs()
            await loadAlerts()
        } finally {
            setGenerating(false)
        }
    }

    const filtered = alerts.filter(a => {
        const matchSeverity = severityFilter === 'ALL' || a.severity === severityFilter
        const matchSearch = !search ||
            a.source_ip?.includes(search) ||
            a.threat_type?.includes(search.toUpperCase()) ||
            a.description?.toLowerCase().includes(search.toLowerCase())
        return matchSeverity && matchSearch
    })

    const counts = {
        CRITICAL: alerts.filter(a => a.severity === 'CRITICAL').length,
        HIGH: alerts.filter(a => a.severity === 'HIGH').length,
        MEDIUM: alerts.filter(a => a.severity === 'MEDIUM').length,
        LOW: alerts.filter(a => a.severity === 'LOW').length,
    }

    return (
        <div className="p-6 space-y-5">
            {/* Header */}
            <div className="flex items-center justify-between">
                <div>
                    <h1 className="text-2xl font-bold text-cyber-text flex items-center gap-2">
                        <AlertTriangle className="w-6 h-6 text-cyber-red" />
                        Threat Monitor
                    </h1>
                    <p className="text-sm text-cyber-muted mt-0.5">
                        Real-time threat detection · Auto-refresh every 5s ·{' '}
                        <span className="font-mono text-xs">Updated: {lastRefresh.toLocaleTimeString()}</span>
                    </p>
                </div>
                <div className="flex gap-3">
                    <button onClick={handleGenerate} disabled={generating} className="cyber-btn flex items-center gap-2">
                        <Zap className="w-4 h-4" />
                        {generating ? 'Generating...' : 'Simulate Traffic'}
                    </button>
                    <button onClick={loadAlerts} className="cyber-btn flex items-center gap-2">
                        <RefreshCw className="w-4 h-4" />
                        Refresh
                    </button>
                </div>
            </div>

            {/* Severity filter pills */}
            <div className="flex items-center gap-3 flex-wrap">
                {['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map(sev => {
                    const cfg = SEVERITY_CONFIG[sev]
                    const isActive = severityFilter === sev
                    const count = sev === 'ALL' ? alerts.length : counts[sev]
                    return (
                        <button
                            key={sev}
                            onClick={() => setSeverityFilter(sev)}
                            className="flex items-center gap-2 px-3 py-1.5 rounded-lg text-xs font-semibold transition-all duration-200"
                            style={{
                                background: isActive ? (cfg ? `${cfg.color}22` : 'rgba(0,212,255,0.15)') : 'rgba(255,255,255,0.03)',
                                border: `1px solid ${isActive ? (cfg?.color || '#00d4ff') : '#1e2d4a'}`,
                                color: isActive ? (cfg?.color || '#00d4ff') : '#64748b',
                            }}
                        >
                            {sev}
                            <span className="px-1.5 py-0.5 rounded text-xs"
                                style={{ background: 'rgba(0,0,0,0.3)' }}>
                                {count}
                            </span>
                        </button>
                    )
                })}

                {/* Search */}
                <div className="ml-auto flex items-center gap-2 bg-cyber-card border border-cyber-border rounded-lg px-3 py-1.5">
                    <Search className="w-3.5 h-3.5 text-cyber-muted" />
                    <input
                        type="text"
                        placeholder="Search IP, threat type..."
                        value={search}
                        onChange={e => setSearch(e.target.value)}
                        className="bg-transparent text-xs text-cyber-text placeholder-cyber-muted outline-none w-44"
                    />
                </div>
            </div>

            {/* Table */}
            <div className="card-glow overflow-hidden">
                {loading ? (
                    <div className="flex items-center justify-center h-48 text-cyber-muted animate-pulse">
                        Loading threat data...
                    </div>
                ) : filtered.length === 0 ? (
                    <div className="flex flex-col items-center justify-center h-48 gap-3">
                        <AlertTriangle className="w-10 h-10 text-cyber-muted/30" />
                        <div className="text-cyber-muted text-sm">
                            {alerts.length === 0
                                ? 'No alerts yet. Click "Simulate Traffic" to generate data.'
                                : 'No alerts match your filters.'}
                        </div>
                    </div>
                ) : (
                    <div className="overflow-x-auto">
                        <table className="w-full text-sm">
                            <thead>
                                <tr className="border-b border-cyber-border">
                                    {['Alert ID', 'Threat Type', 'Severity', 'Source IP', 'Risk Score', 'Timestamp', ''].map(h => (
                                        <th key={h} className="px-4 py-3 text-left text-xs font-semibold text-cyber-muted uppercase tracking-wider">
                                            {h}
                                        </th>
                                    ))}
                                </tr>
                            </thead>
                            <tbody>
                                {filtered.map(alert => (
                                    <AlertRow
                                        key={alert.alert_id}
                                        alert={alert}
                                        expanded={expandedId === alert.alert_id}
                                        onToggle={() => setExpandedId(expandedId === alert.alert_id ? null : alert.alert_id)}
                                    />
                                ))}
                            </tbody>
                        </table>
                    </div>
                )}
            </div>

            {/* Footer count */}
            {filtered.length > 0 && (
                <div className="text-xs text-cyber-muted text-right">
                    Showing {filtered.length} of {alerts.length} alerts
                </div>
            )}
        </div>
    )
}
