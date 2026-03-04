import { useState, useEffect, useCallback } from 'react'
import {
    Shield, Play, Zap, RefreshCw, Network, Terminal, Database,
    Globe, CheckCircle, AlertTriangle, Server, Monitor,
    ChevronDown, ChevronUp, Search, Cpu, Lock
} from 'lucide-react'
import { fetchStats, fetchAlerts, ingestLogs, blockAlert } from '../services/api'

// ── Static endpoint definitions ──────────────────────────────────────────────
const ENDPOINTS = [
    { ip: '192.168.1.10', hostname: 'WORKSTATION-01', os: 'Windows 11', dept: 'Engineering' },
    { ip: '192.168.1.11', hostname: 'WORKSTATION-02', os: 'Windows 10', dept: 'Engineering' },
    { ip: '192.168.1.12', hostname: 'WORKSTATION-03', os: 'Windows 11', dept: 'Marketing' },
    { ip: '192.168.1.20', hostname: 'SERVER-01', os: 'Ubuntu 22.04', dept: 'Infrastructure' },
    { ip: '192.168.1.21', hostname: 'SERVER-02', os: 'CentOS 8', dept: 'Infrastructure' },
    { ip: '192.168.1.30', hostname: 'MGMT-SRV', os: 'Win Server 2022', dept: 'IT Ops' },
    { ip: '10.0.0.5', hostname: 'DB-SERVER-01', os: 'Ubuntu 22.04', dept: 'Data' },
    { ip: '10.0.0.6', hostname: 'DB-SERVER-02', os: 'Ubuntu 20.04', dept: 'Data' },
    { ip: '10.0.0.7', hostname: 'BACKUP-SRV', os: 'Debian 12', dept: 'Infrastructure' },
]

// ── Detection sources ─────────────────────────────────────────────────────────
const SOURCES = [
    { name: 'Network Traffic', sub: 'Zeek / Suricata', Icon: Network },
    { name: 'WMI / PowerShell', sub: 'Process Monitoring', Icon: Terminal },
    { name: 'Syslog / WEF', sub: 'Event Collection', Icon: Database },
    { name: 'Cloud APIs', sub: 'AWS / Azure / GCP', Icon: Globe },
]

// ── MITRE ATT&CK coverage ─────────────────────────────────────────────────────
const MITRE = [
    {
        tactic: 'Reconnaissance',
        techniques: [
            { id: 'T1046', name: 'Network Service Scanning', covered: true },
            { id: 'T1595', name: 'Active Scanning', covered: false },
        ],
    },
    {
        tactic: 'Credential Access',
        techniques: [
            { id: 'T1110', name: 'Brute Force', covered: true },
            { id: 'T1110.001', name: 'Password Guessing', covered: true },
            { id: 'T1557', name: 'Adversary-in-the-Middle', covered: false },
        ],
    },
    {
        tactic: 'Exfiltration',
        techniques: [
            { id: 'T1041', name: 'Exfil Over C2 Channel', covered: true },
            { id: 'T1048', name: 'Exfil Over Alternative Protocol', covered: true },
            { id: 'T1048.004', name: 'Exfil Over DNS', covered: true },
            { id: 'T1030', name: 'Data Transfer Size Limits', covered: false },
        ],
    },
    {
        tactic: 'Command & Control',
        techniques: [
            { id: 'T1071', name: 'Application Layer Protocol', covered: true },
            { id: 'T1071.004', name: 'DNS', covered: true },
            { id: 'T1219', name: 'Remote Access Software', covered: true },
            { id: 'T1573', name: 'Encrypted Channel', covered: false },
        ],
    },
    {
        tactic: 'Lateral Movement',
        techniques: [
            { id: 'T1021', name: 'Remote Services', covered: true },
            { id: 'T1021.002', name: 'SMB / Windows Admin Shares', covered: true },
            { id: 'T1021.006', name: 'Windows Remote Management', covered: true },
            { id: 'T1534', name: 'Internal Spearphishing', covered: false },
        ],
    },
    {
        tactic: 'Impact',
        techniques: [
            { id: 'T1486', name: 'Data Encrypted for Impact', covered: true },
            { id: 'T1489', name: 'Service Stop', covered: false },
            { id: 'T1499', name: 'Endpoint Denial of Service', covered: false },
        ],
    },
]

// ── Threat-type metadata ──────────────────────────────────────────────────────
const SEV_CLASS = {
    CRITICAL: 'sev-critical',
    HIGH: 'sev-high',
    MEDIUM: 'sev-medium',
    LOW: 'sev-low',
}

const SEV_COLOR = {
    CRITICAL: '#ff0055',
    HIGH: '#ff4444',
    MEDIUM: '#ffb800',
    LOW: '#4a9eff',
}

const THREAT_ICONS = {
    PORT_SCAN: '🔍', BRUTE_FORCE: '🔐', DATA_EXFILTRATION: '📤',
    C2_BEACON: '🛰️', DNS_TUNNELING: '🌐', LATERAL_MOVEMENT: '🔀',
    RANSOMWARE_SPREAD: '💀',
}

// ── Sub-components ────────────────────────────────────────────────────────────

function StatCard({ label, value, badge, colorClass, Icon, iconBg }) {
    return (
        <div className="stat-card fade-up">
            <div className="stat-card-top">
                <span className="stat-label">{label}</span>
                {badge && <span className="stat-badge">{badge}</span>}
            </div>
            <div className="stat-card-bottom">
                <span className={`stat-value ${colorClass}`}>{value}</span>
                <div className="stat-icon-wrap" style={{ background: iconBg }}>
                    <Icon size={18} style={{ color: '#888' }} />
                </div>
            </div>
        </div>
    )
}

function SourceCard({ name, sub, Icon }) {
    return (
        <div className="source-card">
            <div className="source-name">{name}</div>
            <div className="source-sub">{sub}</div>
            <div className="source-footer">
                <div className="source-icon-wrap" style={{ background: 'rgba(255,255,255,0.04)' }}>
                    <Icon size={16} color="#555" />
                </div>
                <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                    <span className="source-status-dot" />
                    <CheckCircle size={15} color="#00d4a0" />
                </div>
            </div>
        </div>
    )
}

function AlertsTab({ alerts, generating, onGenerate }) {
    const [search, setSearch] = useState('')
    const [sevFilter, setSevFilter] = useState('ALL')
    const [expandedId, setExpandedId] = useState(null)
    const [blockedIds, setBlockedIds] = useState(new Set())
    const [blockingId, setBlockingId] = useState(null)   // id currently being blocked
    const [toast, setToast] = useState(null)              // { msg, type }

    const showToast = (msg, type = 'success') => {
        setToast({ msg, type })
        setTimeout(() => setToast(null), 3000)
    }

    const handleBlock = async (e, alertId) => {
        e.stopPropagation()   // don't expand the row
        if (blockedIds.has(alertId)) return
        setBlockingId(alertId)
        try {
            await blockAlert(alertId)
            setBlockedIds(prev => new Set([...prev, alertId]))
            showToast('Threat blocked — source IP isolated')
        } catch (err) {
            showToast('Block failed: ' + (err?.response?.data?.detail || err.message), 'error')
        } finally {
            setBlockingId(null)
        }
    }

    const activeAlerts = alerts.filter(a => !blockedIds.has(a.alert_id))
    const blockedAlerts = alerts.filter(a => blockedIds.has(a.alert_id))

    const counts = {
        CRITICAL: activeAlerts.filter(a => a.severity === 'CRITICAL').length,
        HIGH: activeAlerts.filter(a => a.severity === 'HIGH').length,
        MEDIUM: activeAlerts.filter(a => a.severity === 'MEDIUM').length,
        LOW: activeAlerts.filter(a => a.severity === 'LOW').length,
    }

    const filtered = activeAlerts.filter(a => {
        const ms = sevFilter === 'ALL' || a.severity === sevFilter
        const mt = !search || a.source_ip?.includes(search)
            || a.threat_type?.includes(search.toUpperCase())
            || a.description?.toLowerCase().includes(search.toLowerCase())
        return ms && mt
    })

    const renderRow = (a, isBlocked = false) => {
        const isOpen = expandedId === a.alert_id
        const isBlocking = blockingId === a.alert_id
        const ts = new Date(a.timestamp)
        const sevColor = isBlocked ? '#555' : (SEV_COLOR[a.severity] || '#888')

        return (
            <>
                <tr
                    key={a.alert_id}
                    onClick={() => !isBlocked && setExpandedId(isOpen ? null : a.alert_id)}
                    style={{
                        opacity: isBlocked ? 0.45 : 1,
                        cursor: isBlocked ? 'default' : 'pointer',
                        background: isOpen ? 'rgba(255,255,255,0.02)' : undefined,
                    }}
                >
                    {/* Alert ID */}
                    <td>
                        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                            <span style={{ width: 8, height: 8, borderRadius: '50%', background: sevColor, boxShadow: isBlocked ? 'none' : `0 0 6px ${sevColor}`, flexShrink: 0 }} />
                            <span style={{ fontFamily: 'monospace', fontSize: 11.5, color: '#666' }}>
                                {a.alert_id?.slice(0, 8)}…
                            </span>
                        </div>
                    </td>
                    {/* Type */}
                    <td>
                        <div style={{ display: 'flex', alignItems: 'center', gap: 7 }}>
                            <span>{THREAT_ICONS[a.threat_type] || '⚠️'}</span>
                            <span style={{ fontWeight: 500, color: isBlocked ? '#555' : '#d0d0d0', textDecoration: isBlocked ? 'line-through' : 'none' }}>
                                {a.threat_type?.replace(/_/g, ' ')}
                            </span>
                        </div>
                    </td>
                    {/* Severity */}
                    <td>
                        {isBlocked
                            ? <span style={{ display: 'inline-flex', alignItems: 'center', gap: 5, fontSize: 11, fontWeight: 700, padding: '3px 10px', borderRadius: 20, background: 'rgba(0,212,160,0.1)', color: '#00d4a0', border: '1px solid rgba(0,212,160,0.2)' }}>
                                <Shield size={10} /> BLOCKED
                            </span>
                            : <span className={`severity-badge ${SEV_CLASS[a.severity] || 'sev-low'}`}>{a.severity}</span>
                        }
                    </td>
                    {/* Source IP */}
                    <td>
                        <span style={{ fontFamily: 'monospace', fontSize: 12, color: isBlocked ? '#555' : '#4a9eff' }}>
                            {a.source_ip}
                        </span>
                    </td>
                    {/* Risk */}
                    <td>
                        <div className="risk-bar-wrap">
                            <div className="risk-bar-bg">
                                <div className="risk-bar-fill" style={{ width: `${a.risk_score}%`, background: sevColor }} />
                            </div>
                            <span style={{ fontSize: 12, fontWeight: 700, color: sevColor }}>{a.risk_score}</span>
                        </div>
                    </td>
                    {/* Time */}
                    <td style={{ fontFamily: 'monospace', fontSize: 11, color: '#555' }}>
                        {ts.toLocaleTimeString()}
                    </td>
                    {/* Actions */}
                    <td onClick={e => e.stopPropagation()}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                            {!isBlocked && (
                                <button
                                    onClick={e => handleBlock(e, a.alert_id)}
                                    disabled={isBlocking}
                                    style={{
                                        display: 'flex', alignItems: 'center', gap: 5,
                                        padding: '4px 11px', borderRadius: 6,
                                        fontSize: 11.5, fontWeight: 600,
                                        background: isBlocking ? 'rgba(255,68,68,0.06)' : 'rgba(255,68,68,0.1)',
                                        border: '1px solid rgba(255,68,68,0.25)',
                                        color: '#ff4444', cursor: isBlocking ? 'wait' : 'pointer',
                                        transition: 'all 0.15s', whiteSpace: 'nowrap',
                                    }}
                                    onMouseEnter={e => { if (!isBlocking) e.currentTarget.style.background = 'rgba(255,68,68,0.2)' }}
                                    onMouseLeave={e => { e.currentTarget.style.background = 'rgba(255,68,68,0.1)' }}
                                >
                                    <Lock size={11} />
                                    {isBlocking ? 'Blocking…' : 'Block'}
                                </button>
                            )}
                            {!isBlocked && (
                                isOpen
                                    ? <ChevronUp size={14} color="#555" onClick={() => setExpandedId(null)} />
                                    : <ChevronDown size={14} color="#555" onClick={() => setExpandedId(a.alert_id)} />
                            )}
                        </div>
                    </td>
                </tr>
                {isOpen && !isBlocked && (
                    <tr className="expand-row" key={`${a.alert_id}-exp`}>
                        <td colSpan={7}>
                            <div className={`expand-desc ${a.severity?.toLowerCase()}`}>
                                {a.description}
                            </div>
                        </td>
                    </tr>
                )}
            </>
        )
    }

    return (
        <>
            {/* Toast notification */}
            {toast && (
                <div style={{
                    position: 'fixed', bottom: 28, right: 28, zIndex: 999,
                    background: toast.type === 'error' ? '#2a1010' : '#0f2a1a',
                    border: `1px solid ${toast.type === 'error' ? 'rgba(255,68,68,0.4)' : 'rgba(0,212,160,0.4)'}`,
                    color: toast.type === 'error' ? '#ff4444' : '#00d4a0',
                    padding: '12px 20px', borderRadius: 10, fontSize: 13, fontWeight: 500,
                    display: 'flex', alignItems: 'center', gap: 10,
                    boxShadow: '0 8px 32px rgba(0,0,0,0.5)',
                    animation: 'fadeUp 0.25s ease',
                }}>
                    {toast.type === 'error' ? <AlertTriangle size={15} /> : <CheckCircle size={15} />}
                    {toast.msg}
                </div>
            )}

            <div className="filters-bar">
                {['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map(s => (
                    <button
                        key={s}
                        className={`filter-pill ${sevFilter === s ? 'active-pill' : ''}`}
                        onClick={() => setSevFilter(s)}
                    >
                        {s}
                        <span style={{ marginLeft: 5, opacity: 0.75 }}>
                            {s === 'ALL' ? activeAlerts.length : counts[s]}
                        </span>
                    </button>
                ))}
                {blockedIds.size > 0 && (
                    <span style={{ fontSize: 12, color: '#00d4a0', display: 'flex', alignItems: 'center', gap: 5 }}>
                        <Lock size={12} /> {blockedIds.size} blocked
                    </span>
                )}
                <div className="search-box">
                    <Search size={13} color="#666" />
                    <input
                        placeholder="Search IP, type…"
                        value={search}
                        onChange={e => setSearch(e.target.value)}
                    />
                </div>
                <button className="btn-simulate" onClick={onGenerate} disabled={generating}>
                    <Zap size={13} />
                    {generating ? 'Generating…' : 'Simulate Traffic'}
                </button>
            </div>

            {filtered.length === 0 && blockedAlerts.length === 0 ? (
                <div className="empty-state">
                    <div className="empty-check"><CheckCircle size={26} /></div>
                    <span className="empty-label">
                        {alerts.length === 0
                            ? 'No alerts yet — click "Simulate Traffic" to generate data'
                            : 'No alerts match your filter'}
                    </span>
                </div>
            ) : (
                <div style={{ overflowX: 'auto' }}>
                    <table className="alerts-table">
                        <thead>
                            <tr>
                                {['Alert ID', 'Type', 'Severity', 'Source IP', 'Risk', 'Time', 'Actions'].map(h => (
                                    <th key={h}>{h}</th>
                                ))}
                            </tr>
                        </thead>
                        <tbody>
                            {filtered.map(a => renderRow(a, false))}
                            {blockedAlerts.map(a => renderRow(a, true))}
                        </tbody>
                    </table>
                </div>
            )}
        </>
    )
}

function EndpointInventoryTab({ alerts }) {
    const threatenedIPs = new Set(alerts.map(a => a.source_ip))
    return (
        <div className="endpoint-grid">
            {ENDPOINTS.map(ep => {
                const threatened = threatenedIPs.has(ep.ip)
                return (
                    <div key={ep.ip} className={`endpoint-card ${threatened ? 'threatened' : ''}`}>
                        <div className="endpoint-header">
                            <div>
                                <div className="endpoint-hostname">{ep.hostname}</div>
                                <div className="endpoint-ip">{ep.ip}</div>
                            </div>
                            <span className={`endpoint-status ${threatened ? 'status-threatened' : 'status-protected'}`}>
                                {threatened
                                    ? <><AlertTriangle size={10} /> Alert</>
                                    : <><CheckCircle size={10} /> Protected</>}
                            </span>
                        </div>
                        <div className="endpoint-meta">
                            <div className="endpoint-meta-row">
                                <Monitor size={11} />
                                <span>{ep.os}</span>
                            </div>
                            <div className="endpoint-meta-row">
                                <Server size={11} />
                                <span>{ep.dept}</span>
                            </div>
                            <div className="endpoint-meta-row">
                                <Shield size={11} />
                                <span>Gateway-monitored · No agent installed</span>
                            </div>
                        </div>
                    </div>
                )
            })}
        </div>
    )
}

function MitreTab() {
    const totalTech = MITRE.reduce((n, g) => n + g.techniques.length, 0)
    const coveredTech = MITRE.reduce((n, g) => n + g.techniques.filter(t => t.covered).length, 0)
    const pct = Math.round((coveredTech / totalTech) * 100)

    return (
        <div className="mitre-container">
            <div style={{ display: 'flex', alignItems: 'center', gap: 16, padding: '4px 0 12px' }}>
                <div>
                    <div style={{ fontSize: 13, color: '#aaa' }}>
                        Coverage: <span style={{ color: '#00d4a0', fontWeight: 700 }}>{coveredTech}</span>
                        <span style={{ color: '#555' }}> / {totalTech} techniques</span>
                    </div>
                </div>
                <div style={{ flex: 1, height: 4, background: '#2a2a2a', borderRadius: 2, overflow: 'hidden' }}>
                    <div style={{ width: `${pct}%`, height: '100%', background: 'linear-gradient(90deg, #00d4a033, #00d4a0)', borderRadius: 2 }} />
                </div>
                <span style={{ fontSize: 13, fontWeight: 700, color: '#00d4a0' }}>{pct}%</span>
            </div>

            {MITRE.map(group => (
                <div className="mitre-tactic-group" key={group.tactic}>
                    <div className="mitre-tactic-label">{group.tactic}</div>
                    <div className="mitre-techniques-row">
                        {group.techniques.map(t => (
                            <div
                                key={t.id}
                                className={`mitre-technique ${t.covered ? 'mitre-covered' : 'mitre-uncovered'}`}
                            >
                                <span className="mitre-id">{t.id}</span>
                                {t.covered
                                    ? <CheckCircle size={11} color="#00d4a0" />
                                    : <span style={{ width: 11, height: 11, borderRadius: '50%', border: '1px solid #444', display: 'inline-block' }} />}
                                <span>{t.name}</span>
                            </div>
                        ))}
                    </div>
                </div>
            ))}
        </div>
    )
}

// ── Main Dashboard ────────────────────────────────────────────────────────────
export default function Dashboard() {
    const [stats, setStats] = useState(null)
    const [alerts, setAlerts] = useState([])
    const [loading, setLoading] = useState(true)
    const [generating, setGenerating] = useState(false)
    const [monitoring, setMonitoring] = useState(true)
    const [activeTab, setActiveTab] = useState('threats')
    const [lastRefresh, setLastRefresh] = useState(new Date())

    const loadData = useCallback(async () => {
        try {
            const [s, a] = await Promise.all([
                fetchStats(),
                fetch('http://localhost:8000/alerts?limit=200').then(r => r.json()),
            ])
            setStats(s)
            setAlerts(a.alerts || [])
            setLastRefresh(new Date())
        } catch (e) {
            console.error(e)
        } finally {
            setLoading(false)
        }
    }, [])

    useEffect(() => {
        loadData()
        if (!monitoring) return
        const t = setInterval(loadData, 5000)
        return () => clearInterval(t)
    }, [loadData, monitoring])

    const handleGenerate = async () => {
        setGenerating(true)
        try {
            await ingestLogs()
            await loadData()
        } finally {
            setGenerating(false)
        }
    }

    // ── Derived stats ──────────────────────────────────────────────────────────
    const totalEndpoints = ENDPOINTS.length
    const threatenedIPs = new Set(alerts.map(a => a.source_ip))
    const protectedCount = totalEndpoints - threatenedIPs.size
    const activeThreats = stats?.active_threats ?? 0
    const blockedThreats = stats?.severity_breakdown?.CRITICAL ?? 0
    const networkEvents = stats?.total_logs ?? 0
    const criticalCount = alerts.filter(a => a.severity === 'CRITICAL').length

    const TABS = [
        { id: 'threats', label: 'Active Threats', count: activeThreats, countGreen: false },
        { id: 'endpoints', label: 'Endpoint Inventory', count: protectedCount, countGreen: true },
        { id: 'mitre', label: 'MITRE ATT&CK Coverage', count: null },
    ]

    return (
        <div className="app-shell">
            {/* ── Header ─────────────────────────────────────────────────────── */}
            <header className="app-header">
                <div className="header-logo">
                    <div className="logo-icon">
                        <Shield size={20} color="#4a9eff" />
                    </div>
                    <div>
                        <div className="logo-title">Agentless EDR</div>
                        <div className="logo-subtitle">Network-based endpoint protection with zero agent deployment</div>
                    </div>
                </div>

                <div className="header-actions">
                    <span style={{ fontSize: 11, color: '#555', fontFamily: 'monospace' }}>
                        {monitoring ? `Live · ${lastRefresh.toLocaleTimeString()}` : 'Paused'}
                    </span>
                    <button
                        className={`btn-monitor ${monitoring ? 'active' : ''}`}
                        onClick={() => setMonitoring(m => !m)}
                    >
                        <Play size={13} fill={monitoring ? '#00d4a0' : 'none'} />
                        {monitoring ? 'Monitoring' : 'Start Monitoring'}
                    </button>
                    <button
                        className={`btn-threats ${criticalCount > 0 ? 'has-threats' : ''}`}
                        onClick={() => setActiveTab('threats')}
                    >
                        <Zap size={13} fill={criticalCount > 0 ? '#fff' : 'none'} />
                        Threats {criticalCount > 0 && <span style={{ background: 'rgba(255,255,255,0.2)', borderRadius: 10, padding: '0 6px', fontSize: 11 }}>{criticalCount}</span>}
                    </button>
                </div>
            </header>

            {/* ── Main ───────────────────────────────────────────────────────── */}
            <main className="main-content">

                {/* Stats Row */}
                <div className="stats-row">
                    <StatCard
                        label="Total Endpoints"
                        value={totalEndpoints}
                        badge="v0 block"
                        colorClass="green"
                        Icon={Monitor}
                        iconBg="rgba(74,158,255,0.08)"
                    />
                    <StatCard
                        label="Protected Endpoints"
                        value={`${protectedCount}/${totalEndpoints}`}
                        colorClass="green"
                        Icon={CheckCircle}
                        iconBg="rgba(0,212,160,0.07)"
                    />
                    <StatCard
                        label="Active Threats"
                        value={loading ? '…' : activeThreats}
                        colorClass={activeThreats > 0 ? 'red' : 'white'}
                        Icon={AlertTriangle}
                        iconBg="rgba(255,68,68,0.08)"
                    />
                    <StatCard
                        label="Blocked Threats"
                        value={loading ? '…' : blockedThreats}
                        colorClass="green"
                        Icon={Lock}
                        iconBg="rgba(0,212,160,0.07)"
                    />
                    <StatCard
                        label="Network Events"
                        value={loading ? '…' : networkEvents.toLocaleString()}
                        colorClass="blue"
                        Icon={Network}
                        iconBg="rgba(74,158,255,0.08)"
                    />
                </div>

                {/* Detection Sources */}
                <div className="sources-section">
                    <div className="section-title">Detection Sources</div>
                    <div className="sources-grid">
                        {SOURCES.map(s => (
                            <SourceCard key={s.name} name={s.name} sub={s.sub} Icon={s.Icon} />
                        ))}
                    </div>
                </div>

                {/* Tabbed content */}
                <div className="tabs-section">
                    <div className="tab-nav">
                        {TABS.map(t => (
                            <button
                                key={t.id}
                                className={`tab-btn ${activeTab === t.id ? 'active' : ''}`}
                                onClick={() => setActiveTab(t.id)}
                            >
                                {t.label}
                                {t.count !== null && (
                                    <span className={`tab-count ${t.countGreen ? 'green' : ''}`}>
                                        {t.count}
                                    </span>
                                )}
                            </button>
                        ))}
                        <div style={{ marginLeft: 'auto', display: 'flex', alignItems: 'center', gap: 8, paddingRight: 4 }}>
                            <button
                                style={{ background: 'none', border: 'none', cursor: 'pointer', color: '#555', display: 'flex', alignItems: 'center', gap: 5, fontSize: 12 }}
                                onClick={loadData}
                            >
                                <RefreshCw size={13} />
                                Refresh
                            </button>
                        </div>
                    </div>
                    <div className="tab-content">
                        {activeTab === 'threats' && (
                            <AlertsTab
                                alerts={alerts}
                                generating={generating}
                                onGenerate={handleGenerate}
                            />
                        )}
                        {activeTab === 'endpoints' && (
                            <EndpointInventoryTab alerts={alerts} />
                        )}
                        {activeTab === 'mitre' && <MitreTab />}
                    </div>
                </div>
            </main>
        </div>
    )
}
