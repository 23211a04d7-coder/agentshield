import { useState, useEffect, useCallback } from 'react'
import {
    PieChart, Pie, Cell, Tooltip, ResponsiveContainer,
    AreaChart, Area, XAxis, YAxis, CartesianGrid, Legend,
} from 'recharts'
import { Shield, Activity, AlertTriangle, Database, RefreshCw, Zap, TrendingUp } from 'lucide-react'
import { fetchStats, fetchRiskScore, ingestLogs } from '../services/api'

const THREAT_META = {
    PORT_SCAN: { color: '#00d4ff', icon: '🔍', label: 'Port Scan', severity: 'HIGH' },
    BRUTE_FORCE: { color: '#ff3366', icon: '🔐', label: 'Brute Force', severity: 'HIGH' },
    DATA_EXFILTRATION: { color: '#ffcc00', icon: '📤', label: 'Data Exfiltration', severity: 'MEDIUM' },
    C2_BEACON: { color: '#ff6b35', icon: '🛰️', label: 'C2 Beacon', severity: 'CRITICAL' },
    DNS_TUNNELING: { color: '#a855f7', icon: '🌐', label: 'DNS Tunneling', severity: 'HIGH' },
    LATERAL_MOVEMENT: { color: '#06b6d4', icon: '🔀', label: 'Lateral Movement', severity: 'HIGH' },
    RANSOMWARE_SPREAD: { color: '#ef4444', icon: '💀', label: 'Ransomware Spread', severity: 'CRITICAL' },
}

const SEVERITY_COLORS = {
    CRITICAL: '#ff0055',
    HIGH: '#ff3366',
    MEDIUM: '#ffcc00',
    LOW: '#3b82f6',
}

function ThreatDistributionChart({ threatBreakdown }) {
    const total = Object.values(threatBreakdown).reduce((s, v) => s + v, 0)
    if (total === 0) return (
        <div className="flex items-center justify-center h-32 text-cyber-muted text-sm">
            No threat data yet. Click "Simulate Traffic" to generate logs.
        </div>
    )
    const sorted = Object.entries(threatBreakdown).sort(([, a], [, b]) => b - a)
    return (
        <div className="space-y-3">
            {sorted.map(([key, count]) => {
                const meta = THREAT_META[key] || { color: '#64748b', icon: '⚠️', label: key.replace(/_/g, ' '), severity: 'LOW' }
                const pct = Math.round((count / total) * 100)
                const sevColor = SEVERITY_COLORS[meta.severity] || '#64748b'
                return (
                    <div key={key} className="flex items-center gap-3">
                        <span className="text-base w-5 text-center flex-shrink-0">{meta.icon}</span>
                        <span className="text-xs font-semibold text-cyber-text w-36 flex-shrink-0">{meta.label}</span>
                        <div className="flex-1 h-2 rounded-full bg-cyber-border overflow-hidden">
                            <div
                                className="h-full rounded-full transition-all duration-700"
                                style={{
                                    width: `${pct}%`,
                                    background: `linear-gradient(90deg, ${meta.color}cc, ${meta.color})`,
                                    boxShadow: `0 0 8px ${meta.color}66`,
                                }}
                            />
                        </div>
                        <span className="text-xs font-bold w-6 text-right flex-shrink-0" style={{ color: meta.color }}>{count}</span>
                        <span className="text-xs text-cyber-muted w-8 text-right flex-shrink-0">{pct}%</span>
                        <span
                            className="text-xs font-bold px-2 py-0.5 rounded-full flex-shrink-0"
                            style={{ color: sevColor, background: `${sevColor}18`, border: `1px solid ${sevColor}44` }}
                        >{meta.severity}</span>
                    </div>
                )
            })}
        </div>
    )
}

function RiskGauge({ score, level }) {
    const angle = -135 + (score / 100) * 270
    const levelColor = {
        SAFE: '#00ff88',
        LOW: '#00d4ff',
        MEDIUM: '#ffcc00',
        HIGH: '#ff8800',
        CRITICAL: '#ff3366',
    }[level] || '#00d4ff'

    return (
        <div className="flex flex-col items-center justify-center gap-3">
            <div className="relative w-40 h-24 overflow-hidden">
                <svg viewBox="0 0 160 90" className="w-full h-full">
                    {/* Background arc */}
                    <path
                        d="M 20 80 A 60 60 0 0 1 140 80"
                        fill="none"
                        stroke="#1e2d4a"
                        strokeWidth="12"
                        strokeLinecap="round"
                    />
                    {/* Score arc */}
                    <path
                        d="M 20 80 A 60 60 0 0 1 140 80"
                        fill="none"
                        stroke={levelColor}
                        strokeWidth="12"
                        strokeLinecap="round"
                        strokeDasharray={`${(score / 100) * 188} 188`}
                        style={{ filter: `drop-shadow(0 0 6px ${levelColor}88)` }}
                    />
                    {/* Needle */}
                    <g transform={`rotate(${angle}, 80, 80)`}>
                        <line x1="80" y1="80" x2="80" y2="30" stroke={levelColor} strokeWidth="2.5" strokeLinecap="round" />
                        <circle cx="80" cy="80" r="4" fill={levelColor} />
                    </g>
                    {/* Score text */}
                    <text x="80" y="72" textAnchor="middle" fill={levelColor} fontSize="20" fontWeight="700" fontFamily="Inter">
                        {score}
                    </text>
                </svg>
            </div>
            <div className="text-center">
                <div className="text-xs text-cyber-muted mb-1">System Risk Score</div>
                <span
                    className="text-sm font-bold px-3 py-1 rounded-full"
                    style={{ color: levelColor, background: `${levelColor}22`, border: `1px solid ${levelColor}44` }}
                >
                    {level}
                </span>
            </div>
        </div>
    )
}

function StatCard({ icon: Icon, label, value, color, sublabel }) {
    return (
        <div className="stat-card fade-in-up">
            <div className="flex items-center justify-between">
                <div className="text-xs text-cyber-muted font-medium uppercase tracking-wider">{label}</div>
                <div className="w-8 h-8 rounded-lg flex items-center justify-center"
                    style={{ background: `${color}22`, border: `1px solid ${color}44` }}>
                    <Icon className="w-4 h-4" style={{ color }} />
                </div>
            </div>
            <div className="text-3xl font-bold mt-1" style={{ color }}>{value}</div>
            {sublabel && <div className="text-xs text-cyber-muted">{sublabel}</div>}
        </div>
    )
}

const CustomTooltip = ({ active, payload, label }) => {
    if (active && payload && payload.length) {
        return (
            <div className="card px-3 py-2 text-xs">
                <div className="text-cyber-muted mb-1">{label}</div>
                {payload.map((p, i) => (
                    <div key={i} style={{ color: p.color }}>{p.name}: {p.value}</div>
                ))}
            </div>
        )
    }
    return null
}

export default function Dashboard() {
    const [stats, setStats] = useState(null)
    const [riskData, setRiskData] = useState(null)
    const [loading, setLoading] = useState(true)
    const [lastRefresh, setLastRefresh] = useState(new Date())
    const [generating, setGenerating] = useState(false)

    const loadData = useCallback(async () => {
        try {
            const [s, r] = await Promise.all([fetchStats(), fetchRiskScore()])
            setStats(s)
            setRiskData(r)
            setLastRefresh(new Date())
        } catch (e) {
            console.error('Failed to load data:', e)
        } finally {
            setLoading(false)
        }
    }, [])

    useEffect(() => {
        loadData()
        const interval = setInterval(loadData, 5000)
        return () => clearInterval(interval)
    }, [loadData])

    const handleGenerate = async () => {
        setGenerating(true)
        try {
            await ingestLogs()
            await loadData()
        } catch (e) {
            console.error('Failed to generate logs:', e)
        } finally {
            setGenerating(false)
        }
    }

    const threatPieData = stats
        ? Object.entries(stats.threat_breakdown || {}).map(([name, value]) => ({ name, value }))
        : []

    return (
        <div className="p-6 space-y-6">
            {/* Header */}
            <div className="flex items-center justify-between">
                <div>
                    <h1 className="text-2xl font-bold text-cyber-text">Security Dashboard</h1>
                    <p className="text-sm text-cyber-muted mt-0.5">
                        Gateway-based monitoring · No agents on endpoints ·{' '}
                        <span className="font-mono text-xs">
                            Last refresh: {lastRefresh.toLocaleTimeString()}
                        </span>
                    </p>
                </div>
                <div className="flex gap-3">
                    <button
                        onClick={handleGenerate}
                        disabled={generating}
                        className="cyber-btn flex items-center gap-2"
                    >
                        <Zap className="w-4 h-4" />
                        {generating ? 'Generating...' : 'Simulate Traffic'}
                    </button>
                    <button
                        onClick={loadData}
                        className="cyber-btn flex items-center gap-2"
                    >
                        <RefreshCw className="w-4 h-4" />
                        Refresh
                    </button>
                </div>
            </div>

            {loading ? (
                <div className="flex items-center justify-center h-64">
                    <div className="text-cyber-muted animate-pulse">Loading telemetry data...</div>
                </div>
            ) : (
                <>
                    {/* Row 1: Stat Cards + Risk Score */}
                    <div className="grid grid-cols-2 lg:grid-cols-5 gap-4">
                        <StatCard
                            icon={Database}
                            label="Total Logs"
                            value={stats?.total_logs?.toLocaleString() ?? 0}
                            color="#00d4ff"
                            sublabel="Gateway captures"
                        />
                        <StatCard
                            icon={AlertTriangle}
                            label="Total Alerts"
                            value={stats?.total_alerts?.toLocaleString() ?? 0}
                            color="#ff3366"
                            sublabel="All time"
                        />
                        <StatCard
                            icon={Activity}
                            label="Active Threats"
                            value={stats?.active_threats ?? 0}
                            color="#ffcc00"
                            sublabel="CRITICAL + HIGH + MEDIUM"
                        />
                        <StatCard
                            icon={Shield}
                            label="24h Alerts"
                            value={stats?.recent_alerts_24h ?? 0}
                            color="#7c3aed"
                            sublabel="Last 24 hours"
                        />
                        {/* Risk Score — 5th card */}
                        <div className="stat-card fade-in-up flex flex-col items-center justify-center gap-1">
                            <div className="text-xs text-cyber-muted font-medium uppercase tracking-wider w-full">System Risk</div>
                            <RiskGauge
                                score={riskData?.risk_score ?? 0}
                                level={riskData?.level ?? 'SAFE'}
                            />
                        </div>
                    </div>

                    {/* Row 2: Severity Breakdown */}
                    <div className="grid grid-cols-4 gap-4">
                        {[
                            { label: 'Critical', key: 'CRITICAL', color: '#ff0055' },
                            { label: 'High', key: 'HIGH', color: '#ff3366' },
                            { label: 'Medium', key: 'MEDIUM', color: '#ffcc00' },
                            { label: 'Low', key: 'LOW', color: '#3b82f6' },
                        ].map(({ label, key, color }) => (
                            <div key={key} className="card-glow flex items-center gap-4 px-5 py-4">
                                <div
                                    className="w-10 h-10 rounded-xl flex items-center justify-center flex-shrink-0"
                                    style={{ background: `${color}18`, border: `1px solid ${color}44` }}
                                >
                                    <span className="text-lg font-black" style={{ color }}>
                                        {stats?.severity_breakdown?.[key] ?? 0}
                                    </span>
                                </div>
                                <div className="flex-1 min-w-0">
                                    <div className="text-xs text-cyber-muted mb-1">{label} Severity</div>
                                    <div className="h-1.5 rounded-full" style={{ background: `${color}22` }}>
                                        <div
                                            className="h-full rounded-full transition-all duration-700"
                                            style={{
                                                width: `${Math.min(100, ((stats?.severity_breakdown?.[key] ?? 0) / Math.max(1, stats?.total_alerts ?? 1)) * 100)}%`,
                                                background: `linear-gradient(90deg, ${color}99, ${color})`,
                                                boxShadow: `0 0 6px ${color}55`,
                                            }}
                                        />
                                    </div>
                                </div>
                            </div>
                        ))}
                    </div>

                    {/* Row 3: Threat Distribution (full width) */}
                    <div className="card-glow">
                        <div className="text-sm font-semibold text-cyber-text mb-5 flex items-center gap-2">
                            <TrendingUp className="w-4 h-4 text-cyber-accent" />
                            Threat Type Distribution
                            <span className="ml-auto text-xs text-cyber-muted font-normal">sorted by frequency</span>
                        </div>
                        <ThreatDistributionChart threatBreakdown={stats?.threat_breakdown ?? {}} />
                    </div>

                    {/* Row 4: Timeline */}
                    <div className="card-glow">
                        <div className="text-sm font-semibold text-cyber-text mb-4 flex items-center gap-2">
                            <Activity className="w-4 h-4 text-cyber-accent" />
                            Alerts Timeline (Last 12 Hours)
                        </div>
                        <ResponsiveContainer width="100%" height={220}>
                            <AreaChart data={stats?.timeline ?? []}>
                                <defs>
                                    <linearGradient id="alertGrad" x1="0" y1="0" x2="0" y2="1">
                                        <stop offset="5%" stopColor="#00d4ff" stopOpacity={0.3} />
                                        <stop offset="95%" stopColor="#00d4ff" stopOpacity={0} />
                                    </linearGradient>
                                </defs>
                                <CartesianGrid strokeDasharray="3 3" stroke="#1e2d4a" />
                                <XAxis dataKey="hour" tick={{ fill: '#64748b', fontSize: 11 }} axisLine={false} tickLine={false} />
                                <YAxis tick={{ fill: '#64748b', fontSize: 11 }} axisLine={false} tickLine={false} />
                                <Tooltip content={<CustomTooltip />} />
                                <Area
                                    type="monotone"
                                    dataKey="alerts"
                                    stroke="#00d4ff"
                                    strokeWidth={2}
                                    fill="url(#alertGrad)"
                                    name="Alerts"
                                />
                            </AreaChart>
                        </ResponsiveContainer>
                    </div>
                </>
            )}
        </div>
    )
}
