import { Routes, Route, NavLink, useLocation } from 'react-router-dom'
import { Shield, Activity, AlertTriangle, Cpu, Radio } from 'lucide-react'
import Dashboard from './pages/Dashboard'
import ThreatMonitor from './pages/ThreatMonitor'

function App() {
    return (
        <div className="flex min-h-screen">
            {/* Sidebar */}
            <aside className="w-64 flex-shrink-0 border-r border-cyber-border bg-cyber-surface flex flex-col">
                {/* Logo */}
                <div className="p-6 border-b border-cyber-border">
                    <div className="flex items-center gap-3">
                        <div className="w-9 h-9 rounded-lg flex items-center justify-center"
                            style={{ background: 'linear-gradient(135deg, #00d4ff33, #7c3aed33)', border: '1px solid rgba(0,212,255,0.3)' }}>
                            <Shield className="w-5 h-5 text-cyber-accent" />
                        </div>
                        <div>
                            <div className="text-sm font-bold text-cyber-text tracking-wide">AgentShield</div>
                            <div className="text-xs text-cyber-muted">Security Operations</div>
                        </div>
                    </div>
                </div>

                {/* Status indicator */}
                <div className="px-4 py-3 mx-4 mt-4 rounded-lg" style={{ background: 'rgba(0,255,136,0.05)', border: '1px solid rgba(0,255,136,0.15)' }}>
                    <div className="flex items-center gap-2">
                        <span className="pulse-dot bg-cyber-green" style={{ color: '#00ff88' }} />
                        <span className="text-xs text-cyber-green font-medium">GATEWAY ACTIVE</span>
                    </div>
                    <div className="text-xs text-cyber-muted mt-1">No agents on endpoints</div>
                </div>

                {/* Navigation */}
                <nav className="flex-1 p-4 space-y-1 mt-2">
                    <div className="text-xs font-semibold text-cyber-muted uppercase tracking-widest px-4 mb-3">Navigation</div>
                    <NavLink
                        to="/"
                        end
                        className={({ isActive }) => `nav-link ${isActive ? 'active' : ''}`}
                    >
                        <Activity className="w-4 h-4" />
                        Dashboard
                    </NavLink>
                    <NavLink
                        to="/threats"
                        className={({ isActive }) => `nav-link ${isActive ? 'active' : ''}`}
                    >
                        <AlertTriangle className="w-4 h-4" />
                        Threat Monitor
                    </NavLink>
                </nav>

                {/* Footer */}
                <div className="p-4 border-t border-cyber-border">
                    <div className="text-xs text-cyber-muted text-center">
                        <div className="font-mono">v1.0.0 · Agentless PoC</div>
                    </div>
                </div>
            </aside>

            {/* Main content */}
            <main className="flex-1 overflow-auto">
                <Routes>
                    <Route path="/" element={<Dashboard />} />
                    <Route path="/threats" element={<ThreatMonitor />} />
                </Routes>
            </main>
        </div>
    )
}

export default App
