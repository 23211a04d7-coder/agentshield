import axios from 'axios'

const API_BASE = import.meta.env.VITE_API_URL || 'http://localhost:8000'

const api = axios.create({
    baseURL: API_BASE,
    timeout: 10000,
})

export const fetchAlerts = (params = {}) =>
    api.get('/alerts', { params }).then(r => r.data)

export const fetchStats = () =>
    api.get('/stats').then(r => r.data)

export const fetchRiskScore = () =>
    api.get('/risk-score').then(r => r.data)

export const fetchLogs = (params = {}) =>
    api.get('/logs', { params }).then(r => r.data)

export const ingestLogs = (logs = null) =>
    api.post('/logs', logs).then(r => r.data)

export const blockAlert = (alertId) =>
    api.post(`/alerts/${alertId}/block`).then(r => r.data)

export default api
