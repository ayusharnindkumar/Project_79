import axios from 'axios'

const api = axios.create({
  baseURL: '/api',
  timeout: 30000,
  headers: { 'Content-Type': 'application/json' },
})

export const predictSingle  = (record)       => api.post('/predict', record)
export const predictBatch   = (formData)     => api.post('/batch', formData, { headers: { 'Content-Type': 'multipart/form-data' }, timeout: 120000 })
export const getStats       = ()             => api.get('/stats')
export const getHistory     = (params = {})  => api.get('/history', { params })
export const getAnalytics   = (period)       => api.get('/analytics', { params: { period } })
export const getDatabaseInfo = ()            => api.get('/database/info')
export const getHealth      = ()             => api.get('/health')

/** Build SSE URL for simulation stream. Use native EventSource. */
export const getSimulateURL = (speed = 1, count = 200, attackRate = 0.3) =>
  `/api/simulate/stream?speed=${speed}&count=${count}&attack_rate=${attackRate}`

export default api
