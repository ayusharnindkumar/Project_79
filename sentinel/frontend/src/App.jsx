import { useState } from 'react'
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom'
import Sidebar from './components/layout/Sidebar'
import TopBar  from './components/layout/TopBar'
import Dashboard  from './pages/Dashboard'
import Prediction from './pages/Prediction'
import BatchUpload from './pages/BatchUpload'
import Simulation  from './pages/Simulation'
import History     from './pages/History'
import Database    from './pages/Database'

export default function App() {
  return (
    <BrowserRouter>
      <AppShell />
    </BrowserRouter>
  )
}

function AppShell() {
  const [navOpen, setNavOpen] = useState(false)

  return (
    <div className="relative flex h-screen overflow-hidden bg-bg-deep">
      <div className="command-grid" />
      <div className="signal-sweep" />
      {navOpen && (
        <button
          className="fixed inset-0 z-30 bg-black/60 backdrop-blur-sm lg:hidden"
          aria-label="Close navigation"
          onClick={() => setNavOpen(false)}
        />
      )}
      <Sidebar open={navOpen} onClose={() => setNavOpen(false)} />

      <div className="relative z-10 flex flex-col flex-1 min-w-0 overflow-hidden">
        <TopBar onMenu={() => setNavOpen(true)} />
        <main className="flex-1 overflow-y-auto p-4 md:p-5 lg:p-6">
          <Routes>
            <Route path="/"           element={<Navigate to="/dashboard" replace />} />
            <Route path="/dashboard"  element={<Dashboard />} />
            <Route path="/predict"    element={<Prediction />} />
            <Route path="/batch"      element={<BatchUpload />} />
            <Route path="/simulation" element={<Simulation />} />
            <Route path="/history"    element={<History />} />
            <Route path="/database"   element={<Database />} />
          </Routes>
        </main>
      </div>
    </div>
  )
}
