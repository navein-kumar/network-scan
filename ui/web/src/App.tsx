// Root component: error boundary -> toast provider -> hash router -> app shell
// with the page routes. Hash routing keeps the app self-contained behind the
// Go server (URLs look like #/scans).
import { Component, type ReactNode } from 'react'
import { HashRouter, Routes, Route, Navigate } from 'react-router-dom'
import { Layout } from './Layout'
import { ToastProvider } from './toast'
import Dashboard from './pages/Dashboard'
import NewScan from './pages/NewScan'
import Scans from './pages/Scans'
import ScanDetail from './pages/ScanDetail'
import Settings from './pages/Settings'

class ErrorBoundary extends Component<{ children: ReactNode }, { error: Error | null }> {
  state = { error: null as Error | null }

  static getDerivedStateFromError(error: Error) {
    return { error }
  }

  componentDidCatch(error: Error, info: unknown) {
    console.error('Unhandled UI error:', error, info)
  }

  render() {
    if (this.state.error) {
      return (
        <div className="flex min-h-screen flex-col items-center justify-center gap-4 bg-surface-base px-6 text-center">
          <h1 className="text-xl font-semibold text-red-300">Something went wrong</h1>
          <p className="max-w-md text-sm text-slate-400">
            The interface hit an unexpected error. You can reload to recover.
          </p>
          <pre className="max-w-lg overflow-auto rounded-md border border-surface-border bg-surface-card p-3 text-left font-mono text-xs text-slate-500">
            {this.state.error.message}
          </pre>
          <button
            onClick={() => window.location.reload()}
            className="rounded-md bg-blue-600 px-4 py-2 text-sm font-semibold text-white hover:bg-blue-500"
          >
            Reload
          </button>
        </div>
      )
    }
    return this.props.children
  }
}

export default function App() {
  return (
    <ErrorBoundary>
      <ToastProvider>
        <HashRouter>
          <Layout>
            <Routes>
              <Route path="/" element={<Dashboard />} />
              <Route path="/scan/new" element={<NewScan />} />
              <Route path="/scans" element={<Scans />} />
              <Route path="/scan/:id" element={<ScanDetail />} />
              <Route path="/settings" element={<Settings />} />
              <Route path="*" element={<Navigate to="/" replace />} />
            </Routes>
          </Layout>
        </HashRouter>
      </ToastProvider>
    </ErrorBoundary>
  )
}
