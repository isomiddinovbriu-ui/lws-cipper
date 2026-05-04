import { ReactNode } from 'react';
import { NavLink } from 'react-router-dom';
import { useDarkMode } from '../hooks/useDarkMode';
import clsx from 'clsx';

interface LayoutProps {
  children: ReactNode;
}

const navItems = [
  { to: '/', label: 'Home', icon: '🏠' },
  { to: '/encrypt', label: 'Encrypt', icon: '🔒' },
  { to: '/decrypt', label: 'Decrypt', icon: '🔓' },
  { to: '/benchmark', label: 'Benchmark', icon: '📊' },
  { to: '/algorithms', label: 'Algorithms', icon: '🧬' },
];

export default function Layout({ children }: LayoutProps) {
  const [isDark, toggleDark] = useDarkMode();

  return (
    <div className={clsx('min-h-screen transition-colors duration-300', isDark ? 'dark bg-dark-900' : 'bg-slate-100')}>
      {/* Navigation */}
      <nav className={clsx(
        'sticky top-0 z-50 border-b backdrop-blur-xl',
        isDark
          ? 'bg-dark-900/90 border-slate-700/50'
          : 'bg-white/90 border-slate-200'
      )}>
        <div className="max-w-7xl mx-auto px-4 sm:px-6">
          <div className="flex items-center justify-between h-16">
            {/* Logo */}
            <NavLink to="/" className="flex items-center gap-3">
              <div className="w-8 h-8 rounded-lg bg-gradient-to-br from-primary-500 to-accent-500 flex items-center justify-center text-white font-bold text-sm shadow-lg">
                C
              </div>
              <span className={clsx('font-bold text-lg', isDark ? 'text-gradient' : 'text-slate-800')}>
                CryptoPlatform
              </span>
            </NavLink>

            {/* Nav Links */}
            <div className="hidden md:flex items-center gap-1">
              {navItems.map(item => (
                <NavLink
                  key={item.to}
                  to={item.to}
                  end={item.to === '/'}
                  className={({ isActive }) =>
                    clsx(
                      'flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium transition-all duration-200',
                      isActive
                        ? 'bg-primary-600 text-white shadow-lg shadow-primary-500/25'
                        : isDark
                        ? 'text-slate-400 hover:text-slate-200 hover:bg-slate-700/50'
                        : 'text-slate-600 hover:text-slate-900 hover:bg-slate-100'
                    )
                  }
                >
                  <span className="text-base">{item.icon}</span>
                  {item.label}
                </NavLink>
              ))}
            </div>

            {/* Dark mode toggle */}
            <button
              onClick={toggleDark}
              className={clsx(
                'p-2 rounded-lg transition-all duration-200',
                isDark
                  ? 'text-slate-400 hover:text-slate-200 hover:bg-slate-700/50'
                  : 'text-slate-500 hover:text-slate-800 hover:bg-slate-100'
              )}
              title={isDark ? 'Switch to light mode' : 'Switch to dark mode'}
            >
              {isDark ? '☀️' : '🌙'}
            </button>
          </div>
        </div>

        {/* Mobile nav */}
        <div className="md:hidden flex overflow-x-auto border-t border-slate-700/30 px-2 pb-2">
          {navItems.map(item => (
            <NavLink
              key={item.to}
              to={item.to}
              end={item.to === '/'}
              className={({ isActive }) =>
                clsx(
                  'flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium whitespace-nowrap mr-1',
                  isActive ? 'bg-primary-600 text-white' : 'text-slate-400 hover:text-slate-200'
                )
              }
            >
              {item.icon} {item.label}
            </NavLink>
          ))}
        </div>
      </nav>

      {/* Main content */}
      <main className="max-w-7xl mx-auto px-4 sm:px-6 py-8">
        {children}
      </main>

      {/* Footer */}
      <footer className={clsx(
        'border-t mt-16 py-8 text-center text-sm',
        isDark ? 'border-slate-700/50 text-slate-500' : 'border-slate-200 text-slate-400'
      )}>
        <p>CryptoPlatform — Lightweight Cipher Analysis Suite</p>
        <p className="mt-1 text-xs">Trivium · Grain-128AEAD · MICKEY-v2 · ChaCha20 · Ascon-AEAD128</p>
      </footer>
    </div>
  );
}
