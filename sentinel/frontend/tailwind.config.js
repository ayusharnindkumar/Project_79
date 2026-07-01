/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,jsx,ts,tsx}'],
  theme: {
    extend: {
      colors: {
        'bg-deep':    '#060d1a',
        'bg-dark':    '#080f1e',
        'bg-panel':   '#0d1b2e',
        'bg-surface': '#0f2040',
        'bg-hover':   '#152848',
        'c-cyan':     '#00d4ff',
        'c-green':    '#00ff88',
        'c-red':      '#ff3d3d',
        'c-orange':   '#ff6b35',
        'c-gold':     '#ffd700',
        'c-purple':   '#bf5fff',
        'c-blue':     '#4488ff',
        't-primary':  '#e0e8ff',
        't-secondary':'#8aa0c0',
        't-muted':    '#4a607a',
        'b-subtle':   'rgba(0,200,255,0.10)',
        'b-accent':   'rgba(0,212,255,0.25)',
      },
      fontFamily: {
        sans: ['Inter', 'system-ui', 'sans-serif'],
        mono: ['"JetBrains Mono"', '"Fira Code"', 'monospace'],
      },
      animation: {
        'pulse-glow':  'pulseGlow 2s ease-in-out infinite',
        'spin-slow':   'spin 4s linear infinite',
        'fade-in':     'fadeIn 0.4s ease-out',
        'slide-in':    'slideIn 0.3s ease-out',
        'bounce-in':   'bounceIn 0.5s cubic-bezier(0.68,-0.55,0.265,1.55)',
        'alert-flash': 'alertFlash 0.6s ease-in-out',
        'scan-line':   'scanLine 2s linear infinite',
      },
      keyframes: {
        pulseGlow: {
          '0%, 100%': { opacity: '1',  boxShadow: '0 0 8px rgba(255,61,61,0.4)' },
          '50%':      { opacity: '0.6',boxShadow: '0 0 20px rgba(255,61,61,0.8)' },
        },
        fadeIn: {
          '0%':   { opacity: '0', transform: 'translateY(8px)' },
          '100%': { opacity: '1', transform: 'translateY(0)'   },
        },
        slideIn: {
          '0%':   { opacity: '0', transform: 'translateX(16px)' },
          '100%': { opacity: '1', transform: 'translateX(0)'    },
        },
        bounceIn: {
          '0%':   { opacity: '0', transform: 'scale(0.85)' },
          '100%': { opacity: '1', transform: 'scale(1)'    },
        },
        alertFlash: {
          '0%, 100%': { backgroundColor: 'transparent' },
          '25%, 75%': { backgroundColor: 'rgba(255,61,61,0.12)' },
        },
        scanLine: {
          '0%':   { top: '0%',   opacity: '1'  },
          '80%':  { top: '100%', opacity: '0.5'},
          '100%': { top: '100%', opacity: '0'  },
        },
      },
      boxShadow: {
        'panel':       '0 0 0 1px rgba(0,200,255,0.08), 0 4px 24px rgba(0,0,0,0.4)',
        'panel-hover': '0 0 0 1px rgba(0,212,255,0.25), 0 8px 32px rgba(0,0,0,0.5)',
        'glow-cyan':   '0 0 20px rgba(0,212,255,0.3)',
        'glow-green':  '0 0 20px rgba(0,255,136,0.3)',
        'glow-red':    '0 0 20px rgba(255,61,61,0.4)',
        'inset-top':   'inset 0 1px 0 rgba(255,255,255,0.05)',
      },
      backdropBlur: { xs: '2px' },
    },
  },
  plugins: [],
};
