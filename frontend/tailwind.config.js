/** @type {import('tailwindcss').Config} */
export default {
    content: [
        "./index.html",
        "./src/**/*.{js,ts,jsx,tsx}",
    ],
    theme: {
        extend: {
            colors: {
                cyber: {
                    bg: '#0a0e1a',
                    surface: '#0f1629',
                    card: '#131d35',
                    border: '#1e2d4a',
                    accent: '#00d4ff',
                    accent2: '#7c3aed',
                    green: '#00ff88',
                    red: '#ff3366',
                    yellow: '#ffcc00',
                    blue: '#3b82f6',
                    text: '#e2e8f0',
                    muted: '#64748b',
                }
            },
            fontFamily: {
                sans: ['Inter', 'system-ui', 'sans-serif'],
                mono: ['JetBrains Mono', 'monospace'],
            },
            animation: {
                'pulse-slow': 'pulse 3s cubic-bezier(0.4, 0, 0.6, 1) infinite',
                'glow': 'glow 2s ease-in-out infinite alternate',
                'scan': 'scan 2s linear infinite',
            },
            keyframes: {
                glow: {
                    '0%': { boxShadow: '0 0 5px #00d4ff33' },
                    '100%': { boxShadow: '0 0 20px #00d4ff88, 0 0 40px #00d4ff33' },
                },
                scan: {
                    '0%': { transform: 'translateY(-100%)' },
                    '100%': { transform: 'translateY(100vh)' },
                }
            }
        },
    },
    plugins: [],
}
