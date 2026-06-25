/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{ts,tsx}'],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        surface: {
          base: '#0b0f17',
          panel: '#111722',
          card: '#151c2a',
          raised: '#1b2433',
          border: '#222c3d',
          hover: '#1f293a',
        },
      },
      fontFamily: {
        sans: ['Inter', 'system-ui', '-apple-system', 'Segoe UI', 'Roboto', 'sans-serif'],
        mono: ['ui-monospace', 'SFMono-Regular', 'Menlo', 'Monaco', 'Consolas', 'monospace'],
      },
      boxShadow: {
        card: '0 1px 2px 0 rgba(0,0,0,0.3), 0 1px 3px 0 rgba(0,0,0,0.2)',
      },
    },
  },
  plugins: [],
}
