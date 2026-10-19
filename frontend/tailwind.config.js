/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        'soc-dark': '#0f172a',
        'soc-darker': '#020617',
        'soc-card': '#1e293b',
        'soc-border': '#334155',
        'soc-accent': '#3b82f6',
        'soc-success': '#22c55e',
        'soc-warning': '#f59e0b',
        'soc-danger': '#ef4444',
        'soc-critical': '#dc2626'
      }
    },
  },
  plugins: [],
}
