/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        dark: {
          900: '#070d19',
          800: '#0b1528',
          700: '#0f1c33',
          600: '#172745',
          500: '#1e335a',
        },
      },
    },
  },
  plugins: [],
}
