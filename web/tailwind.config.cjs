/** @type {import('tailwindcss').Config} */

// Palette policy
// --------------
// `primary` is the single accent. It is indigo because indigo was already the de
// facto accent (60 uses across the tree) while the previous `primary` scale --
// a blue ramp -- had zero uses anywhere; the token existed but every view reached
// past it for a raw Tailwind colour instead. blue/violet/sky/cyan/teal usages
// converge here.
//
// The semantic ramps below are NOT decorative aliases. Each one carries a fixed
// meaning that the UI relies on, so they must stay distinguishable from `primary`
// and from each other:
//
//   success -> online / ready / delivered
//   warning -> pending / degraded / retrying
//   danger  -> offline / failed / destructive action
//   neutral -> surfaces, borders, muted text
//
// 500 in each ramp is kept in step with the matching Element Plus --el-color-*
// default so a Tailwind-styled control and an el-* control placed side by side
// do not read as two different shades of the same intent.
module.exports = {
  content: ['./index.html', './src/**/*.{vue,js,ts,jsx,tsx}'],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        primary: {
          50: '#eef2ff',
          100: '#e0e7ff',
          200: '#c7d2fe',
          300: '#a5b4fc',
          400: '#818cf8',
          500: '#6366f1',
          600: '#4f46e5',
          700: '#4338ca',
          800: '#3730a3',
          900: '#312e81',
          950: '#1e1b4b'
        },
        success: {
          50: '#ecfdf5',
          100: '#d1fae5',
          200: '#a7f3d0',
          300: '#6ee7b7',
          400: '#34d399',
          500: '#10b981',
          600: '#059669',
          700: '#047857',
          800: '#065f46',
          900: '#064e3b',
          950: '#022c22'
        },
        warning: {
          50: '#fffbeb',
          100: '#fef3c7',
          200: '#fde68a',
          300: '#fcd34d',
          400: '#fbbf24',
          500: '#f59e0b',
          600: '#d97706',
          700: '#b45309',
          800: '#92400e',
          900: '#78350f',
          950: '#451a03'
        },
        danger: {
          50: '#fef2f2',
          100: '#fee2e2',
          200: '#fecaca',
          300: '#fca5a5',
          400: '#f87171',
          500: '#ef4444',
          600: '#dc2626',
          700: '#b91c1c',
          800: '#991b1b',
          900: '#7f1d1d',
          950: '#450a0a'
        }
      },
      fontFamily: {
        sans: ['Inter', 'system-ui', 'sans-serif']
      }
    }
  },
  plugins: []
}
