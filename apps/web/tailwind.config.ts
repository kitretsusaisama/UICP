import type { Config } from 'tailwindcss';

const config: Config = {
  content: ['./app/**/*.{ts,tsx}', './components/**/*.{ts,tsx}', './lib/**/*.{ts,tsx}'],
  theme: {
    extend: {
      colors: {
        surface: '#f7f8fa',
        ink: '#16181d',
        background: '#f7f8fa',
        foreground: '#16181d',
        border: '#e1e4e8',
        input: '#e1e4e8',
        muted: {
          DEFAULT: '#f1f3f5',
          foreground: '#868e96',
        },
        accent: {
          DEFAULT: '#228be6',
          foreground: '#ffffff',
        },
        primary: '#16181d',
        secondary: '#495057',
        destructive: {
          DEFAULT: '#fa5252',
          foreground: '#ffffff',
        },
        danger: '#b42318',
      },
    },
  },
  plugins: [],
};

export default config;
