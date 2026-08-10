// Tailwind v4 moved its PostCSS plugin into a separate package; referencing
// `tailwindcss` directly here fails the build.
export default {
  plugins: {
    "@tailwindcss/postcss": {},
    autoprefixer: {},
  },
};
