// vite.config.js
import { defineConfig, loadEnv } from "vite";

export default ({ mode }) => {
  // Load environment variables based on the current mode (development, production, etc.)
  const env = loadEnv(mode, process.cwd());

  // Merge loaded environment variables into process.env
  process.env = { ...process.env, ...env };

  return defineConfig({
    // Your existing Vite configuration

    ssr: {
      noExternal: false, // Disable noExternal to allow externalization
    },
  });
};
