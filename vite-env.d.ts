// vite-env.d.ts
/// <reference types="vite/client" />

interface ImportMetaEnv {
  readonly VITE_BASE_API_URL: string;
  readonly VITE_API_KEY: string;
  readonly VITE_ACCOUNT_ID: string;
  // Add any other custom environment variables here
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}
