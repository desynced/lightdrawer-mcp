#!/usr/bin/env node
import { startServer } from './server.js';

startServer().catch((err) => {
  console.error(err && err.message ? err.message : err);
  process.exit(1);
});
