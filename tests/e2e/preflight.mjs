import { stopWorkspace } from './lifecycle.mjs';
// Never attach Playwright to an already initialized owner installation.
stopWorkspace();
