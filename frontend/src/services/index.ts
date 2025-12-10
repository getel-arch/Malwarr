// Imports for legacy malwarrApi export
import { systemService } from './systemService';
import { samplesService } from './samplesService';
import { analysisService } from './analysisService';
import { statsService } from './statsService';

// Re-export all services for convenient importing
export { systemService } from './systemService';
export { samplesService } from './samplesService';
export { analysisService } from './analysisService';
export { statsService } from './statsService';
export { tasksService } from './tasksService';
export { capaService } from './capaService';
export { searchService } from './searchService';
export { setApiKey, clearApiKey, getApiKey } from './config';

// Legacy export for backward compatibility (can be removed after migration)
export const malwarrApi = {
  ...systemService,
  ...samplesService,
  ...analysisService,
  ...statsService,
};
