/**
 * Validate SHA-256 hash format
 */
export const isValidSHA256 = (hash: string): boolean => {
  return /^[a-fA-F0-9]{64}$/.test(hash);
};

/**
 * Validate SHA-512 hash format
 */
export const isValidSHA512 = (hash: string): boolean => {
  return /^[a-fA-F0-9]{128}$/.test(hash);
};

/**
 * Validate MD5 hash format
 */
export const isValidMD5 = (hash: string): boolean => {
  return /^[a-fA-F0-9]{32}$/.test(hash);
};

/**
 * Validate SHA-1 hash format
 */
export const isValidSHA1 = (hash: string): boolean => {
  return /^[a-fA-F0-9]{40}$/.test(hash);
};

/**
 * Validate any hash format
 */
export const isValidHash = (hash: string): boolean => {
  return isValidMD5(hash) || isValidSHA1(hash) || isValidSHA256(hash) || isValidSHA512(hash);
};

/**
 * Validate URL format
 */
export const isValidUrl = (url: string): boolean => {
  try {
    new URL(url);
    return true;
  } catch {
    return false;
  }
};

/**
 * Validate email format
 */
export const isValidEmail = (email: string): boolean => {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return emailRegex.test(email);
};

/**
 * Validate filename (no path traversal)
 */
export const isValidFilename = (filename: string): boolean => {
  // Disallow path traversal characters
  const invalidChars = /[<>:"|?*\\/]/;
  return !invalidChars.test(filename) && !filename.includes('..');
};

/**
 * Validate API key format
 */
export const isValidApiKey = (key: string): boolean => {
  // Basic validation: must be non-empty and reasonable length
  return key.length >= 32 && key.length <= 256;
};
