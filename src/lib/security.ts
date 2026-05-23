// Security utilities for input validation and sanitization

export interface ValidationRule {
  required?: boolean;
  type?: 'string' | 'number' | 'email' | 'uuid' | 'json' | 'sql_safe';
  minLength?: number;
  maxLength?: number;
  pattern?: RegExp;
  allowedValues?: string[];
  sanitize?: boolean;
}

export interface ValidationSchema {
  [key: string]: ValidationRule;
}

export class SecurityValidator {
  private static readonly SQL_INJECTION_PATTERNS = [
    /(\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|EXECUTE|UNION|SCRIPT)\b)/gi,
    /(;|--|\*|\/\*|\*\/)/g,
    /(\b(OR|AND)\s+\d+\s*=\s*\d+)/gi,
    /(\b(OR|AND)\s+['"]?\w+['"]?\s*=\s*['"]?\w+['"]?)/gi,
    /(WAITFOR|DELAY|BENCHMARK|SLEEP)/gi,
    /(XP_|SP_)/gi,
    /(\bUNION\b.*\bSELECT\b)/gi
  ];

  private static readonly XSS_PATTERNS = [
    /<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi,
    /<iframe\b[^<]*(?:(?!<\/iframe>)<[^<]*)*<\/iframe>/gi,
    /javascript:/gi,
    /on\w+\s*=/gi,
    /<\s*\/?\s*(script|iframe|object|embed|form|img|svg|math)\b/gi,
    /data:text\/html/gi,
    /vbscript:/gi
  ];

  private static readonly COMMAND_INJECTION_PATTERNS = [
    /(\||&|;|\$\(|`)/g,
    /(wget|curl|nc|netcat|bash|sh|cmd|powershell)/gi,
    /(\.\.|\/etc\/|\/bin\/|\/usr\/)/gi
  ];

  /**
   * Validates input against security patterns and business rules
   */
  static validate(input: any, schema: ValidationSchema): { isValid: boolean; errors: string[]; sanitized?: any } {
    const errors: string[] = [];
    const sanitized: any = {};

    if (typeof input !== 'object' || input === null) {
      return { isValid: false, errors: ['Input must be an object'] };
    }

    for (const [field, rule] of Object.entries(schema)) {
      const value = input[field];
      const fieldErrors = this.validateField(field, value, rule);

      if (fieldErrors.length > 0) {
        errors.push(...fieldErrors);
      } else {
        sanitized[field] = rule.sanitize ? this.sanitizeInput(value, rule.type) : value;
      }
    }

    return {
      isValid: errors.length === 0,
      errors,
      sanitized: errors.length === 0 ? sanitized : undefined
    };
  }

  /**
   * Validates a single field against its rule
   */
  private static validateField(field: string, value: any, rule: ValidationRule): string[] {
    const errors: string[] = [];

    // Required check
    if (rule.required && (value === undefined || value === null || value === '')) {
      errors.push(`${field} is required`);
      return errors;
    }

    // Skip further validation if field is not required and empty
    if (!rule.required && (value === undefined || value === null || value === '')) {
      return errors;
    }

    // Type validation
    if (rule.type) {
      const typeError = this.validateType(field, value, rule.type);
      if (typeError) {
        errors.push(typeError);
        return errors; // Don't continue if type is wrong
      }
    }

    // Length validation
    if (typeof value === 'string') {
      if (rule.minLength && value.length < rule.minLength) {
        errors.push(`${field} must be at least ${rule.minLength} characters`);
      }
      if (rule.maxLength && value.length > rule.maxLength) {
        errors.push(`${field} must be no more than ${rule.maxLength} characters`);
      }
    }

    // Pattern validation
    if (rule.pattern && typeof value === 'string' && !rule.pattern.test(value)) {
      errors.push(`${field} format is invalid`);
    }

    // Allowed values
    if (rule.allowedValues && !rule.allowedValues.includes(value)) {
      errors.push(`${field} must be one of: ${rule.allowedValues.join(', ')}`);
    }

    // Security pattern checks
    if (typeof value === 'string') {
      const securityError = this.checkSecurityPatterns(field, value);
      if (securityError) {
        errors.push(securityError);
      }
    }

    return errors;
  }

  /**
   * Validates data type
   */
  private static validateType(field: string, value: any, type: string): string | null {
    switch (type) {
      case 'string':
        if (typeof value !== 'string') {
          return `${field} must be a string`;
        }
        break;
      case 'number':
        if (typeof value !== 'number' || isNaN(value)) {
          return `${field} must be a valid number`;
        }
        break;
      case 'email':
        if (typeof value !== 'string' || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value)) {
          return `${field} must be a valid email address`;
        }
        break;
      case 'uuid':
        if (typeof value !== 'string' || !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(value)) {
          return `${field} must be a valid UUID`;
        }
        break;
      case 'json':
        if (typeof value === 'string') {
          try {
            JSON.parse(value);
          } catch {
            return `${field} must be valid JSON`;
          }
        } else if (typeof value !== 'object') {
          return `${field} must be a valid JSON object`;
        }
        break;
      case 'sql_safe':
        if (typeof value === 'string' && this.SQL_INJECTION_PATTERNS.some(pattern => pattern.test(value))) {
          return `${field} contains potentially dangerous content`;
        }
        break;
    }
    return null;
  }

  /**
   * Checks for security attack patterns
   */
  private static checkSecurityPatterns(field: string, value: string): string | null {
    // SQL Injection check
    if (this.SQL_INJECTION_PATTERNS.some(pattern => pattern.test(value))) {
      return `${field} contains potentially malicious SQL patterns`;
    }

    // XSS check
    if (this.XSS_PATTERNS.some(pattern => pattern.test(value))) {
      return `${field} contains potentially malicious script content`;
    }

    // Command injection check
    if (this.COMMAND_INJECTION_PATTERNS.some(pattern => pattern.test(value))) {
      return `${field} contains potentially dangerous command patterns`;
    }

    // Path traversal check
    if (value.includes('../') || value.includes('..\\')) {
      return `${field} contains potentially dangerous path traversal patterns`;
    }

    return null;
  }

  /**
   * Sanitizes input based on type
   */
  static sanitizeInput(value: any, type?: string): any {
    if (typeof value !== 'string') {
      return value;
    }

    let sanitized = value;

    // HTML encode special characters
    sanitized = sanitized
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#x27;')
      .replace(/\//g, '&#x2F;');

    // Remove null bytes
    sanitized = sanitized.replace(/\0/g, '');

    // Normalize unicode
    sanitized = sanitized.normalize('NFKC');

    // Trim whitespace
    sanitized = sanitized.trim();

    // Type-specific sanitization
    if (type === 'email') {
      sanitized = sanitized.toLowerCase();
    }

    return sanitized;
  }

  /**
   * Rate limiting helper
   */
  static createRateLimiter(maxRequests: number, windowMs: number) {
    const requests = new Map<string, number[]>();
    let callCount = 0;

    return (identifier: string): boolean => {
      const now = Date.now();
      const windowStart = now - windowMs;

      // Get or create request history for this identifier
      const userRequests = requests.get(identifier) || [];

      // Remove old requests outside the window
      const recentRequests = userRequests.filter(time => time > windowStart);

      // Check if limit exceeded
      if (recentRequests.length >= maxRequests) {
        return false;
      }

      // Add current request
      recentRequests.push(now);
      requests.set(identifier, recentRequests);

      // Cleanup old entries every 100 calls (deterministic, no Math.random)
      callCount++;
      if (callCount % 100 === 0) {
        for (const [key, times] of requests.entries()) {
          const recentTimes = times.filter(time => time > windowStart);
          if (recentTimes.length === 0) {
            requests.delete(key);
          } else {
            requests.set(key, recentTimes);
          }
        }
      }

      return true;
    };
  }

  /**
   * Generate secure random token
   */
  static generateSecureToken(length: number = 32): string {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    let result = '';
    const randomArray = new Uint8Array(length);
    crypto.getRandomValues(randomArray);

    for (let i = 0; i < length; i++) {
      result += chars[randomArray[i] % chars.length];
    }

    return result;
  }

  /**
   * Hash sensitive data
   */
  static async hashSensitiveData(data: string, salt?: string): Promise<string> {
    const encoder = new TextEncoder();
    const saltBytes = salt ? encoder.encode(salt) : crypto.getRandomValues(new Uint8Array(16));
    const dataBytes = encoder.encode(data);

    const combined = new Uint8Array(saltBytes.length + dataBytes.length);
    combined.set(saltBytes);
    combined.set(dataBytes, saltBytes.length);

    const hashBuffer = await crypto.subtle.digest('SHA-256', combined);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');

    return hashHex;
  }
}

// Common validation schemas
export const commonSchemas = {
  userMessage: {
    message: { required: true, type: 'string' as const, maxLength: 5000, sanitize: true },
    sessionId: { required: true, type: 'uuid' as const },
    organizationId: { required: true, type: 'uuid' as const },
    userId: { required: true, type: 'uuid' as const }
  },

  alertData: {
    title: { required: true, type: 'string' as const, maxLength: 200, sanitize: true },
    description: { type: 'string' as const, maxLength: 2000, sanitize: true },
    severity: { required: true, type: 'string' as const, allowedValues: ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'] },
    alert_type: { required: true, type: 'string' as const, maxLength: 50, sanitize: true },
    source_type: { required: true, type: 'string' as const, maxLength: 50, sanitize: true }
  },

  webhookPayload: {
    source: { required: true, type: 'string' as const, maxLength: 100, sanitize: true },
    event_type: { required: true, type: 'string' as const, maxLength: 100, sanitize: true },
    timestamp: { required: true, type: 'string' as const },
    data: { required: true, type: 'json' as const }
  }
};

// Export default instance
export default SecurityValidator;