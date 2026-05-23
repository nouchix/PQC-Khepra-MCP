

export interface RateLimitConfig {
  apiProvider: string;
  endpoint: string;
  maxRequestsPerHour: number;
  maxRequestsPerDay: number;
  maxTokensPerHour?: number;
  maxTokensPerDay?: number;
}

export interface RateLimitResult {
  allowed: boolean;
  reason?: string;
  resetTime?: Date;
  remainingRequests?: number;
  remainingTokens?: number;
}

class RateLimitingService {
  private static instance: RateLimitingService;
  private readonly limitConfigs: Map<string, RateLimitConfig> = new Map();

  static getInstance(): RateLimitingService {
    if (!RateLimitingService.instance) {
      RateLimitingService.instance = new RateLimitingService();
    }
    return RateLimitingService.instance;
  }

  // Initialize with default rate limits for known APIs
  constructor() {
    this.initializeDefaultLimits();
  }

  private initializeDefaultLimits() {
    // OpenAI API limits
    this.limitConfigs.set('openai:chat/completions', {
      apiProvider: 'openai',
      endpoint: 'chat/completions',
      maxRequestsPerHour: 500,
      maxRequestsPerDay: 10000,
      maxTokensPerHour: 150000,
      maxTokensPerDay: 2000000
    });

    // Grok AI limits
    this.limitConfigs.set('grok:v1/chat/completions', {
      apiProvider: 'grok',
      endpoint: 'v1/chat/completions',
      maxRequestsPerHour: 300,
      maxRequestsPerDay: 5000,
      maxTokensPerHour: 100000,
      maxTokensPerDay: 1000000
    });

    // Security tool APIs
    this.limitConfigs.set('shodan:host/search', {
      apiProvider: 'shodan',
      endpoint: 'host/search',
      maxRequestsPerHour: 100,
      maxRequestsPerDay: 1000
    });

    this.limitConfigs.set('virustotal:files/scan', {
      apiProvider: 'virustotal',
      endpoint: 'files/scan',
      maxRequestsPerHour: 200,
      maxRequestsPerDay: 2000
    });
  }

  // Check if request is within rate limits
  async checkRateLimit(
    organizationId: string,
    apiProvider: string,
    endpoint: string,
    tokensRequested: number = 0
  ): Promise<RateLimitResult> {
    const key = `${apiProvider}:${endpoint}`;
    const config = this.limitConfigs.get(key);

    if (!config) {
      // No limits configured, allow request
      return { allowed: true };
    }

    try {
      const usageData: any[] = [];

      const now = new Date();
      const hourAgo = new Date(now.getTime() - 60 * 60 * 1000);

      // Calculate usage in current hour and day
      const hourlyRequests = usageData.filter((u: any) =>
        new Date(u.created_at) > hourAgo
      ).length;

      const dailyRequests = usageData.length;

      const hourlyTokens = usageData
        .filter((u: any) => new Date(u.created_at) > hourAgo)
        .reduce((sum: number, u: any) => sum + (u.tokens_used || 0), 0);

      const dailyTokens = usageData
        .reduce((sum: number, u: any) => sum + (u.tokens_used || 0), 0);

      // Check request limits
      if (hourlyRequests >= config.maxRequestsPerHour) {
        return {
          allowed: false,
          reason: `Hourly request limit exceeded (${config.maxRequestsPerHour}/hour)`,
          resetTime: new Date(Math.ceil(now.getTime() / (60 * 60 * 1000)) * (60 * 60 * 1000))
        };
      }

      if (dailyRequests >= config.maxRequestsPerDay) {
        return {
          allowed: false,
          reason: `Daily request limit exceeded (${config.maxRequestsPerDay}/day)`,
          resetTime: new Date(now.getFullYear(), now.getMonth(), now.getDate() + 1)
        };
      }

      // Check token limits if applicable
      if (config.maxTokensPerHour && (hourlyTokens + tokensRequested) > config.maxTokensPerHour) {
        return {
          allowed: false,
          reason: `Hourly token limit exceeded (${config.maxTokensPerHour}/hour)`,
          resetTime: new Date(Math.ceil(now.getTime() / (60 * 60 * 1000)) * (60 * 60 * 1000))
        };
      }

      if (config.maxTokensPerDay && (dailyTokens + tokensRequested) > config.maxTokensPerDay) {
        return {
          allowed: false,
          reason: `Daily token limit exceeded (${config.maxTokensPerDay}/day)`,
          resetTime: new Date(now.getFullYear(), now.getMonth(), now.getDate() + 1)
        };
      }

      return {
        allowed: true,
        remainingRequests: Math.min(
          config.maxRequestsPerHour - hourlyRequests,
          config.maxRequestsPerDay - dailyRequests
        ),
        remainingTokens: config.maxTokensPerHour ?
          Math.min(
            config.maxTokensPerHour - hourlyTokens,
            (config.maxTokensPerDay || Infinity) - dailyTokens
          ) : undefined
      };

    } catch (error) {
      console.error('Rate limiting error:', error);
      return { allowed: true }; // Fail open on errors
    }
  }

  // Record rate limit hit for monitoring
  async recordRateLimitHit(
    organizationId: string,
    apiProvider: string,
    endpoint: string,
    limitType: string
  ) {
    try {
      // Mock implementation until tables are available
      console.log('Recording rate limit hit:', {
        organizationId,
        apiProvider,
        endpoint,
        limitType,
        timestamp: new Date().toISOString()
      });
    } catch (error) {
      console.error('Failed to record rate limit hit:', error);
    }
  }

  // Update rate limit configuration
  updateLimitConfig(apiProvider: string, endpoint: string, config: RateLimitConfig) {
    const key = `${apiProvider}:${endpoint}`;
    this.limitConfigs.set(key, config);
  }

  // Get current configuration
  getLimitConfig(apiProvider: string, endpoint: string): RateLimitConfig | undefined {
    const key = `${apiProvider}:${endpoint}`;
    return this.limitConfigs.get(key);
  }
}

export const rateLimitingService = RateLimitingService.getInstance();