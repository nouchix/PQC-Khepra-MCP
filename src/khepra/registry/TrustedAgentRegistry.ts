import { AdinkraAlgebraicEngine } from '../aae/AdinkraEngine';

export interface DigitalIdentityDocument {
  id: string;
  did: string;
  publicKey: string;
  culturalSignature: string;
  trustScore: number;
  adinkraContext: string;
  created: Date;
  expires: Date;
  revoked?: boolean;
}

export interface VerifiableCredential {
  id: string;
  issuer: string;
  subject: string;
  credentialType: 'agent_authorization' | 'tool_integration' | 'security_clearance';
  culturalProof: string;
  validUntil: Date;
  adinkraFingerprint: string;
}

export interface AgentRegistration {
  agentId: string;
  did: DigitalIdentityDocument;
  credentials: VerifiableCredential[];
  capabilities: string[];
  culturalContext: string;
  riskScore: number;
  lastVerified: Date;
}

export interface PostQuantumKeyPair {
  publicKey: Uint8Array;
  privateKey: Uint8Array;
  algorithm: 'kyber1024' | 'dilithium5';
  culturalSalt: string;
}

export class TrustedAgentRegistry {
  private static readonly REGISTRY_STORAGE_KEY = 'khepra:agent_registry';
  private static readonly TRUST_THRESHOLD = 70;

  /**
   * Generate DID (Decentralized Identifier) with cultural context
   */
  static generateDID(agentId: string, culturalContext: string): string {
    const culturalFingerprint = AdinkraAlgebraicEngine.generateFingerprint(
      `${agentId}:${culturalContext}:${Date.now()}`,
      ['Nyame', 'Eban']
    );
    return `did:khepra:${culturalFingerprint}`;
  }

  /**
   * Create digital identity document with Adinkra-based verification
   */
  static async createDigitalIdentity(
    agentId: string,
    culturalContext: string,
    publicKey: string
  ): Promise<DigitalIdentityDocument> {
    const did = this.generateDID(agentId, culturalContext);
    const culturalSignature = AdinkraAlgebraicEngine.generateFingerprint(
      `${did}:${publicKey}:${culturalContext}`,
      ['Fawohodie', 'Adwo']
    );

    // Calculate initial trust score based on cultural alignment
    const trustScore = this.calculateCulturalTrust(culturalContext, agentId);

    return {
      id: crypto.randomUUID(),
      did,
      publicKey,
      culturalSignature,
      trustScore,
      adinkraContext: culturalContext,
      created: new Date(),
      expires: new Date(Date.now() + (365 * 24 * 60 * 60 * 1000)), // 1 year
      revoked: false
    };
  }

  /**
   * Issue verifiable credential with cultural proof
   */
  static async issueCredential(
    issuerDID: string,
    subjectDID: string,
    credentialType: VerifiableCredential['credentialType'],
    culturalContext: string
  ): Promise<VerifiableCredential> {
    const credentialData = `${issuerDID}:${subjectDID}:${credentialType}:${culturalContext}`;
    
    // Generate cultural proof using appropriate Adinkra symbols
    const symbols = this.getSymbolsForCredentialType(credentialType);
    const culturalProof = AdinkraAlgebraicEngine.generateFingerprint(credentialData, symbols);
    
    // Create Adinkra fingerprint for verification
    const adinkraFingerprint = AdinkraAlgebraicEngine.generateFingerprint(
      `${credentialData}:${culturalProof}`,
      ['Nyame', 'Nkyinkyim']
    );

    return {
      id: crypto.randomUUID(),
      issuer: issuerDID,
      subject: subjectDID,
      credentialType,
      culturalProof,
      validUntil: new Date(Date.now() + (90 * 24 * 60 * 60 * 1000)), // 90 days
      adinkraFingerprint
    };
  }

  /**
   * Register new agent with cultural verification
   */
  static async registerAgent(
    agentId: string,
    publicKey: string,
    capabilities: string[],
    culturalContext: string
  ): Promise<AgentRegistration> {
    // Create DID
    const did = await this.createDigitalIdentity(agentId, culturalContext, publicKey);
    
    // Issue initial credentials
    const authCredential = await this.issueCredential(
      did.did,
      did.did,
      'agent_authorization',
      culturalContext
    );

    const registration: AgentRegistration = {
      agentId,
      did,
      credentials: [authCredential],
      capabilities,
      culturalContext,
      riskScore: this.calculateRiskScore(capabilities, culturalContext),
      lastVerified: new Date()
    };

    // Store in registry
    this.storeRegistration(registration);
    
    return registration;
  }

  /**
   * Verify agent with cultural signature validation
   */
  static async verifyAgent(agentId: string, challenge: string): Promise<boolean> {
    const registration = this.getRegistration(agentId);
    if (!registration) return false;

    // Check if DID is expired or revoked
    if (registration.did.expires < new Date() || registration.did.revoked) {
      return false;
    }

    // Verify cultural signature
    const expectedSignature = AdinkraAlgebraicEngine.generateFingerprint(
      `${registration.did.did}:${registration.did.publicKey}:${registration.culturalContext}`,
      ['Fawohodie', 'Adwo']
    );

    if (expectedSignature !== registration.did.culturalSignature) {
      return false;
    }

    // Check trust threshold
    if (registration.did.trustScore < this.TRUST_THRESHOLD) {
      return false;
    }

    // Verify challenge response with cultural context
    const _challengeResponse = AdinkraAlgebraicEngine.generateFingerprint(
      `${challenge}:${registration.agentId}:${registration.culturalContext}`,
      ['Eban', 'Nyame']
    );

    // In a real implementation, this would verify the agent's signature
    // For now, we simulate verification success if all checks pass
    return true;
  }

  /**
   * Update agent trust score based on behavior
   */
  static updateTrustScore(agentId: string, delta: number, reason: string): void {
    const registration = this.getRegistration(agentId);
    if (!registration) return;

    registration.did.trustScore = Math.max(0, Math.min(100, registration.did.trustScore + delta));
    registration.lastVerified = new Date();

    this.storeRegistration(registration);

    // Log trust update with cultural context
    console.log(`Trust score updated for ${agentId}: ${delta} (${reason})`);
  }

  /**
   * Generate post-quantum key pair with cultural enhancement
   *
   * SECURITY NOTE: This browser-side client previously generated `crypto.getRandomValues`
   * noise and labeled it as a real 'kyber1024'/'dilithium5' key pair (`PostQuantumKeyPair`),
   * even though no actual ML-KEM/ML-DSA key-generation algorithm was ever run. That output
   * was indistinguishable from a genuine PQC key pair to any caller, which is a serious
   * misrepresentation for a security feature advertised in the UI as "post-quantum security".
   * Real post-quantum key generation exists server-side (see pkg/adinkra/khepra_pqc.go,
   * pkg/license/pqc_signing.go) but is not yet exposed to this browser client. Until that
   * integration exists, this throws instead of fabricating key material, so callers cannot
   * mistake random bytes for real cryptography.
   */
  static async generatePostQuantumKeys(
    algorithm: PostQuantumKeyPair['algorithm'],
    _culturalContext: string
  ): Promise<PostQuantumKeyPair> {
    throw new Error(
      `Post-quantum key generation (${algorithm}) is not implemented in this browser client. ` +
      'Real ML-KEM/ML-DSA key generation must come from the Khepra backend crypto service; ' +
      'this client no longer fabricates random bytes mislabeled as real PQC keys.'
    );
  }

  /**
   * Perform post-quantum key exchange with cultural verification
   *
   * SECURITY NOTE: This previously returned `crypto.getRandomValues` noise XORed with a
   * cultural fingerprint and called it a Kyber-derived shared secret, without performing any
   * real KEM encapsulation/decapsulation. See the note on `generatePostQuantumKeys` above —
   * the same fix applies here: fail loudly instead of returning fake key material.
   */
  static async performKeyExchange(
    _initiatorKeys: PostQuantumKeyPair,
    _responderPublicKey: Uint8Array,
    _culturalContext: string
  ): Promise<Uint8Array> {
    throw new Error(
      'Post-quantum key exchange (Kyber encapsulation/decapsulation) is not implemented in ' +
      'this browser client. This client no longer fabricates a random "shared secret" in place ' +
      'of real KEM output.'
    );
  }

  /**
   * Get symbols appropriate for credential type
   */
  private static getSymbolsForCredentialType(type: VerifiableCredential['credentialType']): string[] {
    switch (type) {
      case 'agent_authorization': return ['Nyame', 'Eban'];
      case 'tool_integration': return ['Nkyinkyim', 'Fawohodie'];
      case 'security_clearance': return ['Eban', 'Adwo'];
      default: return ['Nyame', 'Fawohodie'];
    }
  }

  /**
   * Calculate cultural trust score
   */
  private static calculateCulturalTrust(culturalContext: string, agentId: string): number {
    const contextScore = {
      'security': 85,
      'trust': 90,
      'transformation': 75,
      'unity': 80
    }[culturalContext] || 70;

    // Add randomization based on agent characteristics
    const agentVariation = Math.abs(agentId.charCodeAt(0) - agentId.charCodeAt(agentId.length - 1)) % 20 - 10;
    
    return Math.max(0, Math.min(100, contextScore + agentVariation));
  }

  /**
   * Calculate risk score based on capabilities and cultural context
   */
  private static calculateRiskScore(capabilities: string[], culturalContext: string): number {
    let baseRisk = 30;
    
    // Higher risk for more powerful capabilities
    const riskFactors = {
      'system_modification': 25,
      'network_access': 15,
      'data_access': 20,
      'user_impersonation': 30,
      'administrative': 35
    };

    capabilities.forEach(cap => {
      baseRisk += riskFactors[cap] || 10;
    });

    // Cultural context can reduce risk
    const culturalMitigation = {
      'security': 15,
      'trust': 20,
      'transformation': 10,
      'unity': 12
    }[culturalContext] || 0;

    return Math.max(0, Math.min(100, baseRisk - culturalMitigation));
  }

  /**
   * Store registration in local storage (would be database in production)
   */
  private static storeRegistration(registration: AgentRegistration): void {
    const registry = this.getRegistry();
    registry[registration.agentId] = registration;
    localStorage.setItem(this.REGISTRY_STORAGE_KEY, JSON.stringify(registry));
  }

  /**
   * Get registration from storage
   */
  private static getRegistration(agentId: string): AgentRegistration | null {
    const registry = this.getRegistry();
    return registry[agentId] || null;
  }

  /**
   * Get full registry
   */
  private static getRegistry(): Record<string, AgentRegistration> {
    const stored = localStorage.getItem(this.REGISTRY_STORAGE_KEY);
    return stored ? JSON.parse(stored) : {};
  }

  /**
   * List all registered agents
   */
  static getAllRegistrations(): AgentRegistration[] {
    return Object.values(this.getRegistry());
  }

  /**
   * Revoke agent registration
   */
  static revokeAgent(agentId: string, reason: string): boolean {
    const registration = this.getRegistration(agentId);
    if (!registration) return false;

    registration.did.revoked = true;
    this.storeRegistration(registration);

    console.log(`Agent ${agentId} revoked: ${reason}`);
    return true;
  }
}