import { AdinkraAlgebraicEngine } from '../aae/AdinkraEngine';

export interface DAGNode {
  id: string;
  agentId: string;
  action: string;
  symbol: string;
  timestamp: Date;
  inputs: string[];
  outputs: string[];
  metadata: Record<string, any>;
  trustScore: number;
  culturalContext: string;
}

export interface DAGEdge {
  from: string;
  to: string;
  weight: number;
  transformationType: string;
  verified: boolean;
}

export interface AgentInteraction {
  sourceAgent: string;
  targetAgent: string;
  action: string;
  culturalSignature: string;
  trustLevel: number;
  timestamp: Date;
  success: boolean;
}

export class AgentDAG {
  private nodes: Map<string, DAGNode> = new Map();
  private edges: Map<string, DAGEdge> = new Map();
  private interactions: AgentInteraction[] = [];

  /**
   * Add new agent action to the DAG
   */
  addAgentAction(
    agentId: string,
    action: string,
    culturalContext: string = 'security',
    metadata: Record<string, any> = {}
  ): string {
    const timestamp = Date.now();
    const nodeId = AdinkraAlgebraicEngine.generateNodeId(agentId, action, timestamp);

    // Select appropriate Adinkra symbol based on context
    const symbol = AdinkraAlgebraicEngine.getSymbolByContext(
      culturalContext as 'security' | 'trust' | 'transformation' | 'unity'
    );

    const node: DAGNode = {
      id: nodeId,
      agentId,
      action,
      symbol: symbol.name,
      timestamp: new Date(),
      inputs: [],
      outputs: [],
      metadata: {
        ...metadata,
        culturalMeaning: symbol.meaning,
        symbolCategory: symbol.category
      },
      trustScore: 0,
      culturalContext
    };

    this.nodes.set(nodeId, node);
    this.updateTrustScores();

    return nodeId;
  }

  /**
   * Create connection between two agent actions
   */
  createConnection(fromNodeId: string, toNodeId: string, transformationType: string = 'trust_flow'): boolean {
    const fromNode = this.nodes.get(fromNodeId);
    const toNode = this.nodes.get(toNodeId);

    if (!fromNode || !toNode) {
      return false;
    }

    // Verify cultural compatibility using Adinkra transformations
    const compatibility = this.verifyCulturalCompatibility(fromNode, toNode);

    const edgeId = `${fromNodeId}->${toNodeId}`;
    const edge: DAGEdge = {
      from: fromNodeId,
      to: toNodeId,
      weight: compatibility,
      transformationType,
      verified: compatibility > 0.7
    };

    this.edges.set(edgeId, edge);

    // Update node connections
    fromNode.outputs.push(toNodeId);
    toNode.inputs.push(fromNodeId);

    return edge.verified;
  }

  /**
   * Record agent-to-agent interaction with cultural signature
   */
  recordInteraction(
    sourceAgent: string,
    targetAgent: string,
    action: string,
    success: boolean = true
  ): void {
    // Generate cultural signature using Adinkra encoding
    const interactionData = `${sourceAgent}:${targetAgent}:${action}:${Date.now()}`;
    const culturalSignature = AdinkraAlgebraicEngine.generateFingerprint(
      interactionData,
      ['Nyame', 'Fawohodie'] // Authority + Freedom symbols
    );

    // Calculate trust level based on interaction history
    const trustLevel = this.calculateInteractionTrust(sourceAgent, targetAgent);

    const interaction: AgentInteraction = {
      sourceAgent,
      targetAgent,
      action,
      culturalSignature,
      trustLevel,
      timestamp: new Date(),
      success
    };

    this.interactions.push(interaction);
    this.updateTrustScores();
  }

  /**
   * Validate agent authorization using DAG path analysis
   */
  validateAgentAuthorization(agentId: string, requestedAction: string): boolean {
    // Find all paths to this agent
    const agentNodes = this.getAgentNodes(agentId);

    if (agentNodes.length === 0) {
      return false; // Unknown agent
    }

    // Calculate cumulative trust score
    const totalTrustScore = agentNodes.reduce((sum, node) => sum + node.trustScore, 0) / agentNodes.length;

    // Check for privilege escalation patterns
    const hasEscalationPattern = this.detectPrivilegeEscalation(agentId, requestedAction);

    // Validate using cultural context
    const culturalValidation = this.validateCulturalContext(agentId, requestedAction);

    return totalTrustScore > 75 && !hasEscalationPattern && culturalValidation;
  }

  /**
   * Generate security audit trail with cultural context
   */
  generateAuditTrail(agentId?: string): any[] {
    const relevantNodes = agentId
      ? this.getAgentNodes(agentId)
      : Array.from(this.nodes.values());

    return relevantNodes.map(node => ({
      nodeId: node.id,
      agentId: node.agentId,
      action: node.action,
      culturalSymbol: node.symbol,
      culturalMeaning: node.metadata.culturalMeaning,
      trustScore: node.trustScore,
      timestamp: node.timestamp,
      connections: {
        inputs: node.inputs.length,
        outputs: node.outputs.length
      },
      culturalValidation: this.validateNodeCulturalIntegrity(node)
    }));
  }

  /**
   * Detect anomalous patterns in agent behavior
   */
  detectAnomalies(agentId: string): any[] {
    const agentNodes = this.getAgentNodes(agentId);
    const anomalies: any[] = [];

    // Check for rapid action sequences
    const recentActions = agentNodes
      .filter(node => Date.now() - node.timestamp.getTime() < 300000) // Last 5 minutes
      .length;

    if (recentActions > 10) {
      anomalies.push({
        type: 'rapid_actions',
        severity: 'high',
        description: 'Unusual rapid action sequence detected',
        count: recentActions
      });
    }

    // Check for cultural context violations
    const culturalViolations = agentNodes.filter(node =>
      !this.validateNodeCulturalIntegrity(node)
    ).length;

    if (culturalViolations > 0) {
      anomalies.push({
        type: 'cultural_violation',
        severity: 'medium',
        description: 'Cultural context integrity violations detected',
        count: culturalViolations
      });
    }

    // Check for trust score degradation
    const avgTrustScore = agentNodes.reduce((sum, node) => sum + node.trustScore, 0) / agentNodes.length;
    if (avgTrustScore < 50) {
      anomalies.push({
        type: 'trust_degradation',
        severity: 'high',
        description: 'Agent trust score has degraded significantly',
        currentScore: avgTrustScore
      });
    }

    return anomalies;
  }

  private verifyCulturalCompatibility(nodeA: DAGNode, nodeB: DAGNode): number {
    // Check if symbols are culturally compatible
    const symbolA = AdinkraAlgebraicEngine.getAllSymbols()[nodeA.symbol];
    const symbolB = AdinkraAlgebraicEngine.getAllSymbols()[nodeB.symbol];

    if (!symbolA || !symbolB) return 0;

    // Same category symbols have higher compatibility
    if (symbolA.category === symbolB.category) {
      return 0.9;
    }

    // Cross-category compatibility matrix
    const compatibilityMatrix: Record<string, Record<string, number>> = {
      'protection': { 'wisdom': 0.8, 'strength': 0.9, 'unity': 0.7, 'transformation': 0.6 },
      'wisdom': { 'protection': 0.8, 'strength': 0.7, 'unity': 0.9, 'transformation': 0.8 },
      'strength': { 'protection': 0.9, 'wisdom': 0.7, 'unity': 0.6, 'transformation': 0.5 },
      'unity': { 'protection': 0.7, 'wisdom': 0.9, 'strength': 0.6, 'transformation': 0.8 },
      'transformation': { 'protection': 0.6, 'wisdom': 0.8, 'strength': 0.5, 'unity': 0.8 }
    };

    return compatibilityMatrix[symbolA.category]?.[symbolB.category] || 0.5;
  }

  private updateTrustScores(): void {
    for (const node of this.nodes.values()) {
      // Calculate trust based on connections and interactions
      const incomingTrust = node.inputs.length * 5;
      const outgoingTrust = node.outputs.length * 3;
      const interactionTrust = this.calculateNodeInteractionTrust(node.agentId);

      node.trustScore = Math.min(100, incomingTrust + outgoingTrust + interactionTrust);
    }
  }

  private calculateInteractionTrust(sourceAgent: string, targetAgent: string): number {
    const relevantInteractions = this.interactions.filter(
      interaction =>
        (interaction.sourceAgent === sourceAgent && interaction.targetAgent === targetAgent) ||
        (interaction.sourceAgent === targetAgent && interaction.targetAgent === sourceAgent)
    );

    if (relevantInteractions.length === 0) return 50; // Neutral for new relationships

    const successRate = relevantInteractions.filter(i => i.success).length / relevantInteractions.length;
    return Math.round(successRate * 100);
  }

  private calculateNodeInteractionTrust(agentId: string): number {
    const agentInteractions = this.interactions.filter(
      interaction => interaction.sourceAgent === agentId || interaction.targetAgent === agentId
    );

    if (agentInteractions.length === 0) return 25;

    const successRate = agentInteractions.filter(i => i.success).length / agentInteractions.length;
    return Math.round(successRate * 50); // Max 50 points from interactions
  }

  private getAgentNodes(agentId: string): DAGNode[] {
    return Array.from(this.nodes.values()).filter(node => node.agentId === agentId);
  }

  private detectPrivilegeEscalation(agentId: string, action: string): boolean {
    const recentActions = this.getAgentNodes(agentId)
      .filter(node => Date.now() - node.timestamp.getTime() < 3600000) // Last hour
      .map(node => node.action);

    // Simple pattern detection for privilege escalation
    const escalationPatterns = [
      'admin_access', 'role_modification', 'permission_grant', 'system_override'
    ];

    return escalationPatterns.some(pattern =>
      recentActions.filter(action => action.includes(pattern)).length > 2
    );
  }

  private validateCulturalContext(agentId: string, action: string): boolean {
    // Validate that the action is culturally appropriate for the agent's context
    const agentNodes = this.getAgentNodes(agentId);

    if (agentNodes.length === 0) return false;

    const recentNode = agentNodes[agentNodes.length - 1];
    const symbol = AdinkraAlgebraicEngine.getAllSymbols()[recentNode.symbol];

    // Define action-symbol compatibility
    const actionCompatibility: Record<string, string[]> = {
      'protection': ['security_scan', 'threat_analysis', 'access_control'],
      'wisdom': ['policy_analysis', 'decision_making', 'audit_review'],
      'transformation': ['system_update', 'configuration_change', 'remediation'],
      'unity': ['collaboration', 'data_sharing', 'consensus_building'],
      'strength': ['enforcement', 'blocking', 'isolation']
    };

    const compatibleActions = actionCompatibility[symbol.category] || [];
    return compatibleActions.some(compatibleAction => action.includes(compatibleAction));
  }

  private validateNodeCulturalIntegrity(node: DAGNode): boolean {
    try {
      // Verify the cultural signature hasn't been tampered with
      const expectedId = AdinkraAlgebraicEngine.generateNodeId(
        node.agentId,
        node.action,
        node.timestamp.getTime()
      );
      return node.id === expectedId;
    } catch {
      return false;
    }
  }

  /**
   * Resolve conflict between two competing agent actions using symbol precedence
   * Precedence: Eban (3) > Fawohodie (2) > Nkyinkyim (1)
   */
  resolveSymbolConflict(nodeIdA: string, nodeIdB: string): string {
    const nodeA = this.nodes.get(nodeIdA);
    const nodeB = this.nodes.get(nodeIdB);

    if (!nodeA) return nodeIdB;
    if (!nodeB) return nodeIdA;

    const precedence: Record<string, number> = {
      'Eban': 3,
      'Fawohodie': 2,
      'Nkyinkyim': 1
    };

    const scoreA = precedence[nodeA.symbol] || 0;
    const scoreB = precedence[nodeB.symbol] || 0;

    if (scoreA > scoreB) return nodeIdA;
    if (scoreB > scoreA) return nodeIdB;

    // Tie-break: highest trust score win
    return nodeA.trustScore >= nodeB.trustScore ? nodeIdA : nodeIdB;
  }

  /**
   * Export DAG state for visualization or storage
   */
  exportState(): any {
    return {
      nodes: Array.from(this.nodes.values()),
      edges: Array.from(this.edges.values()),
      interactions: this.interactions,
      metadata: {
        totalNodes: this.nodes.size,
        totalEdges: this.edges.size,
        totalInteractions: this.interactions.length,
        exportedAt: new Date()
      }
    };
  }
}