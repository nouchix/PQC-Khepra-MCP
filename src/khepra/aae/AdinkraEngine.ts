export interface AdinkraSymbol {
  name: string;
  meaning: string;
  matrix: number[][];
  category: 'protection' | 'wisdom' | 'strength' | 'unity' | 'transformation';
}

export interface AdinkraTransformation {
  symbol: string;
  input: number[];
  output: number[];
  timestamp: Date;
  context?: string;
}

export class AdinkraAlgebraicEngine {
  private static readonly SYMBOLS: Record<string, AdinkraSymbol> = {
    'Eban': {
      name: 'Eban',
      meaning: 'Fortress - Security and Protection',
      matrix: [[0, 1], [1, 0]],
      category: 'protection'
    },
    'Fawohodie': {
      name: 'Fawohodie',
      meaning: 'Emancipation - Freedom and Liberation',
      matrix: [[1, 1], [0, 1]],
      category: 'transformation'
    },
    'Nkyinkyim': {
      name: 'Nkyinkyim',
      meaning: 'Journey - Dynamism and Adaptability',
      matrix: [[0, 1], [1, 1]],
      category: 'transformation'
    },
    'Nyame': {
      name: 'Nyame',
      meaning: 'Supreme Being - Authority and Trust',
      matrix: [[1, 0, 1], [0, 1, 0], [1, 0, 1]],
      category: 'wisdom'
    },
    'Adwo': {
      name: 'Adwo',
      meaning: 'Peace - Harmony and Balance',
      matrix: [[1, 0], [0, 1]],
      category: 'unity'
    }
  };

  /**
   * Transform input vector using Adinkra symbol matrix
   */
  static transform(symbolName: string, inputVector: number[]): number[] {
    const symbol = this.SYMBOLS[symbolName];
    if (!symbol) {
      throw new Error(`Unknown Adinkra symbol: ${symbolName}`);
    }

    const matrix = symbol.matrix;
    const matrixSize = matrix.length;
    
    // Ensure input vector matches matrix dimensions
    if (inputVector.length !== matrix[0].length) {
      throw new Error(`Input vector dimension mismatch for symbol ${symbolName}`);
    }

    // Perform matrix multiplication in ℤ₂ (binary field)
    const result: number[] = [];
    for (let i = 0; i < matrixSize; i++) {
      let sum = 0;
      for (let j = 0; j < inputVector.length; j++) {
        sum += matrix[i][j] * inputVector[j];
      }
      result.push(sum % 2); // Modulo 2 for binary field
    }

    return result;
  }

  /**
   * Generate cryptographic fingerprint using Adinkra transformations
   */
  static generateFingerprint(data: string, symbols: string[] = ['Eban', 'Fawohodie']): string {
    // Convert string to binary vector
    const binaryData = this.stringToBinary(data);

    let currentVector = binaryData;
    const transformationPath: string[] = [];

    // Apply multiple Adinkra transformations
    for (const symbolName of symbols) {
      const symbol = this.SYMBOLS[symbolName];
      if (!symbol) throw new Error(`Unknown Adinkra symbol: ${symbolName}`);
      // Resize vector to match the symbol's expected input dimension before transforming
      currentVector = this.resizeVector(currentVector, symbol.matrix[0].length);
      currentVector = this.transform(symbolName, currentVector);
      transformationPath.push(symbolName);
    }

    // Convert result to hex string
    const fingerprint = this.binaryToHex(currentVector);
    
    return `khepra:${transformationPath.join('-')}:${fingerprint}`;
  }

  /**
   * Validate and verify Adinkra-based authentication token
   */
  static validateToken(token: string, originalData: string): boolean {
    const parts = token.split(':');
    if (parts[0] !== 'khepra' || parts.length !== 3) {
      return false;
    }

    const symbols = parts[1].split('-');
    const expectedFingerprint = this.generateFingerprint(originalData, symbols);
    
    return token === expectedFingerprint;
  }

  /**
   * Get symbol by cultural context
   */
  static getSymbolByContext(context: 'security' | 'trust' | 'transformation' | 'unity'): AdinkraSymbol {
    const contextMap = {
      'security': 'Eban',
      'trust': 'Nyame', 
      'transformation': 'Nkyinkyim',
      'unity': 'Adwo'
    };

    const symbolName = contextMap[context];
    return this.SYMBOLS[symbolName];
  }

  /**
   * Generate DAG node identifier using Adinkra encoding
   */
  static generateNodeId(agentId: string, action: string, timestamp: number): string {
    const input = `${agentId}:${action}:${timestamp}`;
    return this.generateFingerprint(input, ['Nyame', 'Eban']);
  }

  /**
   * Calculate cultural trust score based on Adinkra transformations
   */
  static calculateTrustScore(interactions: AdinkraTransformation[]): number {
    if (interactions.length === 0) return 0;

    let totalScore = 0;
    let validTransformations = 0;

    for (const interaction of interactions) {
      const symbol = this.SYMBOLS[interaction.symbol];
      if (!symbol) continue;

      // Base score from symbol category
      let score = this.getCategoryScore(symbol.category);
      
      // Adjust based on transformation success
      const transformationValid = this.validateTransformation(interaction);
      if (transformationValid) {
        score *= 1.2; // Bonus for valid transformations
        validTransformations++;
      } else {
        score *= 0.5; // Penalty for invalid transformations
      }

      totalScore += score;
    }

    // Normalize score between 0 and 100
    const avgScore = totalScore / interactions.length;
    const validityBonus = (validTransformations / interactions.length) * 20;
    
    return Math.min(100, Math.max(0, avgScore + validityBonus));
  }

  private static getCategoryScore(category: AdinkraSymbol['category']): number {
    const scores = {
      'protection': 85,
      'wisdom': 90,
      'strength': 80,
      'unity': 75,
      'transformation': 70
    };
    return scores[category];
  }

  private static validateTransformation(interaction: AdinkraTransformation): boolean {
    try {
      const expectedOutput = this.transform(interaction.symbol, interaction.input);
      return JSON.stringify(expectedOutput) === JSON.stringify(interaction.output);
    } catch {
      return false;
    }
  }

  // XOR-folds or zero-pads vec to targetLen so it can be fed to any symbol matrix
  private static resizeVector(vec: number[], targetLen: number): number[] {
    if (vec.length === targetLen) return vec;
    if (vec.length < targetLen) {
      return [...vec, ...new Array(targetLen - vec.length).fill(0)];
    }
    const result = vec.slice(0, targetLen);
    for (let i = targetLen; i < vec.length; i++) {
      result[i % targetLen] ^= vec[i];
    }
    return result;
  }

  private static stringToBinary(str: string): number[] {
    const binary: number[] = [];
    for (let i = 0; i < str.length; i++) {
      const charCode = str.charCodeAt(i);
      for (let j = 7; j >= 0; j--) {
        binary.push((charCode >> j) & 1);
      }
    }
    // Ensure even length for matrix operations
    while (binary.length % 2 !== 0) {
      binary.push(0);
    }
    return binary.slice(0, 16); // Limit to manageable size
  }

  private static binaryToHex(binary: number[]): string {
    let hex = '';
    for (let i = 0; i < binary.length; i += 4) {
      const nibble = binary.slice(i, i + 4);
      while (nibble.length < 4) nibble.push(0);
      const value = nibble.reduce((acc, bit, idx) => acc + bit * Math.pow(2, 3 - idx), 0);
      hex += value.toString(16);
    }
    return hex;
  }

  /**
   * Get all available symbols
   */
  static getAllSymbols(): Record<string, AdinkraSymbol> {
    return { ...this.SYMBOLS };
  }
}