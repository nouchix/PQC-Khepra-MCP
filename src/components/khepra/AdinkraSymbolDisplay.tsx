import { useEffect, useState } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip';
import { AdinkraAlgebraicEngine, AdinkraSymbol } from '@/khepra/aae/AdinkraEngine';

interface AdinkraSymbolDisplayProps {
  symbolName?: string;
  showMatrix?: boolean;
  showMeaning?: boolean;
  className?: string;
  size?: 'small' | 'medium' | 'large';
}

export const AdinkraSymbolDisplay: React.FC<AdinkraSymbolDisplayProps> = ({
  symbolName,
  showMatrix = false,
  showMeaning = true,
  className = '',
  size = 'medium'
}) => {
  const symbols = AdinkraAlgebraicEngine.getAllSymbols();
  const currentSymbol = symbolName ? symbols[symbolName] : null;

  const getCategoryColor = (category: AdinkraSymbol['category']) => {
    const colors = {
      'protection': 'bg-blue-500/20 text-blue-300 border-blue-500/30',
      'wisdom': 'bg-purple-500/20 text-purple-300 border-purple-500/30',
      'strength': 'bg-red-500/20 text-red-300 border-red-500/30',
      'unity': 'bg-green-500/20 text-green-300 border-green-500/30',
      'transformation': 'bg-yellow-500/20 text-yellow-300 border-yellow-500/30'
    };
    return colors[category];
  };

  const getSizeClasses = () => {
    switch (size) {
      case 'small': return 'w-16 h-16 text-xs';
      case 'large': return 'w-24 h-24 text-lg';
      default: return 'w-20 h-20 text-sm';
    }
  };

  const renderMatrix = (matrix: number[][]) => {
    return (
      <div className="inline-block font-mono text-sm">
        <div className="border border-muted rounded p-2 bg-muted/10">
          {matrix.map((row, i) => (
            <div key={i} className="flex space-x-1">
              {row.map((cell, j) => (
                <span key={j} className="w-6 text-center">
                  {cell}
                </span>
              ))}
            </div>
          ))}
        </div>
      </div>
    );
  };

  if (currentSymbol) {
    return (
      <Card className={`border-primary/20 bg-card/50 backdrop-blur-sm ${className}`}>
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <CardTitle className="text-lg font-semibold">{currentSymbol.name}</CardTitle>
            <Badge className={getCategoryColor(currentSymbol.category)}>
              {currentSymbol.category}
            </Badge>
          </div>
        </CardHeader>
        <CardContent className="space-y-3">
          {showMeaning && (
            <p className="text-sm text-muted-foreground italic">
              {currentSymbol.meaning}
            </p>
          )}
          
          {showMatrix && (
            <div className="space-y-2">
              <p className="text-sm font-medium">Transformation Matrix:</p>
              {renderMatrix(currentSymbol.matrix)}
            </div>
          )}
          
          <div className="flex items-center space-x-2 text-xs text-muted-foreground">
            <span>Dimensions: {currentSymbol.matrix.length}×{currentSymbol.matrix[0].length}</span>
            <span>•</span>
            <span>Binary Field: ℤ₂</span>
          </div>
        </CardContent>
      </Card>
    );
  }

  // Display all symbols in a grid
  return (
    <div className={`grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4 ${className}`}>
      {Object.entries(symbols).map(([name, symbol]) => (
        <Tooltip key={name}>
          <TooltipTrigger asChild>
            <Card className="border-primary/20 bg-card/50 backdrop-blur-sm hover:bg-card/70 transition-colors cursor-help">
              <CardHeader className="pb-2">
                <div className="flex items-center justify-between">
                  <CardTitle className="text-base font-medium">{symbol.name}</CardTitle>
                  <Badge className={getCategoryColor(symbol.category)} variant="outline">
                    {symbol.category}
                  </Badge>
                </div>
              </CardHeader>
              <CardContent>
                {showMeaning && (
                  <p className="text-xs text-muted-foreground mb-2 line-clamp-2">
                    {symbol.meaning}
                  </p>
                )}
                
                {showMatrix && (
                  <div className="mt-2">
                    {renderMatrix(symbol.matrix)}
                  </div>
                )}
                
                <div className="flex items-center justify-between text-xs text-muted-foreground mt-2">
                  <span>{symbol.matrix.length}×{symbol.matrix[0].length}</span>
                  <span>ℤ₂</span>
                </div>
              </CardContent>
            </Card>
          </TooltipTrigger>
          <TooltipContent side="top" className="max-w-sm">
            <div className="space-y-2">
              <p className="font-semibold">{symbol.name}</p>
              <p className="text-sm">{symbol.meaning}</p>
              <div className="space-y-1">
                <p className="text-xs font-medium">Matrix:</p>
                {renderMatrix(symbol.matrix)}
              </div>
            </div>
          </TooltipContent>
        </Tooltip>
      ))}
    </div>
  );
};