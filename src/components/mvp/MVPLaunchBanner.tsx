import { useState } from 'react';
import { Card, CardContent } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { 
  Rocket, 
  Star, 
  Users, 
  Heart,
  ExternalLink,
  X,
  Sparkles,
  TrendingUp
} from 'lucide-react';

export const MVPLaunchBanner = () => {
  const [isVisible, setIsVisible] = useState(true);

  if (!isVisible) return null;

  return (
    <Card className="border-2 border-orange-500/30 bg-gradient-to-r from-orange-500/10 to-red-500/10 sticky top-0 z-30">
      <CardContent className="p-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center space-x-4">
            <div className="flex items-center space-x-2">
              <div className="p-2 bg-orange-500/20 rounded-lg animate-pulse">
                <Rocket className="h-5 w-5 text-orange-400" />
              </div>
              <div>
                <div className="flex items-center space-x-2">
                  <Badge variant="outline" className="text-orange-400 border-orange-400/50 bg-orange-500/10">
                    <Sparkles className="h-3 w-3 mr-1" />
                    MVP Launch
                  </Badge>
                  <span className="font-semibold text-orange-400">We're live on Product Hunt!</span>
                </div>
                <p className="text-sm text-muted-foreground hidden sm:block">
                  Help us reach #1 and get early access to exclusive features
                </p>
              </div>
            </div>
          </div>

          <div className="flex items-center space-x-3">
            {/* Product Hunt */}
            <Button
              variant="outline"
              size="sm"
              className="border-orange-500/30 text-orange-400 hover:bg-orange-500/20"
              onClick={() => globalThis.open('https://www.producthunt.com/', '_blank')}
            >
              <TrendingUp className="h-4 w-4 mr-2" />
              <span className="hidden sm:inline">Vote on</span> Product Hunt
              <ExternalLink className="h-3 w-3 ml-1" />
            </Button>

            {/* IndieHackers */}
            <Button
              variant="outline"
              size="sm"
              className="border-blue-500/30 text-blue-400 hover:bg-blue-500/20"
              onClick={() => globalThis.open('https://www.indiehackers.com/', '_blank')}
            >
              <Users className="h-4 w-4 mr-2" />
              <span className="hidden sm:inline">Follow on</span> IndieHackers
              <ExternalLink className="h-3 w-3 ml-1" />
            </Button>

            {/* Close */}
            <Button
              variant="ghost"
              size="sm"
              onClick={() => setIsVisible(false)}
              className="text-muted-foreground hover:text-foreground"
            >
              <X className="h-4 w-4" />
            </Button>
          </div>
        </div>

        {/* Mobile Actions */}
        <div className="sm:hidden mt-3 flex space-x-2">
          <Button
            variant="outline"
            size="sm"
            className="border-orange-500/30 text-orange-400 hover:bg-orange-500/20 flex-1"
            onClick={() => globalThis.open('https://www.producthunt.com/', '_blank')}
          >
            <Star className="h-4 w-4 mr-2" />
            Product Hunt
          </Button>
          <Button
            variant="outline"
            size="sm"
            className="border-blue-500/30 text-blue-400 hover:bg-blue-500/20 flex-1"
            onClick={() => globalThis.open('https://www.indiehackers.com/', '_blank')}
          >
            <Heart className="h-4 w-4 mr-2" />
            IndieHackers
          </Button>
        </div>
      </CardContent>
    </Card>
  );
};