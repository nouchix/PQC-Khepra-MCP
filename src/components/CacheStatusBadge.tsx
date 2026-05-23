import { useState } from 'react';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle, DialogTrigger } from '@/components/ui/dialog';
import { RefreshCw, Trash2, Info, CheckCircle, AlertCircle } from 'lucide-react';
import { useCacheManager } from '@/hooks/useCacheManager';
import { formatDistanceToNow } from 'date-fns';

const CacheStatusBadge = () => {
  const [isOpen, setIsOpen] = useState(false);
  const { isUpdateAvailable, lastCheck, checkForUpdates, forceUpdate, clearCache } = useCacheManager();

  const getBadgeVariant = () => {
    if (isUpdateAvailable) return 'destructive';
    return 'secondary';
  };

  const getBadgeIcon = () => {
    if (isUpdateAvailable) return <AlertCircle className="h-3 w-3 mr-1" />;
    return <CheckCircle className="h-3 w-3 mr-1" />;
  };

  const getBadgeText = () => {
    if (isUpdateAvailable) return 'Update Available';
    return 'Up to Date';
  };

  return (
    <Dialog open={isOpen} onOpenChange={setIsOpen}>
      <DialogTrigger asChild>
        <Badge 
          variant={getBadgeVariant()} 
          className="cursor-pointer hover:opacity-80 transition-opacity"
        >
          {getBadgeIcon()}
          {getBadgeText()}
        </Badge>
      </DialogTrigger>
      
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <Info className="h-5 w-5" />
            Cache Management
          </DialogTitle>
          <DialogDescription>
            Manage application cache and check for updates
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-4">
          <Card>
            <CardHeader className="pb-3">
              <CardTitle className="text-sm">Status</CardTitle>
            </CardHeader>
            <CardContent className="space-y-2">
              <div className="flex items-center justify-between">
                <span className="text-sm text-muted-foreground">Cache Status:</span>
                <Badge variant={getBadgeVariant()}>
                  {getBadgeIcon()}
                  {getBadgeText()}
                </Badge>
              </div>
              {lastCheck && (
                <div className="flex items-center justify-between">
                  <span className="text-sm text-muted-foreground">Last Check:</span>
                  <span className="text-sm">
                    {formatDistanceToNow(lastCheck, { addSuffix: true })}
                  </span>
                </div>
              )}
            </CardContent>
          </Card>

          {isUpdateAvailable && (
            <Card className="border-orange-200 bg-orange-50">
              <CardHeader className="pb-3">
                <CardTitle className="text-sm text-orange-800">Update Available</CardTitle>
                <CardDescription className="text-orange-700">
                  A new version of the application is available. Update now to get the latest features and bug fixes.
                </CardDescription>
              </CardHeader>
            </Card>
          )}
        </div>

        <DialogFooter className="flex-col sm:flex-row gap-2">
          <Button
            variant="outline"
            onClick={checkForUpdates}
            className="flex items-center gap-2"
          >
            <RefreshCw className="h-4 w-4" />
            Check for Updates
          </Button>
          
          <Button
            variant="outline"
            onClick={clearCache}
            className="flex items-center gap-2"
          >
            <Trash2 className="h-4 w-4" />
            Clear Cache
          </Button>
          
          {isUpdateAvailable && (
            <Button
              onClick={() => {
                forceUpdate();
                setIsOpen(false);
              }}
              className="flex items-center gap-2"
            >
              <RefreshCw className="h-4 w-4" />
              Update Now
            </Button>
          )}
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
};

export default CacheStatusBadge;