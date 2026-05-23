import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/card';

const CommandCenter = () => {
  return (
    <div className="min-h-screen bg-background p-6">
      <Card>
        <CardHeader>
          <CardTitle>Command Center</CardTitle>
        </CardHeader>
        <CardContent>
          <p className="text-muted-foreground">
            Command Center dashboard coming soon...
          </p>
        </CardContent>
      </Card>
    </div>
  );
};

export default CommandCenter;
