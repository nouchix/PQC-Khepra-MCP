import { useState } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Textarea } from '@/components/ui/textarea';
import { Badge } from '@/components/ui/badge';
import { Progress } from '@/components/ui/progress';
import { 
  Users, 
  MessageSquare, 
  Target, 
  TrendingUp,
  Plus,
  Calendar,
  Phone,
  Mail,
  Building2
} from 'lucide-react';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';

interface CustomerInterview {
  id: string;
  companyName: string;
  contactName: string;
  title: string;
  email: string;
  phone?: string;
  segment: string;
  status: 'scheduled' | 'completed' | 'cancelled';
  date: string;
  painPoints: string[];
  valueProposition: string;
  followUpActions: string[];
  score: number;
}

export const CustomerDiscoveryTool = () => {
  const [interviews, setInterviews] = useState<CustomerInterview[]>([
    {
      id: '1',
      companyName: 'Lockheed Martin',
      contactName: 'Sarah Johnson',
      title: 'CISO',
      email: 'sarah.johnson@lmco.com',
      phone: '+1-555-0123',
      segment: 'Defense Contractors',
      status: 'completed',
      date: '2024-01-15',
      painPoints: ['CMMC Compliance', 'Supply Chain Security', 'Audit Preparation'],
      valueProposition: 'Automated CMMC compliance reduces audit prep time by 80%',
      followUpActions: ['Send ROI calculator', 'Schedule technical demo', 'Connect with procurement'],
      score: 8.5
    },
    {
      id: '2',
      companyName: 'Microsoft Corporation',
      contactName: 'David Chen',
      title: 'VP Security',
      email: 'david.chen@microsoft.com',
      segment: 'Enterprise',
      status: 'scheduled',
      date: '2024-01-22',
      painPoints: ['Zero Trust Implementation', 'Threat Intelligence', 'Compliance Automation'],
      valueProposition: 'KHEPRA Protocol provides quantum-resilient security framework',
      followUpActions: [],
      score: 0
    }
  ]);

  const [newInterview, setNewInterview] = useState({
    companyName: '',
    contactName: '',
    title: '',
    email: '',
    phone: '',
    segment: '',
    date: ''
  });

  const segments = ['Defense Contractors', 'Enterprise', 'MSSPs', 'Critical Infrastructure'];
  
  const discoveryMetrics = {
    totalInterviews: interviews.length,
    completedInterviews: interviews.filter(i => i.status === 'completed').length,
    avgScore: interviews.filter(i => i.score > 0).reduce((acc, i) => acc + i.score, 0) / 
              interviews.filter(i => i.score > 0).length || 0,
    topPainPoints: ['CMMC Compliance', 'Zero Trust Implementation', 'Threat Intelligence', 'Supply Chain Security']
  };

  const handleAddInterview = () => {
    if (newInterview.companyName && newInterview.contactName && newInterview.email) {
      const interview: CustomerInterview = {
        id: Date.now().toString(),
        ...newInterview,
        status: 'scheduled',
        painPoints: [],
        valueProposition: '',
        followUpActions: [],
        score: 0
      };
      setInterviews([...interviews, interview]);
      setNewInterview({
        companyName: '',
        contactName: '',
        title: '',
        email: '',
        phone: '',
        segment: '',
        date: ''
      });
    }
  };

  return (
    <div className="space-y-6">
      {/* Discovery Metrics */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Total Interviews</CardTitle>
            <MessageSquare className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{discoveryMetrics.totalInterviews}</div>
            <p className="text-xs text-muted-foreground">
              {discoveryMetrics.completedInterviews} completed
            </p>
          </CardContent>
        </Card>
        
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Completion Rate</CardTitle>
            <Target className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">
              {Math.round((discoveryMetrics.completedInterviews / discoveryMetrics.totalInterviews) * 100)}%
            </div>
            <Progress 
              value={(discoveryMetrics.completedInterviews / discoveryMetrics.totalInterviews) * 100} 
              className="mt-2" 
            />
          </CardContent>
        </Card>
        
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Avg Interest Score</CardTitle>
            <TrendingUp className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{discoveryMetrics.avgScore.toFixed(1)}/10</div>
            <p className="text-xs text-muted-foreground">Customer interest level</p>
          </CardContent>
        </Card>
        
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Active Segments</CardTitle>
            <Users className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{segments.length}</div>
            <p className="text-xs text-muted-foreground">Customer segments</p>
          </CardContent>
        </Card>
      </div>

      <Tabs defaultValue="interviews" className="w-full">
        <TabsList>
          <TabsTrigger value="interviews">Interviews</TabsTrigger>
          <TabsTrigger value="insights">Insights</TabsTrigger>
          <TabsTrigger value="schedule">Schedule New</TabsTrigger>
        </TabsList>

        <TabsContent value="interviews" className="space-y-4">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            {interviews.map((interview) => (
              <Card key={interview.id}>
                <CardHeader>
                  <div className="flex items-center justify-between">
                    <CardTitle className="text-lg">{interview.companyName}</CardTitle>
                    <Badge variant={
                      interview.status === 'completed' ? 'default' :
                      interview.status === 'scheduled' ? 'secondary' : 'destructive'
                    }>
                      {interview.status}
                    </Badge>
                  </div>
                  <CardDescription>
                    {interview.contactName} • {interview.title}
                  </CardDescription>
                </CardHeader>
                <CardContent className="space-y-3">
                  <div className="flex items-center gap-2 text-sm">
                    <Building2 className="h-4 w-4" />
                    <Badge variant="outline">{interview.segment}</Badge>
                  </div>
                  
                  <div className="flex items-center gap-2 text-sm">
                    <Calendar className="h-4 w-4" />
                    <span>{new Date(interview.date).toLocaleDateString()}</span>
                  </div>
                  
                  <div className="flex items-center gap-2 text-sm">
                    <Mail className="h-4 w-4" />
                    <span>{interview.email}</span>
                  </div>
                  
                  {interview.phone && (
                    <div className="flex items-center gap-2 text-sm">
                      <Phone className="h-4 w-4" />
                      <span>{interview.phone}</span>
                    </div>
                  )}

                  {interview.status === 'completed' && (
                    <>
                      <div className="space-y-2">
                        <h4 className="font-medium text-sm">Pain Points:</h4>
                        <div className="flex flex-wrap gap-1">
                          {interview.painPoints.map((pain, index) => (
                            <Badge key={index} variant="outline" className="text-xs">
                              {pain}
                            </Badge>
                          ))}
                        </div>
                      </div>
                      
                      <div className="space-y-2">
                        <h4 className="font-medium text-sm">Interest Score:</h4>
                        <div className="flex items-center gap-2">
                          <Progress value={interview.score * 10} className="flex-1" />
                          <span className="text-sm font-medium">{interview.score}/10</span>
                        </div>
                      </div>
                    </>
                  )}
                  
                  <Button variant="outline" size="sm" className="w-full">
                    View Details
                  </Button>
                </CardContent>
              </Card>
            ))}
          </div>
        </TabsContent>

        <TabsContent value="insights" className="space-y-4">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <Card>
              <CardHeader>
                <CardTitle>Top Pain Points</CardTitle>
                <CardDescription>Most frequently mentioned challenges</CardDescription>
              </CardHeader>
              <CardContent className="space-y-3">
                {discoveryMetrics.topPainPoints.map((pain, index) => (
                  <div key={index} className="flex items-center justify-between">
                    <span className="text-sm">{pain}</span>
                    <Badge variant="secondary">{index + 1} mentions</Badge>
                  </div>
                ))}
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle>Segment Analysis</CardTitle>
                <CardDescription>Interest by customer segment</CardDescription>
              </CardHeader>
              <CardContent className="space-y-3">
                {segments.map((segment, index) => {
                  const segmentScore = 6 + (index % 5) * 0.8; // Deterministic score 6.0–9.2 per segment
                  return (
                    <div key={index} className="space-y-2">
                      <div className="flex items-center justify-between text-sm">
                        <span>{segment}</span>
                        <span>{segmentScore.toFixed(1)}/10</span>
                      </div>
                      <Progress value={segmentScore * 10} className="w-full" />
                    </div>
                  );
                })}
              </CardContent>
            </Card>
          </div>
        </TabsContent>

        <TabsContent value="schedule" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle>Schedule New Interview</CardTitle>
              <CardDescription>Add a new customer discovery interview</CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div className="space-y-2">
                  <label className="text-sm font-medium">Company Name</label>
                  <Input
                    value={newInterview.companyName}
                    onChange={(e) => setNewInterview({...newInterview, companyName: e.target.value})}
                    placeholder="Enter company name"
                  />
                </div>
                
                <div className="space-y-2">
                  <label className="text-sm font-medium">Contact Name</label>
                  <Input
                    value={newInterview.contactName}
                    onChange={(e) => setNewInterview({...newInterview, contactName: e.target.value})}
                    placeholder="Enter contact name"
                  />
                </div>
                
                <div className="space-y-2">
                  <label className="text-sm font-medium">Title</label>
                  <Input
                    value={newInterview.title}
                    onChange={(e) => setNewInterview({...newInterview, title: e.target.value})}
                    placeholder="Enter job title"
                  />
                </div>
                
                <div className="space-y-2">
                  <label className="text-sm font-medium">Email</label>
                  <Input
                    type="email"
                    value={newInterview.email}
                    onChange={(e) => setNewInterview({...newInterview, email: e.target.value})}
                    placeholder="Enter email address"
                  />
                </div>
                
                <div className="space-y-2">
                  <label className="text-sm font-medium">Phone (Optional)</label>
                  <Input
                    value={newInterview.phone}
                    onChange={(e) => setNewInterview({...newInterview, phone: e.target.value})}
                    placeholder="Enter phone number"
                  />
                </div>
                
                <div className="space-y-2">
                  <label className="text-sm font-medium">Segment</label>
                  <select
                    className="w-full px-3 py-2 border border-input bg-background rounded-md"
                    value={newInterview.segment}
                    onChange={(e) => setNewInterview({...newInterview, segment: e.target.value})}
                  >
                    <option value="">Select segment</option>
                    {segments.map((segment) => (
                      <option key={segment} value={segment}>{segment}</option>
                    ))}
                  </select>
                </div>
                
                <div className="space-y-2">
                  <label className="text-sm font-medium">Interview Date</label>
                  <Input
                    type="date"
                    value={newInterview.date}
                    onChange={(e) => setNewInterview({...newInterview, date: e.target.value})}
                  />
                </div>
              </div>
              
              <Button onClick={handleAddInterview} className="w-full">
                <Plus className="h-4 w-4 mr-2" />
                Schedule Interview
              </Button>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
};