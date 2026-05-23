import { useState } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Progress } from '@/components/ui/progress';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { 
  BookOpen, 
  Award, 
  Clock, 
  Users, 
  CheckCircle, 
  PlayCircle,
  Download,
  Star,
  Trophy,
  Target
} from 'lucide-react';
import { useToast } from '@/hooks/use-toast';

interface Course {
  id: string;
  title: string;
  description: string;
  duration: string;
  level: 'beginner' | 'intermediate' | 'advanced';
  category: 'cmmc' | 'nist' | 'general' | 'technical';
  progress: number;
  status: 'not_started' | 'in_progress' | 'completed';
  rating: number;
  enrollments: number;
  certification: boolean;
  prerequisites: string[];
  modules: string[];
}

interface Certification {
  id: string;
  name: string;
  description: string;
  requirements: string[];
  validity: string;
  status: 'available' | 'in_progress' | 'completed' | 'expired';
  issueDate?: string;
  expiryDate?: string;
  credentialId?: string;
}

const courses: Course[] = [
  {
    id: 'cmmc-fundamentals',
    title: 'CMMC 2.0 Fundamentals',
    description: 'Comprehensive introduction to CMMC requirements, controls, and implementation strategies.',
    duration: '4 hours',
    level: 'beginner',
    category: 'cmmc',
    progress: 75,
    status: 'in_progress',
    rating: 4.8,
    enrollments: 1250,
    certification: true,
    prerequisites: [],
    modules: [
      'CMMC Overview and Structure',
      'Level 1 Controls',
      'Level 2 Controls',
      'Assessment Process',
      'Implementation Planning'
    ]
  },
  {
    id: 'nist-800-171',
    title: 'NIST SP 800-171 Implementation',
    description: 'Deep dive into NIST SP 800-171 controls and practical implementation guidance.',
    duration: '6 hours',
    level: 'intermediate',
    category: 'nist',
    progress: 100,
    status: 'completed',
    rating: 4.9,
    enrollments: 890,
    certification: true,
    prerequisites: ['Security Fundamentals'],
    modules: [
      'Access Control',
      'Awareness and Training',
      'Audit and Accountability',
      'Configuration Management',
      'Identification and Authentication'
    ]
  },
  {
    id: 'incident-response',
    title: 'Cybersecurity Incident Response',
    description: 'Learn to effectively respond to and manage cybersecurity incidents.',
    duration: '3 hours',
    level: 'intermediate',
    category: 'general',
    progress: 30,
    status: 'in_progress',
    rating: 4.7,
    enrollments: 560,
    certification: true,
    prerequisites: ['CMMC Fundamentals'],
    modules: [
      'Incident Detection',
      'Response Planning',
      'Containment and Eradication',
      'Recovery and Lessons Learned'
    ]
  },
  {
    id: 'technical-controls',
    title: 'Technical Security Controls Implementation',
    description: 'Hands-on training for implementing technical security controls and configurations.',
    duration: '8 hours',
    level: 'advanced',
    category: 'technical',
    progress: 0,
    status: 'not_started',
    rating: 4.6,
    enrollments: 340,
    certification: true,
    prerequisites: ['NIST SP 800-171 Implementation'],
    modules: [
      'Network Security Configuration',
      'Endpoint Protection',
      'Log Management',
      'Vulnerability Management',
      'Encryption Implementation'
    ]
  }
];

const certifications: Certification[] = [
  {
    id: 'cmmc-certified-professional',
    name: 'CMMC Certified Professional',
    description: 'Demonstrates comprehensive understanding of CMMC requirements and implementation.',
    requirements: [
      'Complete CMMC 2.0 Fundamentals course',
      'Pass certification exam (80% minimum)',
      'Complete practical assessment'
    ],
    validity: '2 years',
    status: 'completed',
    issueDate: '2024-01-15',
    expiryDate: '2026-01-15',
    credentialId: 'CCP-2024-001234'
  },
  {
    id: 'nist-implementation-specialist',
    name: 'NIST Implementation Specialist',
    description: 'Expert-level certification for NIST SP 800-171 implementation and assessment.',
    requirements: [
      'Complete NIST SP 800-171 Implementation course',
      'Complete Technical Controls Implementation course',
      'Pass comprehensive exam (85% minimum)',
      '2 years relevant experience'
    ],
    validity: '3 years',
    status: 'in_progress',
  },
  {
    id: 'cybersecurity-analyst',
    name: 'Cybersecurity Analyst Certification',
    description: 'Validates skills in cybersecurity analysis, incident response, and threat detection.',
    requirements: [
      'Complete Incident Response course',
      'Complete Technical Controls course',
      'Pass practical simulation',
      'Demonstrate 6 months experience'
    ],
    validity: '2 years',
    status: 'available',
  }
];

export const ComplianceCertification = () => {
  const { toast } = useToast();
  const [selectedCourse, setSelectedCourse] = useState<Course | null>(null);

  const startCourse = (courseId: string) => {
    toast({
      title: "Course Started",
      description: "You've been enrolled in the course. Starting first module...",
    });
  };

  const continueCourse = (courseId: string) => {
    toast({
      title: "Resuming Course",
      description: "Continuing where you left off...",
    });
  };

  const downloadCertificate = (certId: string) => {
    toast({
      title: "Downloading Certificate",
      description: "Your certification will be downloaded as a PDF.",
    });
  };

  const getLevelColor = (level: string) => {
    switch (level) {
      case 'beginner': return 'default';
      case 'intermediate': return 'secondary';
      case 'advanced': return 'destructive';
      default: return 'outline';
    }
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'completed': return 'default';
      case 'in_progress': return 'secondary';
      case 'expired': return 'destructive';
      default: return 'outline';
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h2 className="text-2xl font-bold">Training & Certification</h2>
        <div className="flex items-center gap-2">
          <Badge variant="outline" className="px-3 py-1">
            <Trophy className="h-4 w-4 mr-1" />
            {certifications.filter(c => c.status === 'completed').length} Certifications
          </Badge>
          <Badge variant="outline" className="px-3 py-1">
            <BookOpen className="h-4 w-4 mr-1" />
            {courses.filter(c => c.status !== 'not_started').length} Active Courses
          </Badge>
        </div>
      </div>

      <Tabs defaultValue="courses" className="w-full">
        <TabsList>
          <TabsTrigger value="courses">Courses</TabsTrigger>
          <TabsTrigger value="certifications">Certifications</TabsTrigger>
          <TabsTrigger value="progress">My Progress</TabsTrigger>
          <TabsTrigger value="team">Team Training</TabsTrigger>
        </TabsList>

        <TabsContent value="courses" className="space-y-6">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* Course List */}
            <div className="space-y-4">
              <h3 className="text-lg font-semibold">Available Courses</h3>
              {courses.map((course) => (
                <Card 
                  key={course.id}
                  className={`cursor-pointer transition-all hover:shadow-md ${
                    selectedCourse?.id === course.id ? 'ring-2 ring-primary' : ''
                  }`}
                  onClick={() => setSelectedCourse(course)}
                >
                  <CardHeader className="pb-3">
                    <div className="flex items-start justify-between">
                      <div>
                        <CardTitle className="text-base">{course.title}</CardTitle>
                        <p className="text-sm text-muted-foreground mt-1">
                          {course.description}
                        </p>
                      </div>
                      <div className="flex gap-2">
                        <Badge variant={getLevelColor(course.level)} className="capitalize">
                          {course.level}
                        </Badge>
                        {course.certification && (
                          <Badge variant="outline">
                            <Award className="h-3 w-3 mr-1" />
                            Cert
                          </Badge>
                        )}
                      </div>
                    </div>
                  </CardHeader>
                  <CardContent>
                    <div className="space-y-3">
                      {course.status !== 'not_started' && (
                        <div>
                          <div className="flex justify-between text-sm mb-1">
                            <span>Progress</span>
                            <span>{course.progress}%</span>
                          </div>
                          <Progress value={course.progress} className="h-2" />
                        </div>
                      )}
                      
                      <div className="flex items-center justify-between text-sm text-muted-foreground">
                        <div className="flex items-center gap-4">
                          <div className="flex items-center gap-1">
                            <Clock className="h-4 w-4" />
                            {course.duration}
                          </div>
                          <div className="flex items-center gap-1">
                            <Star className="h-4 w-4" />
                            {course.rating}
                          </div>
                          <div className="flex items-center gap-1">
                            <Users className="h-4 w-4" />
                            {course.enrollments}
                          </div>
                        </div>
                      </div>
                    </div>
                  </CardContent>
                </Card>
              ))}
            </div>

            {/* Course Details */}
            <div>
              {selectedCourse ? (
                <Card>
                  <CardHeader>
                    <CardTitle className="flex items-center gap-2">
                      <BookOpen className="h-5 w-5" />
                      {selectedCourse.title}
                    </CardTitle>
                  </CardHeader>
                  <CardContent className="space-y-4">
                    <p className="text-muted-foreground">
                      {selectedCourse.description}
                    </p>

                    <div className="grid grid-cols-2 gap-4">
                      <div>
                        <label className="text-sm font-medium text-muted-foreground">Duration</label>
                        <p className="text-sm">{selectedCourse.duration}</p>
                      </div>
                      <div>
                        <label className="text-sm font-medium text-muted-foreground">Level</label>
                        <Badge variant={getLevelColor(selectedCourse.level)} className="mt-1 capitalize">
                          {selectedCourse.level}
                        </Badge>
                      </div>
                    </div>

                    {selectedCourse.prerequisites.length > 0 && (
                      <div>
                        <label className="text-sm font-medium text-muted-foreground">Prerequisites</label>
                        <div className="flex gap-2 mt-1">
                          {selectedCourse.prerequisites.map((prereq) => (
                            <Badge key={prereq} variant="outline">
                              {prereq}
                            </Badge>
                          ))}
                        </div>
                      </div>
                    )}

                    <div>
                      <label className="text-sm font-medium text-muted-foreground">Course Modules</label>
                      <ul className="mt-2 space-y-1">
                        {selectedCourse.modules.map((module, index) => (
                          <li key={module} className="flex items-center gap-2 text-sm">
                            <CheckCircle className="h-4 w-4 text-green-500" />
                            {index + 1}. {module}
                          </li>
                        ))}
                      </ul>
                    </div>

                    <div className="pt-4 border-t">
                      {selectedCourse.status === 'not_started' ? (
                        <Button 
                          onClick={() => startCourse(selectedCourse.id)}
                          className="w-full"
                        >
                          <PlayCircle className="h-4 w-4 mr-2" />
                          Start Course
                        </Button>
                      ) : selectedCourse.status === 'in_progress' ? (
                        <Button 
                          onClick={() => continueCourse(selectedCourse.id)}
                          className="w-full"
                        >
                          Continue Course ({selectedCourse.progress}%)
                        </Button>
                      ) : (
                        <div className="space-y-2">
                          <Button variant="outline" className="w-full">
                            <CheckCircle className="h-4 w-4 mr-2" />
                            Completed
                          </Button>
                          {selectedCourse.certification && (
                            <Button 
                              onClick={() => downloadCertificate(selectedCourse.id)}
                              variant="secondary" 
                              className="w-full"
                            >
                              <Download className="h-4 w-4 mr-2" />
                              Download Certificate
                            </Button>
                          )}
                        </div>
                      )}
                    </div>
                  </CardContent>
                </Card>
              ) : (
                <Card>
                  <CardContent className="flex items-center justify-center h-64 text-muted-foreground">
                    Select a course to view details
                  </CardContent>
                </Card>
              )}
            </div>
          </div>
        </TabsContent>

        <TabsContent value="certifications" className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
            {certifications.map((cert) => (
              <Card key={cert.id}>
                <CardHeader>
                  <div className="flex items-start justify-between">
                    <div className="flex items-center gap-2">
                      <Award className="h-5 w-5 text-primary" />
                      <CardTitle className="text-lg">{cert.name}</CardTitle>
                    </div>
                    <Badge variant={getStatusColor(cert.status)} className="capitalize">
                      {cert.status.replaceAll('_', ' ')}
                    </Badge>
                  </div>
                </CardHeader>
                <CardContent className="space-y-4">
                  <p className="text-sm text-muted-foreground">
                    {cert.description}
                  </p>

                  <div>
                    <label className="text-sm font-medium text-muted-foreground">Requirements</label>
                    <ul className="mt-2 space-y-1">
                      {cert.requirements.map((req) => (
                        <li key={req} className="flex items-center gap-2 text-sm">
                          <CheckCircle className="h-3 w-3 text-green-500" />
                          {req}
                        </li>
                      ))}
                    </ul>
                  </div>

                  <div className="flex justify-between text-sm">
                    <span className="text-muted-foreground">Valid for:</span>
                    <span>{cert.validity}</span>
                  </div>

                  {cert.status === 'completed' && (
                    <div className="space-y-2 pt-2 border-t">
                      <div className="flex justify-between text-sm">
                        <span className="text-muted-foreground">Issued:</span>
                        <span>{new Date(cert.issueDate!).toLocaleDateString()}</span>
                      </div>
                      <div className="flex justify-between text-sm">
                        <span className="text-muted-foreground">Expires:</span>
                        <span>{new Date(cert.expiryDate!).toLocaleDateString()}</span>
                      </div>
                      <div className="flex justify-between text-sm">
                        <span className="text-muted-foreground">Credential ID:</span>
                        <span className="font-mono text-xs">{cert.credentialId}</span>
                      </div>
                      <Button 
                        onClick={() => downloadCertificate(cert.id)}
                        variant="outline" 
                        className="w-full mt-3"
                      >
                        <Download className="h-4 w-4 mr-2" />
                        Download Certificate
                      </Button>
                    </div>
                  )}
                </CardContent>
              </Card>
            ))}
          </div>
        </TabsContent>

        <TabsContent value="progress" className="space-y-6">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <Card>
              <CardHeader>
                <CardTitle>Learning Progress</CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                {courses.filter(c => c.status !== 'not_started').map((course) => (
                  <div key={course.id} className="space-y-2">
                    <div className="flex justify-between text-sm">
                      <span>{course.title}</span>
                      <span>{course.progress}%</span>
                    </div>
                    <Progress value={course.progress} className="h-2" />
                  </div>
                ))}
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle>Certification Status</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-3">
                  {certifications.map((cert) => (
                    <div key={cert.id} className="flex items-center justify-between">
                      <div>
                        <p className="font-medium">{cert.name}</p>
                        <p className="text-sm text-muted-foreground">
                          {cert.status === 'completed' ? 
                            `Expires ${new Date(cert.expiryDate!).toLocaleDateString()}` :
                            cert.status.replaceAll('_', ' ')
                          }
                        </p>
                      </div>
                      <Badge variant={getStatusColor(cert.status)}>
                        {cert.status === 'completed' && <CheckCircle className="h-3 w-3 mr-1" />}
                        {cert.status.replaceAll('_', ' ')}
                      </Badge>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>
          </div>
        </TabsContent>

        <TabsContent value="team" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle>Team Training Overview</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="text-center py-8 text-muted-foreground">
                <Users className="h-12 w-12 mx-auto mb-4" />
                <p>Team training management features coming soon.</p>
                <p className="text-sm mt-2">
                  Track team progress, assign courses, and manage certifications.
                </p>
              </div>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
};