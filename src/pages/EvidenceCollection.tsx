import { useState } from "react";
import { useToast } from "@/components/ui/use-toast";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { 
  FileText, 
  Download, 
  Search, 
  Filter,
  Calendar,
  Shield,
  CheckCircle,
  Clock,
  AlertTriangle,
  Archive
} from "lucide-react";
import { PageLayout } from "@/components/PageLayout";

const EvidenceCollection = () => {
  const { toast } = useToast();
  const [searchTerm, setSearchTerm] = useState("");

  const handleScheduleCollection = () => {
    toast({
      title: "Collection Scheduled",
      description: "Automated evidence collection scheduled for next compliance cycle",
    });
  };

  const handleExportAll = () => {
    toast({
      title: "Export Started",
      description: "Preparing comprehensive evidence export package...",
    });
    setTimeout(() => {
      toast({
        title: "Export Complete",
        description: "Evidence package ready for download (156.3 MB)",
      });
    }, 3000);
  };

  const handleViewDetails = (itemId: string) => {
    toast({
      title: "Loading Evidence Details",
      description: `Opening detailed view for ${itemId}...`,
    });
  };

  const handleDownload = (itemId: string) => {
    toast({
      title: "Download Started",
      description: `Downloading evidence item ${itemId}...`,
    });
  };

  const handleVerifyEvidence = (itemId: string) => {
    toast({
      title: "Verification Started",
      description: `Cryptographic verification of ${itemId} in progress...`,
    });
    setTimeout(() => {
      toast({
        title: "Evidence Verified",
        description: "Hash verification successful - evidence integrity confirmed",
      });
    }, 2000);
  };

  const handleCreatePackage = () => {
    toast({
      title: "Creating Compliance Package",
      description: "Building new evidence package with selected controls...",
    });
  };

  const handleViewContents = (packageName: string) => {
    toast({
      title: "Loading Package Contents",
      description: `Opening detailed view for ${packageName}...`,
    });
  };

  const handleDownloadPackage = (packageName: string) => {
    toast({
      title: "Package Download Started",
      description: `Preparing ${packageName} for download...`,
    });
  };

  const handleGenerateReport = (packageName: string) => {
    toast({
      title: "Generating Report",
      description: `Creating compliance report for ${packageName}...`,
    });
    setTimeout(() => {
      toast({
        title: "Report Generated",
        description: "Compliance assessment report ready for download",
      });
    }, 2500);
  };

  const evidenceItems = [
    {
      id: "EV-2024-001",
      title: "Windows Server 2022 Security Configuration",
      controlId: "V-220699",
      framework: "STIG",
      type: "Configuration Backup",
      collectedAt: "2024-01-15 14:30:00",
      status: "VERIFIED",
      size: "2.3 MB",
      hash: "sha256:a1b2c3d4...",
      description: "Group Policy objects and registry settings for password complexity"
    },
    {
      id: "EV-2024-002", 
      title: "Network Firewall Rules Audit",
      controlId: "SC-7",
      framework: "NIST",
      type: "Audit Log",
      collectedAt: "2024-01-15 12:15:00",
      status: "PENDING_REVIEW",
      size: "856 KB",
      hash: "sha256:e5f6g7h8...",
      description: "Complete firewall configuration and rule verification"
    },
    {
      id: "EV-2024-003",
      title: "User Access Control Matrix",
      controlId: "AC.1.001",
      framework: "CMMC",
      type: "Access Report",
      collectedAt: "2024-01-15 10:45:00", 
      status: "VERIFIED",
      size: "1.1 MB",
      hash: "sha256:i9j0k1l2...",
      description: "Complete user permissions and role assignments audit"
    },
    {
      id: "EV-2024-004",
      title: "Vulnerability Scan Results",
      controlId: "SI-2",
      framework: "NIST",
      type: "Scan Report",
      collectedAt: "2024-01-15 08:00:00",
      status: "ARCHIVED",
      size: "4.7 MB", 
      hash: "sha256:m3n4o5p6...",
      description: "Comprehensive vulnerability assessment of all systems"
    }
  ];

  const compliancePackages = [
    {
      name: "CMMC Level 3 Evidence Bundle",
      controls: 130,
      evidence: 847,
      lastUpdated: "2024-01-15",
      status: "COMPLETE",
      size: "45.2 MB"
    },
    {
      name: "NIST SP 800-53 Assessment Package",
      controls: 324,
      evidence: 1256,
      lastUpdated: "2024-01-15",
      status: "COMPLETE", 
      size: "78.9 MB"
    },
    {
      name: "Windows Server 2022 STIG Package",
      controls: 267,
      evidence: 743,
      lastUpdated: "2024-01-15",
      status: "IN_PROGRESS",
      size: "32.1 MB"
    }
  ];

  const getStatusIcon = (status) => {
    switch (status) {
      case "VERIFIED":
        return <CheckCircle className="h-4 w-4 text-success" />;
      case "PENDING_REVIEW":
        return <Clock className="h-4 w-4 text-warning" />;
      case "ARCHIVED":
        return <Archive className="h-4 w-4 text-muted-foreground" />;
      default:
        return <AlertTriangle className="h-4 w-4 text-muted-foreground" />;
    }
  };

  const getStatusColor = (status) => {
    switch (status) {
      case "VERIFIED":
      case "COMPLETE":
        return "success";
      case "PENDING_REVIEW":
      case "IN_PROGRESS":
        return "warning";
      case "ARCHIVED":
        return "secondary";
      default:
        return "secondary";
    }
  };

  return (
    <PageLayout>
      <div className="space-y-6">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-3xl font-bold text-foreground">Evidence Collection</h1>
            <p className="text-muted-foreground">
              Automated evidence gathering and compliance documentation
            </p>
          </div>
          <div className="flex gap-2">
            <Button variant="outline" onClick={handleScheduleCollection}>
              <Calendar className="h-4 w-4 mr-2" />
              Schedule Collection
            </Button>
            <Button className="btn-cyber" onClick={handleExportAll}>
              <Download className="h-4 w-4 mr-2" />
              Export All
            </Button>
          </div>
        </div>

        {/* Search and Filters */}
        <Card>
          <CardContent className="pt-6">
            <div className="flex gap-4">
              <div className="flex-1">
                <Input
                  placeholder="Search evidence by control ID, title, or framework..."
                  value={searchTerm}
                  onChange={(e) => setSearchTerm(e.target.value)}
                  className="w-full"
                />
              </div>
              <Button variant="outline" size="icon">
                <Search className="h-4 w-4" />
              </Button>
              <Button variant="outline" size="icon">
                <Filter className="h-4 w-4" />
              </Button>
            </div>
          </CardContent>
        </Card>

        {/* Main Content */}
        <Tabs defaultValue="evidence" className="space-y-6">
          <TabsList className="grid w-full grid-cols-2">
            <TabsTrigger value="evidence" className="flex items-center gap-2">
              <FileText className="h-4 w-4" />
              Evidence Items
            </TabsTrigger>
            <TabsTrigger value="packages" className="flex items-center gap-2">
              <Archive className="h-4 w-4" />
              Compliance Packages
            </TabsTrigger>
          </TabsList>

          <TabsContent value="evidence" className="space-y-4">
            <div className="flex items-center justify-between">
              <h2 className="text-xl font-semibold">Evidence Repository</h2>
              <div className="flex gap-2">
                <Badge variant="success">
                  {evidenceItems.filter(e => e.status === "VERIFIED").length} Verified
                </Badge>
                <Badge variant="warning">
                  {evidenceItems.filter(e => e.status === "PENDING_REVIEW").length} Pending
                </Badge>
              </div>
            </div>

            {evidenceItems.map((item) => (
              <Card key={item.id} className="card-cyber">
                <CardHeader className="pb-3">
                  <div className="flex items-start justify-between">
                    <div className="space-y-1">
                      <div className="flex items-center gap-2">
                        {getStatusIcon(item.status)}
                        <CardTitle className="text-lg">{item.title}</CardTitle>
                        <Badge variant="outline">{item.id}</Badge>
                      </div>
                      <CardDescription>{item.description}</CardDescription>
                    </div>
                    <div className="flex gap-2">
                      <Badge variant="secondary">{item.framework}</Badge>
                      <Badge variant="outline">{item.controlId}</Badge>
                    </div>
                  </div>
                </CardHeader>
                <CardContent className="space-y-4">
                  <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
                    <div>
                      <span className="text-muted-foreground">Type:</span>
                      <div className="font-medium">{item.type}</div>
                    </div>
                    <div>
                      <span className="text-muted-foreground">Size:</span>
                      <div className="font-medium">{item.size}</div>
                    </div>
                    <div>
                      <span className="text-muted-foreground">Collected:</span>
                      <div className="font-medium">{item.collectedAt}</div>
                    </div>
                    <div>
                      <span className="text-muted-foreground">Status:</span>
                      <Badge variant={getStatusColor(item.status)}>
                        {item.status.replaceAll("_", " ")}
                      </Badge>
                    </div>
                  </div>
                  
                  <div className="bg-muted p-3 rounded-md">
                    <p className="text-xs font-mono text-muted-foreground">
                      <strong>Hash:</strong> {item.hash}
                    </p>
                  </div>

                  <div className="flex gap-2">
                    <Button size="sm" variant="outline" onClick={() => handleViewDetails(item.id)}>
                      View Details
                    </Button>
                    <Button size="sm" variant="outline" onClick={() => handleDownload(item.id)}>
                      <Download className="h-3 w-3 mr-1" />
                      Download
                    </Button>
                    {item.status === "PENDING_REVIEW" && (
                      <Button size="sm" className="btn-cyber" onClick={() => handleVerifyEvidence(item.id)}>
                        <Shield className="h-3 w-3 mr-1" />
                        Verify
                      </Button>
                    )}
                  </div>
                </CardContent>
              </Card>
            ))}
          </TabsContent>

          <TabsContent value="packages" className="space-y-4">
            <div className="flex items-center justify-between">
              <h2 className="text-xl font-semibold">Compliance Packages</h2>
              <Button className="btn-cyber" onClick={handleCreatePackage}>
                <Archive className="h-4 w-4 mr-2" />
                Create New Package
              </Button>
            </div>

            {compliancePackages.map((pkg, index) => (
              <Card key={index} className="card-cyber">
                <CardHeader className="pb-3">
                  <div className="flex items-start justify-between">
                    <div className="space-y-1">
                      <CardTitle className="text-lg">{pkg.name}</CardTitle>
                      <CardDescription>
                        {pkg.controls} controls • {pkg.evidence} evidence items
                      </CardDescription>
                    </div>
                    <Badge variant={getStatusColor(pkg.status)}>
                      {pkg.status.replaceAll("_", " ")}
                    </Badge>
                  </div>
                </CardHeader>
                <CardContent className="space-y-4">
                  <div className="grid grid-cols-3 gap-4 text-sm">
                    <div>
                      <span className="text-muted-foreground">Last Updated:</span>
                      <div className="font-medium">{pkg.lastUpdated}</div>
                    </div>
                    <div>
                      <span className="text-muted-foreground">Package Size:</span>
                      <div className="font-medium">{pkg.size}</div>
                    </div>
                    <div>
                      <span className="text-muted-foreground">Evidence Count:</span>
                      <div className="font-medium">{pkg.evidence} items</div>
                    </div>
                  </div>

                  <div className="flex gap-2">
                    <Button size="sm" variant="outline" onClick={() => handleViewContents(pkg.name)}>
                      View Contents
                    </Button>
                    <Button size="sm" variant="outline" onClick={() => handleDownloadPackage(pkg.name)}>
                      <Download className="h-3 w-3 mr-1" />
                      Download Package
                    </Button>
                    <Button size="sm" className="btn-cyber" onClick={() => handleGenerateReport(pkg.name)}>
                      Generate Report
                    </Button>
                  </div>
                </CardContent>
              </Card>
            ))}
          </TabsContent>
        </Tabs>
      </div>
    </PageLayout>
  );
};

export default EvidenceCollection;