import { useState } from 'react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Textarea } from '@/components/ui/textarea';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { ExternalLink, CheckCircle, Download } from 'lucide-react';
import { supabase } from '@/integrations/supabase/client';
import { useToast } from '@/hooks/use-toast';

interface GCPConnectorProps {
  organizationId: string;
  onSuccess: (connectionId: string) => void;
  onError: () => void;
}

export default function GCPConnector({ organizationId, onSuccess, onError }: GCPConnectorProps) {
  const [loading, setLoading] = useState(false);
  const [projectId, setProjectId] = useState('');
  const [serviceAccountKey, setServiceAccountKey] = useState('');
  const { toast } = useToast();

  const downloadTerraformConfig = () => {
    const terraform = `# NouchiX STIGs Discovery - GCP Service Account Setup

terraform {
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 5.0"
    }
  }
}

provider "google" {
  project = "${projectId || '<your-project-id>'}"
  region  = "us-central1"
}

# Create service account for NouchiX discovery
resource "google_service_account" "nouchix_discovery" {
  account_id   = "nouchix-stigs-discovery"
  display_name = "NouchiX STIGs Discovery Service Account"
  description  = "Read-only access for STIG compliance discovery"
}

# Grant Viewer role at project level
resource "google_project_iam_member" "nouchix_viewer" {
  project = "${projectId || '<your-project-id>'}"
  role    = "roles/viewer"
  member  = "serviceAccount:\${google_service_account.nouchix_discovery.email}"
}

# Create and export service account key
resource "google_service_account_key" "nouchix_key" {
  service_account_id = google_service_account.nouchix_discovery.name
}

output "service_account_email" {
  value = google_service_account.nouchix_discovery.email
}

output "project_id" {
  value = "${projectId || '<your-project-id>'}"
}

output "service_account_key" {
  value     = google_service_account_key.nouchix_key.private_key
  sensitive = true
}
`;
    const blob = new Blob([terraform], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'nouchix-gcp-terraform.tf';
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    toast({ title: 'Terraform Config Downloaded', description: 'Run "terraform apply" to create service account' });
  };

  const downloadGCloudScript = () => {
    const script = `#!/bin/bash
# NouchiX STIGs Discovery - GCP Service Account Setup

PROJECT_ID="${projectId || '<your-project-id>'}"
SA_NAME="nouchix-stigs-discovery"
SA_EMAIL="\${SA_NAME}@\${PROJECT_ID}.iam.gserviceaccount.com"
KEY_FILE="nouchix-service-account-key.json"

# Set active project
gcloud config set project \${PROJECT_ID}

# Create service account
gcloud iam service-accounts create \${SA_NAME} \\
  --display-name="NouchiX STIGs Discovery" \\
  --description="Read-only access for STIG compliance discovery"

# Grant Viewer role
gcloud projects add-iam-policy-binding \${PROJECT_ID} \\
  --member="serviceAccount:\${SA_EMAIL}" \\
  --role="roles/viewer"

# Create and download key
gcloud iam service-accounts keys create \${KEY_FILE} \\
  --iam-account=\${SA_EMAIL}

echo ""
echo "✅ Service account created successfully!"
echo "📋 Project ID: \${PROJECT_ID}"
echo "📧 Service Account: \${SA_EMAIL}"
echo "🔑 Key saved to: \${KEY_FILE}"
echo ""
echo "⚠️  Copy the contents of \${KEY_FILE} to NouchiX connection wizard"
`;
    const blob = new Blob([script], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'setup-nouchix-gcp.sh';
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    toast({ title: 'gCloud Script Downloaded', description: 'Run this script in Google Cloud Shell' });
  };

  const handleConnect = async () => {
    if (!projectId || !serviceAccountKey) {
      toast({ title: 'Error', description: 'Please fill in all fields', variant: 'destructive' });
      return;
    }

    let keyData: any;
    try {
      keyData = JSON.parse(serviceAccountKey);
    } catch (e) {
      toast({ title: 'Error', description: 'Invalid JSON in service account key', variant: 'destructive' });
      return;
    }

    setLoading(true);
    try {
      const { data: connection, error: dbError } = await supabase
        .from('cloud_connections' as any)
        .insert({
          organization_id: organizationId,
          cloud_provider: 'gcp',
          connection_type: 'service_account',
          connection_name: 'GCP Project',
          project_id: projectId,
          service_account_email: keyData.client_email,
          status: 'pending'
        })
        .select()
        .single() as any;

      if (dbError) throw dbError;

      const { data: discoveryData, error: discoveryError } = await supabase.functions.invoke(
        'cloud-asset-discovery',
        {
          body: {
            connectionId: connection?.id,
            provider: 'gcp',
            projectId,
            serviceAccountKey: keyData
          }
        }
      );

      if (discoveryError) throw discoveryError;

      toast({
        title: 'GCP Connected Successfully',
        description: `Discovered ${discoveryData.assetsFound || 0} assets. Discovery running...`
      });

      onSuccess(connection?.id);
    } catch (error: any) {
      console.error('GCP connection error:', error);
      toast({
        title: 'Connection Failed',
        description: error.message || 'Failed to connect to GCP',
        variant: 'destructive'
      });
      onError();
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-6">
      <Alert>
        <AlertDescription>
          <strong>GCP Service Account Setup:</strong> Create a service account with Viewer role
          on your project for read-only STIG discovery access.
        </AlertDescription>
      </Alert>

      <div className="grid grid-cols-2 gap-3 mb-4">
        <Button onClick={downloadTerraformConfig} variant="outline">
          <Download className="mr-2 h-4 w-4" />
          Download Terraform
        </Button>
        <Button onClick={downloadGCloudScript} variant="outline">
          <Download className="mr-2 h-4 w-4" />
          Download gCloud Script
        </Button>
      </div>

      <div className="space-y-4">
        <div>
          <Label>Project ID</Label>
          <Input
            placeholder="your-project-id"
            value={projectId}
            onChange={(e) => setProjectId(e.target.value)}
            className="mt-2"
          />
        </div>

        <div>
          <Label>Service Account Key (JSON)</Label>
          <Textarea
            placeholder='{"type": "service_account", "project_id": "...", ...}'
            value={serviceAccountKey}
            onChange={(e) => setServiceAccountKey(e.target.value)}
            className="mt-2 font-mono text-sm"
            rows={8}
          />
          <p className="text-xs text-muted-foreground mt-1">
            Paste the entire JSON key file contents
          </p>
        </div>

        <Button onClick={handleConnect} disabled={loading} className="w-full">
          {loading ? 'Connecting...' : 'Connect GCP Project'}
        </Button>
      </div>

      <Alert>
        <CheckCircle className="h-4 w-4" />
        <AlertDescription>
          <strong>Security:</strong> Service account keys are encrypted at rest. NouchiX only requires
          Viewer role and never modifies your GCP resources.
        </AlertDescription>
      </Alert>

      <Button
        variant="link"
        onClick={() => globalThis.open('https://cloud.google.com/iam/docs/creating-managing-service-accounts', '_blank')}
      >
        <ExternalLink className="mr-2 h-4 w-4" />
        How to create a Service Account
      </Button>
    </div>
  );
}
