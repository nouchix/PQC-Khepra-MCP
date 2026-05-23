import { useState } from "react";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { useToast } from "@/hooks/use-toast";
import { supabase } from "@/integrations/supabase/client";

interface ContactSalesDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
}

const ContactSalesDialog = ({ open, onOpenChange }: ContactSalesDialogProps) => {
  const { toast } = useToast();
  const [company, setCompany] = useState("");
  const [message, setMessage] = useState("");
  const [loading, setLoading] = useState(false);

  const submit = async () => {
    try {
      setLoading(true);
      const { error } = await supabase.functions.invoke('contact-sales', {
        body: { company, message },
      });
      if (error) throw error;
      toast({ title: "Request sent", description: "Our team will contact you shortly." });
      setCompany("");
      setMessage("");
      onOpenChange(false);
    } catch (e: any) {
      toast({ title: "Failed to send", description: e.message || 'Please try again later.', variant: 'destructive' });
    } finally {
      setLoading(false);
    }
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Contact Sales</DialogTitle>
          <DialogDescription>
            Tell us a bit about your organization and needs. We'll follow up with pricing and options.
          </DialogDescription>
        </DialogHeader>
        <div className="space-y-3">
          <Input placeholder="Company / Agency" value={company} onChange={(e) => setCompany(e.target.value)} />
          <Textarea placeholder="Your requirements, number of users, timelines..." value={message} onChange={(e) => setMessage(e.target.value)} />
          <Button onClick={submit} disabled={loading} className="w-full">{loading ? 'Sending...' : 'Send Request'}</Button>
        </div>
      </DialogContent>
    </Dialog>
  );
};

export default ContactSalesDialog;
