import { useState } from 'react';
import { Check, ChevronsUpDown, Plus } from 'lucide-react';
import { Button } from '@/components/ui/button';
import {
  Command,
  CommandEmpty,
  CommandGroup,
  CommandInput,
  CommandItem,
  CommandList,
  CommandSeparator,
} from '@/components/ui/command';
import {
  Popover,
  PopoverContent,
  PopoverTrigger,
} from '@/components/ui/popover';
import { useOrganization } from '@/hooks/useOrganization';
import { Badge } from '@/components/ui/badge';
import { cn } from '@/lib/utils';

export const OrganizationSwitcher = () => {
  const [open, setOpen] = useState(false);
  const { 
    organizations, 
    currentOrganization, 
    switchOrganization,
    subscription 
  } = useOrganization();

  const handleSelect = (organizationId: string) => {
    switchOrganization(organizationId);
    setOpen(false);
  };

  const getSubscriptionBadge = (tier: string) => {
    const variants = {
      trial: 'secondary',
      basic: 'outline',
      professional: 'default',
      enterprise: 'destructive'
    } as const;
    
    return (
      <Badge variant={variants[tier as keyof typeof variants] || 'secondary'} className="ml-2 text-xs">
        {tier.charAt(0).toUpperCase() + tier.slice(1)}
      </Badge>
    );
  };

  if (!currentOrganization) {
    return null;
  }

  return (
    <Popover open={open} onOpenChange={setOpen}>
      <PopoverTrigger asChild>
        <Button
          variant="outline"
          role="combobox"
          aria-expanded={open}
          className="w-[250px] justify-between"
        >
          <div className="flex items-center">
            <div className="flex flex-col items-start">
              <span className="text-sm font-medium">
                {currentOrganization.organization.name}
              </span>
              <span className="text-xs text-muted-foreground">
                {currentOrganization.role}
              </span>
            </div>
            {getSubscriptionBadge(currentOrganization.organization.subscription_tier)}
          </div>
          <ChevronsUpDown className="ml-2 h-4 w-4 shrink-0 opacity-50" />
        </Button>
      </PopoverTrigger>
      <PopoverContent className="w-[250px] p-0">
        <Command>
          <CommandInput placeholder="Search organizations..." />
          <CommandList>
            <CommandEmpty>No organizations found.</CommandEmpty>
            <CommandGroup heading="Organizations">
              {organizations.map((userOrg) => (
                <CommandItem
                  key={userOrg.organization_id}
                  value={userOrg.organization.name}
                  onSelect={() => handleSelect(userOrg.organization_id)}
                >
                  <Check
                    className={cn(
                      "mr-2 h-4 w-4",
                      currentOrganization.organization_id === userOrg.organization_id
                        ? "opacity-100"
                        : "opacity-0"
                    )}
                  />
                  <div className="flex flex-col flex-1">
                    <span className="text-sm font-medium">
                      {userOrg.organization.name}
                    </span>
                    <span className="text-xs text-muted-foreground">
                      {userOrg.role}
                    </span>
                  </div>
                  {getSubscriptionBadge(userOrg.organization.subscription_tier)}
                </CommandItem>
              ))}
            </CommandGroup>
            <CommandSeparator />
            <CommandGroup>
              <CommandItem onSelect={() => {
                setOpen(false);
                // TODO: Open create organization dialog
              }}>
                <Plus className="mr-2 h-4 w-4" />
                Create Organization
              </CommandItem>
            </CommandGroup>
          </CommandList>
        </Command>
      </PopoverContent>
    </Popover>
  );
};