package azure

import (
	"context"
	"fmt"
	"log"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v5"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
)

// FirewallRule represents a flattened network rule entry for reporting.
type FirewallRule struct {
	RuleCollectionGroup string
	RuleCollectionName  string
	RuleName            string
	Action              string
	SourceAddresses     string
	DestinationAddresses string
	DestinationPorts    string
	Protocols           string
	Priority            int32
}

// GetFirewallRulesFromHub retrieves all network rule collections and their rules
// for the Firewall associated with a Virtual Hub.
func GetFirewallRulesFromHub(ctx context.Context, subscriptionID, resourceGroup, hubName string) ([]FirewallRule, error) {
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get credentials: %w", err)
	}

	hubClient, err := armnetwork.NewVirtualHubsClient(subscriptionID, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create hub client: %w", err)
	}

	hub, err := hubClient.Get(ctx, resourceGroup, hubName, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get virtual hub: %w", err)
	}

	// Get the associated firewall ID from the hub
	if hub.Properties == nil || hub.Properties.VirtualHubFirewall == nil || hub.Properties.VirtualHubFirewall.ID == nil {
		return nil, fmt.Errorf("no firewall associated with virtual hub %s", hubName)
	}

	firewallID := *hub.Properties.VirtualHubFirewall.ID
	firewallClient, err := armnetwork.NewAzureFirewallsClient(subscriptionID, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create firewall client: %w", err)
	}

	// Extract firewall name and resource group from its ID
	firewallRG, firewallName, err := parseResourceID(firewallID)
	if err != nil {
		return nil, fmt.Errorf("failed to parse firewall ID: %w", err)
	}

	firewall, err := firewallClient.Get(ctx, firewallRG, firewallName, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get firewall: %w", err)
	}

	if firewall.Properties == nil || firewall.Properties.FirewallPolicy == nil || firewall.Properties.FirewallPolicy.ID == nil {
		return nil, fmt.Errorf("firewall %s has no policy associated", firewallName)
	}

	policyID := *firewall.Properties.FirewallPolicy.ID
	policyRG, policyName, err := parseResourceID(policyID)
	if err != nil {
		return nil, fmt.Errorf("failed to parse firewall policy ID: %w", err)
	}

	rcgClient, err := armnetwork.NewFirewallPolicyRuleCollectionGroupsClient(subscriptionID, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create rule collection group client: %w", err)
	}

	pager := rcgClient.NewListPager(policyRG, policyName, nil)
	var rules []FirewallRule

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to get rule collection group page: %w", err)
		}

		for _, rcg := range page.Value {
			if rcg == nil || rcg.Properties == nil {
				continue
			}
			rcgName := deref(rcg.Name)

			for _, col := range rcg.Properties.RuleCollections {
				if col == nil {
					continue
				}

				// Since we only have network rule collections, cast directly
				filterCol, ok := col.(*armnetwork.FirewallPolicyFilterRuleCollection)
				if !ok || filterCol == nil || filterCol.Properties == nil {
					continue
				}

				colName := deref(filterCol.Name)
				action := ""
				if filterCol.Properties.Action != nil && filterCol.Properties.Action.Type != nil {
					action = string(*filterCol.Properties.Action.Type)
				}

				priority := int32(0)
				if filterCol.Properties.Priority != nil {
					priority = *filterCol.Properties.Priority
				}

				for _, rule := range filterCol.Properties.Rules {
					netRule, ok := rule.(*armnetwork.NetworkRule)
					if !ok || netRule == nil {
						continue
					}

					r := FirewallRule{
						RuleCollectionGroup: rcgName,
						RuleCollectionName:  colName,
						RuleName:            deref(netRule.Name),
						Action:              action,
						SourceAddresses:     join(derefSlice(netRule.Properties.SourceAddresses)),
						DestinationAddresses: join(derefSlice(netRule.Properties.DestinationAddresses)),
						DestinationPorts:    join(derefSlice(netRule.Properties.DestinationPorts)),
						Protocols:           join(convertProtocols(netRule.Properties.Protocols)),
						Priority:            priority,
					}

					rules = append(rules, r)
				}
			}
		}
	}

	log.Printf("Retrieved %d firewall rules from %s", len(rules), hubName)
	return rules, nil
}

// Helper to safely dereference pointers
func deref[T any](ptr *T) T {
	var zero T
	if ptr != nil {
		return *ptr
	}
	return zero
}

// Helper to join string slices with commas
func join(items []string) string {
	out := ""
	for i, s := range items {
		if i > 0 {
			out += ", "
		}
		out += s
	}
	return out
}

// Helper to dereference slices of *string
func derefSlice(ptrs []*string) []string {
	result := make([]string, 0, len(ptrs))
	for _, p := range ptrs {
		if p != nil {
			result = append(result, *p)
		}
	}
	return result
}

// Helper to convert protocol enum pointers to strings
func convertProtocols(protocols []*armnetwork.NetworkRuleProtocol) []string {
	result := make([]string, 0, len(protocols))
	for _, p := range protocols {
		if p != nil {
			result = append(result, string(*p))
		}
	}
	return result
}

// parseResourceID extracts the resource group and name from a resource ID.
func parseResourceID(id string) (string, string, error) {
	// Expected format:
	// /subscriptions/<sub>/resourceGroups/<rg>/providers/Microsoft.Network/azureFirewalls/<name>
	var rg, name string
	_, err := fmt.Sscanf(id, "/subscriptions/%*[^/]/resourceGroups/%[^/]/providers/Microsoft.Network/%*[^/]/%s", &rg, &name)
	if err != nil {
		return "", "", fmt.Errorf("invalid resource ID format: %s", id)
	}
	return rg, name, nil
}

