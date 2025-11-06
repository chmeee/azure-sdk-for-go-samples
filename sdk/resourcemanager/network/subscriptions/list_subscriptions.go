package main

import (
    "context"
    "fmt"
    "log"

    "github.com/Azure/azure-sdk-for-go/sdk/azidentity"
    "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armsubscriptions"
)

func main() {
    ctx := context.Background()
    cred, err := azidentity.NewDefaultAzureCredential(nil)
    if err != nil {
        log.Fatalf("failed to get credential: %v", err)
    }

    client, err := armsubscriptions.NewClient(cred, nil)
    if err != nil {
        log.Fatalf("failed to create subscriptions client: %v", err)
    }

    pager := client.NewListPager(nil)
    for pager.More() {
        page, err := pager.NextPage(ctx)
        if err != nil {
            log.Fatalf("failed to get subscriptions: %v", err)
        }

        for _, sub := range page.Value {
            fmt.Printf("Subscription: %s (%s)\n", *sub.DisplayName, *sub.SubscriptionID)
        }
    }
}

