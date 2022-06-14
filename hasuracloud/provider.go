package hasuracloud

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/machinebox/graphql"
)

const (
	endpointKey = "endpoint"
	patKey      = "pat"
)

type patHeaderRoundTripper struct {
	pat          string
	roundTripper http.RoundTripper
}

func (p *patHeaderRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	req.Header.Set("Authorization", fmt.Sprintf("pat %s", p.pat))
	return p.roundTripper.RoundTrip(req)
}

func Provider() *schema.Provider {
	return &schema.Provider{
		Schema: map[string]*schema.Schema{
			patKey: {
				Type:     schema.TypeString,
				Required: true,
			},
			endpointKey: {
				Type:     schema.TypeString,
				Optional: true,
				Default:  "https://data.pro.hasura.io/v1/graphql",
			},
		},
		ResourcesMap: map[string]*schema.Resource{
			"hasuracloud_tenant": resourceTenant(),
		},
		DataSourcesMap: map[string]*schema.Resource{
			"hasuracloud_gateways": dataSourceGatewayIP(),
		},
		ConfigureContextFunc: func(ctx context.Context, data *schema.ResourceData) (interface{}, diag.Diagnostics) {
			var diags diag.Diagnostics

			endpoint := data.Get(endpointKey).(string)
			pat := data.Get(patKey).(string)

			client := &http.Client{
				Transport: &patHeaderRoundTripper{pat: pat, roundTripper: http.DefaultTransport},
				Timeout:   time.Second * 10,
			}

			return graphql.NewClient(endpoint, graphql.WithHTTPClient(client)), diags
		},
	}
}
