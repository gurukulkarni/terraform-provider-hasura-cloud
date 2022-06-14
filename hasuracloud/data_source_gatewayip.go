package hasuracloud

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/machinebox/graphql"
)

func dataSourceGatewayIP() *schema.Resource {
	return &schema.Resource{
		ReadContext: dataSourceGatewayIPRead,
		Schema: map[string]*schema.Schema{
			"ips": {
				Type:     schema.TypeList,
				Computed: true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
		},
	}
}

func dataSourceGatewayIPRead(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	var diags diag.Diagnostics
	c := m.(*graphql.Client)

	var response struct {
		Region []struct {
			NatIP string `json:"nat_ip"`
		} `json:"region"`
	}
	if err := c.Run(ctx, graphql.NewRequest(`
query getGatewayIP {
  region(where: {is_active: {_eq: true}, nat_ip: {_is_null: false}}) {
    nat_ip
  }
}
`), &response); err != nil {
		return diag.FromErr(fmt.Errorf("error reading gateway ip: %w", err))
	}

	ipsToWhiteList := make([]string, len(response.Region))

	for index, region := range response.Region {
		ipsToWhiteList[index] = region.NatIP
	}
	if err := d.Set("ips", ipsToWhiteList); err != nil {
		return diag.FromErr(err)
	}

	d.SetId(strconv.FormatInt(time.Now().Unix(), 10))

	return diags
}
