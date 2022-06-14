package hasuracloud

import (
	"bytes"
	"context"
	"crypto/sha1"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/machinebox/graphql"
)

const (
	cloudKey                 = "cloud"
	regionKey                = "region"
	planKey                  = "plan"
	slugKey                  = "slug"
	projectIDKey             = "project_id"
	projectNameKey           = "project_name"
	customDomainKey          = "custom_domain"
	customDomainPrimaryKeyId = "custom_domain_primary_key"
	adminSecretKey           = "admin_secret"
)

type Tenant struct {
	ID      string `json:"id"`
	Slug    string `json:"slug"`
	Project struct {
		ID       string `json:"id"`
		Endpoint string `json:"endpoint"`
	} `json:"project"`
}

type EnvVars map[string]string

func UnmarshalEnvVar(v interface{}) (string, error) {
	switch x := v.(type) {
	case string:
		return x, nil
	default:
		data, err := json.Marshal(x)
		if err != nil {
			return "", err
		}

		return string(data), nil
	}
}

func (e *EnvVars) UnmarshalJSON(data []byte) error {
	var nested map[string]interface{}
	if err := json.Unmarshal(data, &nested); err != nil {
		return err
	}

	out := make(map[string]string)
	for k, a := range nested {
		if k == "environment" {
			environment, ok := a.(map[string]interface{})
			if ok {
				for kn, an := range environment {
					v, err := UnmarshalEnvVar(an)
					if err != nil {
						return err
					}
					out[kn] = v
				}
			}
		} else {
			v, err := UnmarshalEnvVar(a)
			if err != nil {
				return err
			}
			out[k] = v
		}
	}
	*e = out
	return nil
}

const (
	envVarsKey = "env_vars"
	hashKey    = "hash"
)

func getTenantEnv(ctx context.Context, c *graphql.Client, tenantID string) (hash string, envVars map[string]string, err error) {
	req := graphql.NewRequest(`
query getTenantENV($tenant_id: uuid!) {
  getTenantEnv(
    tenantId: $tenant_id
  ) {
    hash
    envVars
  }
}`)
	req.Var("tenant_id", tenantID)

	var res struct {
		GetTenantEnv struct {
			Hash    string  `json:"hash"`
			EnvVars EnvVars `json:"envVars"`
		} `json:"getTenantEnv"`
	}
	if err := c.Run(ctx, req, &res); err != nil {
		return "", nil, fmt.Errorf("error getting tenant env: %w", err)
	}

	return res.GetTenantEnv.Hash, res.GetTenantEnv.EnvVars, nil
}

func updateTenantEnv(ctx context.Context, c *graphql.Client, tenantID string, currentHash string, newEnvVar map[string]string) (hash string, envVars map[string]string, err error) {
	q := fmt.Sprintf(`
mutation updateTenantEnv($envs: [UpdateEnvObject!]!) {
  updateTenantEnv(
    tenantId: "%s"
    currentHash: "%s"
	envs: $envs,
  ) {
	hash
	envVars
  }
}`, tenantID, currentHash)

	var res struct {
		UpdateTenantEnv struct {
			Hash    string  `json:"hash"`
			EnvVars EnvVars `json:"envVars"`
		} `json:"getTenantEnv"`
	}

	req := graphql.NewRequest(q)
	type UpdateEnvObject struct {
		Key   string `json:"key"`
		Value string `json:"value"`
	}
	var updates []UpdateEnvObject
	for k, v := range newEnvVar {
		updates = append(updates, UpdateEnvObject{k, v})
	}

	req.Var("envs", updates)
	if err := c.Run(ctx, req, &res); err != nil {
		return "", nil, fmt.Errorf("error updating tenant env: %w", err)
	}

	return res.UpdateTenantEnv.Hash, res.UpdateTenantEnv.EnvVars, nil
}

func filterEnvVarsByDesiredEnvVars(remoteEnvVars, desiredEnvVars map[string]string) map[string]string {
	out := make(map[string]string)
	for k, v := range remoteEnvVars {
		if _, ok := desiredEnvVars[k]; ok {
			out[k] = v
		}
	}
	return out
}

func applyTenantEnv(ctx context.Context, c *graphql.Client, tenantID string, envVars map[string]string) (string, map[string]string, error) {
	hash, remoteEnvVars, err := getTenantEnv(ctx, c, tenantID)
	if err != nil {
		return "", nil, err
	}

	updateRequired := make(map[string]string)
	for k, v := range envVars {
		if v2, ok := remoteEnvVars[k]; !ok || v2 != v {
			updateRequired[k] = v
		}
	}

	if len(updateRequired) > 0 {
		hash, _, err = updateTenantEnv(ctx, c, tenantID, hash, updateRequired)
		if err != nil {
			return "", nil, fmt.Errorf("error applying env (current %#v, update required %#v): %w", remoteEnvVars, updateRequired, err)
		}
	}
	return hash, envVars, nil
}

func decodeEnvVars(v interface{}) (map[string]string, error) {
	switch m := v.(type) {
	case map[string]interface{}:
		out := make(map[string]string, len(m))
		for k, a := range m {
			out[k] = fmt.Sprintf("%v", a)
		}
		return out, nil
	case map[string]string:
		return m, nil
	default:
		return nil, fmt.Errorf("unknown env var type %T", m)
	}
}

func getEnvVars(data *schema.ResourceData) (map[string]string, error) {
	return decodeEnvVars(data.Get(envVarsKey))
}

func getCloud(data *schema.ResourceData) (string, error) {
	v := data.Get(cloudKey)
	if cloud, ok := v.(string); ok {
		return cloud, nil
	}
	return "", fmt.Errorf("%s is not of type string but %T", cloudKey, v)
}

func getRegion(data *schema.ResourceData) (string, error) {
	v := data.Get(regionKey)
	if region, ok := v.(string); ok {
		return region, nil
	}
	return "", fmt.Errorf("%s is not of type string but %T", regionKey, v)
}

func getPlan(data *schema.ResourceData) (string, error) {
	v := data.Get(planKey)
	if region, ok := v.(string); ok {
		return region, nil
	}
	return "", fmt.Errorf("%s is not of type string but %T", planKey, v)
}

func getProjectName(data *schema.ResourceData) (string, error) {
	v := data.Get(projectNameKey)
	if projectName, ok := v.(string); ok {
		return projectName, nil
	}
	return "", fmt.Errorf("%s is not of type string but %T", projectNameKey, v)
}

func getAdminSecret(data *schema.ResourceData) (string, error) {
	v := data.Get(adminSecretKey)
	if adminSecret, ok := v.(string); ok {
		return adminSecret, nil
	}
	return "", fmt.Errorf("%s is not of type string but %T", adminSecretKey, v)
}

func resourceTenant() *schema.Resource {
	return &schema.Resource{
		Schema: map[string]*schema.Schema{
			cloudKey: {
				Type:     schema.TypeString,
				Required: true,
				ForceNew: true,
			},
			regionKey: {
				Type:     schema.TypeString,
				Required: true,
				ForceNew: true,
			},
			planKey: {
				Type:     schema.TypeString,
				Required: true,
				ForceNew: true,
			},
			hashKey: {
				Type:     schema.TypeString,
				Computed: true,
			},
			envVarsKey: {
				Type: schema.TypeMap,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
				Optional: true,
			},
			projectNameKey: {
				Type:     schema.TypeString,
				Required: true,
			},
			customDomainKey: {
				Type:     schema.TypeString,
				Required: true,
			},
			customDomainPrimaryKeyId: {
				Type:     schema.TypeString,
				Computed: true,
			},
			slugKey: {
				Type:     schema.TypeString,
				Computed: true,
			},
			endpointKey: {
				Type:     schema.TypeString,
				Computed: true,
			},
			projectIDKey: {
				Type:     schema.TypeString,
				Computed: true,
			},
			adminSecretKey: {
				Type:      schema.TypeString,
				Required:  true,
				Sensitive: true,
			},
		},
		CreateContext: func(ctx context.Context, data *schema.ResourceData, i interface{}) diag.Diagnostics {
			var diags diag.Diagnostics

			c := i.(*graphql.Client)
			c.Log = func(s string) { log.Printf("[INFO] ------- CreateContext : %v\n", s) }
			cloud, err := getCloud(data)
			if err != nil {
				return diag.FromErr(err)
			}
			log.Printf("[INFO] CreateContext : Got Cloud input : %v\n", cloud)

			region, err := getRegion(data)
			if err != nil {
				return diag.FromErr(err)
			}
			log.Printf("[INFO] CreateContext : Got Region Input : %v\n", region)

			plan, err := getPlan(data)
			if err != nil {
				return diag.FromErr(err)
			}
			log.Printf("[INFO] CreateContext : Got Plan Input : %v\n", plan)

			envVars, err := getEnvVars(data)
			if err != nil {
				return diag.FromErr(err)
			}
			log.Printf("[INFO] CreateContext : Got %v Env Vars : \n", len(envVars))

			projectName, err := getProjectName(data)
			log.Printf("[INFO] CreateContext : Got Project Name : %v\n", projectName)

			tenantID, err := createTenant(ctx, c, cloud, projectName, region, plan)
			if err != nil {
				return diag.FromErr(err)
			}
			log.Printf("[INFO] CreateContext : Created Tenant, Id is %v\n", tenantID)

			adminSecret, err := getAdminSecret(data)
			if err != nil {
				return diag.FromErr(err)
			}
			log.Printf("[INFO] CreateContext : Got admin secret (Showing sha1 sum) : %v\n", sha1.Sum([]byte(adminSecret)))

			data.SetId(tenantID)

			log.Printf("[INFO] CreateContext : Sleeping for %v until the project is provisioned\n", LeadTimeToUpdateNewlyCreatedProject)
			time.Sleep(LeadTimeToUpdateNewlyCreatedProject)
			tenant, err := getTenantByID(ctx, c, tenantID)
			if err != nil {
				return diag.FromErr(err)
			}
			log.Printf("[INFO] CreateContext : Got Tenant Details  %v\n", tenant)

			if err := data.Set(slugKey, tenant.Slug); err != nil {
				return diag.FromErr(fmt.Errorf("error setting slug: %w", err))
			}

			if err := data.Set(projectIDKey, tenant.Project.ID); err != nil {
				return diag.FromErr(fmt.Errorf("error setting project id: %w", err))
			}
			if err := data.Set(endpointKey, tenant.Project.Endpoint); err != nil {
				return diag.FromErr(fmt.Errorf("error setting project endpoint: %w", err))
			}

			log.Printf("[INFO] CreateContext : Updating %v Env Variables\n", len(envVars))
			hash, envVars, err := applyTenantEnv(ctx, c, tenantID, envVars)
			if err != nil {
				return diag.FromErr(fmt.Errorf("error applying tenant env: %w", err))
			}

			if err := data.Set(hashKey, hash); err != nil {
				return diag.FromErr(err)
			}
			if err := data.Set(envVarsKey, envVars); err != nil {
				return diag.FromErr(err)
			}

			log.Printf("[INFO] CreateContext : Saved Env Vars and it's hashKey %v\n", hash)

			log.Printf("[INFO] CreateContext : Calling Health check %v to see if project is ready every %v for %v times\n", tenant.Project.Endpoint, DefaultHealthzInterval, HealthCheckRetryTimes)
			if err := initialWaitForEndpointHealthz(ctx, DefaultHealthzInterval, HealthCheckRetryTimes, tenant.Project.Endpoint); err != nil {
				return diag.FromErr(err)
			}

			log.Printf("[INFO] CreateContext : Health check %v Successful\n", tenant.Project.Endpoint)
			customDomain, err := createCustomDomain(ctx, c, tenant.ID, data)
			if err != nil {
				data.SetId("")
				return diag.FromErr(fmt.Errorf("create context : error creating custom domain : %w", err))
			}
			log.Printf("[INFO] CreateContext : Created Custom Domain %v \n", customDomain)

			_ = initialWaitForEndpointHealthz(ctx, DefaultHealthzInterval, HealthCheckRetryTimes, fmt.Sprintf("https://%s", customDomain.Fqdn))

			return diags
		},
		ReadContext: func(ctx context.Context, data *schema.ResourceData, i interface{}) diag.Diagnostics {
			var diags diag.Diagnostics
			c := i.(*graphql.Client)
			c.Log = func(s string) { log.Printf("[INFO] ------- ReadContext : %v\n", s) }

			tenantID := data.Id()
			tenant, err := getTenantByID(ctx, c, tenantID)
			if err != nil {
				return diag.FromErr(err)
			}

			data.SetId(tenant.ID)
			if err := data.Set(slugKey, tenant.Slug); err != nil {
				return diag.FromErr(err)
			}
			if err := data.Set(projectIDKey, tenant.Project.ID); err != nil {
				return diag.FromErr(err)
			}
			if err := data.Set(endpointKey, tenant.Project.Endpoint); err != nil {
				return diag.FromErr(err)
			}

			hash, remoteEnvVars, err := getTenantEnv(ctx, c, tenantID)
			if err != nil {
				data.SetId("")
				return diags
			}
			envVars, err := getEnvVars(data)
			if err != nil {
				return diag.FromErr(err)
			}

			if err := data.Set(hashKey, hash); err != nil {
				return diag.FromErr(err)
			}
			if err := data.Set(envVarsKey, filterEnvVarsByDesiredEnvVars(remoteEnvVars, envVars)); err != nil {
				return diag.FromErr(err)
			}

			if customDomainFromTenantQuery, errFromQueryCustomDomainByTenantId := queryCustomDomainByTenantId(ctx, c, tenantID); errFromQueryCustomDomainByTenantId == nil && customDomainFromTenantQuery.Fqdn != "" {
				log.Printf("[INFO] Resposne tenantByPk : %v\n", customDomainFromTenantQuery)
				if err = data.Set(customDomainPrimaryKeyId, customDomainFromTenantQuery.Id); err != nil {
					return diag.FromErr(fmt.Errorf("read context : error when updating customDomainPrimaryKeyId : %w", err))
				}

			}

			return diags
		},
		UpdateContext: func(ctx context.Context, data *schema.ResourceData, i interface{}) diag.Diagnostics {
			var diags diag.Diagnostics
			c := i.(*graphql.Client)
			c.Log = func(s string) { log.Printf("[INFO] ------ UpdateContext : %v\n", s) }
			tenantID := data.Id()

			var endpoint = data.Get(endpointKey).(string)
			projectName, err := getProjectName(data)
			if err == nil && len(projectName) > 0 {
				updatedEndpoint, err := updateProjectNameIfRequired(ctx, data, c, tenantID, projectName)
				if err != nil {
					return diag.FromErr(err)
				}

				if err := data.Set(endpointKey, updatedEndpoint); err != nil {
					return diag.FromErr(err)
				}
			}

			envVars, err := getEnvVars(data)
			if err != nil {
				return diag.FromErr(err)
			}

			hash, envVars, err := applyTenantEnv(ctx, c, tenantID, envVars)
			if err != nil {
				return diag.FromErr(fmt.Errorf("error applying tenant env: %w", err))
			}

			if err := data.Set(hashKey, hash); err != nil {
				return diag.FromErr(err)
			}
			if err := data.Set(envVarsKey, envVars); err != nil {
				return diag.FromErr(err)
			}

			log.Printf("[INFO] Health Endpoint Base %v\n", endpoint)
			if err := waitForEndpointHealthz(ctx, DefaultHealthzInterval, 3, endpoint, false); err != nil {
				return diag.FromErr(err)
			}

			customDomain, err := createCustomDomain(ctx, c, tenantID, data)
			if err != nil {
				return diag.FromErr(fmt.Errorf("update context : error when creating custom domain : %w", err))
			}

			if err = data.Set(customDomainPrimaryKeyId, customDomain.Id); err != nil {
				return diag.FromErr(fmt.Errorf("update context : error when updating customDomainPrimaryKeyId : %w", err))
			}

			return diags
		},
		DeleteContext: func(ctx context.Context, data *schema.ResourceData, i interface{}) diag.Diagnostics {
			var diags diag.Diagnostics
			c := i.(*graphql.Client)

			if err := deleteTenant(ctx, c, data.Id()); err != nil {
				return diag.FromErr(err)
			}

			return diags
		},
	}
}

func updateProjectNameIfRequired(ctx context.Context, data *schema.ResourceData, c *graphql.Client, tenantID string, projectName string) (string, error) {
	tenant, err := getTenantByID(ctx, c, tenantID)
	if err != nil {
		return "", err
	}

	log.Printf("[INFO] Tenant Project Endpoint: %v | Tenant Project Name: %v | Project Name: %v | \n", tenant.Project.Endpoint, tenant.Slug, projectName)
	if tenant.Slug == projectName {
		return tenant.Project.Endpoint, nil
	}
	projectId := tenant.Project.ID
	if err = data.Set(projectIDKey, projectId); err != nil {
		return "", err
	}

	req := graphql.NewRequest(`query getProjectDetails($id: uuid!) { project: projects_by_pk(id: $id) { id name endpoint } }`)
	req.Var("id", projectId)
	var res struct {
		Data struct {
			Project struct {
				Id       string `json:"id"`
				Name     string `json:"name"`
				Endpoint string `json:"endpoint"`
			} `json:"project"`
		} `json:"data"`
	}
	if err := c.Run(ctx, req, &res); err != nil {
		return "", fmt.Errorf("error getting project name for %s, when stored name was %s for tenant %s: %w", projectId, projectName, tenantID, err)
	}

	if res.Data.Project.Name == projectName {
		err := updateProjectName(ctx, c, tenantID, projectName)
		if err != nil {
			return "", err
		}
	}

	return res.Data.Project.Endpoint, nil
}

func createCustomDomain(ctx context.Context, c *graphql.Client, tenantID string, data *schema.ResourceData) (CustomDomain, error) {
	customDomain, err := getCustomDomainInput(data)
	if err != nil {
		return CustomDomain{}, fmt.Errorf("update context : error in getting custom domain from the input : %w", err)
	}

	customDomainId, err := getCustomDomainId(data)
	log.Printf("[INFO] Custom Domain Id from data : %v\n", customDomainId)
	if err == nil && customDomainId != "" {

		if domain, err2 := queryCustomDomain(ctx, c, customDomain, customDomainId); err2 == nil && domain.Fqdn != "" {
			return domain, nil
		}
	}

	log.Printf("[INFO] No Custom Domain Id Found, ignoring as it may not exist, error was %v\n trying to create %v", err, customDomain)

	req := graphql.NewRequest(`mutation createCustomDomain($tenantId: uuid!, $fqdn: String!) {  insert_custom_domain_one(object: {fqdn: $fqdn, tenant_id: $tenantId}) {    id    created_at    dns_validation    fqdn    cert    __typename  }}`)

	//log.Printf("[INFO] Auth Header: %v and passed Pat %v\n", req.Header.Get("Authorization"), personalAccessToken)
	req.Var("tenantId", tenantID)
	req.Var("fqdn", customDomain)

	var res struct {
		Data struct {
			InsertCustomDomainOne struct {
				ID            string `json:"id"`
				CreatedAt     string `json:"created_at"`
				DnsValidation string `json:"dns_validation"`
				Fqdn          string `json:"fqdn"`
				Cert          string `json:"cert"`
			} `json:"insert_custom_domain_one"`
		} `json:"data"`
	}
	if err := c.Run(ctx, req, &res); err != nil {
		/*	    if strings.Contains(err.Error(), "Uniqueness violation. duplicate key value violates unique constraint") {
			    return CustomDomain{"", customDomain}, nil
			}*/
		return CustomDomain{}, fmt.Errorf("error in createCustomDomain: %w", err)
	}
	return CustomDomain{res.Data.InsertCustomDomainOne.ID, res.Data.InsertCustomDomainOne.Fqdn}, nil
}

func queryCustomDomain(ctx context.Context, c *graphql.Client, customDomain string, customDomainId string) (CustomDomain, error) {
	log.Printf("[INFO] Checking Custom Domain against input: %v with customDomainId %v\n", customDomain, customDomainId)
	queryReq := graphql.NewRequest(`query getCustomDomain($id: uuid!) { custom_domain_by_pk( id: $id ) { fqdn } }`)

	queryReq.Var("id", customDomainId)

	log.Printf("[INFO] Query Req: %v\n", queryReq)
	var queryRes struct {
		Data struct {
			Fqdn string `json:"fqdn"`
		} `json:"custom_domain_by_pk"`
	}

	if err := c.Run(ctx, queryReq, &queryRes); err != nil {
		log.Printf("[WARN] error in reading createCustomDomain: %v\n", err)
		return CustomDomain{}, nil
	}

	log.Printf("[INFO] createCustomDomain query call successful: %v\n", queryRes.Data)
	return CustomDomain{customDomainId, queryRes.Data.Fqdn}, nil
}

func queryCustomDomainByTenantId(ctx context.Context, c *graphql.Client, tenantId string) (CustomDomain, error) {
	log.Printf("[INFO] Reading Custom Domain using tenent id: %v \n", tenantId)
	req := graphql.NewRequest(`query getTenantDetails($tenant_id: uuid!) { tenant_by_pk( id: $tenant_id ) { custom_domains { id fqdn } } }`)

	req.Var("tenant_id", tenantId)

	log.Printf("[INFO] Query Req: %v\n", req)

	var res map[string]map[string][]map[string]string

	if err := c.Run(ctx, req, &res); err != nil {
		log.Printf("[WARN] error in reading queryCustomDomainByTenantId: %v : read this %v\n", err, res)
		return CustomDomain{}, err
	}
	log.Printf("[INFO] queryCustomDomainByTenantId query call response %v\n", res["tenant_by_pk"]["custom_domains"][0])

	for _, domain := range res["tenant_by_pk"]["custom_domains"] {
		log.Printf("[INFO] For Id: %v | Fqdn: %v\n", domain["id"], domain["fqdn"])
	}

	return CustomDomain{res["tenant_by_pk"]["custom_domains"][0]["id"], res["tenant_by_pk"]["custom_domains"][0]["fqdn"]}, nil
}

type CustomDomainByTenant struct {
	Data struct {
		TenantByPk struct {
			CustomDomains []CustomDomain `json:"custom_domains"`
		} `json:"tenant_by_pk"`
	} `json:"data"`
}

type CustomDomain struct {
	Id   string `json:"id"`
	Fqdn string `json:"fqdn"`
}

func getCustomDomainInput(data *schema.ResourceData) (string, error) {
	v := data.Get(customDomainKey)
	if customDomain, ok := v.(string); ok {
		return customDomain, nil
	}
	return "", fmt.Errorf("%s is not of type string but %T", customDomainKey, v)
}

func getCustomDomainId(data *schema.ResourceData) (string, error) {
	v := data.Get(customDomainPrimaryKeyId)
	if customDomainId, ok := v.(string); ok {
		return customDomainId, nil
	}
	return "", fmt.Errorf("error when updating customDomainPrimaryKeyId %s", customDomainPrimaryKeyId)
}

func addDefaultDatabaseUsingEnvVariables(adminSecret, projectName string) error {
	metadataUrl := fmt.Sprintf("https://%s.hasura.app/v1/metadata", projectName)

	var jsonStr = []byte(`{
                            "type": "pg_add_source",
                            "args": {
                                "configuration": {
                                    "connection_info": {
                                        "database_url": {
                                            "from_env": "DB_URL"
                                        },
                                        "pool_settings": {}
                                    }
                                },
                                "name": "default",
                                "replace_configuration": true
                            }`)
	req, err := http.NewRequest("POST", metadataUrl, bytes.NewBuffer(jsonStr))
	if err != nil {
		return fmt.Errorf("could not create http request for %s", projectName)
	}
	req.Header.Set("x-hasura-admin-secret", adminSecret)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}

	log.Printf("[INFO] : addDefaultDatabaseUsingEnvVariables : Request %v | response code %v  | response boby | %v\n", req, resp.StatusCode, resp.Body)
	if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusCreated {
		return nil
	}

	return fmt.Errorf("could not update database url using the metadata API for %s", projectName)
}

func getTenantByID(ctx context.Context, c *graphql.Client, tenantID string) (*Tenant, error) {
	req := graphql.NewRequest(`
query getTenantDetails($tenant_id: uuid!) {
  tenant_by_pk(
    id: $tenant_id
  ) {
    id
	slug
	project {
		id
		endpoint
	}
  }
}`)
	req.Var("tenant_id", tenantID)

	var res struct {
		TenantByPK Tenant `json:"tenant_by_pk"`
	}
	if err := c.Run(ctx, req, &res); err != nil {
		return nil, fmt.Errorf("error reading tenant: %w", err)
	}
	return &res.TenantByPK, nil
}

/*
mutation createTenant($cloud: String!, $region: String!, $name: String, $plan: String!) { createTenant(cloud: $cloud, region: $region, name: $name, plan: $plan) { id }

mutation createProject { createTenant( cloud: "aws" region: "us-east-2" ) { id } }

*/

func createTenant(ctx context.Context, c *graphql.Client, cloud, name, region, plan string) (string, error) {
	req := graphql.NewRequest(`mutation createTenant($name: String, $plan: String!, $region: String!, $cloud: String!) { createTenant(cloud: $cloud, region: $region, name: $name, plan: $plan) {  id } }`)
	req.Var("cloud", cloud)
	req.Var("name", name)
	req.Var("region", region)
	req.Var("plan", plan)

	var res struct {
		CreateTenant struct {
			ID string `json:"id"`
		}
	}
	if err := c.Run(ctx, req, &res); err != nil {
		return "", fmt.Errorf("error creating tenant: %w", err)
	}
	return res.CreateTenant.ID, nil
}

func deleteTenant(ctx context.Context, c *graphql.Client, tenantID string) error {
	req := graphql.NewRequest(`
mutation deleteTenant($tenant_id: uuid!) {
	deleteTenant(
		tenantId: $tenant_id
) {
	status
}
}`)
	req.Var("tenant_id", tenantID)

	var res struct{}
	if err := c.Run(ctx, req, &res); err != nil {
		return fmt.Errorf("error deleting tenant: %w", err)
	}
	return nil
}

func initialWaitForEndpointHealthz(ctx context.Context, interval time.Duration, healthCheckRetryTimes int, endpoint string) error {
	return waitForEndpointHealthz(ctx, interval, healthCheckRetryTimes, endpoint, true)
}

func waitForEndpointHealthz(ctx context.Context, interval time.Duration, healthCheckRetryTimes int, endpoint string, initialWait bool) error {
	if initialWait {
		time.Sleep(LeadTimeToUpdateNewlyCreatedProject)
	}
	if err := pollImmediateUntil(ctx, interval, healthCheckRetryTimes, func() (bool, error) {
		res, err := http.Get(fmt.Sprintf("%s/healthz", endpoint))
		if err != nil {
			return false, err
		}
		return res.StatusCode == http.StatusOK, nil
	}); err != nil {
		return fmt.Errorf("error waiting for endpoint health: %w", err)
	}
	return nil
}

func updateProjectName(ctx context.Context, c *graphql.Client, tenantID string, projectName string) error {
	req := graphql.NewRequest(`mutation updateProjectName($name: String!, $tenantId: uuid!) { updateTenantName(name: $name, tenantId: $tenantId) { tenant { id } }}`)
	req.Var("name", projectName)
	req.Var("tenantId", tenantID)

	var res struct {
		Data struct {
			UpdateTenantName struct {
				Tenant struct {
					Project struct {
						Endpoint string `json:"endpoint"`
					} `json:"project"`
				} `json:"tenant"`
			} `json:"updateTenantName"`
		} `json:"data"`
	}
	if err := c.Run(ctx, req, &res); err != nil {
		return fmt.Errorf("error updating project name to %s for tenant %s: %w", projectName, tenantID, err)
	}
	return nil
}
