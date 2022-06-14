package hasuracloud

import "time"

const (
	LeadTimeToUpdateNewlyCreatedProject = 30 * time.Second
	DefaultHealthzInterval              = 3 * time.Second
	HealthCheckRetryTimes               = 10
	LeadTimeBeforeUpdatingDbUrl         = 2 * time.Minute
)
