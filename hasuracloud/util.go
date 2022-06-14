package hasuracloud

import (
	"context"
	"time"
)

func pollImmediateUntil(ctx context.Context, interval time.Duration, retryTimes int, condition func() (bool, error)) error {
	ok, err := condition()
	if err == nil && ok {
		return nil
	}

	var counter = retryTimes
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			ok, err := condition()
			if err == nil && ok {
				return nil
			}
			counter--
			if counter <= 0 {
				if err != nil {
					return err
				}
				return ctx.Err()
			}
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func equalStringToStringMaps(m1, m2 map[string]string) bool {
	if len(m1) != len(m2) {
		return false
	}
	for k, v1 := range m1 {
		if v2, ok := m2[k]; !ok || v1 != v2 {
			return false
		}
	}
	return true
}
