package api

import (
	"strconv"
	"time"
)

func retryAfterSeconds(delay time.Duration) string {
	if delay <= 0 {
		return "0"
	}

	seconds := int64(delay / time.Second)
	if delay%time.Second != 0 {
		seconds++
	}
	return strconv.FormatInt(seconds, 10)
}

func cookieMaxAgeSeconds(ttl time.Duration) int {
	if ttl <= 0 {
		return 0
	}

	seconds := int64(ttl / time.Second)
	maxInt := int(^uint(0) >> 1)
	if ttl%time.Second != 0 {
		if seconds >= int64(maxInt) {
			return maxInt
		}
		seconds++
	}
	if seconds > int64(maxInt) {
		return maxInt
	}
	return int(seconds)
}
