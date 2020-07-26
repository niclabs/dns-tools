package tools

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

type parseableDuration int

const (
	seconds parseableDuration = iota
	minutes
	hours
	days
	weeks
	months
	years
)

var strToParseableDuration = map[string]parseableDuration{
	"s":      seconds,
	"sec":    seconds,
	"second": seconds,

	"min":    minutes,
	"minute": minutes,

	"h":    hours,
	"hour": hours,
	"hr":   hours,

	"w":    weeks,
	"week": weeks,

	"d":   days,
	"day": days,

	"m":     months,
	"month": months,

	"y":    years,
	"year": years,
}

// DurationToTime parses a duration string and returns a time relative to now.
func DurationToTime(now time.Time, dStr string) (d time.Time, err error) {
	parts := strings.Fields(dStr)
	if len(parts)%2 != 0 {
		err = fmt.Errorf("wrong duration string format (it could be like \"10 years 2 months 3 days 4 hours 22 minutes 13 seconds\"")
		return
	}
	parsed := map[parseableDuration]int{
		seconds: 0,
		minutes: 0,
		hours:   0,
		days:    0,
		weeks:   0,
		months:  0,
		years:   0,
	}
	for i := 0; i < len(parts); i += 2 {
		strType := strings.TrimRight(strings.ToLower(parts[i+1]), ",") // trims commas
		if strType != "s" {                                            // in we do not check this, we will delete the type completely
			strType = strings.TrimRight(strType, "s") // trims plurals
		}
		durationType, ok := strToParseableDuration[strType]
		if !ok {
			err = fmt.Errorf("unknown duration keyword: %s", parts[i])
			return
		}
		var durationValue int
		durationValue, err = strconv.Atoi(parts[i])
		if err != nil {
			err = fmt.Errorf("cannot parse duration value \"%s\" as int: %s", parts[i+1], err)
			return
		}
		if durationValue < 0 {
			err = fmt.Errorf("duration for keyword %s is negative", strType)
		}
		if parsed[durationType] != 0 {
			err = fmt.Errorf("duration keyword %s already defined", strType)
			return
		}
		parsed[durationType] = durationValue
	}

	d = now.
		AddDate(parsed[years], parsed[months], parsed[days]+7*parsed[weeks]).
		Add(time.Duration(parsed[hours])*time.Hour +
			time.Duration(parsed[minutes])*time.Minute +
			time.Duration(parsed[seconds])*time.Second)
	return
}
