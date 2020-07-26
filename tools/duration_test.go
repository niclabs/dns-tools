package tools_test

import (
	"strings"
	"testing"
	"time"

	"github.com/niclabs/dns-tools/tools"
)

type DurationTestCase struct {
	str    string
	years  int
	months int
	weeks  int
	days   int
	hours  int
	mins   int
	secs   int
	err    string
}

var testCases []DurationTestCase = []DurationTestCase{
	{
		str:    "6 months",
		months: 6,
	},
	{
		str:    "5 years 3 months 3 weeks 2 days 15 hours 7 mins 4 secs",
		years:  5,
		months: 3,
		weeks:  3,
		days:   2,
		hours:  15,
		mins:   7,
		secs:   4,
	},
	{
		str:   "9 y, 7 min, 4 s",
		years: 9,
		mins:  7,
		secs:  4,
	},
	{
		str: "4 secs      3 hours  1 year    3 secs",
		err: "already defined",
	},
	{
		str: "one second",
		err: "cannot parse duration value",
	},
	{
		str: "5 milleniums",
		err: "unknown duration keyword",
	},
	{
		str: "-2 years",
		err: "is negative",
	},
}

func Test_DurationToTime(t *testing.T) {
	now := time.Now()
	for _, test := range testCases {
		parsedDate, err := tools.DurationToTime(now, test.str)
		if err != nil {
			t.Logf("\"%s\" is not parseable: %s", test.str, err)
			if !strings.Contains(err.Error(), test.err) {
				t.Logf("expected error %s but %s was obtained", test.err, err)
				t.Fail()
			}
			continue
		}
		expectedDate := now.
			AddDate(test.years, test.months, test.days+7*test.weeks).
			Add(time.Duration(test.hours)*time.Hour +
				time.Duration(test.mins)*time.Minute +
				time.Duration(test.secs)*time.Second)
		if !expectedDate.Equal(parsedDate) {
			t.Logf("%s is equal to %s and not to %s", test.str, parsedDate, expectedDate)
			t.Fail()
			return
		}
		t.Logf("%s is equal to %s", test.str, expectedDate.String())
	}
}
