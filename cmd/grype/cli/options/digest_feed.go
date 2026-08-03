package options

import (
	"time"

	"github.com/anchore/clio"
)

type digestFeed struct {
	Source string        `yaml:"source" json:"source" mapstructure:"source"` // URL or file path; empty disables the feature
	TTL    time.Duration `yaml:"ttl" json:"ttl" mapstructure:"ttl"`
}

var _ clio.FieldDescriber = (*digestFeed)(nil)

func defaultDigestFeed() digestFeed {
	return digestFeed{
		TTL: time.Hour,
	}
}

func (cfg *digestFeed) DescribeFields(descriptions clio.FieldDescriptionSet) {
	descriptions.Add(&cfg.Source, `URL or file path of a feed listing file content hashes and the CVEs they are patched against,
used to clear matches on binaries that were patched without a version bump (default is unset, which disables this)`)
	descriptions.Add(&cfg.TTL, `how long a downloaded digest feed is reused before being fetched again`)
}
