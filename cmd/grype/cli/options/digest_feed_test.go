package options

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/anchore/clio"
)

func Test_digestFeedIsEnabledByDefault(t *testing.T) {
	feed := DefaultGrype(clio.Identification{Name: "grype"}).DigestFeed

	assert.Equal(t, DefaultDigestFeedURL, feed.Source)
	assert.Equal(t, time.Hour, feed.TTL)
}
