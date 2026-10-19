package controlplane

import (
	"strings"
	"testing"
)

// A completed upload supersedes the unfinished uploads of the same scope that started before it; their
// chunks (whole-inventory copies) go at once instead of waiting 24 hours.
func TestSupersededUploadsAreDeletedOnCompletion(t *testing.T) {
	for _, required := range []string{
		"DELETE FROM identity_snapshot_uploads o USING identity_snapshot_uploads c",
		"c.upload_id=$1",
		"o.source=c.source AND o.sensor_id=c.sensor_id AND o.campus_id=c.campus_id AND o.access_domain=c.access_domain",
		"o.status<>'completed'",
		"o.created_at<c.created_at",
	} {
		if !strings.Contains(supersededUploadsDeleteSQL, required) {
			t.Fatalf("cleanup lacks %q: %s", required, supersededUploadsDeleteSQL)
		}
	}
}
