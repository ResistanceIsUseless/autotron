package parsers

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/resistanceisuseless/autotron/internal/graph"
)

type cloudBucketJSONParser struct{}

func init() {
	Register(&cloudBucketJSONParser{})
}

func (p *cloudBucketJSONParser) Name() string { return "cloud_bucket_json" }

type bucketRecord struct {
	Provider string   `json:"provider"`
	Bucket   string   `json:"bucket"`
	Region   string   `json:"region"`
	Public   bool     `json:"public"`
	Listable bool     `json:"listable"`
	Readable bool     `json:"readable"`
	Objects  []string `json:"objects"`
}

func (p *cloudBucketJSONParser) Parse(ctx context.Context, trigger graph.Node, stdout io.Reader, stderr io.Reader) (Result, error) {
	var out Result

	s := bufio.NewScanner(stdout)
	s.Buffer(make([]byte, 0, 1024*1024), 1024*1024)

	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if line == "" || !strings.HasPrefix(line, "{") {
			continue
		}

		var rec bucketRecord
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			continue
		}
		if strings.TrimSpace(rec.Bucket) == "" {
			continue
		}

		sev := "info"
		ftype := "bucket-observed"
		title := fmt.Sprintf("Cloud bucket observed: %s", rec.Bucket)
		switch {
		case rec.Public && rec.Readable:
			sev = "high"
			ftype = "public-object-read"
			title = fmt.Sprintf("Public readable bucket: %s", rec.Bucket)
		case rec.Public && rec.Listable:
			sev = "medium"
			ftype = "public-bucket-listing"
			title = fmt.Sprintf("Public listable bucket: %s", rec.Bucket)
		case rec.Public:
			sev = "low"
			ftype = "public-bucket-exposure"
			title = fmt.Sprintf("Public bucket exposure: %s", rec.Bucket)
		}

		fid := fmt.Sprintf("bucket-%s", hashKey(trigger.PrimaryKey+"|"+rec.Provider+"|"+rec.Bucket))
		out.Findings = append(out.Findings, graph.Finding{
			ID:         fid,
			Type:       ftype,
			Title:      title,
			Severity:   sev,
			Confidence: "firm",
			Tool:       "cloud-bucket-check",
			Evidence: map[string]any{
				"provider": rec.Provider,
				"bucket":   rec.Bucket,
				"region":   rec.Region,
				"public":   rec.Public,
				"listable": rec.Listable,
				"readable": rec.Readable,
				"objects":  rec.Objects,
			},
			FirstSeen: time.Now().UTC(),
			LastSeen:  time.Now().UTC(),
		})
	}

	if err := s.Err(); err != nil {
		return Result{}, err
	}
	return out, nil
}
