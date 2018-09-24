package fetcher

import (
	"fmt"
)

const feedURL = "https://alas.aws.amazon.com/alas.rss"

func newAmazonFetchRequest() (reqs fetchRequest) {
	return fetchRequest{
		url: feedURL,
	}
}

// FetchAmazonFile fetch from ALAS
// https://alas.aws.amazon.com/alas.rss
func FetchAmazonFile() (*FetchResult, error) {
	req := newAmazonFetchRequest()
	results, err := fetchFeedFiles([]fetchRequest{req})
	if err != nil || len(results) != 1 {
		return nil,
			fmt.Errorf("Failed to fetch. err: %s", err)
	}
	return &results[0], nil
}
