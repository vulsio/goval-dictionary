package redhat

import (
	"encoding/xml"
	"fmt"
	"net/http"
	"time"

	"github.com/cheggaaa/pb"
	c "github.com/kotakanbe/goval-dictionary/config"
	log "github.com/kotakanbe/goval-dictionary/log"
	"github.com/kotakanbe/goval-dictionary/util"
	"github.com/parnurzeal/gorequest"
	"github.com/ymomoi/goval-parser/oval"
)

// FetchFiles fetch OVAL from RedHat
func FetchFiles(versions []int) (defs []oval.Definition, err error) {
	urls := makeFeedURLs(versions)
	roots, err := fetchFeedFileConcurrently(urls)
	if err != nil {
		return nil,
			fmt.Errorf("Failed to fetch. err: %s", err)
	}
	for _, r := range roots {
		defs = append(defs, r.Definitions.Definitions...)
	}
	return
}

func makeFeedURLs(versions []int) (urls []string) {
	t := "https://www.redhat.com/security/data/oval/Red_Hat_Enterprise_Linux_%d.xml"
	for _, v := range versions {
		urls = append(urls, fmt.Sprintf(t, v))
	}
	return
}

func fetchFeedFileConcurrently(urls []string) (roots []oval.Root, err error) {
	reqChan := make(chan string, len(urls))
	resChan := make(chan *oval.Root, len(urls))
	errChan := make(chan error, len(urls))
	defer close(reqChan)
	defer close(resChan)
	defer close(errChan)

	go func() {
		for _, url := range urls {
			reqChan <- url
		}
	}()

	concurrency := len(urls)
	tasks := util.GenWorkers(concurrency)
	for range urls {
		tasks <- func() {
			select {
			case url := <-reqChan:
				log.Infof("Fetching... %s", url)
				root, err := fetchFeedFile(url)
				if err != nil {
					errChan <- err
					return
				}
				resChan <- root
			}
		}
	}

	errs := []error{}
	bar := pb.StartNew(len(urls))
	timeout := time.After(10 * 60 * time.Second)
	for range urls {
		select {
		case root := <-resChan:
			roots = append(roots, *root)
		case err := <-errChan:
			errs = append(errs, err)
		case <-timeout:
			return roots, fmt.Errorf("Timeout Fetching")
		}
		bar.Increment()
	}
	//  bar.FinishPrint("Finished to fetch CVE information from JVN.")
	if 0 < len(errs) {
		return roots, fmt.Errorf("%s", errs)
	}
	return roots, nil
}

func fetchFeedFile(url string) (root *oval.Root, err error) {
	var body string
	var errs []error
	var resp *http.Response

	resp, body, errs = gorequest.New().Proxy(c.Conf.HTTPProxy).Get(url).End()
	//  defer resp.Body.Close()
	if len(errs) > 0 || resp == nil || resp.StatusCode != 200 {
		return nil, fmt.Errorf(
			"HTTP error. errs: %v, url: %s", errs, url)
	}
	if err = xml.Unmarshal([]byte(body), &root); err != nil {
		return nil, fmt.Errorf(
			"Failed to unmarshal. url: %s, err: %s", url, err)
	}
	return
}
