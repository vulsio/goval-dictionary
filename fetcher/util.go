package fetcher

import (
	"bytes"
	"compress/bzip2"
	"encoding/xml"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/cheggaaa/pb"
	c "github.com/kotakanbe/goval-dictionary/config"
	"github.com/kotakanbe/goval-dictionary/log"
	"github.com/kotakanbe/goval-dictionary/util"
	"github.com/parnurzeal/gorequest"
	"github.com/ymomoi/goval-parser/oval"
)

type fetchRequest struct {
	target string
	url    string
	bzip2  bool
}

//FetchResult has url and OVAL definitions
type FetchResult struct {
	Target string
	URL    string
	Root   *oval.Root
}

func fetchFeedFileConcurrently(reqs []fetchRequest) (results []FetchResult, err error) {
	reqChan := make(chan fetchRequest, len(reqs))
	resChan := make(chan FetchResult, len(reqs))
	errChan := make(chan error, len(reqs))
	defer close(reqChan)
	defer close(resChan)
	defer close(errChan)

	go func() {
		for _, r := range reqs {
			reqChan <- r
		}
	}()

	concurrency := len(reqs)
	tasks := util.GenWorkers(concurrency)
	for range reqs {
		tasks <- func() {
			select {
			case req := <-reqChan:
				log.Infof("Fetching... %s", req.url)
				root, err := fetchFeedFile(req)
				if err != nil {
					errChan <- err
					return
				}
				resChan <- FetchResult{
					Target: req.target,
					URL:    req.url,
					Root:   root,
				}
			}
		}
	}

	errs := []error{}
	bar := pb.StartNew(len(reqs))
	timeout := time.After(10 * 60 * time.Second)
	for range reqs {
		select {
		case res := <-resChan:
			results = append(results, res)
		case err := <-errChan:
			errs = append(errs, err)
		case <-timeout:
			return results, fmt.Errorf("Timeout Fetching")
		}
		bar.Increment()
	}
	//  bar.FinishPrint("Finished to fetch CVE information from JVN.")
	if 0 < len(errs) {
		return results, fmt.Errorf("%s", errs)
	}
	return results, nil
}

func fetchFeedFile(req fetchRequest) (root *oval.Root, err error) {
	var body string
	var errs []error
	var resp *http.Response

	resp, body, errs = gorequest.New().Proxy(c.Conf.HTTPProxy).Get(req.url).End()
	//  defer resp.Body.Close()
	if len(errs) > 0 || resp == nil || resp.StatusCode != 200 {
		return nil, fmt.Errorf(
			"HTTP error. errs: %v, url: %s", errs, req.url)
	}

	var bytesBody []byte
	if req.bzip2 {
		bz := bzip2.NewReader(strings.NewReader(body))
		var buf bytes.Buffer
		buf.ReadFrom(bz)
		bytesBody = buf.Bytes()
	} else {
		bytesBody = []byte(body)
	}

	if err = xml.Unmarshal(bytesBody, &root); err != nil {
		return nil, fmt.Errorf(
			"Failed to unmarshal. url: %s, err: %s", req.url, err)
	}
	return
}
