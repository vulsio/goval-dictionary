package fetcher

import (
	"bytes"
	"compress/bzip2"
	"fmt"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/htcat/htcat"
	"github.com/inconshreveable/log15"
	c "github.com/kotakanbe/goval-dictionary/config"
	"github.com/kotakanbe/goval-dictionary/util"
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
	Body   []byte
}

func fetchFeedFileConcurrently(reqs []fetchRequest) (results []FetchResult, err error) {
	reqChan := make(chan fetchRequest, len(reqs))
	resChan := make(chan FetchResult, len(reqs))
	errChan := make(chan error, len(reqs))
	defer close(reqChan)
	defer close(resChan)
	defer close(errChan)

	for _, r := range reqs {
		log15.Info("Fetching... ", "URL", r.url)
	}

	go func() {
		for _, r := range reqs {
			reqChan <- r
		}
	}()

	concurrency := len(reqs)
	tasks := util.GenWorkers(concurrency)
	wg := new(sync.WaitGroup)
	for range reqs {
		wg.Add(1)
		tasks <- func() {
			select {
			case req := <-reqChan:
				body, err := fetchFile(req, 40/len(reqs))
				wg.Done()
				if err != nil {
					errChan <- err
					return
				}
				resChan <- FetchResult{
					Target: req.target,
					URL:    req.url,
					Body:   body,
				}
			}
			return
		}
	}
	wg.Wait()

	errs := []error{}
	timeout := time.After(10 * 60 * time.Second)
	for range reqs {
		select {
		case res := <-resChan:
			results = append(results, res)
			log15.Info("Fetched... ", "URL", res.URL)
		case err := <-errChan:
			errs = append(errs, err)
		case <-timeout:
			return results, fmt.Errorf("Timeout Fetching")
		}
	}
	log15.Info("Finished to fetch OVAL definitions")
	if 0 < len(errs) {
		return results, fmt.Errorf("%s", errs)
	}
	return results, nil
}

func fetchFile(req fetchRequest, parallelism int) (body []byte, err error) {
	var proxyURL *url.URL
	httpCilent := &http.Client{}
	if c.Conf.HTTPProxy != "" {
		if proxyURL, err = url.Parse(c.Conf.HTTPProxy); err != nil {
			return nil, fmt.Errorf("Failed to parse proxy url: %s", err)
		}
		httpCilent = &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}
	}

	u, err := url.Parse(req.url)
	if err != nil {
		return nil, fmt.Errorf("aborting: could not parse given URL: %v", err)
	}

	buf := bytes.Buffer{}
	htc := htcat.New(httpCilent, u, parallelism)
	if _, err := htc.WriteTo(&buf); err != nil {
		return nil, fmt.Errorf("aborting: could not write to output stream: %v",
			err)
	}

	var bytesBody []byte
	if req.bzip2 {
		var b bytes.Buffer
		b.ReadFrom(bzip2.NewReader(bytes.NewReader(buf.Bytes())))
		bytesBody = b.Bytes()
	} else {
		bytesBody = buf.Bytes()
	}

	return bytesBody, nil
}
