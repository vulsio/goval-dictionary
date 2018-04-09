package fetcher

import (
	"bytes"
	"compress/bzip2"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sync"
	"time"

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
				body, err := fetchFile(req)
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
		case err := <-errChan:
			errs = append(errs, err)
		case <-timeout:
			return results, fmt.Errorf("Timeout Fetching")
		}
	}
	log15.Info("Finished to fetch OVAL definitions.")
	if 0 < len(errs) {
		return results, fmt.Errorf("%s", errs)
	}
	return results, nil
}

func fetchFile(req fetchRequest) (body []byte, err error) {
	//	var body string
	var errs []error
	var proxyURL *url.URL
	var resp *http.Response

	httpCilent := &http.Client{}
	if c.Conf.HTTPProxy != "" {
		if proxyURL, err = url.Parse(c.Conf.HTTPProxy); err != nil {
			return nil, fmt.Errorf("Failed to parse proxy url: %s", err)
		}
		httpCilent = &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}
	}

	if resp, err = httpCilent.Get(req.url); err != nil {
		fmt.Fprintf(os.Stderr, "Download failed: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	buf := bytes.NewBuffer(nil)
	io.Copy(buf, resp.Body)

	if len(errs) > 0 || resp == nil || resp.StatusCode != 200 {
		return nil, fmt.Errorf(
			"HTTP error. errs: %v, url: %s", errs, req.url)
	}

	var bytesBody []byte
	if req.bzip2 {
		bz := bzip2.NewReader(buf)
		var b bytes.Buffer
		b.ReadFrom(bz)
		bytesBody = b.Bytes()
	} else {
		bytesBody = buf.Bytes()
	}

	return bytesBody, nil
}

func getFileSize(req fetchRequest) int {
	var proxyURL *url.URL
	var resp *http.Response
	var err error

	httpCilent := &http.Client{}
	if c.Conf.HTTPProxy != "" {
		if proxyURL, err = url.Parse(c.Conf.HTTPProxy); err != nil {
			return 0
		}
		httpCilent = &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}
	}

	if resp, err = httpCilent.Head(req.url); err != nil {
		return 0
	}
	defer resp.Body.Close()

	if resp.Header.Get("Accept-Ranges") != "bytes" {
		log15.Warn("Not supported range access.")
	}

	// the value -1 indicates that the length is unknown.
	if resp.ContentLength <= 0 {
		log15.Info("Failed to get content length.")
		return 0
	}
	return int(resp.ContentLength)
}
