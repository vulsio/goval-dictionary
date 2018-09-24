package fetcher

import (
	"bytes"
	"compress/bzip2"
	"fmt"
	"io"
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
	target       string
	url          string
	bzip2        bool
	concurrently bool
}

//FetchResult has url and OVAL definitions
type FetchResult struct {
	Target string
	URL    string
	Body   []byte
}

func fetchFeedFiles(reqs []fetchRequest) (results []FetchResult, err error) {
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
				var body []byte
				if req.concurrently {
					body, err = fetchFileConcurrently(req, 20/len(reqs))
				} else {
					body, err = fetchFileWithUA(req)
				}
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
	log15.Info("Finished fetching OVAL definitions")
	if 0 < len(errs) {
		return results, fmt.Errorf("%s", errs)
	}
	return results, nil
}

func fetchFileConcurrently(req fetchRequest, concurrency int) (body []byte, err error) {
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
	htc := htcat.New(httpCilent, u, concurrency)
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

func fetchFileWithUA(req fetchRequest) (body []byte, err error) {
	var errs []error
	var proxyURL *url.URL
	var resp *http.Response

	httpClient := &http.Client{}
	if c.Conf.HTTPProxy != "" {
		if proxyURL, err = url.Parse(c.Conf.HTTPProxy); err != nil {
			return nil, fmt.Errorf("Failed to parse proxy url: %s", err)
		}
		httpClient = &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}
	}

	httpreq, err := http.NewRequest("GET", req.url, nil)
	if err != nil {
		return nil, fmt.Errorf("Download failed: %v", err)
	}

	httpreq.Header.Set("User-Agent", "curl/7.37.0")
	resp, err = httpClient.Do(httpreq)
	if err != nil {
		return nil, fmt.Errorf("Download failed: %v", err)
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
