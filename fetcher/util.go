package fetcher

import (
	"bytes"
	"compress/bzip2"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/cheggaaa/pb"
	"github.com/future-architect/vuls/util"
	"github.com/k0kubun/pp"
	c "github.com/kotakanbe/goval-dictionary/config"
	"github.com/kotakanbe/goval-dictionary/log"
	"github.com/ymomoi/goval-parser/oval"
)

type fetchRequest struct {
	target string
	url    string
	bzip2  bool
	bar    *pb.ProgressBar
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

	for _, r := range reqs {
		log.Infof("Fetching... %s", r.url)
	}

	var pool *pb.Pool
	go func() {
		for _, r := range reqs {
			prefix := filepath.Base(r.url) + ":"
			r.bar = pb.New(getFileSize(r)).SetUnits(pb.U_BYTES).Prefix(prefix)

			if pool == nil {
				if pool, err = pb.StartPool(r.bar); err != nil {
					pp.Println(err)
				}
			} else {
				pool.Add(r.bar)
			}
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
				root, err := fetchFeedFile(req)
				wg.Done()
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
			return
		}
	}
	wg.Wait()
	pool.Stop()

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
	log.Info("Finished to fetch OVAL definitions.")
	if 0 < len(errs) {
		return results, fmt.Errorf("%s", errs)
	}
	return results, nil
}

func fetchFeedFile(req fetchRequest) (root *oval.Root, err error) {
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
	req.bar.Start()
	rd := req.bar.NewProxyReader(resp.Body)
	io.Copy(buf, rd)

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

	if err = xml.Unmarshal(bytesBody, &root); err != nil {
		return nil, fmt.Errorf(
			"Failed to unmarshal. url: %s, err: %s", req.url, err)
	}
	return
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
		log.Warn("Not supported range access.")
	}

	// the value -1 indicates that the length is unknown.
	if resp.ContentLength <= 0 {
		log.Info("Failed to get content length.")
		return 0
	}
	return int(resp.ContentLength)
}
