package fetcher

import (
	"bytes"
	"compress/bzip2"
	"compress/gzip"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/htcat/htcat"
	"github.com/inconshreveable/log15"
	"github.com/spf13/viper"
	"github.com/ulikunitz/xz"
	"github.com/vulsio/goval-dictionary/util"
	"golang.org/x/xerrors"
)

type mimeType int

const (
	mimeTypeXML mimeType = iota
	mimeTypeBzip2
	mimeTypeXz
	mimeTypeGzip
)

func (m mimeType) String() string {
	switch m {
	case mimeTypeXML:
		return "xml"
	case mimeTypeBzip2:
		return "bzip2"
	case mimeTypeXz:
		return "xz"
	default:
		return "Unknown"
	}
}

type fetchRequest struct {
	target       string
	url          string
	mimeType     mimeType
	concurrently bool
}

// FetchResult has url and OVAL definitions
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
	httpClient := &http.Client{}
	httpProxy := viper.GetString("http-proxy")
	if httpProxy != "" {
		if proxyURL, err = url.Parse(httpProxy); err != nil {
			return nil, xerrors.Errorf("Failed to parse proxy url. err: %w", err)
		}
		httpClient = &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}
	}

	u, err := url.Parse(req.url)
	if err != nil {
		return nil, xerrors.Errorf("Failed to parse given URL: %w", err)
	}

	buf := bytes.Buffer{}
	htc := htcat.New(httpClient, u, concurrency)
	if _, err := htc.WriteTo(&buf); err != nil {
		return nil, xerrors.Errorf("Failed to write to output stream: %w", err)
	}

	var bytesBody []byte
	switch req.mimeType {
	case mimeTypeXML:
		bytesBody = buf.Bytes()
	case mimeTypeBzip2:
		var b bytes.Buffer
		if _, err := b.ReadFrom(bzip2.NewReader(bytes.NewReader(buf.Bytes()))); err != nil {
			return body, err
		}
		bytesBody = b.Bytes()
	case mimeTypeXz:
		var b bytes.Buffer
		r, err := xz.NewReader(bytes.NewReader(buf.Bytes()))
		if err != nil {
			return nil, xerrors.Errorf("can not open xz file: %w", err)
		}
		if _, err := b.ReadFrom(r); err != nil {
			return body, err
		}
		bytesBody = b.Bytes()
	case mimeTypeGzip:
		var b bytes.Buffer
		r, err := gzip.NewReader(bytes.NewReader(buf.Bytes()))
		if err != nil {
			return nil, xerrors.Errorf("can not open gzip file: %w", err)
		}
		if _, err := b.ReadFrom(r); err != nil {
			return body, err
		}
		bytesBody = b.Bytes()
	}

	return bytesBody, nil
}

func fetchFileWithUA(req fetchRequest) (body []byte, err error) {
	var proxyURL *url.URL
	var resp *http.Response

	httpClient := &http.Client{}
	httpProxy := viper.GetString("http-proxy")
	if httpProxy != "" {
		if proxyURL, err = url.Parse(httpProxy); err != nil {
			return nil, xerrors.Errorf("Failed to parse proxy url. err: %w", err)
		}
		httpClient = &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}
	}

	httpreq, err := http.NewRequest("GET", req.url, nil)
	if err != nil {
		return nil, xerrors.Errorf("Failed to download. err: %w", err)
	}

	httpreq.Header.Set("User-Agent", "curl/7.37.0")
	resp, err = httpClient.Do(httpreq)
	if err != nil {
		return nil, xerrors.Errorf("Failed to download. err: %w", err)
	}
	defer func() {
		if resp != nil {
			resp.Body.Close()
		}
	}()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("Failed to HTTP GET. url: %s, response: %+v", req.url, resp)
	}

	buf := bytes.NewBuffer(nil)
	if _, err := io.Copy(buf, resp.Body); err != nil {
		return nil, err
	}

	var bytesBody []byte
	switch req.mimeType {
	case mimeTypeXML:
		bytesBody = buf.Bytes()
	case mimeTypeBzip2:
		bz := bzip2.NewReader(buf)
		var b bytes.Buffer
		if _, err := b.ReadFrom(bz); err != nil {
			return nil, err
		}
		bytesBody = b.Bytes()
	case mimeTypeXz:
		r, err := xz.NewReader(buf)
		if err != nil {
			return nil, xerrors.Errorf("can not open xz file: %w", err)
		}
		var b bytes.Buffer
		if _, err = b.ReadFrom(r); err != nil {
			return nil, err
		}
		bytesBody = b.Bytes()
	case mimeTypeGzip:
		r, err := gzip.NewReader(buf)
		if err != nil {
			return nil, xerrors.Errorf("can not open gzip file: %w", err)
		}
		var b bytes.Buffer
		if _, err = b.ReadFrom(r); err != nil {
			return nil, err
		}
		bytesBody = b.Bytes()
	}

	return bytesBody, nil
}
