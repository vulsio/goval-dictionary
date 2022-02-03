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
	mimeTypeTxt
	mimeTypeYml
	mimeTypeBzip2
	mimeTypeXz
	mimeTypeGzip
)

func (m mimeType) String() string {
	switch m {
	case mimeTypeXML:
		return "xml"
	case mimeTypeTxt:
		return "txt"
	case mimeTypeYml:
		return "yml"
	case mimeTypeBzip2:
		return "bzip2"
	case mimeTypeXz:
		return "xz"
	default:
		return "Unknown"
	}
}

type fetchRequest struct {
	target        string
	url           string
	mimeType      mimeType
	concurrently  bool
	logSuppressed bool
}

// FetchResult has url and OVAL definitions
type FetchResult struct {
	Target        string
	URL           string
	Body          []byte
	LogSuppressed bool
}

func fetchFeedFiles(reqs []fetchRequest) (results []FetchResult, err error) {
	reqChan := make(chan fetchRequest, len(reqs))
	resChan := make(chan FetchResult, len(reqs))
	errChan := make(chan error, len(reqs))
	defer close(reqChan)
	defer close(resChan)
	defer close(errChan)

	for _, r := range reqs {
		if !r.logSuppressed {
			log15.Info("Fetching... ", "URL", r.url)
		}
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
					Target:        req.target,
					URL:           req.url,
					Body:          body,
					LogSuppressed: req.logSuppressed,
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

	var b bytes.Buffer
	switch req.mimeType {
	case mimeTypeXML, mimeTypeTxt, mimeTypeYml:
		b = buf
	case mimeTypeBzip2:
		if _, err := b.ReadFrom(bzip2.NewReader(bytes.NewReader(buf.Bytes()))); err != nil {
			return nil, xerrors.Errorf("Failed to open bzip2 file. err: %w", err)
		}
	case mimeTypeXz:
		r, err := xz.NewReader(bytes.NewReader(buf.Bytes()))
		if err != nil {
			return nil, xerrors.Errorf("Failed to open xz file. err: %w", err)
		}
		if _, err := b.ReadFrom(r); err != nil {
			return nil, xerrors.Errorf("Failed to read xz file. err: %w", err)
		}
	case mimeTypeGzip:
		r, err := gzip.NewReader(bytes.NewReader(buf.Bytes()))
		if err != nil {
			return nil, xerrors.Errorf("Failed to open gzip file. err: %w", err)
		}
		if _, err := b.ReadFrom(r); err != nil {
			return nil, xerrors.Errorf("Failed to read gzip file. err: %w", err)
		}
	}

	return b.Bytes(), nil
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

	buf := bytes.Buffer{}
	if _, err := io.Copy(&buf, resp.Body); err != nil {
		return nil, err
	}

	var b bytes.Buffer
	switch req.mimeType {
	case mimeTypeXML, mimeTypeTxt, mimeTypeYml:
		b = buf
	case mimeTypeBzip2:
		if _, err := b.ReadFrom(bzip2.NewReader(bytes.NewReader(buf.Bytes()))); err != nil {
			return nil, xerrors.Errorf("Failed to open bzip2 file. err: %w", err)
		}
	case mimeTypeXz:
		r, err := xz.NewReader(bytes.NewReader(buf.Bytes()))
		if err != nil {
			return nil, xerrors.Errorf("Failed to open xz file. err: %w", err)
		}
		if _, err = b.ReadFrom(r); err != nil {
			return nil, xerrors.Errorf("Failed to read xz file. err: %w", err)
		}
	case mimeTypeGzip:
		r, err := gzip.NewReader(bytes.NewReader(buf.Bytes()))
		if err != nil {
			return nil, xerrors.Errorf("Failed to open gzip file. err: %w", err)
		}
		if _, err = b.ReadFrom(r); err != nil {
			return nil, xerrors.Errorf("Failed to read gzip file. err: %w", err)
		}
	}

	return b.Bytes(), nil
}
