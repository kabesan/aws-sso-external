package main

import (
	"context"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/chromedp"
)

const (
	defaultSessionDuration = 1 * time.Hour
)

var (
	userDataDir     string
	sessionDuration time.Duration
)

func init() {
	flag.StringVar(&userDataDir, "user-data-dir", "", "user data directory for chrome")
	flag.DurationVar(&sessionDuration, "session-duration", defaultSessionDuration, "assume role session duration")
}

type SAMLResponse struct {
	Assertion Assertion
}

type Assertion struct {
	AttributeStatement AttributeStatement
}

type AttributeStatement struct {
	Attributes []Attribute `xml:"Attribute"`
}

type Attribute struct {
	Name            string           `xml:",attr"`
	AttributeValues []AttributeValue `xml:"AttributeValue"`
}

type AttributeValue struct {
	Value string `xml:",innerxml"`
}

type Credentials struct {
	Version         int
	AccessKeyId     string
	SecretAccessKey string
	SessionToken    string
	Expiration      string
}

func main() {
	flag.Parse()
	if flag.NArg() == 0 {
		panic("invalid args")
	}

	targetURL := flag.Arg(0)
	cachePath := getCacheFilePath(targetURL)
	creds, err := readCredentialsCache(cachePath)
	if err != nil {
		panic(err)
	}
	if creds != nil {
		printCredentials(creds)
		return
	}

	opts := []chromedp.ExecAllocatorOption{
		chromedp.NoFirstRun,
		chromedp.NoDefaultBrowserCheck,
	}
	if userDataDir != "" {
		opts = append(opts, chromedp.UserDataDir(userDataDir))
	}
	allocCtx, cancel := chromedp.NewExecAllocator(context.Background(), opts...)
	defer cancel()

	ctx, cancel := chromedp.NewContext(allocCtx, chromedp.WithLogf(log.Printf))
	defer cancel()

	reqChan := make(chan *network.Request)
	chromedp.ListenTarget(ctx, func(ev interface{}) {
		go func() {
			if ev, ok := ev.(*network.EventRequestWillBeSent); ok {
				reqChan <- ev.Request
			}
		}()
	})

	if err := chromedp.Run(
		ctx,
		network.Enable(),
		chromedp.Navigate(targetURL),
	); err != nil {
		panic(err)
	}

	var req *network.Request
	for {
		select {
		case <-ctx.Done():
			return
		case req = <-reqChan:
		}

		if req.URL != "https://signin.aws.amazon.com/saml" {
			continue
		}

		form, err := url.ParseQuery(req.PostData)
		if err != nil {
			panic(err)
		}

		base64SAMLResponse := form["SAMLResponse"][0]
		samlResponseData, err := base64.StdEncoding.DecodeString(base64SAMLResponse)
		if err != nil {
			panic(err)
		}

		res := new(SAMLResponse)
		if err := xml.Unmarshal(samlResponseData, res); err != nil {
			panic(err)
		}

		var principalArn, roleArn string
		for _, attr := range res.Assertion.AttributeStatement.Attributes {
			if attr.Name != "https://aws.amazon.com/SAML/Attributes/Role" {
				continue
			}

			s := strings.Split(attr.AttributeValues[0].Value, ",")
			principalArn = s[0]
			roleArn = s[1]
			break
		}
		if principalArn == "" || roleArn == "" {
			panic(errors.New("invalid SAMLResponse"))
		}

		ses := session.Must(session.NewSession())
		stsAPI := sts.New(ses)
		out, err := stsAPI.AssumeRoleWithSAML(&sts.AssumeRoleWithSAMLInput{
			PrincipalArn:    aws.String(principalArn),
			RoleArn:         aws.String(roleArn),
			SAMLAssertion:   aws.String(base64SAMLResponse),
			DurationSeconds: aws.Int64(int64(sessionDuration / time.Second)),
		})
		if err != nil {
			panic(err)
		}

		creds := &Credentials{
			Version:         1,
			AccessKeyId:     *out.Credentials.AccessKeyId,
			SecretAccessKey: *out.Credentials.SecretAccessKey,
			SessionToken:    *out.Credentials.SessionToken,
			Expiration:      out.Credentials.Expiration.Format(time.RFC3339),
		}
		if err := writeCredentialsCache(cachePath, creds); err != nil {
			panic(err)
		}

		printCredentials(creds)

		break
	}
}

func getCacheFilePath(targetURL string) string {
	urlSHA1 := sha1.Sum([]byte(targetURL))
	cacheFileName := hex.EncodeToString(urlSHA1[:]) + ".json"
	homeDir, err := os.UserHomeDir()
	if err != nil {
		panic(err)
	}
	cacheDirPath := filepath.Join(homeDir, ".aws", "cli", "cache")
	if err := os.MkdirAll(cacheDirPath, 0755); err != nil && !os.IsExist(err) {
		panic(err)
	}
	return filepath.Join(cacheDirPath, cacheFileName)
}

func readCredentialsCache(cacheFilePath string) (*Credentials, error) {
	bytes, err := os.ReadFile(cacheFilePath)
	if err != nil {
		return nil, err
	}
	if len(bytes) == 0 {
		return nil, nil
	}

	creds := new(Credentials)
	if err := json.Unmarshal(bytes, creds); err != nil {
		return nil, err
	}

	expiration, err := time.Parse(time.RFC3339, creds.Expiration)
	if err != nil {
		return nil, err
	}
	if expiration.Before(time.Now()) {
		return nil, nil
	}

	return creds, nil
}

func writeCredentialsCache(cacheFilePath string, creds *Credentials) error {
	bytes, err := json.Marshal(creds)
	if err != nil {
		return err
	}
	if err := os.WriteFile(cacheFilePath, bytes, 0600); err != nil {
		return err
	}

	return nil
}

func printCredentials(creds *Credentials) {
	bytes, _ := json.Marshal(creds)
	fmt.Println(string(bytes))
}
