package chatgptauth

import (
	"bufio"
	"bytes"
	b64 "encoding/base64"
	"errors"
	"fmt"
	"image"
	"image/png"
	"io"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/PuerkitoBio/goquery"
	"github.com/rs/zerolog"
	http "github.com/saucesteals/fhttp"
	"github.com/saucesteals/fhttp/cookiejar"
	"github.com/saucesteals/mimic"
	"github.com/srwiley/oksvg"
	"github.com/srwiley/rasterx"
	"github.com/tidwall/gjson"
)

type Credentials struct {
	AccessToken string `json:"access_token"`
	ExpiresAt   string `json:"expires_at"`
}

type Auth struct {
	EmailAddress string
	Password     string
	UserAgent    string
	session      *http.Client
	m            *mimic.ClientSpec
	logger       *zerolog.Logger
}

// Thanks usual human
// https://stackoverflow.com/questions/42993407/how-to-create-and-export-svg-to-png-jpeg
func svgSrcToPng(src string) error {
	decoded, err := b64.StdEncoding.DecodeString(src[26:])

	if err != nil {
		return err
	}

	icon, _ := oksvg.ReadIconStream(bytes.NewReader(decoded))

	w := int(icon.ViewBox.W) * 5 // Make it big
	h := int(icon.ViewBox.H) * 5

	icon.SetTarget(0, 0, float64(w), float64(h))
	rgba := image.NewRGBA(image.Rect(0, 0, w, h))
	icon.Draw(rasterx.NewDasher(w, h, rasterx.NewScannerGV(w, h, rgba, rgba.Bounds())), 1)

	out, err := os.Create("captcha.png")
	if err != nil {
		return err
	}
	defer out.Close()

	err = png.Encode(out, rgba)
	if err != nil {
		return err
	}
	return nil
}

func NewAuthClient(email, password, proxy string, logger *zerolog.Logger) (auth *Auth, err error) {
	jar, _ := cookiejar.New(nil)
	userAgent := "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.0.0 Safari/537.36"
	m, _ := mimic.Chromium(mimic.BrandChrome, "107.0.0.0")

	var lg *zerolog.Logger

	if logger == nil {
		l := zerolog.Nop()
		lg = &l
	} else {
		lg = logger
	}

	lg.Info().Msg("Creating auth client")

	defer func() {
		if err != nil {
			lg.Error().Err(err).Msg("")
		}
	}()

	var newClient *http.Client
	if proxy != "" {
		proxyUrl, err := url.Parse(proxy)
		if err != nil {
			return nil, err
		}
		newClient = &http.Client{Jar: jar, Transport: m.ConfigureTransport(&http.Transport{Proxy: http.ProxyURL(proxyUrl)}), Timeout: 20 * time.Second}
	} else {
		newClient = &http.Client{Jar: jar, Transport: m.ConfigureTransport(&http.Transport{}), Timeout: 20 * time.Second}
	}

	return &Auth{EmailAddress: email, Password: password, UserAgent: userAgent, session: newClient, m: m, logger: lg}, nil
}

func (a *Auth) performGet(url string, headers http.Header) (resp *http.Response, body []byte, statusCode int, err error) {
	a.logger.Debug().Interface("headers", headers).Str("url", url).Str("method", "GET").Msg("Starting request")
	defer func() {
		if err != nil {
			a.logger.Error().Err(err).Msg("performGet failed")
		}
	}()

	req, err := http.NewRequest(http.MethodGet, url, nil)

	if err != nil {
		return nil, nil, 0, err
	}

	headers[http.PHeaderOrderKey] = a.m.PseudoHeaderOrder()

	req.Header = headers

	resp, err = a.session.Do(req)

	if err != nil {
		return nil, nil, 0, err
	}

	defer resp.Body.Close()

	body, err = io.ReadAll(resp.Body)

	if err != nil {
		return nil, nil, 0, err
	}

	a.logger.Debug().Int("status", resp.StatusCode).Bytes("body", body).Msg("request successful")

	return resp, body, resp.StatusCode, nil
}

func (a *Auth) performPost(url string, headers http.Header, query url.Values, reqBody []byte) (resp *http.Response, body []byte, statusCode int, err error) {
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(reqBody))
	req.URL.RawQuery = query.Encode()

	defer func() {
		if err != nil {
			a.logger.Error().Err(err).Msg("performPost failed")
		}
	}()

	if err != nil {
		return nil, nil, 0, err
	}

	headers[http.PHeaderOrderKey] = a.m.PseudoHeaderOrder()

	req.Header = headers

	resp, err = a.session.Do(req)

	if err != nil {
		return nil, nil, 0, err
	}

	defer resp.Body.Close()

	body, err = io.ReadAll(resp.Body)

	if err != nil {
		return nil, nil, 0, err
	}

	return resp, body, resp.StatusCode, nil
}

func (a *Auth) begin() error {
	endpoint := "https://chat.openai.com/auth/login"

	headers := http.Header{
		"sec-ch-ua":                 {a.m.ClientHintUA()},
		"sec-ch-ua-mobile":          {"?0"},
		"sec-ch-ua-platform":        {"\"Windows\""},
		"dnt":                       {"1"},
		"upgrade-insecure-requests": {"1"},
		"user-agent":                {a.UserAgent},
		"accept":                    {"text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9"},
		"sec-fetch-site":            {"none"},
		"sec-fetch-mode":            {"navigate"},
		"sec-fetch-user":            {"?1"},
		"sec-fetch-dest":            {"document"},
		"accept-encoding":           {"gzip, deflate, br"},
		"accept-language":           {"pt,pt-PT;q=0.9,en-US;q=0.8,en;q=0.7,es;q=0.6"},
		http.HeaderOrderKey:         beginHeaderOrder,
	}

	_, _, statusCode, err := a.performGet(endpoint, headers)

	if err != nil {
		return err
	}

	switch statusCode {
	case http.StatusOK:
		return nil
	default:
		return fmt.Errorf("begin: invalid status code returned (%d)", statusCode)
	}
}

func (a *Auth) getCsrf() (token string, err error) {
	endpoint := "https://chat.openai.com/api/auth/csrf"

	headers := http.Header{
		"sec-ch-ua":          {a.m.ClientHintUA()},
		"dnt":                {"1"},
		"sec-ch-ua-mobile":   {"?0"},
		"user-agent":         {a.UserAgent},
		"sec-ch-ua-platform": {"\"Windows\""},
		"accept":             {"*/*"},
		"sec-fetch-site":     {"same-origin"},
		"sec-fetch-mode":     {"cors"},
		"sec-fetch-dest":     {"empty"},
		"referer":            {"https://chat.openai.com/auth/login"},
		"accept-encoding":    {"gzip, deflate, br"},
		"accept-language":    {"pt,pt-PT;q=0.9,en-US;q=0.8,en;q=0.7,es;q=0.6"},
		"if-none-match":      {"\"gz0126uyw328\""},
		http.HeaderOrderKey:  getCsrfHeaderOrder,
	}

	_, body, statusCode, err := a.performGet(endpoint, headers)

	if err != nil {
		return "", err
	}

	switch statusCode {
	case http.StatusOK:
		token := gjson.Get(string(body), "csrfToken").String()
		if token == "" {
			return "", errors.New("csrfToken not found")
		}
		return token, nil
	default:
		return "", fmt.Errorf("getCsrf: invalid status code returned (%d)", statusCode)
	}
}

func (a *Auth) postLoginPrompt(token string) (nextUrl string, err error) {
	endpoint := "https://chat.openai.com/api/auth/signin/auth0"

	headers := http.Header{
		"sec-ch-ua":          {a.m.ClientHintUA()},
		"sec-ch-ua-platform": {"\"Windows\""},
		"dnt":                {"1"},
		"sec-ch-ua-mobile":   {"?0"},
		"user-agent":         {a.UserAgent},
		"content-type":       {"application/x-www-form-urlencoded"},
		"accept":             {"*/*"},
		"origin":             {"https://chat.openai.com"},
		"sec-fetch-site":     {"same-origin"},
		"sec-fetch-mode":     {"cors"},
		"sec-fetch-dest":     {"empty"},
		"referer":            {"https://chat.openai.com/auth/login"},
		"accept-encoding":    {"gzip, deflate, br"},
		http.HeaderOrderKey:  postLoginPromptHeaderOrder,
	}

	payload := url.Values{
		"callbackUrl": {"/"},
		"csrfToken":   {token},
		"json":        {"true"},
	}

	query := url.Values{
		"prompt": {"login"},
	}

	_, body, statusCode, err := a.performPost(endpoint, headers, query, []byte(payload.Encode()))

	if err != nil {
		return "", err
	}

	switch statusCode {
	case http.StatusOK:
		nextUrl := gjson.Get(string(body), "url").String()
		if nextUrl == "" {
			return "", errors.New("postLoginPrompt: url not found")
		}
		if nextUrl == "https://chat.openai.com/api/auth/error?error=OAuthSignin" || strings.Contains(nextUrl, "error") {
			return "", errors.New("postLoginPrompt: invalid url returned, possibly rate limited")
		}
		return nextUrl, nil
	case http.StatusBadRequest:
		return "", errors.New("postLoginPrompt: Bad request") // Shows as bad credentials in OpenAIAuth but makes no sense since no credentials were sent
	default:
		return "", fmt.Errorf("postLoginPrompt: invalid status code returned (%d)", statusCode)
	}
}

// Follows the 302 redirect to Identifier
func (a *Auth) auth0AuthorizeAndIdentifier(endpoint string) (state string, hasCaptcha bool, err error) {
	//This function actually does two requests because it follow the redirect, the header order fo the second one might not be correct
	headers := http.Header{
		"sec-ch-ua":                 {a.m.ClientHintUA()},
		"sec-ch-ua-mobile":          {"?0"},
		"sec-ch-ua-platform":        {"\"Windows\""},
		"upgrade-insecure-requests": {"1"},
		"dnt":                       {"1"},
		"user-agent":                {a.UserAgent},
		"accept":                    {"text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9"},
		"sec-fetch-site":            {"same-site"},
		"sec-fetch-mode":            {"navigate"},
		"sec-fetch-user":            {"?1"},
		"sec-fetch-dest":            {"document"},
		"referer":                   {"https://chat.openai.com/"},
		"accept-encoding":           {"gzip, deflate, br"},
		http.HeaderOrderKey:         auth0AuthorizeHeaderOrder,
	}

	resp, body, statusCode, err := a.performGet(endpoint, headers)

	if err != nil {
		return "", false, err
	}

	switch statusCode {
	case http.StatusOK:
		state := resp.Request.URL.Query().Get("state")

		if state == "" {
			return "", false, errors.New("auth0AuthorizeAndIdentifier: state not found")
		}

		doc, err := goquery.NewDocumentFromReader(strings.NewReader(string(body)))
		if err != nil {
			return "", false, errors.New("auth0AuthorizeAndIdentifier: invalid html")
		}

		challange, exists := doc.Find("img[alt='captcha']").First().Attr("src")

		if exists {
			a.logger.Info().Msg("Captcha detected, saving as captcha.png")
			err := svgSrcToPng(challange)
			if err != nil {
				return "", false, err
			}
			return state, true, nil
		}

		return state, false, nil
	default:
		return "", false, fmt.Errorf("auth0AuthorizeAndIdentifier: invalid status code returned (%d)", statusCode)
	}
}

func (a *Auth) postUserName(state, captcha string) error {
	endpoint := "https://auth0.openai.com/u/login/identifier"

	headers := http.Header{
		"cache-control":             {"max-age=0"},
		"sec-ch-ua":                 {a.m.ClientHintUA()},
		"sec-ch-ua-mobile":          {"?0"},
		"sec-ch-ua-platform":        {"\"Windows\""},
		"origin":                    {"https://auth0.openai.com"},
		"dnt":                       {"1"},
		"upgrade-insecure-requests": {"1"},
		"content-type":              {"application/x-www-form-urlencoded"},
		"user-agent":                {a.UserAgent},
		"accept":                    {"text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9"},
		"sec-fetch-site":            {"same-origin"},
		"sec-fetch-mode":            {"navigate"},
		"sec-fetch-user":            {"?1"},
		"sec-fetch-dest":            {"document"},
		"referer":                   {"https://auth0.openai.com/u/login/identifier?state=" + state},
		"accept-encoding":           {"gzip, deflate, br"},
		http.HeaderOrderKey:         postUserPassHeaderOrder,
	}

	payload := url.Values{
		"state":                       {state},
		"username":                    {a.EmailAddress},
		"js-available":                {"false"},
		"webauthn-available":          {"true"},
		"is-brave":                    {"false"},
		"webauthn-platform-available": {"true"},
		"action":                      {"default"},
	}

	if captcha != "" {
		payload.Add("captcha", captcha)
	}

	query := url.Values{
		"state": {state},
	}

	_, _, statusCode, err := a.performPost(endpoint, headers, query, []byte(payload.Encode()))

	if err != nil {
		return err
	}

	switch statusCode {
	case http.StatusFound:
		return nil
	default:
		return fmt.Errorf("postUserName: invalid status code returned (%d)", statusCode)
	}
}

func (a *Auth) postPassword(state string) (newState string, err error) {

	endpoint := "https://auth0.openai.com/u/login/password"

	headers := http.Header{
		"cache-control":             {"max-age=0"},
		"sec-ch-ua":                 {a.m.ClientHintUA()},
		"sec-ch-ua-mobile":          {"?0"},
		"sec-ch-ua-platform":        {"\"Windows\""},
		"origin":                    {"https://auth0.openai.com"},
		"dnt":                       {"1"},
		"upgrade-insecure-requests": {"1"},
		"content-type":              {"application/x-www-form-urlencoded"},
		"user-agent":                {a.UserAgent},
		"accept":                    {"text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9"},
		"sec-fetch-site":            {"same-origin"},
		"sec-fetch-mode":            {"navigate"},
		"sec-fetch-user":            {"?1"},
		"sec-fetch-dest":            {"document"},
		"referer":                   {"https://auth0.openai.com/u/login/password?state=" + state},
		"accept-encoding":           {"gzip, deflate, br"},
		http.HeaderOrderKey:         postUserPassHeaderOrder, //exactly the same
	}

	payload := url.Values{
		"state":    {state},
		"username": {a.EmailAddress},
		"password": {a.Password},
		"action":   {"default"},
	}

	query := url.Values{
		"state": {state},
	}

	resp, _, statusCode, err := a.performPost(endpoint, headers, query, []byte(payload.Encode()))

	if err != nil {
		return "", err
	}

	switch statusCode {
	case http.StatusFound:
		loc, err := resp.Location()
		if err != nil {
			return "", fmt.Errorf("postPassword: status found but no loc (%w)", err)
		}
		newState = loc.Query().Get("state")
		//newState = resp.Request.URL.Query().Get("state")
		return newState, nil
	default:
		return "", fmt.Errorf("postPassword: invalid status code returned (%d), password incorrect or wrong captcha", statusCode)
	}
}

func (a *Auth) resumeSession(newState, oldState string) (nextUrl string, err error) {
	endpoint := "https://auth0.openai.com/authorize/resume?state=" + newState

	headers := http.Header{
		"cache-control":             {"max-age=0"},
		"dnt":                       {"1"},
		"upgrade-insecure-requests": {"1"},
		"user-agent":                {a.UserAgent},
		"accept":                    {"text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9"},
		"sec-fetch-site":            {"same-origin"},
		"sec-fetch-mode":            {"navigate"},
		"sec-fetch-user":            {"?1"},
		"sec-fetch-dest":            {"document"},
		"sec-ch-ua":                 {a.m.ClientHintUA()},
		"sec-ch-ua-mobile":          {"?0"},
		"sec-ch-ua-platform":        {"\"Windows\""},
		"referer":                   {"https://auth0.openai.com/u/login/password?state=" + oldState},
		"accept-encoding":           {"gzip, deflate, br"},
		"accept-language":           {"pt,pt-PT;q=0.9,en-US;q=0.8,en;q=0.7,es;q=0.6"},
		http.HeaderOrderKey:         resumeSessionHeaderOrder,
	}

	resp, _, statusCode, err := a.performGet(endpoint, headers)

	if err != nil {
		return "", err
	}

	switch statusCode {
	case http.StatusFound:
		nextUrl := resp.Header.Get("Location")
		if nextUrl == "" {
			return "", errors.New("resumeSession: couldn't find redirect url")
		}
		return nextUrl, nil

	default:
		return "", fmt.Errorf("resumeSession: invalid status code returned (%d)", statusCode)
	}
}

func (a *Auth) authCallback(endpoint string) (token string, err error) {

	headers := http.Header{
		"cache-control":             {"max-age=0"},
		"sec-ch-ua":                 {a.m.ClientHintUA()},
		"sec-ch-ua-mobile":          {"?0"},
		"sec-ch-ua-platform":        {"\"Windows\""},
		"dnt":                       {"1"},
		"upgrade-insecure-requests": {"1"},
		"user-agent":                {a.UserAgent},
		"accept":                    {"text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9"},
		"sec-fetch-site":            {"same-site"},
		"sec-fetch-mode":            {"navigate"},
		"sec-fetch-dest":            {"document"},
		"accept-encoding":           {"gzip, deflate, br"},
		http.HeaderOrderKey:         authCallbackHeaderOrder,
	}

	_, body, statusCode, err := a.performGet(endpoint, headers)

	if err != nil {
		return "", err
	}

	//If everything goes right, this should follow a 302 redirect to "/" and a 307 to "/chat", which returns 200
	switch statusCode {
	case http.StatusOK:
		doc, err := goquery.NewDocumentFromReader(strings.NewReader(string(body)))

		if err != nil {
			return "", fmt.Errorf("authCallback: invalid html (%w)", err)
		}

		nextData := doc.Find("#__NEXT_DATA__").First().Text()

		a.logger.Debug().Str("__NEXT_DATA__", nextData).Msg("")

		if !gjson.Valid(nextData) {
			return "", errors.New("authCallback: invalid __NEXT_DATA__ json")
		}

		token := gjson.Get(nextData, "props.pageProps.accessToken").String()

		if token == "" {
			return "", errors.New("authCallback: couldn't find token")
		}

		return token, nil
	default:
		return "", fmt.Errorf("authCallback: invalid status code returned (%d)", statusCode)
	}
}

func (a *Auth) authSession() (creds *Credentials, err error) {
	endpoint := "https://chat.openai.com/api/auth/session"

	headers := http.Header{
		"sec-ch-ua":          {a.m.ClientHintUA()},
		"dnt":                {"1"},
		"sec-ch-ua-mobile":   {"?0"},
		"user-agent":         {a.UserAgent},
		"sec-ch-ua-platform": {"\"Windows\""},
		"accept":             {"*/*"},
		"sec-fetch-site":     {"same-origin"},
		"sec-fetch-mode":     {"cors"},
		"sec-fetch-dest":     {"empty"},
		"referer":            {"https://chat.openai.com/chat"},
		"accept-encoding":    {"gzip, deflate, br"},
		"accept-language":    {"pt,pt-PT;q=0.9,en-US;q=0.8,en;q=0.7,es;q=0.6"},
		http.HeaderOrderKey:  authSessionHeaderOrder,
	}

	_, body, statusCode, err := a.performGet(endpoint, headers)

	if err != nil {
		return nil, err
	}

	switch statusCode {
	case http.StatusOK:

		jsonData := string(body)

		if !gjson.Valid(jsonData) {
			return nil, errors.New("authSession: invalid json")
		}

		creds = &Credentials{
			AccessToken: gjson.Get(jsonData, "accessToken").String(),
			ExpiresAt:   gjson.Get(jsonData, "expires").String(), //TODO: Parse expires
		}

		return creds, nil
	default:
		return nil, fmt.Errorf("authSession: invalid status code returned (%d)", statusCode)
	}
}

func (a *Auth) Authenticate() (cred *Credentials, err error) {
	defer func() {
		if err != nil {
			a.logger.Error().Err(err).Msg("failed to authenticate")
		}
	}()

	if a.EmailAddress == "" || a.Password == "" {
		return nil, errors.New("invalid credentials")
	}

	a.logger.Info().Str("password", a.Password).Str("username", a.EmailAddress).Msg("Starting authentication process")

	err = a.begin()

	if err != nil {
		return nil, err
	}
	a.logger.Info().Msg("Got main page")

	csrfToken, err := a.getCsrf()

	if err != nil {
		return nil, err
	}

	a.logger.Info().Str("token", csrfToken).Msg("Got CSRF token")

	nextUrl, err := a.postLoginPrompt(csrfToken)

	if err != nil {
		return nil, err
	}

	a.logger.Info().Str("url", nextUrl).Msg("Got auth0 URL")

	firstState, hasCaptcha, err := a.auth0AuthorizeAndIdentifier(nextUrl)

	if err != nil {
		return nil, err
	}

	a.logger.Info().Bool("hasCaptcha", hasCaptcha).Msg("Got auth0 authorization")

	captchaAnswer := ""

	if hasCaptcha {
		reader := bufio.NewReader(os.Stdin)
		fmt.Print("Captcha answer: ")
		captchaAnswer, err = reader.ReadString('\n')
		if err != nil {
			return nil, err
		}
		captchaAnswer = strings.Replace(captchaAnswer, "\n", "", -1)
	}

	oldCheckRedirect := a.session.CheckRedirect

	//Redirect cause problems due to go setting headers that don't match with the browser, resume causes the next request to have two referer headers for some reason
	a.session.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}

	//Clean the client
	defer func() {
		a.session.CheckRedirect = oldCheckRedirect
	}()

	err = a.postUserName(firstState, captchaAnswer)

	if err != nil {
		return nil, err
	}

	a.logger.Info().Msg("Username sent")

	newState, err := a.postPassword(firstState)

	if err != nil {
		return nil, err
	}
	a.logger.Info().Msg("Password sent")

	nextUrl, err = a.resumeSession(newState, firstState)

	a.logger.Info().Msg("Session resumed")

	if err != nil {
		return nil, err
	}

	a.session.CheckRedirect = oldCheckRedirect // go doens't break the redirect chain in this request

	token, err := a.authCallback(nextUrl)

	if err != nil {
		return nil, err
	}

	a.logger.Info().Str("token", token).Msg("Logged in")

	creds, err := a.authSession()

	if err != nil {
		return nil, err
	}

	a.logger.Debug().Str("access token", creds.AccessToken).Str("expiration", creds.ExpiresAt).Msg("got creds")

	return creds, nil
}
