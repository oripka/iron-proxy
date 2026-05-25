package awssigv4

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/ironsh/iron-proxy/internal/hostmatch"
	"github.com/ironsh/iron-proxy/internal/transform"
)

func fixedClock() time.Time {
	return time.Unix(0, 0).UTC()
}

func testSigner(t *testing.T, cfg signerConfig) *AWSSigV4 {
	t.Helper()
	sgn, err := newFromConfig(sigv4Config{Signers: []signerConfig{cfg}}, fixedClock)
	require.NoError(t, err)
	return sgn
}

func dynamoDBTestRequest(t *testing.T, body string) *http.Request {
	t.Helper()

	req, err := http.NewRequest("POST", "https://dynamodb.us-east-1.amazonaws.com", strings.NewReader(body))
	require.NoError(t, err)
	req.Host = req.URL.Host
	req.URL.Opaque = "//example.org/bucket/key-._~,!@#$%^&*()"
	req.Header.Set("X-Amz-Target", "prefix.Operation")
	req.Header.Set("Content-Type", "application/x-amz-json-1.0")
	req.Header.Set("X-Amz-Meta-Other-Header", "some-value=!@#$%^&* (+)")
	req.Header.Add("X-Amz-Meta-Other-Header_With_Underscore", "some-value=!@#$%^&* (+)")
	req.Header.Add("X-amz-Meta-Other-Header_With_Underscore", "some-value=!@#$%^&* (+)")
	req.ContentLength = int64(len(body))
	req.Body = transform.NewBufferedBody(req.Body, 1<<20)
	return req
}

func TestTransformRequest_SignsDeterministicallyAndRestoresBody(t *testing.T) {
	t.Setenv("TEST_AWS_ACCESS_KEY_ID", "AKID")
	t.Setenv("TEST_AWS_SECRET_ACCESS_KEY", "SECRET")
	t.Setenv("TEST_AWS_SESSION_TOKEN", "SESSION")

	s := testSigner(t, signerConfig{
		Service:            "dynamodb",
		Region:             "us-east-1",
		AccessKeyIDEnv:     "TEST_AWS_ACCESS_KEY_ID",
		SecretAccessKeyEnv: "TEST_AWS_SECRET_ACCESS_KEY",
		SessionTokenEnv:    "TEST_AWS_SESSION_TOKEN",
		Rules: []hostmatch.RuleConfig{
			{Host: "dynamodb.us-east-1.amazonaws.com"},
		},
	})
	req := dynamoDBTestRequest(t, "{}")
	req.Header.Set("Authorization", "dummy-app-side-signature")
	req.Header.Set("X-Amz-Date", "19991231T235959Z")
	req.Header.Set("X-Amz-Security-Token", "dummy-app-side-token")

	tctx := &transform.TransformContext{Mode: transform.ModeMITM}
	result, err := s.TransformRequest(context.Background(), tctx, req)
	require.NoError(t, err)
	require.Equal(t, transform.ActionContinue, result.Action)

	expectedAuth := "AWS4-HMAC-SHA256 Credential=AKID/19700101/us-east-1/dynamodb/aws4_request, SignedHeaders=content-length;content-type;host;x-amz-date;x-amz-meta-other-header;x-amz-meta-other-header_with_underscore;x-amz-security-token;x-amz-target, Signature=a518299330494908a70222cec6899f6f32f297f8595f6df1776d998936652ad9"
	require.Equal(t, expectedAuth, req.Header.Get("Authorization"))
	require.Equal(t, "19700101T000000Z", req.Header.Get("X-Amz-Date"))
	require.Equal(t, "SESSION", req.Header.Get("X-Amz-Security-Token"))

	body, err := io.ReadAll(req.Body)
	require.NoError(t, err)
	require.Equal(t, "{}", string(body))
	require.Equal(t, int64(2), req.ContentLength)
	require.NotContains(t, req.Header.Get("Authorization"), "dummy")
}

func TestTransformRequest_OmitsSessionTokenWhenNotConfigured(t *testing.T) {
	t.Setenv("TEST_AWS_ACCESS_KEY_ID", "AKID")
	t.Setenv("TEST_AWS_SECRET_ACCESS_KEY", "SECRET")

	s := testSigner(t, signerConfig{
		Service:            "ses",
		Region:             "eu-central-1",
		AccessKeyIDEnv:     "TEST_AWS_ACCESS_KEY_ID",
		SecretAccessKeyEnv: "TEST_AWS_SECRET_ACCESS_KEY",
		Rules: []hostmatch.RuleConfig{
			{Host: "email.eu-central-1.amazonaws.com"},
		},
	})
	req, err := http.NewRequest("POST", "https://email.eu-central-1.amazonaws.com/", strings.NewReader("Action=GetSendQuota"))
	require.NoError(t, err)
	req.Host = req.URL.Host
	req.Header.Set("X-Amz-Security-Token", "dummy-app-side-token")
	req.ContentLength = int64(len("Action=GetSendQuota"))
	req.Body = transform.NewBufferedBody(req.Body, 1<<20)

	_, err = s.TransformRequest(context.Background(), &transform.TransformContext{Mode: transform.ModeMITM}, req)
	require.NoError(t, err)

	require.NotEmpty(t, req.Header.Get("Authorization"))
	require.Equal(t, "", req.Header.Get("X-Amz-Security-Token"))
}

func TestTransformRequest_DoesNotRequireCredentialsForNonMatchingHost(t *testing.T) {
	s := testSigner(t, signerConfig{
		Service:            "ses",
		Region:             "eu-central-1",
		AccessKeyIDEnv:     "MISSING_AWS_ACCESS_KEY_ID",
		SecretAccessKeyEnv: "MISSING_AWS_SECRET_ACCESS_KEY",
		Rules: []hostmatch.RuleConfig{
			{Host: "email.eu-central-1.amazonaws.com"},
		},
	})
	req, err := http.NewRequest("POST", "https://example.com/", strings.NewReader("body"))
	require.NoError(t, err)
	req.Host = req.URL.Host
	req.Header.Set("Authorization", "unchanged")
	req.Body = transform.NewBufferedBody(req.Body, 1<<20)

	_, err = s.TransformRequest(context.Background(), &transform.TransformContext{Mode: transform.ModeMITM}, req)
	require.NoError(t, err)
	require.Equal(t, "unchanged", req.Header.Get("Authorization"))
}

func TestTransformRequest_ErrorsWhenCredentialsMissing(t *testing.T) {
	s := testSigner(t, signerConfig{
		Service:            "ses",
		Region:             "eu-central-1",
		AccessKeyIDEnv:     "MISSING_AWS_ACCESS_KEY_ID",
		SecretAccessKeyEnv: "MISSING_AWS_SECRET_ACCESS_KEY",
		Rules: []hostmatch.RuleConfig{
			{Host: "email.eu-central-1.amazonaws.com"},
		},
	})
	req, err := http.NewRequest("POST", "https://email.eu-central-1.amazonaws.com/", strings.NewReader("body"))
	require.NoError(t, err)
	req.Host = req.URL.Host
	req.Body = transform.NewBufferedBody(req.Body, 1<<20)

	_, err = s.TransformRequest(context.Background(), &transform.TransformContext{Mode: transform.ModeMITM}, req)
	require.ErrorContains(t, err, "MISSING_AWS_ACCESS_KEY_ID")
}

func TestTransformRequest_FailsClosedWhenBodyWasTruncated(t *testing.T) {
	t.Setenv("TEST_AWS_ACCESS_KEY_ID", "AKID")
	t.Setenv("TEST_AWS_SECRET_ACCESS_KEY", "SECRET")

	s := testSigner(t, signerConfig{
		Service:            "ses",
		Region:             "eu-central-1",
		AccessKeyIDEnv:     "TEST_AWS_ACCESS_KEY_ID",
		SecretAccessKeyEnv: "TEST_AWS_SECRET_ACCESS_KEY",
		Rules: []hostmatch.RuleConfig{
			{Host: "email.eu-central-1.amazonaws.com"},
		},
	})
	req, err := http.NewRequest("POST", "https://email.eu-central-1.amazonaws.com/", strings.NewReader("hello world"))
	require.NoError(t, err)
	req.Host = req.URL.Host
	req.ContentLength = int64(len("hello world"))
	req.Body = transform.NewBufferedBody(req.Body, 5)

	_, err = s.TransformRequest(context.Background(), &transform.TransformContext{Mode: transform.ModeMITM}, req)
	require.ErrorContains(t, err, "max_request_body_bytes")
}

func TestSHA256Hex(t *testing.T) {
	sum := sha256.Sum256([]byte("Action=SendRawEmail"))
	require.Equal(t, hex.EncodeToString(sum[:]), sha256Hex([]byte("Action=SendRawEmail")))
}
