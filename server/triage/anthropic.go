package triage

import (
	"context"
	"encoding/json"
	"errors"
	"strings"

	"github.com/anthropics/anthropic-sdk-go/v2"
	"github.com/anthropics/anthropic-sdk-go/v2/option"
	"github.com/anthropics/anthropic-sdk-go/v2/shared/constant"
)

type anthropicProvider struct {
	client anthropic.Client
	model  string
	effort anthropic.BetaOutputConfigEffort
}

// NewAnthropic triages with Claude through the Anthropic API.
func NewAnthropic(apiKey, model, effort string) *Triager {
	return &Triager{
		provider: &anthropicProvider{
			client: anthropic.NewClient(option.WithAPIKey(apiKey)),
			model:  model,
			effort: anthropic.BetaOutputConfigEffort(effort),
		},
		model: model,
	}
}

func (p *anthropicProvider) complete(ctx context.Context, system, user string, schema json.RawMessage) (string, string, error) {
	resp, err := p.client.Beta.Messages.New(ctx, anthropic.BetaMessageNewParams{
		Model:     p.model,
		MaxTokens: 16000,
		System: []anthropic.BetaTextBlockParam{{
			Text:         system,
			CacheControl: anthropic.NewBetaCacheControlEphemeralParam(),
		}},
		Messages: []anthropic.BetaMessageParam{
			anthropic.NewBetaUserMessage(anthropic.NewBetaTextBlock(user)),
		},
		OutputConfig: anthropic.BetaOutputConfigParam{
			Effort: p.effort,
			Format: anthropic.BetaJSONOutputFormatParam{Schema: schema},
		},
		// Route a safety-classifier refusal to Anthropic's recommended
		// fallback model instead of failing the triage.
		Fallbacks: anthropic.BetaFallbacksParamUnion{OfDefault: constant.ValueOf[constant.Default]()},
		Betas:     []anthropic.AnthropicBeta{anthropic.AnthropicBetaServerSideFallback2026_07_01},
	})
	if err != nil {
		return "", "", err
	}
	if resp.StopReason == anthropic.BetaStopReasonRefusal {
		return "", "", errors.New("model declined to triage this actor")
	}
	var text strings.Builder
	for _, block := range resp.Content {
		if b, ok := block.AsAny().(anthropic.BetaTextBlock); ok {
			text.WriteString(b.Text)
		}
	}
	return text.String(), string(resp.Model), nil
}
