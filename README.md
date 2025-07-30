# CVE Threat Scoring Pipeline

A threat scoring system that analyzes CVE (Common Vulnerabilities and Exposures) data by fetching social media posts and computing threat scores using multiple sentiment analysis approaches.

##  Overview

This project implements a rule-based threat scoring pipeline that:
1. **Loads CVE data** from JSON files
2. **Fetches social media posts** from Twitter/X and Reddit
3. **Analyzes sentiment** using three different approaches
4. **Matches posts to CVEs** using exact, alias, and fuzzy matching
5. **Computes threat scores** based on CVSS, mentions, and sentiment

##  Files

### Core Scripts
- **attribution_rule.py** - VADER sentiment analysis (rule-based)
- **attribution_gpt.py** - OpenAI GPT-3.5 sentiment analysis  FIXED
- **attribution_claude.py** - Anthropic Claude 3.5 sentiment analysis

### Data Files
- **mock_cves.json** - Sample CVE data for testing
- **requirements.txt** - Python dependencies

### Output Files
- **latest_scored_rule_based.json** - VADER-based results
- **latest_scored_gpt.json** - GPT-based results (now functional)
- **latest_scored_claude.json** - Claude-based results
- **key_takeaways.txt** - Performance analysis and recommendations

##  Setup

### 1. Install Dependencies
`pip install -r requirements.txt
`

### 2. Environment Variables
Set up the following environment variables:

**Required for social media data:**
`
export X_BEARER_TOKEN="your_twitter_bearer_token"
export REDDIT_USER_AGENT="your_reddit_user_agent"
`

**Required for LLM sentiment analysis:**
`
export OPENAI_API_KEY="your_openai_api_key"      # For GPT version
export CLAUDE_API_KEY="your_anthropic_api_key"   # For Claude version
`

### 3. Run Scripts
`
#Rule-Based
python attribution_rule.py
#GPT-Based
python attribution_gpt.py
#CClaude-Based
python attribution_claude.py
`

##  Threat Scoring Formula

`
threat_score = 0.7  CVSS + 0.3  min(mentions, 10)/10 + 0.1  avg_sentiment
`

**Components:**
- **CVSS Score** (70% weight): Base vulnerability severity
- **Social Mentions** (30% weight): Capped at 10 mentions maximum
- **Average Sentiment** (10% weight): Compound sentiment score (-1 to +1)

##  Matching Strategy

Posts are matched to CVEs using three methods:
1. **Exact Match**: CVE ID appears in post text
2. **Alias Match**: CVE aliases (case-insensitive) appear in text
3. **Fuzzy Match**: Description similarity > 60% using rapidfuzz

##  Performance Comparison (UPDATED)

| Method | Speed | Cost | Sentiment Quality | Sentiment Range | Recommendation |
|--------|-------|------|------------------|-----------------|----------------|
| **VADER** |  Fastest |  Free |  Good | -0.05 to 0.91 | **Production** |
| **GPT-3.5** |  Moderate |  .10-0.50 |  **Fixed** | 0.01 to 0.49 | **Balanced** |
| **Claude 3.5** |  Slowest |  .05-0.25 |  Best | -0.05 to 0.39 | **Research** |

##  Key Findings (UPDATED)

### Recent Improvements:
- **GPT API Fixed**: Updated from deprecated ChatCompletion.create() to chat.completions.create()
- **All Methods Working**: GPT now provides meaningful sentiment analysis (0.01-0.49 range)
- **Improved Rankings**: All three methods show proper differentiation

### Sentiment Analysis Comparison:
**Top CVE (CVE-2025-4285):**
- **VADER**: 0.589 sentiment  7.359 threat score (optimistic)
- **GPT-3.5**: 0.302 sentiment  7.330 threat score (balanced) 
- **Claude**: 0.051 sentiment  7.305 threat score (conservative)

### Method Characteristics:
- **VADER**: Most optimistic, fastest execution
- **GPT-3.5**: Balanced approach, good cost/performance ratio
- **Claude**: Most conservative, includes negative sentiment detection

##  Technical Notes

### Known Characteristics:
- **VADER**: May be over-optimistic for security content
- **GPT-3.5**: Conservative but realistic sentiment assessment  
- **Claude**: Only method detecting negative sentiment (-0.05 minimum)

##  API Requirements

### Twitter/X API v2
- Bearer token authentication
- Recent search endpoint access
- Rate limit: 300 requests/15min + additional security limitations on Free

### Reddit API
- Public JSON API (no authentication required)
- User-Agent header required
- Rate limit: ~60 requests/minute

### OpenAI API (FIXED)
- GPT-3.5-turbo-16k model access
- Updated API syntax: openai.chat.completions.create()
- Estimated cost: ~.002 per 1K tokens

### Anthropic API
- Claude 3.5 Haiku model access
- Estimated cost: ~.001 per 1K tokens

##  Sentiment Analysis Insights

### Distribution Patterns:
- **VADER**: Wide range, generally positive bias
- **GPT-3.5**: Moderate range, balanced assessment
- **Claude**: Conservative range, includes negative sentiment

### Use Case Recommendations:
1. **Speed-Critical**: Use VADER (instant results)
2. **Balanced Analysis**: Use GPT-3.5 (good middle ground)
3. **Comprehensive Research**: Use Claude (most nuanced)
4. **Ensemble Approach**: Combine all three for robust assessment

##  Future Enhancements

- [ ] **Ensemble Method**: Weighted combination of all three approaches
- [ ] **Confidence Scoring**: Add uncertainty measures to sentiment predictions
- [ ] **Negative Sentiment Weighting**: Emphasize negative sentiment for threat assessment
- [ ] **Temporal Analysis**: Track sentiment changes over time
- [ ] **Domain-Specific Training**: Fine-tune models for cybersecurity content
- [ ] **Real-time Monitoring**: Continuous CVE threat score updates



**Latest Update**: GPT-3.5 sentiment analysis now fully functional after API syntax fix. All three methods provide meaningful sentiment analysis for comprehensive threat assessment.
