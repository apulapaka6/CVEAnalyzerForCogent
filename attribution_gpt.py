import os
import json
import requests
from rapidfuzz import fuzz
import openai


def load_cves():
    """
    Load CVE data from mock_cves.json file.
    """
    try:
        with open('mock_cves.json', 'r', encoding='utf-8') as f:
            cves = json.load(f)
        print(f"Loaded {len(cves)} CVEs from mock_cves.json")
        return cves
    except FileNotFoundError:
        print("Error: mock_cves.json not found in current directory")
        return []
    except json.JSONDecodeError as e:
        print(f"Error parsing mock_cves.json: {e}")
        return []


def fetch_posts(cves):
    """
    Fetch posts from Twitter/X (5 max) and Reddit public API (15 max) for each CVE.
    """
    posts = []
    x_token = os.getenv('X_BEARER_TOKEN')
    reddit_ua = os.getenv('REDDIT_USER_AGENT')

    for cve in cves:
        cid = cve['cve_id']
        # use up to two descriptive aliases
        aliases = [a for a in cve['aliases'][:2] if len(a) > 2]
        parts = [cid] + [f'"{a}"' for a in aliases]
        query = f"({ ' OR '.join(parts) }) lang:en -is:retweet -is:reply"

        # X free tier: fetch up to 5 tweets
        if x_token:
            x_posts = fetch_x_posts(query, x_token, max_results=5)
            posts.extend(x_posts)
            print(f"Fetched {len(x_posts)} posts from X for {cid}")

        # Reddit public API: fetch up to 15 results
        if reddit_ua:
            r_posts = fetch_reddit_posts(" ".join(parts), reddit_ua, limit=15)
            posts.extend(r_posts)
            print(f"Fetched {len(r_posts)} posts from Reddit for {cid}")

    print(f"Total posts fetched: {len(posts)}")
    return posts


def fetch_x_posts(query, bearer, max_results=5):
    url = "https://api.twitter.com/2/tweets/search/recent"
    headers = {"Authorization": f"Bearer {bearer}"}
    params = {"query": query, "max_results": max_results, "tweet.fields": "created_at,text"}
    resp = requests.get(url, headers=headers, params=params)
    if resp.status_code != 200:
        print(f"X API error {resp.status_code}: {resp.text}")
        return []
    return [
        {"id": t["id"], "source": "x", "text": t["text"], "created_at": t.get("created_at", "")}  
        for t in resp.json().get("data", [])
    ]


def fetch_reddit_posts(query, ua, limit=15):
    url = "https://api.reddit.com/r/all/search"
    headers = {"User-Agent": ua}
    params = {"q": query, "limit": limit, "sort": "new"}
    resp = requests.get(url, headers=headers, params=params)
    if resp.status_code != 200:
        print(f"Reddit API error {resp.status_code}: {resp.text}")
        return []
    items = resp.json().get("data", {}).get("children", [])
    return [
        {
            "id": itm["data"]["id"],
            "source": "r",
            "text": f"{itm['data'].get('title','')} {itm['data'].get('selftext','')}".strip(),
            "created_at": str(itm["data"].get("created_utc", ""))
        }
        for itm in items
    ]


def analyze_sentiment(posts):
    """
    Analyze sentiment using OpenAI GPT API with few-shot prompting.
    """
    api_key = os.getenv('OPENAI_API_KEY')
    if not api_key:
        print("Warning: OPENAI_API_KEY not found, setting all sentiment to 0.0")
        for p in posts:
            p["sentiment"] = 0.0
        return posts

    openai.api_key = api_key
    
    # Few-shot prompt for sentiment analysis
    system_prompt = """You are a sentiment analyzer. Analyze the sentiment of social media posts and return a single number between -1.0 and 1.0, where:
-1.0 = very negative
-0.5 = negative  
0.0 = neutral
0.5 = positive
1.0 = very positive

Examples:
Post: "This vulnerability is absolutely terrible and will destroy everything!"
Sentiment: -0.8

Post: "Great security research, thanks for the disclosure"
Sentiment: 0.6

Post: "CVE-2024-1234 affects version 1.2.3"
Sentiment: 0.0

Post: "Another day, another security bug. Not surprised."
Sentiment: -0.3

Return only the numerical score, nothing else."""

    for p in posts:
        try:
            response = openai.chat.completions.create(
                model="gpt-3.5-turbo-16k",
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": f"Post: {p['text'][:500]}\nSentiment:"}
                ],
                max_tokens=10,
                temperature=0.1
            )
            
            sentiment_str = response.choices[0].message.content.strip()
            try:
                sentiment = float(sentiment_str)
                # Clamp to valid range
                sentiment = max(-1.0, min(1.0, sentiment))
                p["sentiment"] = sentiment
            except ValueError:
                print(f"Invalid sentiment response: {sentiment_str}, using 0.0")
                p["sentiment"] = 0.0
                
        except Exception as e:
            print(f"OpenAI API error for post {p['id']}: {e}")
            p["sentiment"] = 0.0

    print(f"Analyzed sentiment for {len(posts)} posts using OpenAI GPT")
    return posts


def match_cves(posts, cves):
    """
    Match each post to CVEs via exact ID, aliases, and fuzzy description.
    """
    for p in posts:
        text_lower = p["text"].lower()
        p["matches"] = []
        for c in cves:
            cid, desc, aliases = c["cve_id"], c["desc"], c["aliases"]
            if cid.lower() in text_lower or any(a.lower() in text_lower for a in aliases[:2]):
                p["matches"].append(cid)
            elif fuzz.partial_ratio(p["text"], desc) > 60:
                p["matches"].append(cid)
    matched = sum(1 for p in posts if p["matches"])
    print(f"Matched {matched} posts to CVEs")
    return posts


def compute_scores(posts, cves):
    """
    Compute a threat score: 0.7*CVSS + 0.3*(mentions/10) + 0.1*avg_sentiment
    """
    results = []
    for c in cves:
        cid, cvss = c["cve_id"], c["cvss"]
        matched = [p for p in posts if cid in p["matches"]]
        cnt = len(matched)
        avg = sum(p["sentiment"] for p in matched) / cnt if cnt else 0.0
        score = 0.7*cvss + 0.3*min(cnt, 10)/10 + 0.1*avg
        results.append({"cve_id": cid, "cvss": cvss, "mentions": cnt, "avg_sentiment": avg, "threat_score": score})
    results.sort(key=lambda x: x["threat_score"], reverse=True)
    print(f"Computed threat scores for {len(results)} CVEs")
    return results


def main():
    print("Starting threat scoring pipeline with OpenAI GPT...")
    cves = load_cves()
    if not cves:
        return

    posts = fetch_posts(cves)
    if not posts:
        print("No posts fetched; proceeding with empty list.")
        posts = []

    posts = analyze_sentiment(posts)
    posts = match_cves(posts, cves)
    scores = compute_scores(posts, cves)

    print("\nTop 5 CVEs by threat score:")
    for i, r in enumerate(scores[:5], 1):
        print(f"{i}. {r['cve_id']}: {r['threat_score']:.2f} (mentions={r['mentions']}, avg_sent={r['avg_sentiment']:.2f})")

    with open('latest_scored_gpt.json', 'w', encoding='utf-8') as f:
        json.dump(scores, f, indent=2)
    print("Saved latest_scored_gpt.json")


if __name__ == "__main__":
    main() 