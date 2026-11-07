import re
from urllib.parse import urlparse

# Improvement B Helper: Separate benign notices from security warnings
BENIGN_NOTICES = (
    "No URL entered.",
    "Could not identify a hostname.",
    "No listed warning signs found. This does NOT prove safety."
)


def has_security_warnings(findings: list[str]) -> bool:
    """Return True if findings contain actionable security flags."""
    if not findings:
        return False
    return not findings[0].startswith(BENIGN_NOTICES)


def inspect_url(raw_link: str) -> list[str]:
    """Analyze static URL text for suspicious phishing heuristics."""
    clean_url = raw_link.strip()
    results = []

    if not clean_url:
        return ["No URL entered."]

    # Normalize protocol prefix so urlparse can extract the host correctly
    eval_target = clean_url if "://" in clean_url else "http://" + clean_url
    parsed_target = urlparse(eval_target)
    domain_host = (parsed_target.hostname or "").lower()

    if not domain_host:
        return ["Could not identify a hostname."]

    # Check 1: Userinfo delimiter spoofing (@ symbol)
    if "@" in eval_target:
        results.append("Contains an @ symbol; inspect carefully.")

    # Check 2: Total string length exceeds 100 characters
    if len(clean_url) > 100:
        results.append("Unusually long URL (over 100 characters).")

    # Check 3: Host is an explicit IPv4 numeric address
    if re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", domain_host):
        results.append("Uses an IP address instead of a familiar domain.")

    # Check 4: Deep subdomain nesting (5 or more dot-separated parts)
    host_tokens = [seg for seg in domain_host.split(".") if seg]
    if len(host_tokens) >= 5:
        results.append("Contains many hostname segments/subdomains.")

    # Check 5: Punycode internationalized string indicator
    if "xn--" in domain_host:
        results.append("Contains a punycode-style hostname.")

    # Check 6: Unencrypted HTTP transmission protocol
    if parsed_target.scheme.lower() == "http":
        results.append("Uses HTTP. HTTPS alone does not prove trust.")

    # Fallback status if no criteria matched
    if not results:
        results.append("No listed warning signs found. This does NOT prove safety.")

    return results


def main():
    print("=" * 50)
    print("URL Phishing Risk Heuristic Analyzer")
    print("Defensive static analysis - no outbound connections made.")
    print("=" * 50)

    user_link = input("\nEnter the target URL to evaluate: ").strip()
    flags = inspect_url(user_link)

    print("\nEvaluation Output:")

    # Improvement E: Clean numbered itemization
    for idx, item in enumerate(flags, start=1):
        print(f" [{idx}] {item}")

    # Improvement B: Summary banner highlighting risk levels
    if has_security_warnings(flags):
        print("\n" + "!" * 50)
        print(f"REVIEW CAREFULLY: {len(flags)} warning sign(s) detected in the link.")
        print("!" * 50)
    else:
        print("\nNotice: Clean text scan does not guarantee the destination is safe.")

    print("\nSecurity Tip: Always verify credentials before entering them online.")


if __name__ == "__main__":
    main()