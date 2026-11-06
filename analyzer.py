from email import policy
from email.parser import BytesParser
from urlextract import URLExtract
from dotenv import load_dotenv
import requests
import os
import base64
import hashlib
import csv
from email.utils import parseaddr

load_dotenv()

VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")


def extract_urls(message):
    extractor = URLExtract()
    urls = []

    for part in message.walk():
        if part.get_content_type() in ["text/plain", "text/html"]:
            try:
                text = part.get_content()
                urls.extend(extractor.find_urls(text))
            except Exception:
                pass

    return list(set(urls))


def check_url_virustotal(url):
    if not VIRUSTOTAL_API_KEY:
        return None

    url_id = base64.urlsafe_b64encode(
        url.encode()
    ).decode().strip("=")

    api_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"

    headers = {
        "x-apikey": VIRUSTOTAL_API_KEY
    }

    try:
        response = requests.get(
            api_url,
            headers=headers,
            timeout=15
        )

        if response.status_code == 200:
            data = response.json()
            return data["data"]["attributes"]["last_analysis_stats"]

    except requests.RequestException:
        pass

    return None


def extract_attachments(message):
    attachments = []

    for part in message.walk():
        if part.get_content_disposition() == "attachment":
            filename = part.get_filename()
            content = part.get_payload(decode=True)

            if content:
                file_hash = hashlib.sha256(content).hexdigest()

                attachments.append({
                    "filename": filename,
                    "sha256": file_hash
                })

    return attachments


def check_file_virustotal(file_hash):
    if not VIRUSTOTAL_API_KEY:
        return None

    api_url = f"https://www.virustotal.com/api/v3/files/{file_hash}"

    headers = {
        "x-apikey": VIRUSTOTAL_API_KEY
    }

    try:
        response = requests.get(
            api_url,
            headers=headers,
            timeout=15
        )

        if response.status_code == 200:
            data = response.json()
            return data["data"]["attributes"]["last_analysis_stats"]

    except requests.RequestException:
        pass

    return None


def check_display_name_spoof(sender):
    display_name, email_address = parseaddr(sender)

    if not display_name or not email_address:
        return False

    domain = email_address.split("@")[-1].lower()

    suspicious_names = [
        "paypal",
        "microsoft",
        "google",
        "amazon",
        "apple",
        "security team",
        "support team",
        "bank"
    ]

    for name in suspicious_names:
        if name in display_name.lower() and name not in domain:
            return True

    return False


def check_reply_to_mismatch(sender, reply_to):
    if not sender or not reply_to:
        return False

    sender_email = parseaddr(sender)[1]
    reply_email = parseaddr(reply_to)[1]

    if not sender_email or not reply_email:
        return False

    sender_domain = sender_email.split("@")[-1].lower()
    reply_domain = reply_email.split("@")[-1].lower()

    return sender_domain != reply_domain


def check_authentication_failures(auth_results):
    failures = []

    for result in auth_results:
        result_lower = result.lower()

        if "spf=fail" in result_lower:
            failures.append("SPF")

        if "dkim=fail" in result_lower:
            failures.append("DKIM")

        if "dmarc=fail" in result_lower:
            failures.append("DMARC")

    return failures


def get_verdict(score):
    if score <= 29:
        return "Low"
    elif score <= 59:
        return "Medium"
    elif score <= 79:
        return "High"
    else:
        return "Critical"


def save_to_csv(file_path, sender, score, verdict):
    csv_path = os.path.join("output", "summary.csv")

    file_exists = os.path.exists(csv_path)

    with open(
        csv_path,
        "a",
        newline="",
        encoding="utf-8"
    ) as csv_file:

        writer = csv.writer(csv_file)

        if not file_exists:
            writer.writerow([
                "Filename",
                "Sender",
                "Risk Score",
                "Verdict"
            ])

        writer.writerow([
            os.path.basename(file_path),
            sender,
            score,
            verdict
        ])

    return csv_path


def analyze_email(file_path):
    with open(file_path, "rb") as file:
        message = BytesParser(
            policy=policy.default
        ).parse(file)

    sender = message.get("From")
    reply_to = message.get("Reply-To")
    return_path = message.get("Return-Path")
    subject = message.get("Subject")

    received_headers = message.get_all(
        "Received",
        []
    )

    auth_results = message.get_all(
        "Authentication-Results",
        []
    )

    score = 0
    indicators = []
    url_results = []
    attachment_results = []

    if check_display_name_spoof(sender):
        score += 20
        indicators.append(
            "Display-name spoofing"
        )

    if check_reply_to_mismatch(
        sender,
        reply_to
    ):
        score += 15
        indicators.append(
            "Reply-To mismatch"
        )

    auth_failures = check_authentication_failures(
        auth_results
    )

    for failure in auth_failures:
        score += 20
        indicators.append(
            f"{failure} failure"
        )

    urls = extract_urls(message)

    for url in urls:
        stats = check_url_virustotal(url)

        url_results.append({
            "url": url,
            "stats": stats
        })

        if stats and stats.get(
            "malicious",
            0
        ) > 0:
            score += 30
            indicators.append(
                "Malicious URL"
            )

    attachments = extract_attachments(message)

    for attachment in attachments:
        stats = check_file_virustotal(
            attachment["sha256"]
        )

        attachment_results.append({
            "filename": attachment["filename"],
            "sha256": attachment["sha256"],
            "stats": stats
        })

        if stats and stats.get(
            "malicious",
            0
        ) > 0:
            score += 40
            indicators.append(
                "Malicious attachment"
            )

    score = min(score, 100)

    verdict = get_verdict(score)

    report_folder = os.path.join(
        "output",
        "reports"
    )

    os.makedirs(
        report_folder,
        exist_ok=True
    )

    filename = os.path.splitext(
        os.path.basename(file_path)
    )[0]

    report_path = os.path.join(
        report_folder,
        filename + "_report.txt"
    )

    with open(
        report_path,
        "w",
        encoding="utf-8"
    ) as report:

        report.write(
            "===== PHISHING EMAIL ANALYSIS REPORT =====\n\n"
        )

        report.write(
            "EMAIL DETAILS\n"
        )

        report.write(
            "------------------------------\n"
        )

        report.write(
            f"File: {file_path}\n"
        )

        report.write(
            f"Subject: {subject}\n"
        )

        report.write(
            f"From: {sender}\n"
        )

        report.write(
            f"Reply-To: {reply_to}\n"
        )

        report.write(
            f"Return-Path: {return_path}\n\n"
        )

        report.write(
            "RECEIVED HEADERS\n"
        )

        report.write(
            "------------------------------\n"
        )

        if received_headers:
            for received in received_headers:
                report.write(
                    received + "\n"
                )
        else:
            report.write(
                "No Received headers found.\n"
            )

        report.write(
            "\nAUTHENTICATION RESULTS\n"
        )

        report.write(
            "------------------------------\n"
        )

        if auth_results:
            for result in auth_results:
                report.write(
                    result + "\n"
                )
        else:
            report.write(
                "No Authentication-Results header found.\n"
            )

        report.write(
            "\nAUTHENTICATION FAILURES\n"
        )

        report.write(
            "------------------------------\n"
        )

        if auth_failures:
            for failure in auth_failures:
                report.write(
                    f"- {failure} failure\n"
                )
        else:
            report.write(
                "None detected.\n"
            )

        report.write(
            "\nURL ANALYSIS\n"
        )

        report.write(
            "------------------------------\n"
        )

        if url_results:
            for item in url_results:

                report.write(
                    f"URL: {item['url']}\n"
                )

                if item["stats"]:
                    report.write(
                        f"Malicious: {item['stats'].get('malicious', 0)}\n"
                    )

                    report.write(
                        f"Suspicious: {item['stats'].get('suspicious', 0)}\n"
                    )

                    report.write(
                        f"Harmless: {item['stats'].get('harmless', 0)}\n"
                    )

                    report.write(
                        f"Undetected: {item['stats'].get('undetected', 0)}\n"
                    )
                else:
                    report.write(
                        "VirusTotal result unavailable.\n"
                    )

                report.write("\n")

        else:
            report.write(
                "No URLs found.\n"
            )

        report.write(
            "ATTACHMENT ANALYSIS\n"
        )

        report.write(
            "------------------------------\n"
        )

        if attachment_results:

            for item in attachment_results:

                report.write(
                    f"Filename: {item['filename']}\n"
                )

                report.write(
                    f"SHA-256: {item['sha256']}\n"
                )

                if item["stats"]:

                    report.write(
                        f"Malicious: {item['stats'].get('malicious', 0)}\n"
                    )

                    report.write(
                        f"Suspicious: {item['stats'].get('suspicious', 0)}\n"
                    )

                    report.write(
                        f"Harmless: {item['stats'].get('harmless', 0)}\n"
                    )

                    report.write(
                        f"Undetected: {item['stats'].get('undetected', 0)}\n"
                    )

                else:
                    report.write(
                        "File hash not found in VirusTotal.\n"
                    )

                report.write("\n")

        else:
            report.write(
                "No attachments found.\n"
            )

        report.write(
            "RISK ASSESSMENT\n"
        )

        report.write(
            "------------------------------\n"
        )

        report.write(
            f"Risk Score: {score}/100\n"
        )

        report.write(
            f"Verdict: {verdict}\n\n"
        )

        report.write(
            "INDICATORS\n"
        )

        report.write(
            "------------------------------\n"
        )

        if indicators:
            for indicator in indicators:
                report.write(
                    f"- {indicator}\n"
                )
        else:
            report.write(
                "No risk indicators detected.\n"
            )

    csv_path = save_to_csv(
        file_path,
        sender,
        score,
        verdict
    )

    return {
        "score": score,
        "verdict": verdict,
        "sender": sender,
        "reply_to": reply_to,
        "return_path": return_path,
        "subject": subject,
        "received_headers": received_headers,
        "auth_results": auth_results,
        "auth_failures": auth_failures,
        "indicators": indicators,
        "urls": url_results,
        "attachments": attachment_results,
        "report_path": report_path,
        "csv_path": csv_path
    }


if __name__ == "__main__":
    file_path = input(
        "Enter path to .eml file: "
    )

    result = analyze_email(file_path)

    print("\n===== RISK ASSESSMENT =====")
    print(
        "Risk Score:",
        result["score"]
    )

    print(
        "Verdict:",
        result["verdict"]
    )

    print("\nReport saved to:")
    print(result["report_path"])

    print("\nSummary CSV:")
    print(result["csv_path"])