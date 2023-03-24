import csv
from bs4 import BeautifulSoup
import requests

# First create the new file with our options
with open("cve_cvss_mydate.csv", "w") as cvss_file:
    writer = csv.writer(cvss_file)
    writer.writerow(["cve", "cvss_cna_3.0", "cvss_nist_3.1", "cvss_cna_2.0", "cvss_nist_2.0"])


with open("cveid_24_03_2023.csv") as csv_file:
    csvreader = csv.reader(csv_file)

    for row in csvreader:
        print(f"https://nvd.nist.gov/vuln/detail/{row[0]}")
        rq = requests.get(f"https://nvd.nist.gov/vuln/detail/{row[0]}").text
        soup = BeautifulSoup(rq, "html.parser")

        # Select the span element with the < tooltipCvss2NistMetrics >
        # NIST framework 2.0
        try:
            span_cvss2_nist = soup.select_one("span[class*=tooltipCvss2NistMetrics]").text
            span_cvss2_nist = span_cvss2_nist.replace("(", "").replace(")", "")
        except AttributeError:
            span_cvss2_nist = "NoValue"

        # Select the span element with the < tooltipCvss2CnaMetrics >
        # CNA framework 2.0
        try:
            span_cvss2_cna = soup.select_one("span[class*=tooltipCvss2CnaMetrics]").text
            span_cvss2_cna = span_cvss2_cna.replace("(", "").replace(")", "")
        except AttributeError:
            span_cvss2_cna = "NoValue"

        # Select the span element with the < tooltipCvss3CnaMetrics >
        # CNA Framework 3.0
        try:
            span_cvss3_0_cna = soup.select_one("span[class*=tooltipCvss3CnaMetrics]").text
            span_cvss3_0_cna = span_cvss3_0_cna.replace("CVSS:3.0", "")
        except AttributeError:
            span_cvss3_0_cna = "NoValue"

        # Select the span element with the < tooltipCvss3NistMetrics >
        # NIST Framework 3.1
        try:
            span_cvss3_1_nist = soup.select_one("span[class*=tooltipCvss3NistMetrics]").text
            span_cvss3_1_nist = span_cvss3_1_nist.replace("CVSS:3.1", "")
        except AttributeError:
            span_cvss3_1_nist = "NoValue"

        my_row = [row[0], span_cvss3_0_cna, span_cvss3_1_nist, span_cvss2_cna, span_cvss2_nist]
        with open("cve_cvss_mydate.csv", "a") as cvss_file:
            writer = csv.writer(cvss_file)
            writer.writerow(my_row)




