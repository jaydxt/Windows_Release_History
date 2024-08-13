import requests
from bs4 import BeautifulSoup
import pandas as pd
import os

# URLs to scrape
urls = {
    "Windows 11": "https://learn.microsoft.com/en-us/windows/release-health/windows11-release-information",
    "Windows 10": "https://learn.microsoft.com/en-us/windows/release-health/release-information"
}

def scrape_data(url):
    response = requests.get(url)
    soup = BeautifulSoup(response.content, 'html.parser')
    
    # Locate the specific table by heading and extract the relevant data
    tables = soup.find_all('table')
    data = []
    for table in tables:
        headers = [header.text.strip() for header in table.find_all('th')]
        if set(["Servicing option", "Availability date", "Build", "KB article"]).issubset(headers):
            rows = table.find_all('tr')
            for row in rows[1:]:  # Skip the header row
                cells = row.find_all('td')
                data.append([cell.text.strip() for cell in cells])
    return data

def update_csv(data, csv_file, os_version):
    new_data = pd.DataFrame(data, columns=["Servicing option", "Availability date", "Build", "KB article"])
    new_data['OS Version'] = os_version  # Add a column to differentiate between Windows 10 and 11
    if os.path.exists(csv_file):
        existing_data = pd.read_csv(csv_file)
        combined_data = pd.concat([existing_data, new_data]).drop_duplicates()
        combined_data.to_csv(csv_file, index=False)
    else:
        new_data.to_csv(csv_file, index=False)

# Main execution
csv_filename = "Windows_Release_History.csv"
for os_version, url in urls.items():
    scraped_data = scrape_data(url)
    update_csv(scraped_data, csv_filename, os_version)
