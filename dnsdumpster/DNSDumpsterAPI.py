import requests
import re
import base64
from bs4 import BeautifulSoup


class DNSDumpsterAPI:
    def __init__(self, verbose=False):
        """
        Initialize the DNSDumpsterAPI class.

        :param verbose: Boolean flag to enable/disable verbose logging.
        """
        self.verbose = verbose
        self.authorization = self.get_token()

    def get_token(self):
        """
        Get the Authorization token from DNSDumpster's public API page.
        """
        url = "https://dnsdumpster.com/"
        session = requests.Session()
        response = session.get(url)

        if response.status_code == 200:
            match = re.search(r'{"Authorization":\s?"([^"]+)\"', response.text)
            if match:
                token = match.group(1)
                if self.verbose:
                    print(f"Authorization Token found: {token}")
                return token
            else:
                if self.verbose:
                    print('Authorization Token not found in HTML content.')
                return None
        else:
            if self.verbose:
                print(f"Error in request: {response.status_code}")
            return None

    def get_dnsdumpster(self, target):
        """
        Make the POST request to DNSDumpster API.

        :param target: Domain name to search for DNS records.
        :return: HTML response or None if failed.
        """
        if not self.authorization:
            print("Authorization token is missing.")
            return None

        url = "https://api.dnsdumpster.com/htmld/"
        headers = {"Authorization": self.authorization}
        data = {"target": target}
        response = requests.post(url, headers=headers, data=data)

        if response.status_code != 200:
            if self.verbose:
                print(f"Error: Request failed with status code {response.status_code}")
            return None

        return response.text  # Return server response

    def parse_dnsdumpster(self, html, domain):
        """
        Parse the DNSDumpster HTML response and extract DNS records.

        :param html: HTML response from DNSDumpster.
        :param domain: Domain name used for the search.
        :return: Parsed data (DNS records, images, XLS) or None if failed.
        """
        soup = BeautifulSoup(html, 'html.parser')
        tables = soup.findAll('table')
        res = {}
        res['domain'] = domain
        res['dns_records'] = {}

        if len(tables) >= 4:
            res['dns_records']['a'] = self.retrieve_results(tables[1])
            res['dns_records']['mx'] = self.retrieve_results(tables[2])
            res['dns_records']['ns'] = self.retrieve_results(tables[3])
            res['dns_records']['txt'] = self.retrieve_txt_record(tables[4])

            # Network mapping image
            try:
                pattern = r'https://api.dnsdumpster.com/static/maps/' + re.escape(domain) + r'-[a-f0-9-]+\.png'
                map_url = re.findall(pattern, html)[0]
                if self.verbose:
                    print(f"Network mapping image URL: {map_url}")
                image_data = base64.b64encode(requests.get(map_url).content).decode('utf-8')
            except Exception as e:
                if self.verbose:
                    print(f"Error obtaining mapping image: {e}")
                image_data = None
            finally:
                res['image_data'] = image_data

            # XLS hosts
            try:
                pattern = r'https://api.dnsdumpster.com/static/xlsx/' + re.escape(domain) + r'-[a-f0-9-]+\.xlsx'
                xls_url = re.findall(pattern, html)[0]
                if self.verbose:
                    print(f"XLS URL: {xls_url}")
                xls_data = base64.b64encode(requests.get(xls_url).content).decode('utf-8')
            except Exception as e:
                if self.verbose:
                    print(f"Error obtaining XLS file: {e}")
                xls_data = None
            finally:
                res['xls_data'] = xls_data
        else:
            if self.verbose:
                print("Not enough tables found to process.")
            res = None

        return res

    def retrieve_results(self, table):
        """
        Extract data from DNS result tables (A, MX, NS records).

        :param table: The HTML table containing DNS records.
        :return: List of parsed records.
        """
        res = []
        trs = table.findAll('tr')
        for tr in trs:
            tds = tr.findAll('td')
            pattern_ip = r'([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})'
            try:
                host = str(tds[0]).split('<br/>')[0].split('>')[1].split('<')[0]
                ip = re.findall(pattern_ip, tds[1].text)[0]
                reverse_dns = tds[1].find('span', attrs={}).text if tds[1].find('span', attrs={}) else ""
                autonomous_system = tds[2].text if len(tds) > 2 else ""
                asn = autonomous_system.split('\n')[1] if '\n' in autonomous_system else ""
                asn_range = autonomous_system.split('\n')[2] if '\n' in autonomous_system else ""
                span_elements = tds[3].find_all('span', class_='sm-text') if len(tds) > 3 else []
                asn_name = span_elements[0].text.strip() if len(span_elements) > 0 else ""
                country = span_elements[1].text.strip() if len(span_elements) > 1 else ""
                open_service = (
                    "\n".join(
                        line.strip()
                        for line in tds[4].text.splitlines()
                        if line.strip()  # Filtra líneas que no sean vacías
                    )
                    if len(tds) > 4 else "N/A"
                )
                data = {
                    'host': host,
                    'ip': ip,
                    'reverse_dns': reverse_dns,
                    'as': asn,
                    'asn_range': asn_range,
                    'asn_name': asn_name,
                    'asn_country': country,
                    'open_service': open_service
                }
                res.append(data)
            except Exception as e:
                pass  # Avoid processing errors that stop the entire table
        return res

    def retrieve_txt_record(self, table):
        """
        Extract TXT records from the DNS records table.

        :param table: The HTML table containing TXT records.
        :return: List of TXT records.
        """
        res = []
        for td in table.findAll('td'):
            res.append(td.text.strip())
        return res

    def search(self, domain):
        """
        Main search function to get the DNS records for a domain.

        :param domain: Domain name to search for DNS records.
        :return: Parsed DNS records or None if failed.
        """
        if self.verbose:
            print(f"Searching for domain: {domain}")
        html = self.get_dnsdumpster(domain)
        if html:
            return self.parse_dnsdumpster(html, domain)
        else:
            return None

# import json
#
# if __name__ == "__main__":
#     # Script usage
#     url_to_search = "google.com"
#     res = DNSDumpsterAPI(verbose=True).search(url_to_search)
#
#     if res:
#         # Process and print DNS records
#         dns_res = res.get('dns_records', {}).get('a')
#         if dns_res:
#             print("####### A #######")
#             for entry in dns_res:
#                 print(
#                     "{host} ({ip}) AS: {as}, Range: {asn_range}, Name: {asn_name}, "
#                     "Country: {asn_country}, Reverse DNS: {reverse_dns}, Services: {open_service}"
#                     .format(**{
#                         **entry,
#                         "open_service": entry.get("open_service", "").replace("\n", " ")
#                     })
#                 )
#
#         mx_res = res.get('dns_records', {}).get('mx')
#         if mx_res:
#             print("\n####### MX #######")
#             for entry in mx_res:
#                 print(
#                     "{host} ({ip}) AS: {as}, Range: {asn_range}, Name: {asn_name}, "
#                     "Country: {asn_country}, Reverse DNS: {reverse_dns}, Services: {open_service}"
#                     .format(**{
#                         **entry,
#                         "open_service": entry.get("open_service", "").replace("\n", " ")
#                     })
#                 )
#
#         ns_res = res.get('dns_records', {}).get('ns')
#         if ns_res:
#             print("\n####### NS #######")
#             for entry in ns_res:
#                 print(
#                     "{host} ({ip}) AS: {as}, Range: {asn_range}, Name: {asn_name}, "
#                     "Country: {asn_country}, Reverse DNS: {reverse_dns}, Services: {open_service}"
#                     .format(**{
#                         **entry,
#                         "open_service": entry.get("open_service", "").replace("\n", " ")
#                     })
#                 )
#
#         txt_res = res.get('dns_records', {}).get('txt')
#         if txt_res:
#             print("\n####### TXT #######")
#             for entry in txt_res:
#                 print(entry)
#
#         # Path to save the JSON file
#         output_file = f"{url_to_search}_dnsdumpster_results.json"
#
#         # Save the response in a JSON file
#         with open(output_file, "w", encoding="utf-8") as file:
#             json.dump(res, file, indent=4, ensure_ascii=False)
#
#         print(f"\nResults saved to: {output_file}")
#
#         # Save image_data if it exists
#         image_data = res.get('image_data')
#         if image_data:
#             try:
#                 with open(f"{url_to_search}_network_map.png", "wb") as image_file:
#                     image_file.write(base64.b64decode(image_data))
#                 print(f"\nNetwork mapping image saved to: {url_to_search}_network_map.png")
#             except Exception as e:
#                 print(f"Error saving network mapping image: {e}")
#
#         # Save xls_data if it exists
#         xls_data = res.get('xls_data')
#         if xls_data:
#             try:
#                 with open(f"{url_to_search}_hosts.xlsx", "wb") as xls_file:
#                     xls_file.write(base64.b64decode(xls_data))
#                 print(f"\nXLS hosts file saved to: {url_to_search}_hosts.xlsx")
#             except Exception as e:
#                 print(f"Error saving XLS hosts file: {e}")
#
#     else:
#         print("No DNS records found.")
