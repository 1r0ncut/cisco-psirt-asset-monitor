import requests, argparse, rapidjson, urllib3, xlrd, xlsxwriter, openpyxl
from tqdm import tqdm
import os
import sys

# Disable requests warning
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ---------------------------------------------------------------------
# Cisco API endpoints and credentials (update client_id / client_pass)
# ---------------------------------------------------------------------
api_token_url = "https://id.cisco.com/oauth2/default/v1/token"
client_id =   ""     # Your Cisco API "Key" from the new PSIRT app
client_pass = ""     # Your Cisco API "Client Secret" from the new PSIRT app

# OpenVuln v2 endpoints on apix.cisco.com
BASE_API = "https://apix.cisco.com/security/advisories/v2"
api_sec_adv_ios = f"{BASE_API}/OSType/ios?version="
api_sec_adv_nx  = f"{BASE_API}/OSType/nxos?version="

access_token = ""

# ---------------------------------------------------------------------
# Argument parser definition (no parse_args() here)
# ---------------------------------------------------------------------
parser = argparse.ArgumentParser(
    prog="CiscoAssetsMonitor",
    description=(
        "Query Cisco PSIRT APIs (IOS / NX-OS) for security advisories "
        "based on an Excel asset inventory."
    ),
    epilog=(
        "Examples:\n"
        "  python3 CiscoAssetsMonitor.py -f inventory.xlsx --output-by-adv\n"
        "  python3 CiscoAssetsMonitor.py -f inventory.xlsx --output-by-ip\n"
        "  python3 CiscoAssetsMonitor.py -f inventory.xlsx --output-all\n\n"
        "The input Excel file must have at least these columns:\n"
        "  - 'IP Address'        (device IP)\n"
        "  - 'Hostname'          (device hostname)\n"
        "  - 'Hardware Model'    (device hardware model)\n"
        "  - 'image'             (Cisco IOS/NX-OS image or version)"
    ),
    formatter_class=argparse.RawDescriptionHelpFormatter,
)

parser.add_argument(
    "-f", "--file",
    required=True,
    metavar="INVENTORY.xlsx",
    help=(
        "Path to the Excel asset inventory file. "
        "The first sheet will be parsed and the first row must contain column headers."
    ),
)

parser.add_argument(
    "--output-by-adv",
    help=(
        "Generate an .xlsx sheet grouped by advisory, with merged rows for impacted "
        "IP addresses and versions. Default if no output option is provided."
    ),
    action="store_true",
)

parser.add_argument(
    "--output-by-ip",
    help=(
        "Generate an .xlsx sheet grouped by IP address (advisories may be repeated "
        "across rows)."
    ),
    action="store_true",
)

parser.add_argument(
    "--output-all",
    help=(
        "Generate both output formats in a single .xlsx file (one sheet per view)."
    ),
    action="store_true",
)

# ---------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------
def get_api_token(url):
    global access_token
    
    response = requests.post(
        url,
        verify=False,
        data={
            "grant_type": "client_credentials",
            "client_id": client_id,
            "client_secret": client_pass,
        },
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    resp_json = rapidjson.loads(response.text)
    if "access_token" not in resp_json:
        access_token = resp_json.get("error_description", "Unknown error")
        return False
    else:
        access_token = resp_json["access_token"]
        return True


def rest_api_request(url):
    global access_token
    response = requests.get(
        url,
        verify=False,
        headers={"Authorization": "Bearer " + access_token},
    )
    return rapidjson.loads(response.text)


def parse_excel_file(excel_file):
    entry_array = []

    if excel_file.lower().endswith(".xlsx"):
        wb = openpyxl.load_workbook(excel_file, data_only=True)
        sheet = wb[wb.sheetnames[0]]

        # First row = headers
        header_row = next(sheet.iter_rows(min_row=1, max_row=1, values_only=True))
        headers = list(header_row)

        # Subsequent rows = data
        for row in sheet.iter_rows(min_row=2, values_only=True):
            if all(cell is None for cell in row):
                continue  # skip completely empty rows
            curr_dict = {}
            for idx, value in enumerate(row):
                if idx < len(headers) and headers[idx] is not None:
                    curr_dict[headers[idx]] = value
            entry_array.append(curr_dict)

        return entry_array

    # Handle legacy .xls files with xlrd (old behavior)
    xls_file = xlrd.open_workbook(excel_file)
    sheet = xls_file.sheet_by_index(0)

    # Create a dictionary for each row and then add it to the asset inventory array
    for i in range(1, sheet.nrows):
        curr_dict = {}
        for j in range(sheet.ncols):
            curr_dict[sheet.cell_value(0, j)] = sheet.cell_value(i, j)
        entry_array.append(curr_dict)

    return entry_array


def get_vers_adv_dict(parsed_excel):
    # Array of dictionaries containing advisories for each version
    version_adv_map = {}

    print("Starting searching for Cisco Security Advisories...")
    for excel_entry in tqdm(parsed_excel):
        # If we already have all the advisories for a specific version we can continue
        if (excel_entry["image"] not in version_adv_map):
            res = rest_api_request(api_sec_adv_ios + excel_entry["image"])
        else:
            continue

        if ("errorCode" in res.keys()):
            if (res["errorCode"] == "INVALID_IOS_VERSION"):
                res = rest_api_request(api_sec_adv_nx + excel_entry["image"])
            else:
                continue

        if ("advisories" not in res.keys()):
            continue

        advisories = res["advisories"]
        version_adv_map[excel_entry["image"]] = []

        for adv in advisories:
            adv_dict = {}
            adv_dict["cvss"] = adv["cvssBaseScore"]
            adv_dict["impact"] = adv["sir"]
            adv_dict["advisoryTitle"] = adv["advisoryTitle"].replace(",", "")
            adv_dict["publicationUrl"] = adv["publicationUrl"]
            version_adv_map[excel_entry["image"]].append(adv_dict)

    return version_adv_map


def array_to_str(array):
    res = ""
    for i in range(0, len(array)):
        if (i == len(array)):
            res += array[i]
        else:
            res += array[i] + "\n"

    return res


# ---------------------------------------------------------------------
# main() – all argument handling and flow control happens here
# ---------------------------------------------------------------------
def main():
    # If no arguments at all, show help and exit before doing anything
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    args = parser.parse_args()

    # Basic validation of input file
    if not os.path.isfile(args.file):
        parser.error(f"Input file not found: {args.file}")

    if not (args.file.lower().endswith(".xls") or args.file.lower().endswith(".xlsx")):
        parser.error("Input file must be an Excel .xls or .xlsx file")

    # If user did not specify any output option, default to output-by-adv
    if not (args.output_by_adv or args.output_by_ip or args.output_all):
        args.output_by_adv = True

    excel_asset_inventory_path = args.file

    # Validate credentials before hitting Cisco
    if not client_id or not client_pass:
        print("Error: client_id / client_pass are not configured in the script.")
        sys.exit(1)

    if get_api_token(api_token_url):
        parsed_excel = parse_excel_file(excel_asset_inventory_path)

        # Array of dictionaries containing advisories for each version
        vers_adv_map = get_vers_adv_dict(parsed_excel)

        # New Excel object
        workbook = xlsxwriter.Workbook("assets_cisco_advisories.xlsx")

        if (args.output_by_ip or args.output_all):
            # Create new excel sheet
            worksheet = workbook.add_worksheet("CiscoAssetsMonitorByIP")

            # Writing all column names
            worksheet.write(0, 0, "IP Address")
            worksheet.write(0, 1, "Hostname")
            worksheet.write(0, 2, "Hardware Model")
            worksheet.write(0, 3, "Version")
            worksheet.write(0, 4, "CVSS")
            worksheet.write(0, 5, "Impact")
            worksheet.write(0, 6, "Advisory Title")
            worksheet.write(0, 7, "Publication URL")

            rows_count = 1
            for excel_entry in parsed_excel:
                # Skip invalid versions
                if (excel_entry["image"] not in vers_adv_map):
                    continue

                for adv in vers_adv_map[excel_entry["image"]]:
                    worksheet.write(rows_count, 0, excel_entry["IP Address"])
                    worksheet.write(rows_count, 1, excel_entry["Hostname"])
                    worksheet.write(rows_count, 2, excel_entry["Hardware Model"])
                    worksheet.write(rows_count, 3, excel_entry["image"])
                    worksheet.write(rows_count, 4, adv["cvss"])
                    worksheet.write(rows_count, 5, adv["impact"])
                    worksheet.write(rows_count, 6, adv["advisoryTitle"])
                    worksheet.write(rows_count, 7, adv["publicationUrl"])

                    # Increment row number
                    rows_count += 1

        if (args.output_by_adv or args.output_all or (args.output_by_adv and args.output_all)):
            # Create new excel sheet
            worksheet = workbook.add_worksheet("CiscoAssetsMonitorByAdv")

            # Writing all column names
            worksheet.write(0, 0, "Advisory Title")
            worksheet.write(0, 1, "CVSS")
            worksheet.write(0, 2, "Impact")
            worksheet.write(0, 3, "Publication URL")
            worksheet.write(0, 4, "Impacted IP Addresses")
            worksheet.write(0, 5, "Impacted Version")

            # Format to use in the merged range
            merge_format_ip = workbook.add_format({"align": "left", "valign": "vcenter"})
            merge_format_version = workbook.add_format({"align": "center", "valign": "vcenter"})

            rows_count = 1
            already_processed_vers = []
            for excel_entry in parsed_excel:
                # Skip invalid versions
                if (excel_entry["image"] not in vers_adv_map or excel_entry["image"] in already_processed_vers):
                    continue

                # Add current version to already processed versions
                already_processed_vers.append(excel_entry["image"])

                # Save from which row we start adding entry
                initial_row = rows_count

                for adv in vers_adv_map[excel_entry["image"]]:
                    worksheet.write(rows_count, 0, adv["advisoryTitle"])
                    worksheet.write(rows_count, 1, adv["cvss"])
                    worksheet.write(rows_count, 2, adv["impact"])
                    worksheet.write(rows_count, 3, adv["publicationUrl"])

                    # Increment row number
                    rows_count += 1

                # Retrieving all IPs with the same version
                ip_same_vers = []
                for entry in parsed_excel:
                    if (entry["image"] == excel_entry["image"] and entry["IP Address"] not in ip_same_vers):
                        ip_same_vers.append(entry["IP Address"] + " (" + entry["Hostname"] + ")")

                # Merging rows for "Impacted IP Addresses"
                worksheet.merge_range(initial_row, 4, rows_count - 1, 4, array_to_str(ip_same_vers), merge_format_ip)

                # Merging rows for "Impacted Version"
                worksheet.merge_range(initial_row, 5, rows_count - 1, 5, excel_entry["image"], merge_format_version)

        workbook.close()
        print("File created: assets_cisco_advisories.xlsx")
    else:
        print("Error: " + access_token)


# ---------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------
if __name__ == "__main__":
    main()
