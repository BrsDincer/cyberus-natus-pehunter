
# CYBERUS NATUS PEHunter

CYBERUS NATUS PEHunter is a comprehensive tool designed to analyze PE files and extract vital metadata, import/export information, suspicious behavior, and potential indicators of compromise (IOC). It is particularly useful in malware analysis and threat intelligence workflows. The tool offers several command-line options for targeted analysis based on the user’s needs.

## Features

- **Metadata Extraction**: Extract detailed metadata such as PE timestamp, checksum, and subsystem information, offering a thorough overview of the file's attributes.
  
- **Suspicious Imports Detection**: Identifies potentially malicious imports by analyzing patterns commonly associated with malware behavior, such as functions tied to process injection, network activity, or privilege escalation.

- **Normal Imports Analysis**: Lists all regular imports used by the PE file for deeper inspection of its functional dependencies.

- **Section Information**: Analyzes PE sections, including their entropy, size, and permissions, to determine whether sections exhibit unusual characteristics such as excessive entropy or non-standard flags.

- **Export Analysis**: Extracts and displays information on the exported functions of the PE file, helping to detect trojanized or backdoored software.

- **Debug Information**: Parses the debug directory of PE files to expose details about how the binary was built, which can provide insight into compiler behavior or potential misconfigurations.

- **Relocation Table Parsing**: Provides details on the relocation table, useful for identifying binary characteristics like ASLR (Address Space Layout Randomization) compatibility.

- **Threat Local Storage**: Extracts any threat-related information from the local storage, including data structures tied to persistent threats.

- **Resource Information**: Inspects the resources embedded within the PE file, such as icons, strings, and version information, which might contain hidden malicious payloads.

- **Certificate Extraction**: Displays the digital signature information of the binary, allowing verification of the file’s authenticity and trustworthiness.

- **YARA Rule Matching**: Matches YARA rules either from a specified file or folder against the PE file to detect malicious signatures and behavioral patterns.

- **Anti-VM Behavior Detection**: Identifies techniques used by malware to detect and evade analysis within virtual machine environments, such as timing checks, CPUID exploitation, or unusual system calls.

- **Overlay Information**: Displays overlay information in the file, often used by packers or malware to store additional code or data.

- **Packer Signature Detection**: Detects whether the binary has been packed using known packers, which could indicate attempts to obfuscate malicious payloads.

- **Entry Point Detection**: Extracts the entry point of the PE file to help pinpoint where execution starts, crucial in reverse engineering and unpacking efforts.

- **String Behavior Analysis**: Analyzes strings within the PE file, detecting common malicious patterns or anomalous strings that could indicate C2 communication, encoded payloads, or sensitive data.

- **XOR Ratio Detection**: Evaluates the XOR delta ratio to detect obfuscation techniques that involve XOR encoding, a common tactic used in malware to hide its payload.

- **Section Extraction**: Extracts specific sections from the binary for deeper offline analysis, useful in situations where only certain parts of the binary need further investigation.

- **Binary Behavior Detection**: Analyzes the binary behavior, including its interaction with system resources and external connections, to detect suspicious activity.

- **Botnet C2 IP Detection**: Cross-references the file with FeodoTracker to detect known botnet command and control (C2) IP addresses.

- **Malicious IP and URL Detection**: Integrates with URLHaus and Digital Side threat intelligence to detect known malicious IPs and URLs associated with the file.

- **Geolocation Information**: Provides geolocation data for IP addresses found within the PE file, aiding in threat attribution efforts.

- **Threat Fox Integration**: Queries IOC information from Threat Fox, providing real-time threat intelligence on indicators like file hashes, domains, and IPs.

- **Personal Identifiable Information (PII) Detection**: Extracts PII values present in the file, providing critical information when handling privacy-sensitive data.

- **DLL List Extraction**: Retrieves a comprehensive list of DLLs utilized by the PE file, allowing analysts to detect dependencies that may signal malicious behavior.

- **Capability Detection**: Detects capabilities within the binary, such as file system access, network communication, or privilege escalation techniques, helping assess the overall threat level.

## Usage

Below are the primary command-line arguments supported by CYBERUS NATUS PEHunter:

| Argument               | Description                                             |
|------------------------|---------------------------------------------------------|
| `--metainfo`            | Extracts metadata information from the PE file.         |
| `--simport`             | Displays suspicious imports.                            |
| `--nimport`             | Displays normal imports.                                |
| `--sections`            | Provides detailed section information.                  |
| `--exports`             | Extracts export information.                            |
| `--debugs`              | Displays debug information.                             |
| `--relocations`         | Extracts relocations.                                   |
| `--threatlocalstorage`  | Shows threat-related local storage details.             |
| `--resources`           | Displays resource information.                          |
| `--certificate`         | Extracts the certificate attached to the PE file.       |
| `--yaraFile`            | Matches YARA rules from a specified file.               |
| `--yaraFolder`          | Matches YARA rules from a specified folder.             |
| `--general`             | Displays general information about the file.            |
| `--antivmbehaviour`     | Detects anti-virtual machine behavior.                  |
| `--overlay`             | Displays overlay information in the file.               |
| `--packersignature`     | Detects packer signatures.                              |
| `--entrypoint`          | Extracts the entry point of the PE file.                |
| `--strbehaviour`        | Analyzes string behavior in the file.                   |
| `--strlogical`          | Displays logical strings in the file.                   |
| `--xorratio`            | Shows XOR ratio details.                                |
| `--sectionInit`         | Extracts a specific section from the file.              |
| `--binarybehaviour`     | Analyzes binary behavior of the file.                   |
| `--drivebehaviour`      | Detects driver behavior.                                |
| `--botnetIP`            | Detects botnet C2 IPs using FeodoTracker.               |
| `--maliciousIP`         | Detects malicious IPs using URLHaus.                    |
| `--digitalURL`          | Detects malicious URLs using Digital Side.              |
| `--digitalIP`           | Detects malicious IPs using Digital Side.               |
| `--digitalAPI`          | Queries IOCs using Digital Side API.                    |
| `--domainDB`            | Retrieves domain information using DomainsDB.           |
| `--geolocationIP`       | Retrieves geolocation information using IP API.         |
| `--threatfox`           | Queries IOC information from Threat Fox.                |
| `--pii`                 | Extracts potential PII values.                          |
| `--dlllist`             | Extracts a list of DLLs used by the file.               |
| `--capability`          | Detects capabilities present in the PE file.            |

## Installation

To install the CYBERUS NATUS PEHunter tool, clone the repository and install the required dependencies:

```bash
git clone https://github.com/yourrepo/cyberus-natus-pehunter.git
cd cyberus-natus-pehunter
pip install -r requirements.txt
```

## Example Usage

Analyze a PE file for suspicious imports:

```bash
python pehunter.py --simport /path/to/pefile
```

Detect YARA rules from a specific folder:

```bash
python pehunter.py --yaraFolder /path/to/yara/folder /path/to/pefile
```

Extract and analyze PII values from the binary:

```bash
python pehunter.py --pii /path/to/pefile
```

## Contributing

Contributions are welcome! Please submit pull requests or open issues for any bugs or feature requests.
